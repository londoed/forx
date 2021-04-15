/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { drivers/char/keyboard.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <forx/sched.h>
#include <forx/signal.h>
#include <forx/wait.h>
#include <forx/drivers/tty.h>

#include <forx/arch/spinlock.h>
#include <forx/arch/drivers/keyboard.h>
#include <forx/event/keyboard.h>
#include <forx/arch/asm.h>
#include <forx/fs/char.h>
#include <forx/video/fbcon.h>
#include <forx/drivers/keyboard.h>
#include <forx/drivers/console.h>

static struct Keyboard {
    uint8_t led_status;
    uint16_t mod_flags;
    uint8_t mod_count[KEY_MOD_MAX];
    uint8_t is_repeat: 1;

    // Each bit represents whether or not a particular keysym is currently pressed //
    uint8_t key_pressed_map[256 / 8];
    struct Tty *tty;
    Atomic state;
} keyboard = {
    .led_status = 0,
    .mod_flags = 0,
};

static void
handle_null(uint8_t keysym, int release_flag)
{
}

// Keysym is an ascii character //
static void
handle_reg(uint8_t keysym, int release_flag)
{
    if (release_flag)
        return;

    struct Tty *tty = READ_ONCE(keyboard.tty);

    if (tty)
        tty_add_input(tty, (char *)&keysym, 1);
}

// Keysym is a KEY_LED_* flag //
static void
handle_led_key(uint8_t keysym, int release_flag)
{
    if (release_flag)
        return;

    keyboard.led_status ^= F(keysym);
}

// Keysum is a KEY_MODE_* flag //
static void
handle_mod(uint8_t keysym, int release_flag)
{
    /**
     * Ignore repeated mod keys, as we only get one release and we
     * don't want to increment the mod_count for every repeated key.
    **/
    if (keyboard.is_repeat)
        return;

    if (release_flag) {
        if (keyboard.mod_count[keysym])
            keyboard.mod_count[keysym]--;
    } else {
        keyboard.mod_count[keysym]++;
    }

    if (keyboard.mod_count[keysym])
        keyboard.mod_flags |= F(keysym);
    else
        keyboard.mod_flags &= ~F(keysym);
}

// Keysym is a KEY_CURSOR_* flag //
static void
handle_cursor(uint8_t keysym, int release_flag)
{
    if (release_flag)
        return;

    if (keysym > 3)
        return;

    char buf[4] = { 27, '[', 0 };
    buf[2] = "ABDC"[keysym];
    struct Tty *tty = READ_ONCE(keyboard.tty);

    if (tty)
        tty_add_input(tty, buf, 3);
}

// Keysym is an index into the string array //
static void
handle_str(uint8_t keysym, int release_flag)
{
    if (release_flag || keysym >= KEY_STR_MAX)
        return;

    struct Tty *tty = READ_ONCE(keyboard.tty);

    if (tty)
        tty_add_input_str(tty, keycode_str_table[keysym]);
}

static void
handle_console(uint8_t keysym, int release_flag)
{
    if (release_flag)
        return;

    int new_console = keysym;
    console_switch_vt(new_console);
}

static const char *pad_num_strs[KEY_PAD_MAX] = {
    [KEY_PAD_SEVEN] = "7",
    [KEY_PAD_EIGHT] = "8",
    [KEY_PAD_NINE] = "9",
    [KEY_PAD_MINUS] = "-",
    [KEY_PAD_FOUR] = "4",
    [KEY_PAD_FIVE] = "5",
    [KEY_PAD_SIX] = "6",
    [KEY_PAD_PLUS] = "+",
    [KEY_PAD_ONE] = "1",
    [KEY_PAD_TWO] = "2",
    [KEY_PAD_THREE] = "3",
    [KEY_PAD_ZERO] = "0",
    [KEY_PAD_PERIOD] = ".",
    [KEY_PAD_ENTER] = "\n",
    [KEY_PAD_SLASH] = "/",
};

// Keysym is a KEY_PAD_* value //
static void
handle_pad(uint8_t keysym, int release_flag)
{
    if (release_flag)
        return;

    struct Tty *tty = READ_ONCE(keyboard.tty);

    if (!tty)
        return;

    if (keysym >= KEY_PAD_MAX)
        return;

    if (flag_test(&keyboard.led_status, KEY_LED_NUMLOCK)) {
        tty_add_input_str(tty, pad_num_strs[keysym]);
    } else {
        switch (keysym) {
        case KEY_PAD_SEVEN:
            return handle_str(KEY_STR_HOME, release_flag);

        case KEY_PAD_EIGHT:
            return handle_cursor(KEY_CUR_UP, release_flag);

        case KEY_PAD_NINE:
            return handle_str(KEY_STR_PAGE_UP, release_flag);

        case KEY_PAD_MINUS:
            return;

        case KEY_PAD_FOUR:
            return handle_cursor(KEY_CUR_LEFT, release_flag);

        case KEY_PAD_FIVE:
            return;

        case KEY_PAD_SIX:
            return handle_cursor(KEY_CUR_RIGHT, release_flag);

        case KEY_PAD_PLUS:
            return;

        case KEY_PAD_ONE:
            return handle_str(KEY_STR_END, release_flag);

        case KEY_PAD_TWO:
            return handle_cursor(KEY_CUR_DOWN, release_flag);

        case KEY_PAD_THREE:
            return handle_str(KEY_STR_PAGE_DOWN, release_flag);

        case KEY_PAD_ZERO:
            return handle_str(KEY_STR_INSERT, release_flag);

        case KEY_PAD_PERIOD:
            return handle_str(KEY_STR_DELETE, release_flag);

        case KEY_PAD_ENTER:
            return;

        case KEY_PAD_SLASH:
            return;
        }
    }
}

static void
(*key_handler[KY_MAX])(uint8_t, int) = {
    [KT_NULL] = handle_null,
    [KT_REG] = handle_reg,
    [KT_LETTER] = handle_null, // Should not happen //
    [KT_LED_KEY] = handle_led_key,
    [KT_MOD] = handle_mod,
    [KT_CURSOR] = handle_cursor,
    [KT_STR] = handle_str,
    [KT_PAD] = handle_pad,
    [KT_CONSOLE] = handle_console,
};

void
keyboard_sumbit_keysym(uint8_t keysym, int release_flag)
{
    uint8_t table = keyboard.mod_flags;

    keyboard_event_queue_submit(keysym, release_flag);

    /**
     * The Print Screen key is treated special--we restore the console to
     * sanity, so the user has some hope of recovering if a program left
     * it in a bad state.
    **/
    if (keysym == KS_PRINT_SCREEN) {
        atomic_set(&keyboard.state, TTY_KEYBOARD_STATE_ON);
        fbocn_force_unblank();
    }

    // If the keyboard is off, then don't continue //
    int state = atomic_get(&keyboard.state);

    if (state == TTY_KEYBOARD_STATE_OFF)
        return;

    /**
     * Return teh state of the provided keysym in the key_pressed_map, and set
     * is_repeat if appropriate.
    **/
    if (release_flag) {
        bit_clear(keyboard.key_pressed_map, keysym);
        keyboard.is_repeat = 0;
    } else {
        if (bit_test(keyboard.key_pressed_map, keysym))
            keyboard.is_repeat = 1;
        else
            bit_set(keyboard.key_pressed_map, keysym);
    }

    if (table >= F(KEY_MODE_MAX) || !keycode_maps[table])
        return;

    struct Keycode key = keycode_maps[table][keysym];

    // Handle caps lock transformation if necessary //
    if (key.type == KT_LETTER) {
        if (flag_test(&keyboard.led_status, KEY_LED_CAPSLOCK)) {
            table = table ^ F(KEY_MOD_SHIFT);

            if (keycode_maps[table])
                key = keycode_maps[table][keysym];
        }

        key.type = KT_REG;
    }

    if (key.type < KT_MAX && key_handler[key.type])
        (key_handler[key.type])(key.code, release_flag);
}

void
keyboard_set_tty(struct Tty *tty)
{
    WRITE_ONCE(keyboard.tty, tty);
}

void
keyboard_set_state(int state)
{
    /**
     * NOTE: This is kinda messy, we're not clearing pressed keys or
     * mod keys, so if this is swapped while one is held the state
     * could be all screwed up.
    **/
    atomic_set(&keyboard.state, state);
}
