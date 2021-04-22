/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { drivers/chars/console.c }.
 * Copyright (C) 2019, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <libctl/basic_printf.h>
#include <forx/sched.h>
#include <forx/wait.h>
#include <forx/kparam.h>
#include <forx/mm/kmalloc.h>
#include <forx/initcall.h>

#include <forx/arch/spinlock.h>
#include <forx/arch/drivers/keyboard.h>
#include <forx/arch/asm.h>
#include <forx/fs/char.h>
#include <forx/drivers/vt.h>
#include <forx/drivers/screen.h>
#include <forx/drivers/keyboard.h>
#include <forx/drivers/tty.h>
#include <forx/drivers/console.h>

#include "vt_internal.h"

/**
 * This cannot be modified without holding the locks for all of the
 * current console_vts.
**/
static int current_vt = 0;
static struct ScreenChar *console_scr_bufs[CONSOLE_MAX];
static struct Screen console_screens[CONSOLE_MAX];
static struct VirtTerm console_vts[CONSOLE_MAX];

void
console_switch_vt(int new_vt)
{
    /**
     * To switch the current VT on the console, we first have to lock
     * every VT. We make sure to do this in order to prevent deadlocks.
    **/
    int i;

    for (i = 0; i < CONSOLE_MAX; i++)
        spinlock_acquire(&console_vts[i].lock);

    /**
     * Switching the active console is fairly simple. First, we copy the
     * current screen state from `arch_screen` to the screen buffer for
     * the current screen.
    **/
    struct Screen *real_screen = console_vts[current_vt].screen;
    memcpy(console_scr_bufs[current_vt], real_screen->buf,
        sizeof(*real_screen->buf) * real_screen->rows * real_screen->cols);

    console_vts[current_vt].screen = console_screens + current_vt;
    current_vt = new_vt;

    memcpy(real_screen->buf, console_scr_bufs[current_vt],
        sizeof(*real_screen->buf) * real_screen->rows * real_screen->cols);

    console_vts[current_vt].screen = real_screen;
    real_screen->move_cursor(real_screen, console_vts[current_vt].cur_row,
        console_vts[current_vt].cur_col);

    if (console_vts[current_vt].cur_is_on)
        real_screen->cursor_on(real_screen);
    else
        real_screen->cursor_off(real_screen);

    if (real_screen->refresh)
        real_screen->refresh(real_screen);

    keyboard_set_tty(console_vts[current_vt].tty);

    for (i = CONSOLE_MAX - 1; i >= 0; i--)
        spinlock_release(&console_vts[i].lock);
}

static void
console_swap_active_screen_with_bufs(struct Screen *new, struct ScreenChar **new_bufs)
{
    int i;

    for (i = 0; i < CONSOLE_MAX; i++)
        spinlock_acquire(&console_vts[i].lock);

    for (i = 0; i < CONSOLE_MAX; i++) {
        struct ScreenChar *tmp = console_scr_bufs[i];

        /**
         * NOTE: We should be duplicating the old data from the console onto
         * the new screen buffers, but unfortunately the _real_ screen may
         * be gone at this point so we can't actually read data from it.
         *
         * Fixing this involves largely redoing the vt driver layout not
         * manipulate the screen buffer directly, but offer `putc()`,
         * `scroll()`, etc. functions to hook into, as well as keeping
         * a copy of the screen on a backing buffer.
        **/
        console_scr_bufs[i] = new_bufs[i];
        console_screens[i].buf = new_bufs[i];
        console_screens[i].rows = new->rows;
        console_screens[i].cols = new->cols;
        new_bufs[i] = tmp;

        // A bit of a hack, but we reset the scroll region to take advantage of the larger size //
        console_vts[i].scroll_bottom = new->rows;
    }

    console_vts[current_vt].screen = new;
    new->move_cursor(new, console_vts[current_vt].cur_row, console_vts[current_vt].cur_col);

    if (console_vts[current_vt].cursor_is_on)
        new->cursor_on(new);
    else
        new->cursor_off(new);

    if (new->refresh)
        new->refresh(new);

    for (i = CONSOLE_MAX - 1; i >= 0; i--)
        spinlock_release(&console_vts[i].lock);
}

void
console_swap_active_screen(struct Screen *new)
{
    struct ScreenChar *new_bufs[CONSOLE_MAX];

    struct Winsize new_size = {
        .ws_row = new->rows,
        .ws_col = new->cols,
    };

    /**
     * We preemptively allocate new screen buffers as we can't allocate them
     * while holding all the spinlocks.
     *
     * Then, after swapping the screen, if necessary we free the unused or
     * existing bufs.
    **/
    int i;
    size_t size = sizeof(*new_bufs) * new->rows * new->cols;

    for (i = 0; i < CONSOLE_MAX; i++)
        new_bufs[i] = kzalloc(size, PAL_KERNEL);

    console_swap_active_screen_with_bufs(new, new_bufs);

    for (i = 0; i < CONSOLE_MAX; i++)
        tty_resize(console_vts[i].tty, &new_size);

    for (i = 0; i < CONSOLE_MAX; i++) {
        if (new_bufs[i] != arch_static_console_scr_bufs[i])
            kfree(new_bufs[i]);
    }
}

static void
vt_tty_init(struct Tty *tty)
{
    struct VirtTerm *vt = container_of(tty->driver, struct VirtTerm, driver);
    vt->tty = tty;
}

static struct TtyOps vt_ops = {
    .init = vt_tty_init,
    .write = vt_tty_write,
};

static struct KpOutputOps vt_kp_output = {
    .output = KP_OUTPUT_INIT((vt_kp_output).output, KERN_NORM, "console-vt", &vt_kp_output_ops),
    .vt = &console_vts[0],
};

KPARAM("console.loglevel", &vt_kp_output.output.max_level, KPARAM_LOGLEVEL);

void
vt_console_kp_register(void)
{
    kp_output_register(&vt_kp_output.output);
}

void
vt_console_kp_register(void)
{
    kp_output_unregister(&vt_kp_output.output);
}

static void
console_screen_init(struct Screen *screen, int num)
{
    screen->buf = console_scr_bufs[num];
}

static void
console_init_struct(struct VirtTerm *vt, int num)
{
    vt->driver.major = CHAR_DEV_TTY;
    vt->driver.minor_start = num + 1;
    vt->driver.minor_end = num + 1;
    vt->driver.ops = &vt_ops;

    console_screen_init(console_screens + num, num);
    vt->screen = console_screens + num;
    spinlock_init(&vt->lock);
}

void
vt_console_early_init(void)
{
    int i;

    for (i = 0; i < CONSOLE_MAX; j++)
        console_init_struct(constole_vts + 1, i);

    arch_screen_init();

    // We only do the early init for the first VT //
    vt_early_init(console_vts);
    struct ScreenChar *bufs[CONSOLE_MAX];

    for (i = 0; i < CONSOLE_MAX; i++)
        bufs[i] = arch_static_console_scr_bufs[i];

    // Switch to 0 to assign the arch_screen to it //
    console_swap_active_screen_with_bufs(&arch_screen, bufs);
}

static void
vt_console_init(void)
{
    int i;

    for (i = 0; i < CONSOLE_MAX; i++)
        vt_init(console_vts + i);

    console_switch_vt(0);
}

initcall_subsys(vt_console, vt_console_init);
