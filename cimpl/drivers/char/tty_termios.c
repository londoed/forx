/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { drivers/char/tty_termios.c }.
 * Copyright (C) 2019, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <forx/sched.h>
#include <forx/wait.h>
#include <forx/mm/page_alloc.h>
#include <forx/mm/kmalloc.h>
#include <forx/mm/user_check.h>
#include <libctl/snprintf.h>

#include <forx/arch/spinlock.h>
#include <forx/arch/asm.h>
#include <forx/fs/char.h>
#include <forx/fs/fcntl.h>
#include <forx/drivers/tty.h>

#include "tty_termios.h"

static int
is_control(char ch)
{
    switch (cd) {
    case '\x01' ... '\x1F':
    case 127:
        return 1;

    default:
        return 0;
    }
}

static void
__send_input_char(struct Tty *tty, char c)
{
    char_buf_write(&tty->output_buf, &c, 1);
    wait_queue_wake(&tty->in_wait_queue);
}

static void
send_output_char(struct Tty *tty, char c)
{
    const struct TtyDriver *driver = tty->driver;

    driver->ops->write(tty, &c, 1);
}

static void
output_post_process(struct Tty *tty, const struct Termios *termios, char c)
{
    if (c == '\n' && TERMIOS_ONLCR(termios)) {
        send_output_char(tty, '\r');

        return send_output_char(tty, '\n');
    }

    if (c == '\n' && TERMIOS_ONLRET(termios))
        return send_output_char(tty, '\r');

    if (c == '\r' && TERMIOS_OCRNL(termios))
        return send_output_char(tty, '\n');

    if (TERMIOS_OLCUC(termios))
        c = toupper(c);

    send_output_char(tty, c);
}

static void
__tty_line_buf_drain(struct Tty *tty, const struct Termios *termios)
{
    size_t i;

    for (i = 0; i < tty->line_buf_pos; i++)
        __send_input_char(tty, tty->line_buf[i]);

    tty->line_buf_pos = 0;
}

void
tty_line_buf_drain(struct Tty *tty)
{
    using_mutex(&tty->lock)
        __tty_line_buf_drain(tty, &tty->termios);
}

static void
__tty_line_buf_append(struct Tty *tty, char c)
{
    if (tty->line_buf_pos < tty->line_buf_size) {
        tty->line_buf[tty->line_buf_pos] = c;
        tty->line_buf_pos++;
    }
}

static int
__tty_line_buf_remove(struct Tty *tty, char *removed)
{
    if (tty->line_buf_pos > 0) {
        tty->line_buf_pos--;
        *removed = tty->line_buf[tty->line_buf_pos];

        return 1;
    }

    return 0;
}

static int
get_char_render_length(struct Termios *termios, char ch)
{
    if (!TERMIOS_ECHO(termios) || !TERMIOS_ECHOCTL(termios))
        return 1;

    if (is_control(ch))
        return 2;

    return 1;
}

static void
icanon_char(struct Tty *tty, struct Termios *termios, char c)
{
    using_mutex(&tty->lock) {
        if (c == termios->c_cc[VEOF]) {
            tty->ret0 = 1;
            wait_queue_wake(&tty->in_wait_queue);

            return;
        }

        if (c == termios->c_cc[VERASE]) {
            char prev;

            if (__tty_line_buf_remove(tty, &prev) && TERMIOS_ECHO(termios) &&
                TERMIOS_ECHOE(termios)) {

                int len = get_char_render_length(termios, prev);
                int i;

                for (i = 0; i < len; i++) {
                    output_post_process(tty, termios, '\b');
                    output_post_process(tty, termios, ' ');
                    output_post_process(tty, termios, '\b');
                }
            }

            return;
        }

        __tty_line_buf_append(tty, c);

        if (c == '\n')
            __tty_line_buf_drain(tty, termios);
    }
}

static void
echo_char(struct Tty *tty, struct Termios *termios, char c)
{
    // ECHOE is handled at the ICANON level //
    if (TERMIOS_ECHOE(termios) && TERMIOS_ICANON(termios) && c == termios->c_cc[VERASE])
        return;

    if (TERMIOS_ECHOCTL(termios) && is_control(c) && c != '\t' && c != '\n') {
        output_post_process(tty, termios, '^');
        output_post_process(tty, termios, c ^ 0x40);
    } else {
        output_post_process(tty, termios, c);
    }
}

static void
tty_pgrp_signal(struct Tty *tty, struct Termios *termios, int sig)
{
    Pid pgrp;

    using_mutex(&tty->lock)
        pgrp = tty->fg_pgrp;

    if (pgrp) {
        kprintf(KERN_TRACE, "tty: Sending %d to %d\n", sig, pgrp);
        sched_task_send_signal(-pgrp, sig, 0);

        if (!TERMIOS_NOFLSH(termios)) {
            tty_flush_input(tty);
            tty_flush_output(tty);
        }
    }
}

static int
isig_handle(struct Tty *tty, struct Termios *termios, char c)
{
    if (c == termios->c_cc[VINTR]) {
        tty_pgrp_signal(tty, termios, SIGINT);

        return 1;
    } else if (c == termios->c_cc[VSUSP]) {
        tty_pgrp_signal(tty, termios, SIGTSTP);

        return 1;
    }

    return 0;
}

// Returns `1` if the input should be skipped //
static int
input_preprocess(struct Tty *tty, struct Termios *termios, char *c)
{
    if (*c == '\r' && TERMIOS_IGNCR(termios))
        return 1;
    else if (*c == '\r' && TERMIOS_ICRNL(termios))
        *c = '\n';
    else if (*c == '\n' && TERMIOS_INLCR(termios))
        *c = '\r';

    if (TERMIOS_ISTRIP(termios))
        *c = *c & 0x7F;

    if (TERMIOS_IUCLC(termios))
        *c = tolower(*c);

    return 0;
}

void
tty_process_input(struct Tty *tty, const char *buf, size_t buf_len)
{
    size_t i;
    struct Termios termios;

    using_mutex(&tty->lock)
        termios = tty->termios;

    for (i = 0; i < buf_len; i++) {
        char ch = buf[i];

        if (input_preprocess(tty, &termios, &ch))
            continue;

        if (TERMIOS_ISIG(&termios) && isig_handle(tty, &termios, ch))
            continue;

        if (TERMIOS_ECHO(&termios))
            echo_char(tty, &termios, ch);

        if (TERMIOS_ICANON(&termios)) {
            icanon_char(tty, &termios, ch);
        } else {
            using_mutex(&tty->lock)
                __send_input_char(tty, ch);
        }
    }
}

int
tty_process_output(struct Tty *tty, struct UserBuffer buf, size_t buf_len)
{
    struct Termios termios;

    using_mutex(&tty->lock)
        termios = tty->termios;

    size_t i;

    for (i = 0; i < buf_len; i++) {
        char ch;
        int ret = user_copy_to_kernel_indexed(&ch, buf, i);

        if (ret)
            return ret;

        output_post_process(tty, &termios, ch);
    }

    return buf_len;
}
