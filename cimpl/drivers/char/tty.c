/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { drivers/char/tty.c }.
 * Copyright (C) 2016, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <forx/sched.h>
#include <forx/wait.h>
#include <forx/dev.h>
#include <forx/mm/page_alloc.h>
#include <forx/mm/kmalloc.h>
#include <forx/mm/user_check.h>
#include <libctl/snprintf.h>

#include <forx/area/spinlock.h>
#include <forx/arch/asm.h>
#include <forx/fs/char.h>
#include <forx/fs/fcntl.h>
#include <forx/event/dev.h>
#include <forx/drivers/screen.h>
#include <forx/drivers/keyboard.h>
#include <forx/drivers/console.h>
#include <forx/drivers/com.h>
#include <forx/drivers/tty.h>

#include "tty_termios.h"

const struct Termios default_termios = {
    .c_iflag = ICRNL,
    .c_oflag = OPOST | ONCLR,
    .c_lflag = ISIG | ICANON | ECHO | ECHOE | ECHOCTL,
    .c_cflag = B38400,
    .c_cc = {
        [VINTR] = 0x03,
        [VERASE] = 0x7F,
        [VSUSP] = 0x1A,
        [VEOF] = 0x04,
    },
};

/**
 * The TTY system sits in-between the terminal (The combination of the screen +
 * keyboard) and the processes being run (ex. Shell). The kernel does processing
 * on the characters received from the terminal and sends them to the process,
 * and then also does processing on the characters received from the process,
 * and eventually sends them to the terminal.
 *
 * The settings for the TTY are controlled via the `termios` structure (which
 * userspace can modify), and most the the handling happens in tty_termios.c.
 *
 * When teh hardware has data ready, it saves it into an internal buffer
 * (somewhere) and wakes up the tty's work entry. The tty_pump() will then
 * be scheduled onto any existing kwork threads to have the data from the
 * hardware processed.
 *
 * Processes using the tty call the tty_read() function from a `struct File`.
 * The tty_read() function then attempts to read from the buffer on the tty
 * holding data ready to be read. If not enough data is there, the process
 * sleeps on the `in_wait_queue`. The kernel-thread wakes up the in_wait_queue
 * after processing data that results in data ready to be sent to the process.
 *
 * For data coming in via processes, they call tty_write(), at which point the
 * data is immediately processed by the kernel as it comes in.
**/
static Spinlock tty_list_lock = SPINLOCK_INIT();
static ListHead tty_list = LIST_HEAD_INIT(tty_list);

void
tty_pump(struct Work *work)
{
    struct Tty *tty = container_of(work, struct Tty, work);
    char buf[64];
    size_t buf_len = 0;

    using_spinlock(&tty->input_buf_lock)
        buf_len = char_buf_read(&tty->input_buf, buf, sizeof(buf));

    /**
     * If it's possible input_buf still has data, then schedule us to run again
     * to read more.
    **/
    if (buf_len == sizeof(buf))
        work_schedule(work);

    tty_process_input(tty, buf, buf_len);
}

static void
tty_create(struct TtyDriver *driver, Device devno)
{
    struct Tty *tty = kmalloc(sizeof(*tty), PAL_KERNEL);

    if (!tty)
        return;

    tty_init(tty);
    tty->driver = driver;
    tty->device_no = devno;
    tty->output_buf.buffer = page_alloc_va(0, PAL_KERNEL);
    tty->output_buf.len = PAGE_SIZE;

    tty->input_buf.buffer = page_alloc_va(0, PAL_KERNEL);
    tty->input_buf.len = PAGE_SIZE;
    tty->winsize = default_winsize;
    tty->termios = default_termios;

    kprintf(KERN_TRACE, "Termios setting: %d\n", tty->termios.c_lflag);

    tty->line_buf = page_alloc_va(0, PAL_KERNEL);
    tty->line_buf_size = PAGE_SIZE;
    tty->line_buf_pos = 0;

    using_spinlock(&tty_list_lock)
        list_add_tail(&tty_list, &tty->tty_node);

    (driver->ops->init)(tty);
    device_submit_char(KERN_EVENT_DEVICE_ADD, devno);
}

void
tty_driver_register(struct TtyDriver *driver)
{
    size_t i;

    for (i = driver->minor_size; i <= driver->minor_end; i++)
        tty_create(driver, DEV_MAKE(driver->major, i));
}

static struct Tty *
tty_find(Device dev)
{
    struct Tty *tty;

    using_spinlock(&tty_list_lock) {
        list_foreach_entry(&tty_list, tty, tty_node) {
            if (tty->device_no != dev)
                continue;

            return tty;
        }
    }

    return NULL;
}

void
tty_add_input(struct Tty *tty, const char *buf, size_t len)
{
    using_spinlock(&tty->input_buf_lock) {
        char_buf_write(&tty->input_buf, buf, len);
        work_schedule(&tty->work);
    }
}

void
tty_add_input_str(struct Tty *tty, const char *str)
{
    size_t len = strlen(str);

    using_spinlock(&tty->input_buf_lock) {
        char_buf_write(&tty->input_buf, str, len);
        work_schedule(&tty->work);
    }
}

void
tty_flush_input(struct Tty *tty)
{
    using_spinlock(&tty->input_buf_lock)
        char_buf_char(&tty->input_buf);
}

void
tty_flush_output(struct Tty *tty)
{
    using_mutex(&tty->lock)
        char_buf_clear(&tty->output_buf);
}

static int
tty_read(struct File *filp, struct UserBuffer vbuf, size_t len)
{
    struct Tty *tty = filp->priv_data;
    size_t orig_len = len;
    int ret = 0;

    if (!tty)
        return -ENOTTY;

    using_mutex(&tty->lock) {
        while (orig_len == len) {
            size_t read_count = char_buf_read_user(&tty->output_buf, vbuf, len);
            vbuf = user_buffer_index(vbuf, read_count);
            len -= read_count;

            /**
             * The ret0 flag forces an immediate return from read.
             * When there is no data, we end-up returning zero, which
             * represents EOF.
            **/
            if (tty->ret0) {
                tty->ret0 = 0;
                break;
            }

            if (len != orig_len)
                break;

            if (flag_test(&filp->flags, FILE_NONBLOCK)) {
                ret = -EAGAIN;
                break;
            }

            // Nice little dance to wait for data or a signal //
            ret = wait_queue_event_intr_mutex(&tty->in_wait_queue,char_buf_has_data(&tty->output_buf) ||
                tty->ret0, &tty->lock);

            if (ret)
                return ret;
        }
    }

    if (!ret)
        return orig_len - len;
    else
        return ret;
}

/**
 * Used for things like the seg-fault message.
**/
int
tty_write_buf_user(struct Tty *tty, struct UserBuffer buf, size_t len)
{
    if (!tty)
        return -ENOTTY;

    return tty_process_output(tty, buf, len);
}

int
tty_write_buf(struct Tty *tty, const char *buf, size_t len)
{
    return tty_write_buf_user(tty, make_kernel_buffer(buf), len);
}

static int
tty_write(struct File *filp, struct UserBuffer vbuf, size_t len)
{
    return tty_write_buf_user(filp->priv_data, vbuf, len);
}

static int
tty_poll(struct File *filp, struct PollTable *table, int events)
{
    struct Tty *tty = filp->priv_data;
    int ret = 0;

    if (!tty)
        return POLLERR;

    using_mutex(&tty->lock) {
        if (events & POLLIN) {
            if (char_buf_has_data(&tty->output_buf))
                ret |= POLLIN;

            poll_table_add(table, &tty->in_wait_queue);
        }

        if (events & POLLOUT)
            ret |= POLLOUT;
    }

    return ret;
}

static int
tty_open(struct Inode *ino, struct File *filp)
{
    struct Task *current = cpu_get_local()->current;
    int noctty = flag_test(&filp->flags, FILE_NOCTTY);
    int major = DEV_MAJOR(ino->dev_no);
    Device minor = DEV_MINOR(ino->dev_no);
    struct Tty *tty;

    // Special case for /dev/tty--open the current controlling TTY //
    if (minor == 0 && major == CHAR_DEV_TTY) {
        if (!current->tty)
            return -ENXIO;

        filp->priv_data = current->tty;

        return 0;
    }

    tty = tty_find(ino->dev_no);

    if (!tty)
        return -ENXIO;

    filp->priv_data = tty;
    kprintf(KERN_TRACE, "tty_open: noctty: %d, slead: %d, cur->tty: %p, id: %d\n",
        noctty, flag_test(&current->flags, TASK_FLAG_SESSION_LEADER), current->tty,
        tty->session_id);

    if (!noctty && flag_test(&current->flags, TASK_FLAG_SESSION_LEADER) && !current->tty &&
        tty->session_id == 0) {

        current->tty = tty;

        using_mutex(&tty->lock) {
            tty->session_id = current->session_id;
            tty->fg_pgrp = current->pgid;
            char_buf_clear(&tty->output_buf);
        }
    }

    return 0;
}

int
tty_resize(struct Tty *tty, const struct WinSize *new_size)
{
    Pid pgrp;

    using_mutex(&tty->lock) {
        tty->winsize = *new_size;
        pgrp = tty->fg_pgrp;
    }

    if (pgrp)
        sched_task_send_signal(-tty->fg_pgrp, SIGWINCH, 0);

    return 0;
}

static int
tty_ioctl(struct File *filp, int cmd, UserBuffer arg)
{
    int ret, state, console;
    struct Task *current = cpu_get_local()->current;
    struct Tty *tty = filp->priv_data;
    Pid tmp;
    struct Temios tmp_tios;
    struct WinSize tmp_wins;

    kprintf(KERN_TRACE, "tty_ioctl: tty: %p, cmd: %d, ctty: %p\n", tty, cmd, current->tty);

    if ((cmd >> 8) != __TIO && tty != current->tty)
        return -ENOTTY;

    switch (cmd) {
    case TIOCGPGRP:
        kprintf(KERN_TRACE, "tty_ioctl: gpgrp\n");

        using_mutex(&tty->lock)
            tmp = tty->fg_pgrp;

        return user_copy_from_kernel(arg, tmp);

    case TIOCSPGRP:
        kprintf(KERN_TRACE, "tty_ioctl: spgrp\n");
        ret = user_copy_from_kernel(&tmp, arg);

        if (ret)
            return ret;

        using_mutex(&tty->lock)
            tty->fg_pgrp = tmp;

        return 0;

    case TIOCGSID:
        kprintf(KERN_TRACE, "tty_ioctl: gsid\n");

        using_mutex(&tty->lock)
            tmp = tty->session_id;

        return user_copy_from_kernel(arg, tmp);

    case TCGETS:
        kprintf(KERN_TRACE, "tty_ioctl: get termios\n");

        using_mutex(&tty->lock)
            tmp_tios = tty->termios;

        return user_copy_from_kernel(arg, tmp_tios);

    case TCSETS:
        kprintf(KERN_TRACE, "tty_ioctl: set termios\n");
        ret = user_copy_from_kernel(&tmp_tios, arg);

        if (ret)
            return ret;

        using_mutex(&tty->lock)
            tty->termios = tmp_tios;

        tty_line_buf_drain(tty);

        return 0;

    case TIOCGWINSZ:
        kprintf(KERN_TRACE, "tty_ioctl: get winsize\n");

        using_mutex(&tty->lock)
            tmp_wins = tty->winsize;

        return user_copy_from_kernel(arg, tmp_wins);

    case TIOCSWINSZ:
        kprintf(KERN_TRACE, "tty_ioctl: set winsize\n");
        ret = user_copy_to_kernel(&tmp_wins, arg);

        if (ret)
            return ret;

        return tty_resize(tty, &tmp_wins);

    case TCFLSH:
        switch ((uintptr_t)arg.ptr) {
        case TCIFLUSH:
            tty_flush_input(tty);
            break;

        case TCOFLUSH:
            tty_flush_output(tty);
            break;

        case TCIOFLUSH:
            tty_flush_input(tty);
            tty_flush_output(tty);
            break;
        }

        break;

    case TIOSETKBD:
        state = (int)arg.ptr;

        if (state != TTY_KEYBOARD_STATE_ON && state != TTY_KEYBOARD_STATE_OFF)
            return -EINVAL;

        keyboard_set_state(state);

        return 0;

    case TIOSETCONSOLE:
        constole = (int)arg.ptr;

        if (console < 0 || console >= CONSOLE_MAX)
            return -EINVAL;

        console_switch_vt(console);

        return 0;
    }

    kprintf(KERN_TRACE, "tty_ioctl: INVALID CMD: 0x%04x\n", cmd);

    return -EINVAL;
}

struct FileOps tty_file_ops = {
    .open = tty_open,
    .read = tty_read,
    .write = tty_write,
    .poll = tty_poll,
    .ioctl = tty_ioctl,
};

static void
tty_subsystem_init(void)
{
    device_submit_char(KERN_EVENT_DEVICE_ADD, DEV_MAKE(CHAR_DEV_TTY, 0));
}

initcall_subsys(TtySubsystem, tty_subsystem_init);
