/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { drivers/char/serial/qemudbg.c }.
 * Copyright (C) 2020, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <forx/dev.h>
#include <forx/mm/user_check.h>
#include <forx/initcall.h>
#include <forx/arch/asm.h>

#include <forx/event/dev.h>
#include <forx/fs/char.h>
#include <forx/drivers/qemudbg.h>

static int
qemu_dbg_open(struct Inode *ino, struct File *filp)
{
    Device major = DEV_MAJOR(ino->dev_no);
    Device minor = DEV_MINOR(ino->dev_no);

    if (major != CHAR_DEV_QEMU_DBG || minor != 0)
        return -ENODEV;

    return 0;
}

static int
qemu_dbg_read(struct File *filp, struct UserBuffer vbuf, size_t len)
{
    return 0;
}

static int
qemu_dbg_write(struct File *filp, struct UserBuffer vbuf, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        char c;
        int ret = user_copy_from_kernel_indexed(&c, vbuf, i);

        if (ret)
            return ret;

        outb(QEMUDBG_PORT, c);
    }

    return len;
}

struct FileOps qemu_dbg_file_ops = {
    .open = qemu_dbg_open,
    .read = qemu_dbg_read,
    .write = qemu_dbg_write,
};

static void
qemu_dbg_init(void)
{
    device_submit_char(KERN_EVENT_DEVICE_ADD, DEV_MAKE(CHAR_DEV_QEMU_DBG, 0));
}

initcall_device(qemu_dbg, qemu_dbg_init);
