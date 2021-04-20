/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { drivers/char/mem.c }.
 * Copyright (C) 2016, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <forx/dev.h>
#include <forx/initcall.h>

#include <forx/event/dev.h>
#include <forx/fs/char.h>
#include <forx/drivers/loop.h>
#include <forx/drivers/mem.h>

static int
mem_open(struct Inode *ino, struct File *filp)
{
    Device minor = DEV_MINOR(ino->dev_no);
    int ret = 0;

    switch (minor) {
    case MEM_MINOR_ZERO:
        filp->ops = &mem_zero_file_ops;
        break;

    case MEM_MINOR_FULL:
        filp->ops = &mem_full_file_ops;
        break;

    case MEM_MINOR_NULL:
        filp->ops = &mem_null_file_ops;
        break;

    case MEM_MINOR_LOOP_CONTROL:
        filp->ops = &loop_control_ops;
        break;

    default:
        ret = -ENODEV;
        break;
    }

    return ret;
}

struct FileOps mem_file_ops = {
    .open = mem_open,
    .release = NULL,
    .read = NULL,
    .write = NULL,
    .lseek = NULL,
    .readdir = NULL,
};

static void
mem_init(void)
{
    device_submit_char(KERN_EVENT_DEVICE_ADD, DEV_MAKE(CHAR_DEV_MEM, MEM_MINOR_ZERO));
    device_submit_char(KERN_EVENT_DEVICE_ADD, DEV_MAKE(CHAR_DEV_MEM, MEM_MINOR_NULL));
    device_submit_char(KERN_EVENT_DEVICE_ADD, DEV_MAKE(CHAR_DEV_MEM, MEM_MINOR_FULL));
    device_submit_char(KERN_EVENT_DEVICE_ADD, DEV_MAKE(CHAR_DEV_MEM, MEM_MINOR_LOOP_CONTROL));
}

initcall_device(mem, mem_init);
