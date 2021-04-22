/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { drivers/char/mem_zero.c }.
 * Copyright (C) 2016, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <forx/mm/user_check.h>

#include <forx/fs/char.h>
#include <forx/drivers/mem.h>

static int
mem_zero_read(struct File *filp, struct UserBuffer buf, size_t len)
{
    int ret = user_memset_from_kernel(buf, 0, len);

    if (ret)
        return ret;

    return len;
}

static int
mem_zero_write(struct File *filp, struct UserBuffer buf, size_t len)
{
    return len;
}

static Off
mem_zero_lseek(struct File *filp, Off offset, int whence)
{
    return filp->offset = 0;
}

struct FileOps mem_zero_file_ops = {
    .open = NULL,
    .release = NULL,
    .read = mem_zero_read,
    .write = mem_zero_write,
    .lseek = mem_zero_lseek,
    .readdir = NULL,
};
