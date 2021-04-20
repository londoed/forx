/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { drivers/char/mem_full.c }.
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
mem_full_read(struct File *filp, struct UserBuffer buf, size_t len)
{
    int ret = user_memset_from_kernel(buf, 0, len);

    if (ret)
        return ret;

    return len;
}

static int
mem_full_write(struct File *filp, struct UserBuffer buf, size_t len)
{
    return -ENOSPC;
}

static off_t
mem_full_lseek(struct File *filp, Off offset, int whence)
{
    switch (whence) {
    case SEEK_SET:
        return filp->offset = offset;

    case SEEK_CUR:
        filp->offset += offset;

        if (filp->offset < 0)
            filp->offset = 0;

        return filp->offset;

    default:
        return -EINVAL;
    }
}

struct FileOps mem_full_file_ops = {
    .open = NULL,
    .release = NULL,
    .read = mem_full_read,
    .write = mem_full_write,
    .lseek = mem_full_lseek,
    .readdir = NULL,
};
