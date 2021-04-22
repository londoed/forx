/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { drivers/chars/mem_null.c }.
 * Copyright (C) 2016, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>

#include <forx/fs/char.h>
#include <forx/drivers/mem.h>

static int
mem_null_read(struct File *filp, struct UserBuffer buf, size_t len)
{
    return 0;
}

static int
mem_null_write(struct File *filp, struct UserBuffer buf, size_t len)
{
    return len;
}

static Off
mem_null_lseek(struct File *filp, Off offset, int whence)
{
    return filp->offset = 0;
}

struct FileOps mem_null_file_ops = {
    .open = NULL,
    .release = NULL,
    .read = mem_null_read,
    .write = mem_null_write,
    .lseek = mem_null_lseek,
    .readdir = NULL,
};
