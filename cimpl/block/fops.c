/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { block/fops.c }.
 * Copyright (C) 2020, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <libctl/snprintf.h>
#include <forx/mm/kmalloc.h>
#include <forx/mm/user_check.h>
#include <forx/dev.h>
#include <forx/fs/inode.h>
#include <forx/fs/file.h>
#include <forx/fs/pipe.h>
#include <forx/block/bcache.h>
#include <forx/block/disk.h>
#include <forx/block/bdev.h>

static int
block_dev_pread_generic(struct File *filp, struct UserBuffer buf, size_t len, off_t off)
{
    size_t have_read = 0;
    struct BlockDev *bdev = filp->inode->bdev;

    if (!file_is_readable(filp) || !bdev)
        return -EBADF;

    size_t total_len = block_dev_capacity(bdev);

    if (off + len > total_len) {
        // If the length would be negative, the "seek" is not allowed //
        if (total_len < off)
            return -EOVERFLOW;

        len = total_len - off;
    }

    // Access the block device for this file, and get it's block size //
    size_t block_size = block_dev_block_size_get(bdev);
    Sector sec = off / block_size;
    off_t sec_off = off - sec * block_size;

    while (have_read < len) {
        struct Block *b;
        off_t left = (len - have_read > block_size - sec_off) ?
            block_size - sec_off : len - have_read;

        using_block_locked(bdev, sec, b) {
            int ret = user_memcpy_from_kernel(user_buffer_index(buf, have_read),
                b->data + sec_off, left);

            if (ret)
                return ret;
        }

        have_read += left;
        sec_off = 0;
        sec++;
    }

    kprintf(KERN_NORM, "block: pread: have_read(): %d\n", have_read);
    filp->offset += have_read;

    return have_read;
}

static int
block_dev_read_generic(struct File *filp, struct UserBuffer buf, size_t len)
{
    int ret = block_dev_pread_generic(filp, buf, len, filp->offset);

    if (ret > 0)
        filp->offset += ret;

    return ret;
}

static int
block_dev_write_generic(struct File *filp, struct UserBuffer buf, size_t len)
{
    size_t have_written = 0;
    struct BlockDev *bdev = filp->inode->bdev;
    off_t off = filp->offset;

    if (!file_is_writable(filp) || !bdev)
        return -EBADF;

    size_t total_len = block_dev_capacity_get(bdev);

    if (off + len > total_len) {
        // If the length would be negative, the "seek" is not allowed //
        if (total_len < off)
            return -EOVERFLOW;

        len = total_len - off;
    }

    // Access the block device for this file, and get it's block size //
    size_t block_size = block_dev_block_size_get(bdev);
    Sector sec = off / block_size;
    off_t sec_off = off - sec * block_size;

    while (have_written < len) {
        struct Block *b;
        off_t left = (len - have_written > block_size - sec_off) ?
            block_size - sec_off : len - have_written;

        using_block_locked(bdev, sec, b) {
            int ret = user_memcpy_to_kernel(b->data + sec_off, user_buffer_index(buf,
                have_written), left);
            block_mark_dirty(b);

            if (ret)
                return ret;
        }

        have_written += left;
        sec_off = 0;
        sec++;
    }

    kprintf(KERN_NORM, "block: write: have_written: %d\n", have_written);
    filp->offset += have_written;

    return have_written;
}

static int
block_dev_fops_open(struct Inode *ino, struct File *filp)
{
    return block_dev_open(ino->bdev, filp->flags);
}

static int
block_dev_fops_close(struct File *filp)
{
    block_dev_close(filp->inode->bdev);
}

struct FileOps block_dev_file_ops = {
    .open = block_dev_fops_open,
    .release = block_dev_fops_close,
    .pread = block_dev_pread_generic,
    .read = block_dev_read_generic,
    .write = block_dev_write_generic,
    .lseek = fs_file_generic_lseek,
};
