/**
 * FORX: An open and collaborative operating system kernel for the research community.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/fs/file.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/list.h>
#include <forx/string.h>
#include <arch/spinlock.h>
#include <arch/asm.h>
#include <forx/atomic.h>
#include <forx/mm/kmalloc.h>
#include <forx/mm/user_check.h>

#include <forx/block/bcache.h>
#include <forx/fs/super.h>
#include <forx/fs/inode.h>
#include <forx/fs/file.h>
#include <forx/fs/ioctl.h>
#include <forx/fs/vfs.h>

// Generic read implemented using bmap //
int
fs_file_generic_pread(struct File *filp, struct UserBuffer buf, size_t sizet_len, off_t off)
{
    off_t len;
    off_t have_read = 0;
    struct BlockDev *bdev = filp->inode->sb->bdev;

    if (!file_is_readable(filp))
        return -EBADF;

    if (off < 0)
        return -EINVAL;

    // We have to reconcile the difference between the unsigned size_t and signed off_t //
    if (sizet_len > __OFF_MAX || (off_t)sizet_len < 0)
        return -EINVAL;

    len = (off_t)sizet_len;

    // Guard against reading past the end of the file //
    if (off + len > filp->inode->size)
        len = filp->inode->size - off;

    // Access the block device for this file, and get it's block size //
    off_t block_size = block_dev_block_size_get(bdev);
    Sector sec = off / block_size;
    off_t sec_off = off - sec * block_size;

    using_inode_lock_read(filp->inode) {
        while (have_read < len) {
            struct Block *b;
            Sector on_dev = vfs_bmap(filp->inode, sec);
            off_t left = (len - have_read > block_size - sec_off) ?
                block_size - sec_off : len - have_read;

            /**
             * Invalid sectors are treated as though they're a block of all zeros.
             *
             * This allows `sparese` files, which don't have sectors allocated for
             * every position to save space.
            **/
            if (on_dev != SECTOR_INVALID) {
                int err;

                using_block_locked(bdev, on_dev, b)
                    err = user_memcpy_from_kernel(user_buffer_index(buf, have_read),
                        b->data + sec_off, left);

                if (err)
                    return err;
            } else {
                int err = user_memset_from_kernel(user_buffer_index(buf, have_read), 0, left);

                if (err)
                    return err;
            }

            have_read += left;
            sec_off = 0;
            sec++;
        }
    }

    filp->inode->atime = forx_current_time();
    inode_set_dirty(filp->inode);

    return have_read;
}

int
fs_file_generic_read(struct File *filp, struct UserBuffer buf, size_t len)
{
    int ret = fs_file_generic_pread(filp, buf, len, filp->offset);

    if (ret < 0)
        return ret;

    filp->offset += ret;

    return ret;
}

int
fs_file_generic_write(struct File *filp, struct UserBuffer buf, size_t sizet_len)
{
    int ret = 0;
    off_t len;
    off_t have_written = 0;
    struct BlockDev *bdev = filp->inode->sb->bdev;

    if (!file_is_writeable(filp))
        return -EBADF;

    if (flag_test(&filp->flags, FILE_APPEND)) {
        ret = vfs_lseek(filp, 0, SEEK_END);

        if (ret < 0)
            return ret;
    }

    // We have to recncile the difference between the unsigned size_t and signed off_t //
    if ((off_t)sizet_len > __OFF_MAX && (off_t)sizet_len > 0)
        return -EINVAL;

    len = (off_t)sizet_len;

    if (filp->inode->size - filp->offset < len) {
        ret = vfs_truncate(filp->inode, filp->offset + len);

        if (ret)
            return ret;
    }

    off_t block_size = block_dev_block_size_get(bdev);
    Sector sec = filp->offset / block_size;
    off_t sec_off = filp->offset - sec * block_size;

    using_inode_lock_write(filp->inode) {
        while (have_written < len) {
            struct Block *b;
            Sector on_dev = vfs_bmap_alloc(filp->inode, sec);

            if (on_dev == SECTOR_INVALID) {
                ret = -ENOSPC;
                break;
            }

            off_t left = (len - have_written > block_size - sec_off) ?
                block_size - sec_off : len - have_written;
            int err;

            using_block_locked(bdev, on_dev, b) {
                err = user_memcpy_to_kernel(b->data + sec_off, user_buffer_index(buf,
                    have_written), left);
                block_mark_dirty(b);
            }

            if (err)
                return err;

            have_written += left;
            sec_off = 0;
            sec++;
        }
    }

    filp->inode->ctime = filp->inode->mtime = forx_current_time();
    inode_set_dirty(filp->inode);

    if (ret == 0) {
        filp->offset += have_written;
        ret = have_written;
    }

    return ret;
}

off_t
fs_file_generic_lseek(struct File *filp, off_t off, int whence)
{
    switch (whence) {
    case SEEK_SET:
        filp->offset = off;
        break;

    case SEEK_END:
        filp->offset = filp->inode->size + off;
        break;

    case SEEK_CUR:
        filp->offset += off;
        break;

    default:
        return -EINVAL;
    }

    if (filp->offset < 0)
        filp->offset = 0;

    return filp->offset;
}

struct File *
file_dup(struct File *filp)
{
    atomic_inc(&filp->ref);

    return filp;
}

int
fs_file_ioctl(struct File *filp, int cmd, struct UserBuffer arg)
{
    int ret, ip;

    switch (cmd) {
    case FIBMAP:
        if (!inode_has_bmap(filp->inode))
            return -EINVAL;

        // TODO: Wrong type of check here //
        ret = user_copy_to_kernel(&ip, arg);

        if (ret)
            return ret;

        ip = vfs_bmap(filp->inode, ip);

        return user_copy_from_kernel(arg, ip);

    case FIGETBSZ:
        return user_copy_from_kernel(arg, (int)(filp->inode->e - filp->offset));

    case FIONREAD:
        return user_copy_from_kernel(arg, (int)(filp->inode->size - filp->offset))
    }

    return -EINVAL;
}
