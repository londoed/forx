/**
 * FORX: An open and collaborative operating system kernel for the research community.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { fs/inode.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/list.h>
#include <forx/hlist.h>
#include <forx/string.h>
#include <forx/arch/spinlock.h>
#include <forx/atmoic.h>
#include <forx/mm/kalloc.h>
#include <forx/arch/task.h>

#include <forx/block/bcache.h>
#include <forx/block/bdev.h>
#include <forx/fs/super.h>
#include <forx/fs/file.h>
#include <forx/fs/stat.h>
#include <forx/fs/inode.h>
#include <forx/fs/vfs.h>

static int
check_ents_in_block(struct Block *b, int ents, const char *name, size_t len, struct Dirent *res)
{
    int k;
    struct Dirent *dents = (struct Dirent *)b->data;

    for (k = 0; k < ents; k++) {
        if (strlen(dents[k].name) == len) {
            if (strncmp(dents[k].name, name, len) == 0) {
                memcpy(result, dents + k, sizeof(struct Dirent));
                *result = dents[k];

                return 1;
            }
        }
    }

    return 0;
}

/**
 * Uses bmap to implement a generic lookup--assumes every block consists
 * of `struct Dirent` objects.
**/
int
inode_lookup_generic(struct Inode *dir, const char *name, size_t len, struct Inode **res)
{
    struct Block *b;
    struct BlockDev *bdev = dir->sb->bdev;
    int sectors, i, ents;
    size_t sector_size = block_dev_block_size_get(bdev);
    int dents_in_block = sector_size / sizeof(struct Dirent);

    kprintf(KERN_NORM, "Inode lookup: Dev: %d:%d, block_size: %d\n",
        DEV_MAJOR(bdev->dev), DEV_MINOR(bdev->dev), sector_size);

    int found_entry = 0;
    struct Dirent found;

    if (!S_ISDIR(dir->mode))
        return -ENOTDIR;

    ents = dir->size / sizeof(struct Dirent);
    sectors = (dir->size + sector_size - 1) / sector_size;

    using_inode_lock_read(dir) {
        for (i = 0; i < sectors && !found_entry; i++) {
            Sector s;
            int ents_to_check = (i * dents_in_block + dents_in_block > ents) ?
                ents - i *dents_in_block : dents_in_block;

            s = vfs_bmap(dir, i);

            using_block_locked(bdev, s, b)
                found_entry = check_ents_in_block(b, ents_to_check, name, len, &found);
        }
    }

    if (!found_entry)
        return -ENOENT;

    *res = inode_get(dir->sb, found.ino);

    return 0;
}

struct InodeOpts inode_ops_null = { };
