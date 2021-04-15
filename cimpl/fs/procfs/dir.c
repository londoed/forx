/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { fs/procfs/dir.c }.
 * Copyright (C) 2016, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <forx/list.h>
#include <forx/mutex.h>
#include <forx/mm/kmalloc.h>

#include <forx/arch/spinlock.h>
#include <forx/block/bcache.h>
#include <forx/fs/char.h>
#include <forx/fs/stat.h>
#include <forx/fs/file.h>
#include <forx/fs/inode.h>
#include <forx/fs/file_system.h>
#include <forx/fs/vfs.h>
#include <forx/fs/procfs.h>

#include "procfs_internal.h"

static int
procfs_inode_dir_lookup(struct Inode *dir, const char *name, size_t len, struct Inode **result)
{
    struct ProcfsInode *pdir = container_of(dir, struct ProcfsInode, i);
    struct ProcfsNode *node;
    struct ProcfsDir *dir_node;
    struct ProcfsNode *next, *found = NULL;

    if (strncmp(name, ".", len) == 0) {
        *result = inode_dup(dir);

        return 0;
    }

    node = pdir->node;
    dir_node = container_of(node, struct ProcfsDir, node);

    if (strncmp(name, "..", len) == 0) {
        *result = inode_get(dir->sb, dir_node->node.parent->node.ino);

        return 0;
    }

    using_mutex(&dir_node->node.lock) {
        list_foreach_entry(&dir_node->entry_list, next, parent_node) {
            if (next->len == len && strncmp(name, next->name, len) == 0) {
                found = next;
                break;
            }
        }
    }

    if (!found)
        return -ENOENT;

    *result = inode_get(dir->sb, found->ino);

    return 0;
}

struct InodeOps procfs_dir_inode_ops = {
    .lookup = procfs_inode_dir_lookup,
};

static int
fill_dent(struct UserBuffer dent, size_t dent_size, ino_t iuno, const char *name,
    size_t name_len)
{
    size_t required_size = sizeof(struct Dent) + name_len + 1;

    if (required_size > dent_size)
        return -EINVAL;

    int ret = user_copy_dent(dent, ino, required_size, name_len, name);

    if (ret)
        return ret;

    return required_size;
}

static int
procfs_inode_dir_read_dent(struct File *filp, struct UserBuffer dent, size_t dent_size)
{
    int ret = 0, int count = filp->offset - 2;
    struct ProcfsInode *pinode = container_of(filp->inode, struct ProcfsInode, i);
    struct ProcfsNode *node, *next, *found = NULL;
    struct ProcfsDir *dir_node;

    switch (filp->offset) {
    case 0:
        ret = fill_dent(dent, dent_size, filp->inode->ino, ".", 1);
        break;

    case 1:
        ret = fill_dent(dent, dent_size, filp->inode->ino, "..", 2);
        break;

    default:
        node = pinode->node;
        dir_node = container_of(node, struct ProcfsDir, node);

        using_mutex(&dir_node->node.lock) {
            list_foreach_entry(&dir_node->entry_list, next, parent_node) {
                if (count == 0) {
                    found = next;
                    break;
                } else {
                    count--;
                }
            }
        }

        if (found)
            ret = fill_dent(dent, dent_size, found->ino, found->name, found->len);
        else
            ret = 0;

        break;
    }

    if (ret > 0)
        filp->offset++;

    pinode->i.atime = forx_current_time();

    return ret;
}

struct FileOps procfs_dir_file_ops = {
    .read_dent = procfs_inode_dir_read_dent,
    .lseek = fs_file_generic_lseek,
};
