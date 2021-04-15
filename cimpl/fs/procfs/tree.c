/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { fs/procfs/tree.c }.
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
#include <forx/fs/file_system.h>
#include <forx/fs/vfs.h>
#include <forx/fs/procfs.h>

#include "procfs_internal.h"

static void
procfs_add_node(struct ProcfsDir *parent, struct ProcfsNode *node)
{
    using_mutex(&parent->node.lock) {
        using_mutex(&node->lock) {
            parent->node.nlinks++;
            node->nlinks = 1;

            procfs_hash_add_node(node);
            list_add(&parent->entry_list, &node->parent_node);
            parent->entry_count++;
        }
    }
}

static struct ProcfsEntry *
procfs_entry_new(struct ProcfsDir *parent, const char *name)
{
    struct ProcfsEntry *entry = kmalloc(sizeof(*entry), PAL_KERNEL);

    procfs_entry_init(entry);
    entry->node.name = kstrdup(name, PAL_KERNEL);
    entry->node.len = strlen(name);
    entry->node.mode = S_IFREG | 0444;
    entry->node.parent = parent;
    entry->node.ctime = forx_current_time();
    entry->node.ino = procfs_next_ino();

    return entry;
}

void
procfs_register_entry(struct ProcfsDir *parent, const char *name, const struct FileOps *ops)
{
    struct ProcfsEntry *entry = procfs_entry_new(parent, name);

    entry->file_ops = ops;
    procfs_add_node(parent, &entry->node);
}

void
procfs_register_entry_ops(struct ProcfsDir *parent, const char *name, const struct ProcfsEntryOps *ops)
{
    struct ProcfsEntry *entry = procfs_entry_new(parent, name);

    entry->ops = ops;
    procfs_add_node(parent, &entry->node);
}

struct ProcfsDir *
procfs_register_dir(struct ProcfsDir *parent, const char *name)
{
    struct ProcfsDir *new = kmalloc(sizeof(*new), PAL_KERNEL);

    procfs_dir_init(new);
    new->node.name = kstrdup(name, PAL_KERNEL);
    new->node.len = strlen(name);
    new->node.mode = S_IFDIR | 0555;
    new->node.parent = parent;
    new->node.ctime = forx_current_time();
    new->node.ino = procfs_next_ino();

    procfs_add_node(parent, &new->node);

    return new;
}

struct ProcfsDir procfs_root = {
    .node = {
        .name = "",
        .len = 0,
        .ino = PROCFS_ROOT_INO,
        .mode = S_IFDIR | 0555,
        .nlinks = 1,
        .parent = &procfs_root,
        .parent_node = LIST_NODE_INIT(procfs_root.node.parent_node),
        .lock = MUTEX_INIT(procfs_root.node.lock),
        .inode_hash_entry = HLIST_NODE_INIT(),
    },
    .entry_list = LIST_HEAD_INIT(procfs_root.entry_list);
};
