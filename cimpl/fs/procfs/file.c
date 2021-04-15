/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { fs/procfs/file.c }.
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
#include <forx/mm/user_check.h>

#include <forx/arch/spinlock.h>
#include <forx/block/bcache.h>
#include <forx/fs/char.h>
#include <forx/fs/file.h>
#include <forx/fs/inode.h>
#include <forx/fs/file_system.h>
#include <forx/fs/vfs.h>
#include <forx/fs/procfs.h>

#include "procfs_internal.h"

static int
procfs_file_read(struct File *filp, struct UserBuffer buf, size_t size)
{
    struct ProcfsInode *pinode = container_of(filp->inode, struct ProcfsInode, i);
    struct ProcfsNode *node = pinode->node;
    struct ProcfsEntry *entry = container_of(node, struct ProcfsEntry, node);
    void *p;
    size_t data_len, cpysize = 0;
    int ret;

    pinode->i.atime = forx_current_time();

    if (entry->ops->read)
        return (entry->ops->read)(filp, buf, size);

    if (filp->offset > 0)
        return 0;

    if (!entry->ops->readpage)
        return 0;

    p = page_alloc_va(0, PAL_KERNEL);

    if (!p)
        return -ENOMEM;

    ret = (entry->ops->readpage)(p, PAGE_SIZE, &data_len);
    kprintf(KERN_TRACE, "procfs output len: %d\n", data_len);

    if (!ret) {
        cpysize = (data_len > size) ? size : data_len;
        ret = user_memcpy_from_kernel(buf, p, cpysize);
    }

    page_free_va(p, 0);

    if (ret) {
        return ret;
    } else {
        filp->offset = cpysize;

        return cpysize;
    }
}

static int
procfs_file_ioctl(struct File *filp, int cmd, struct UserBuffer ptr)
{
    struct ProcfsInode *pinode = container_of(filp->inode, struct ProcfsInode, i);
    struct ProcfsNode *node = pinode->node;
    struct ProcfsEntry *entry = container_of(node, struct ProcfsEntry, node);

    if (entry->ops->ioctl)
        return (entry->ops->ioctl)(filp, cmd, ptr);

    return -EINVAL;
}

struct FileOps procfs_file_file_ops = {
    .read = procfs_file_read,
    .ioctl = procfs_file_ioctl,
};

struct InodeOps procfs_file_inode_ops = {
    // Nothing to implement //
};
