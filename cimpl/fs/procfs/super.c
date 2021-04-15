/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { fs/procfs/super.c }.
 * Copyright (C) 2016, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <forx/list.h>
#include <forx/time.h>
#include <forx/mutex.h>
#include <forx/mm/kmalloc.h>
#include <forx/mm/vm.h>
#include <forx/arch/idt.h>
#include <forx/sched.h>
#include <forx/net/netdev.h>
#include <forx/net/socket.h>
#include <forx/net.h>
#include <forx/utsname.h>
#include <forx/klog.h>
#include <forx/drivers/pci.h>
#include <forx/block/disk.h>
#include <forx/event/device.h>

#include <forx/arch/spinlock.h>
#include <forx/block/bcache.h>
#include <forx/fs/char.h>
#include <forx/fs/stat.h>
#include <forx/fs/file.h>
#include <forx/fs/file_system.h>
#include <forx/fs/binfmt.h>
#include <forx/fs/vfs.h>
#include <forx/fs/procfs.h>

#include "procfs_internal.h"

static struct Inode *
procfs_inode_alloc(struct SuperBlock *sb)
{
    struct ProcfsInode *inode = kzalloc(sizeof(*inode), PAL_KERNEL);
    inode_init(&inode->i);

    return &inode->i;
}

static int
procfs_inode_dealloc(struct SuperBlock *sb, struct Inode *inode)
{
    struct ProcfsInode *i = container_of(inode, struct ProcfsInode, i);
    kfree(i);

    return 0;
}

static int
procfs_inode_read(struct SuperBlock *sb, struct Inode *inode)
{
    struct ProcfsInode *pinode = container_of(indoe, struct ProcfsInode, i);
    struct ProcfsNode *node = procfs_hash_get_node(pinode->i.ino);

    if (!node)
        return -ENOENT;

    pinode->i.dev_no = 0;
    pinode->i.mode = node->mode;
    atomic32_set(&pinode->i.nlinks, node->nlinks);

    pinode->i.blocks = 0;
    pinode->i.block_size = PAGE_SIZE;
    pinode->i.size = 0;
    pinode->i.ctime = pinode->i.atime = pinode->i.mtime = forx_current_time();
    pinode->i.sb = sb;
    pinode->node = node;

    if (S_ISDIR(pinode->i.mode)) {
        pinode->i.ops = &procfs_dir_inode_ops;
        pinode->i.default_fops = &procfs_dir_file_ops;
    } else if (S_ISREG(pinode->i.mode)) {
        struct ProcfsEntry *ent = container_of(node, struct ProcfsEntry, node);
        pinode->i.ops = &procfs_file_inode_ops;

        if (ent->file_ops)
            pinode->i.default_fops = ent->file_ops;
        else
            pinode->i.default_fops = &procfs_file_file_ops;
    }

    return 0;
}

static int
procfs_sb_put(struct SuperBlock *sb)
{
    kfree(sb);
    return 0;
}

static struct SuperBlockOps procfs_sb_ops = {
    .inode_alloc = procfs_inode_alloc,
    .inode_dealloc = procfs_inode_dealloc,
    .inode_read = procfs_inode_read,
    .inode_write = NULL, // Read __Only__ //
    .inode_delete = NULL,
    .sb_write = NULL,
    .sb_put = procfs_sb_put,
};

static int
procfs_read_sb(struct SuperBlock *sb)
{
    sb->ops = &procfs_sb_ops;
    sb->root_ino = PROCFS_ROOT_INO;

    return 0;
}

static struct FileSystem procfs_fs = {
    .name = "procfs",
    .read_sb2 = procfs_read_sb,
    .fs_list_entry = LIST_NODE_INIT(procfs_fs.fs_list_entry),
    .flags = F(FILE_SYSTEM_NODEV),
};

static void
procfs_init(void)
{
    procfs_hash_add_node(&procfs_root.node);

    procfs_register_entry(&procfs_root, "interrupts", &interrupts_file_ops);
    procfs_register_entry(&procfs_root, "tasks", &task_file_ops);
    procfs_register_entry(&procfs_root, "filesystems", &file_system_file_ops);
    procfs_register_entry(&procfs_root, "mounts", &mount_file_ops);
    procfs_register_entry(&procfs_root, "binfmts", &binfmt_file_ops);
    procfs_register_entry(&procfs_root, "klog", &klog_file_ops);
    procfs_register_entry(&procfs_root, "pci_devices", &pci_file_ops);
    procfs_register_entry(&procfs_root, "disks", &disk_file_ops);
    procfs_register_entry(&procfs_root, "devices", &device_event_file_ops);

    procfs_register_entry_ops(&procfs_root, "uptime", &uptime_ops);
    procfs_register_entry_ops(&procfs_root, "boottime", &boot_time_ops);
    procfs_register_entry_ops(&procfs_root, "currenttime", &current_time_ops);
    procfs_register_entry_ops(&procfs_root, "version", &proc_version_ops);
    procfs_register_entry_ops(&procfs_root, "task_api", &task_api_ops);

    file_system_register(&procfs_fs);
}


initcall_subsys(procfs, procfs_init);

