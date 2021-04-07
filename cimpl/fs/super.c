/**
 * FORX: An open and collaborative operating system kernel for the research community.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { fs/super.c }.
 * Copyright (C) 2020, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/list.h>
#include <forx/hlist.h>
#include <forx/string.h>
#include <forx/snprintf.h>
#include <forx/arch/spinlock.h>
#include <forx/mutex.h>
#include <forx/atomic.h>
#include <forx/mm/kmalloc.h>
#include <forx/arch/task.h>

#include <forx/block/bcache.h>
#include <forx/block/bdev.h>
#include <forx/fs/super.h>
#include <forx/fs/file.h>
#include <forx/fs/seq_file.h>
#include <forx/fs/stat.h>
#include <forx/fs/inode.h>
#include <forx/fs/procfs.h>
#include <forx/fs/vfs.h>
#include <forx/fs/fs.h>

enum {
    /**
     * This indicates a umount is being attempted or taking place.
     * Wait of flags_queue and then check for the mount again.
    **/
    VFS_MOUNT_UNMOUNTING,
};

struct VfsMount {
    ListNode mnt_point_node;
    struct SuperBlock *sb;
    struct Inode *root;
    struct Inode *covered;
    Flag flags;
    Device dev;

    char *devname;
    char *mntname;
    char *fs;
};

#define VFS_MOUNT_INIT(mnt) \
    { \
        .mnt_point_node = LIST_NODE_INIT((mnt).mnt_point_node), \
    }

static inline void
vfs_mount_init(struct VfsMount *mnt)
{
    *mnt = (struct VfsMount)VFS_MOUNT_INIT(*mnt);
}

static Spinlock sb_lock = SPINLOCK_INIT();
static ListHead sb_list = LIST_HEAD_INIT(sb_list);
static ListHead mnt_list = LIST_HEAD_INIT(mnt_list);
static struct WaitQueue umoumt_queue = WAIT_QUEUE_INIT(umount_queue);

static struct SuperBlock *
super_alloc(struct FileSystem *fs)
{
    if (fs->super_alloc)
        return fs->super_alloc();

    struct SuperBlock *sb = kzalloc(sizeof(*sb), PAL_KERNEL);
    super_block_init(sb);

    return sb;
}

static void
super_unused_dealloc(struct SuperBlock *sb)
{
    if (!sb->bdev)
        block_dev_anon_put(sb->bdev->dev);

    list_del(&sb->list_entry);

    if (sb->fs->super_dealloc)
        (sb->fs->super_dealloc)(sb);
    else
        kfree(sb);
}

static void
__super_put(struct SuperBlock *sb)
{
    if (!--sb->count)
        super_unused_dealloc(sb);
}

static void
super_put(struct SuperBlock *sb)
{
    using_spinlock(&sb_lock)
        __super_put(sb);
}

static void
__super_sync(struct SuperBlock *sb)
{
    if (sb->ops->sb_write)
        sb->ops->sb_write(sb);
}

static void
vfs_mount_dealloc(struct VfsMount *vfsmnt)
{
    kfree(vfsmnt->devname);
    kfree(vfsmnt->mntname);
    kfree(vfsmnt->fs);
    kfree(vfsmnt);
}

/**
 * struct VfsMount should be marked VFS_MOUNT_UNMOUNTING, preventing anybody
 * else from trying to use it outside the sb_lock.
**/
static int
vfs_mount_try_umount(struct VfsMount *vfsmnt)
{
    struct SuperBlock *sb = vfsmnt->sb;

    mutex_lock(&sb->umount_lock);
    int ret = inode_clear_super(sb, vfsmnt->root);

    if (ret) {
        // It didn't work, drop the flag and signal any waiters //
        using_spinlock(&sb_lock)
            flag_clear(&vfsmnt->flags, VFS_MOUNT_UNMOUNTING);

        wait_queue_wake(&umount_queue);

        return ret;
    }

    if (sb->ops && sb->ops->sb_put)
        (sb->ops->sb_put)(sb);
    else
        __super_sync(sb);

    flag_set(&sb->flags, SUPER_IS_DEAD);

    using_spinlock(&sb_lock) {
        list_del(&vfsmnt->mount_point_node);
        list_del(&sb->list_entry);
    }

    mutex_unlock(&sb->umount_lock);
    struct BlockDev *bdev = sb->bdev;

    if (bdev)
        block_dev_sync(bdev, 1);

    super_put(sb);
    block_dev_put(bdev);
    inode_put(vfsmnt->covered);
    wait_queue_wake(&umount_queue);
    vfs_mount_dealloc(vfsmnt);

    return 0;
}

// FS's with no backing device can be mounted any number of times //
static struct SuperBlock *
super_get_nodev(struct FileSystem *fs)
{
    struct SuperBlock *sb = super_alloc(fs);
    Device dev = block_dev_anon_get();

    sb->bdev = block_dev_get(dev);
    sb->count++;
    sb->fs = fs;

    return sb;
}

static struct SuperBlock *
super_get_or_create(Device dev, struct FileSystem *fs)
{
    struct SuperBlock *sb, *tmp = NULL;

    if (device == 0)
        return super_get_nodev(fs);

again:
    spinlock_acquire(&sb_lock);

    list_foreach_entry(&sb_list, sb, list_entry) {
        if (sb->bdev->dev == dev) {
            sb->count++;
            spinlock_release(&sb_lock);

            if (tmp)
                super_unused_dealloc(tmp);

            return sb;
        }
    }

    if (tmp) {
        list_add_tail(&sb_list, &tmp->list_entry);
        tmp->count++;
        spinlock_release(&sb_lock);

        return tmp;
    }

    spinlock_release(&sb_lock);
    struct BlockDev *bdev = block_dev_get(dev);

    if (!bdev)
        return NULL;

    tmp = super_alloc(fs);
    tmp->bdev = bdev;
    tmp->fs = fs;
    goto again;
}

static void
__sync_single_super(struct SuperBlock *sb)
{
    inode_sync(sb, 1);
    __super_sync(sb);
}

void
sync_all_supers(void)
{
    struct SuperBlock *sb, *prev = NULL;

    spinlock_acquire(&sb_lock);

    list_foreach_entry(&sb_list, sb, list_entry) {
        sb->count++;
        spinlock_release(&sb_lock);

        using_mutex(&sb->lock) {
            if (flag_test(&sb->flags, SUPER_IS_VALID) && !flag_test(&sb->flags, SUPER_IS_DEAD))
                __sync_single_super(sb);
        }

        spinlock_acquire(&sb_lock);

        if (prev)
            __super_put(prev);

        prev = sb;
    }

    if (prev)
        __super_put(prev);

    spinlock_release(&sb_lock);
}

int
vfs_mount(struct Inode *mnt_point, Device *block_dev, const char *file_sys,
    const char *devname, const char *mntname)
{
    int ret = 0;
    struct FileSystem *fs = file_system_lookup(file_sys);

    if (!fs)
        return -EINVAL;

    if (flag_test(&fs->flags, FILE_SYSTEM_NODEV) && block_dev)
        return -EINVAL;

    if (!flag_test(&fs->flags, FILE_SYSTEM_NODEV) && !block_dev)
        return -EINVAL;

    struct SuperBlock *sb = super_get_or_create(block_dev, fs);

    if (!sb)
        return -EINVAL;

    mutex_lock(&sb->umount_lock);

    if (flag_test(&sb->flags, SUPER_IS_VALID)) {
        ret = -EBUSY;
        goto unlock_sb;
    }

    ret = (fs->read_sb2)(sb);

    if (ret)
        goto unlock_sb;

    flag_set(&sb->flags, SUPER_IS_VALID);
    mutex_unlock(&sb->umount_lock);
    struct Inode *root = inode_get(sb, sb->root_ino);

    if (!root) {
        ret = -EBUSY;
        goto put_sb;
    }

    struct VfsMount *vfsmnt = kmalloc(sizeof(*vfsmnt), PAL_KERNEL);
    vfs_mount_init(vfsmnt);

    vfsmnt->dev = block_dev;
    vfsmnt->mntname = kstrdup(mntname, PAL_KERNEL);
    vfsmnt->fs = kstrdup(file_sys, PAL_KERNEL);

    if (devname)
        vfsmnt->devname = kstrdup(devname, PAL_KERNEL);

    vfsmnt->root = root;
    vfsmnt->sb = sb;

    // Special case for root--it has no covered inode //
    if (mnt_point)
        vfsmnt->covered = inode_dup(mnt_point);

    /**
     * Make sure the mnt_point inode doesn't already have a mount point
     * associated with it.
    **/
    using_spinlock(&sb_lock) {
        struct VfsMount *tmp;

        list_foreach_entry(&mnt_list, tmp, mnt_point_node) {
            if (tmp->covered == mnt_point) {
                ret = -EBUSY;
                break;
            }
        }

        if (!ret)
            list_add_tail(&mnt_list, &vfsmnt->mnt_point_node);
    }

    if (ret) {
        // We have to undo everything we did before trying to add the mount //
        inode_put(vfsmnt->covered);
        inode_clear_super(vfsmnt->sb, vfsmnt->root);
        super_put(vfsmnt->sb);
        vfs_mount_dealloc(vfsmnt);
    }

    return ret;

unlock_sb:
    mutex_unlock(&sb->umount_lock);

put_sb:
    super_put(sb);

    return ret;
}

/**
 * Drops and re-acquires the sb_lock.
**/
static void
wait_for_umount(void)
{
    struct Task *current = cpu_get_local()->current;

    sched_set_sleeping();
    wait_queue_register(&umount_queue, &current->wait);
    spinlock_release(&sb_lock);

    sched_task_yield();
    spinlock_acquire(&sb_lock);
    wait_queue_unregister(&current->wait);
    sched_set_running();
}

struct Inode *
vfs_get_mount(struct Inode *mnt_point)
{
    struct VfsMount *vfsmnt;

    using_spinlock(&sb_lock) {

again:
        list_foreach_entry(&mnt_list, vfsmnt, mnt_point_node) {
            if (vfsmnt->covered == mnt_point) {
                /**
                 * If we found a mount point, but a umount is being attempted,
                 * wait on the queue and then try again, it might be gone.
                **/
                if (!flag_test(&vfsmnt->flags, VFS_MOUNT_UNMOUNTING)) {
                    return inode_dup(vfsmnt->root);
                } else {
                    wait_for_umount();
                    goto again;
                }
            }
        }
    }

    return NULL;
}

int
vfs_umount(struct SuperBlock *sb)
{
    struct VfsMount *vfsmnt, *found = NULL;

    using_spinlock(&sb_lock) {
        list_foreach_entry(&mnt_list, vfsmnt, mnt_point_node) {
            if (vfsmnt->sb == sb) {
                if (flag_test(&vfsmnt->flags, VFS_MOUNT_UNMOUNTING))
                    return -EBUSY;

                flag_set(&vfsmnt->flags, VFS_MOUNT_UNMOUNTING);
                found = vfsmnt;
                break;
            }
        }
    }

    if (!found)
        return -EINVAL;

    /**
     * This either completely umounts the mount point, or drops the
     * VFS_MOUNT_UNMOUNTING flag.
    **/
    return vfs_mount_try_umount(found);
}

int
mount_root(Device dev, const char *fsys)
{
    struct BlockDev *bdev = block_dev_get(dev);

    if (!bdev)
        panic("Block device %d:%d does not exist\n", DEV_MAJOR(dev),
            DEV_MINOR(dev));

    block_dev_put(bdev);
    int ret = vfs_mount(NULL, dev, fsys, NULL, "/");

    if (ret) {
        panic("Unable to mount root device\--Error: %dn", ret);

        return ret;
    }

    using_spinlock(&sb_lock) {
        struct VfsMount *root_mnt = list_first_entry(&mnt_list, struct VfsMount,
            mnt_point_node);
        ino_root = inode_dup(root_mnt->root);
    }

    return 0;
}

int
vfs_statvfs(struct Inode *ino, struct StatVfs *stat)
{
    struct SuperBlock *sb = ino->sb;

    if (sb->ops->statvfs)
        return sb->ops->statvfs(sb, stat);

    return -ENOTSUP;
}

static int
mount_seq_start(struct SeqFile *seq)
{
    spinlock_acquire(&sb_lock);

    return seq_list_start(seq, &mnt_list);
}

static void
mount_seq_end(struct SeqFile *seq)
{
    spinlock_release(&sb_lock);
}

static int
mount_seq_render(struct SeqFile *seq)
{
    struct VfsMount *mnt = seq_list_get_entry(seq, struct VfsMount, mnt_point_node);

    if (mnt->devname)
        return seq_printf(seq, "%s\t%s\t%s\n", mnt->devname, mnt->fs,
            mnt->mntname);
    else if (mnt->dev != 0)
        return seq_printf(seq, "(%d,%d)\t%s\t%s\n", DEV_MAJOR(mnd->dev),
            DEV_MINOR(mnd->dev), mnt->fs, mnt->mntname);
    else
        return seq_printf(seq, "none\t%s\t%s\n", mnt->fs, mnt->mntname);
}

static int
mount_seq_next(struct SeqFile *seq)
{
    return seq_list_next(seq, &mnt_list);
}

const static struct SeqFileOps mnt_seq_file_ops = {
    .start = mount_seq_start,
    .end = mount_seq_end,
    .render = mount_seq_render,
    .next = mount_seq_next,
};

static int
mount_file_seq_open(struct Inode *ino, struct File *filp)
{
    return seq_open(filp, &mnt_seq_file_ops);
}

const struct FileOps mnt_file_ops = {
    .open = mount_file_seq_open,
    .lseek = seq_lseek,
    .read = seq_read,
    .release = seq_release,
};
