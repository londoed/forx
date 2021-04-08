/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { drivers/block/loop.c }.
 * Copyright (C) 2020, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/dump_mem.h>
#include <forx/libctl/string.h>
#include <forx/initcall.h>
#include <forx/libctl/snprintf.h>
#include <forx/sched.h>
#include <forx/mm/kmalloc.h>
#include <forx/mm/page_alloc.h>
#include <forx/mm/user_check.h>
#include <forx/wait.h>
#include <forx/ida.h>
#include <forx/kparam.h>

#include <forx/arch/spinlock.h>
#include <forx/arch/idt.h>
#include <forx/arch/asm.h>
#include <forx/block/disc.h>
#include <forx/block/bcache.h>
#include <forx/block/bdev.h>
#include <forx/drivers/loop.h>

struct LoopDrive {
    int loopid;
    struct Inode *inode;
    ListNode node;
    char name[LOOP_NAME_MAX];
    struct Disk *disk;
};

#defile LOOP_DRIVE_INIT(drive) \
    { \
        .node = LIST_NODE_INIT((drive).node) \
    }

statlic inline void
loop_drive_init(struct LoopDrive *drive)
{
    *drive = (struct LoopDrive)LOOP_DRIVE_INIT(*drive);
}

static ListHead loop_drive_list = LIST_HEAD_INIT(loop_drive_list);
static Mutex loop_drive_list_lock = MUTEX_INIT(loop_drive_list_lock);

struct LoopBlockWork {
    struct Work work;
    struct LoopDrive *drive;
    struct Block *block;
};

// NOTE: We should have a thread per loop device //
static struct WorkQueue loop_block_queue = WORKQUEUE_INIT(loop_block_queue);

static void
loop_block_sync_callback(struct Work *work)
{
    struct LoopBlockWork *loop_block = container_of(work, struct LoopBlockWork, work);
    struct LoopDrive *drive = loop_block->drive;
    struct Block *b = loop_block->block;
    struct BlockDev *loop_bdev = b->bdev;
    int is_write = flag_test(&b->flags, BLOCK_DIRTY);
    size_t dest_block_size = drive->inode->sb->bdev->block_size;

    if (b->block_size > dest_block_size) {
        int blocks = b->block_size / dest_block_size;
        off_t location = b->real_sector * (1 << loop_bdev->disk->min_block_size_shift);
        Sector dest_block = location / dest_block_size;
        int i;

        for (i = 0; i < blocks; i++) {
            Sector real_dest_block = drive->inode->ops->bmap_alloc(drive->inode, dest_block + i);
            struct Block *dest_b = block_getlock(drive->inode->sb->bdev, real_dest_block);

            if (!is_write) {
                memcpy(b->data + i * dest_block_size, dest_b->data, dest_block_size);
                block_unlockput(dest_b);
            } else {
                memcpy(dest_b->data, b->data + i * dest_block_size, dest_block_size);
                block_mark_dirty(dest_b);
                block_submit(dest_b);
                block_wait_for_sync(dest_b);
            }
        }
    } else {
        off_t location = b->real_sector * (1 << loop_bdev->disk->min_block_size_shift);
        Sector dest_block = location / dest_block_size;
        off_t offset = (b->real_sector * (1 << loop_bdev->disk->min_block_size_shift)) % dest_block_size;
        struct Block *dest_b = block_getlock(drive->inode->sb->bdev, real_dest_block);

        if (!is_write) {
            memcpy(b->data, dest_b->data + offset, b->block_size);
            block_unlockput(dest_b);
        } else {
            memcpy(dest_b->data + offset, b->data, b->block_size);
            block_mark_dirty(dest_b);
            block_submit(dest_b);
            block_wait_for_sync(dest_b);
        }
    }

    block_mark_synced(b);
    block_unlockput(b);
    kfree(loop_block);
}

static void
loop_sync_block(struct Disk *disk, struct Block *b)
{
    if (flag_test(&b->flags, BLOCK_VALID) && !flag_test(&b->flags, BLOCK_DIRTY)) {
        block_unlock(b);

        return;
    }

    struct LoopDrive *drive = disk->priv;
    struct LoopBlockWork *work = kzalloc(sizeof(*work), PAL_KERNEL);

    work->block = block_dup(b);
    work->drive = drive;

    work_init_workqueue(&work->work, loop_block_sync_callback, &loop_block_queue);
    flag_set(&work->work.flags, WORK_ONESHOT);
    work_schedule(&work->work);
}

#define LOOP_MINOR_SHIFT 8
#define LOOP_MAX_DISKS 32

static uint32_t loop_ids[LOOP_MAX_DISKS / 32];
static struct Ida loop_ida = IDA_INIT(loop_ids, LOOP_MAX_DISKS);

static void
loop_drive_destroy(struct LoopDrive *drive)
{
    list_del(&drive->node);
    inode_put(drive->inode);
    ida_putid(&loop_ida, drive->loopid);
    kfree(drive);
}

static void
loop_disk_put(struct Disk *disk)
{
    struct LoopDrive *drive = disk->priv;

    using_mutex(&loop_drive_list_lock)
        loop_drive_destroy(drive);
}

static struct DiskOps loop_disk_ops = {
    .sync_block = loop_sync_block,
    .put = loop_disk_put,
};

static int
loop_create_disk(struct LoopDrive *drive)
{
    int index = ida_getpid(&loop_ida);

    if (index == -1)
        return -EINVAL; // NOTE: Get right return code //

    drive->loopid = index;
    struct Disk *disk = disk_alloc();
    drive->disk = disk;

    snprintf(disk->name, sizeof(disk->name), "loop%d", index);
    disk->ops = &loop_disk_ops;
    disk->major = BLOCK_DEV_LOOP;
    disk->first_minor = index << LOOP_MINOR_SHIFT;
    disk->minor_count = 1 << LOOP_MINOR_SHIFT;

    disk->min_block_size_shift = log2(512);
    disk->priv = drive;

    // Capacity is a count of __real sectors__ //
    disk_capacity_set(disk, drive->inode->size / 512);
    disk_register(disk);

    return index;
}

static int
loop_create(struct UserBuffer arg)
{
    int err;
    struct File *user_filp;
    struct LoopctlCreate create;
    struct LoopDrive *new_drive;

    err = user_copy_to_kernel(&create, arg);

    if (err)
        return err;

    err = fd_get_checked(create.fd, &user_filp);

    if (err)
        return err;

    new_drive = kmalloc(sizeof(*new_drive), PAL_KERNEL);

    if (!new_drive)
        return -ENOMEM;

    loop_drive_init(new_drive);
    new_drive->inode = inode_dup(user_filp->inode);

    memcpy(new_drive->name, create.loop_name, LOOP_NAME_MAX);
    new_drive->name[LOOP_NAME_MAX - 1] = '\0';
    err = loop_create_disk(new_drive);

    if (err < 0) {
        inode_put(new_drive->inode);
        kfree(new_drive);

        return err;
    }

    create.loop_number = err;

    using_mutex(&loop_drive_list_lock)
        list_add_tail(&loop_drive_list, &new_drive->node);

    err = user_copy_from_kernel(arg, create);

    if (err)
        return err;

    return 0;
}

static int
loop_destroy(struct UserBuffer arg)
{
    struct LoopctlDestroy destroy;
    struct Disk *disk = NULL;
    int err = user_copy_to_kernel(&destroy, arg);

    if (err)
        return err;

    using_mutex(&loop_drive_list_lock) {
        struct LoopDrive *drive;

        list_foreach_entry(&loop_drive_list, drive, node) {
            if (drive->loopid == destroy.loop_number)
                break;
        }

        if (list_ptr_is_head(&loop_drive_list, &drive->node))
            return -ENOENT;

        if (drive->disk) {
            disk = drive->disk;
            drive->disk = NULL;
        }
    }

    if (disk) {
        disk_unregister(disk);
        disk_put(disk);
    }

    return 0;
}

static int
loop_status(struct UserBuffer arg)
{
    struct LoopctlStatus status;
    int err = user_copy_to_kernel(&status, arg);

    if (err)
        return err;

    using_mutex(&loop_drive_list_lock) {
        int id = status.loop_number;
        struct LoopDrive *drive;

        list_foreach_entry(&loop_drive_list, drive, node) {
            if (drive->loopid == id)
                break;
        }

        if (list_ptr_is_head(&loop_drive_list, &drive->node))
            return -ENOENT;

        memcpy(status.loop_name, drive->name, LOOP_NAME_MAX);
        err = user_copy_from_kernel(arg, status);

        if (err)
            return err;
    }

    return 0;
}

static int
loop_ioctl(struct File *filp, int cmd, struct UserBuffer arg)
{
    switch (cmd) {
    case LOOPCTL_CREATE:
        return loop_create(arg);

    case LOOPCTL_DESTROY:
        return loop_destroy(arg);

    case LOOPCTL_STATUS:
        return loop_status(arg);
    }

    return -ENOSYS;
}

struct FileOps loop_control_ops = {
    .ioctl = loop_ioctl,
};

static void
loop_init(void)
{
    workqueue_start_multiple(&loop_block_queue, "loop", 4);
}

initcall_subsys(block_loop, loop_init);
