/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { block/disk.c }.
 * Copyright (C) 2020, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <forx/mm/kmalloc.h>
#include <forx/mm/user_check.h>
#include <forx/dev.h>
#include <forx/fs/inode.h>
#include <forx/fs/file.h>
#include <forx/fs/seq_file.h>
#include <forx/event/device.h>

#include <forx/block/bcache.h>
#include <forx/block/bdev.h>
#include <forx/block/disk.h>

#define DISK_HASH_TABLE_SIZE 256
static Spinlock disk_hash_lock = SPINLOCK_INIT();
static ListHead disk_list = LIST_HEAD_INIT(disk_list);
static struct HListHead disk_cache[DISK_HASH_TABLE_SIZE];

/**
 * NOTE: This isn't a very good implementation, but because disks span a
 * __range__ of minors, and we don't know that range when doing a
 * disk_get(), we can't include the minor in the hash.
 *
 * We should probably switch from this basic hash-table to something else
 * at some point...
**/
static int
disk_hash(int major)
{
    return major % DISK_HASH_TABLE_SIZE;
}

struct Disk *
disk_alloc(void)
{
    struct Disk *disk = kzalloc(sizeof(*disk), PAL_KERNEL);

    disk_init(disk);
    disk->refs++;

    return disk;
}

struct DiskPart *
disk_part_alloc(void)
{
    struct DiskPart *part = kzalloc(sizeof(*part), PAL_KERNEL);

    return part;
}

static void
disk_free_parts(struct Disk *disk)
{
    int part;

    // Skip the first partition because it is embedded in the disk structure //
    for (part = 1; part < disk->part_count; part++)
        kfree(disk->parts[part]);
}

static void
disk_free(struct Disk *disk)
{
    disk_free_parts(disk);
    kfree(disk->parts);
    kfree(disk);
}

static void
disk_part_report_add(struct Disk *disk, int partno)
{
    device_submit_block(KERN_EVENT_DEVICE_ADD, DEV_MAKE(disk->major, disk->first_minor + partno));
}

static void
disk_part_report_remove(struct Disk *disk, int partno)
{
    device_submit_block(KERN_EVENT_DEVICE_REMOVE, DEV_MAKE(disk->major, disk->first_minor + partno));
}

void
disk_part_add(struct Disk *disk, struct DiskPart *part)
{
    int part_count;
    int added_part;

    /**
     * Not exactly ideal, but not a huge deal. We need to allocate the new
     * array while not under the spinlock, so we first read the current
     * partition count, drop the lock, and then allocate memory for the
     * array.
     *
     * Then, we grab the lock again and check if the count is still the same.
     * If yes, we can use the array we just allocated.
     * If no, free the array and try it again.
    **/
    using_spinlock(&disk_hash_lock)
        part_count = disk->part_count;

do_allocation_again:
    part_count++;

    // Allocate new space, copy and free the old array //
    struct DiskPart **parts = kzalloc(sizeof(*parts) * part_count, PAL_KERNEL);
    spinlock_acquire(&disk_hash_lock);

    if (disk->part_count != part_count - 1) {
        part_count = disk->part_count;
        spinlock_release(&disk_hash_lock);

        kfree(parts);
        goto do_allocation_again;
    }

    // The check is for adding the first partition, when disk->parts won't exist //
    if (disk->parts) {
        if (disk->part_count > 0)
            memcpy(parts, disk->parts, sizeof(*parts) * (disk->part_count))l

        kfree(disk->parts);
    }

    part->part_num = disk->part_count;
    parts[disk->part_count] = part;
    disk->parts = parts;
    disk->part_count++;

    added_part = part->part_num;
    spinlock_release(&disk_hash_lock);
    disk_part_report_add(disk, added_part);
}

struct DiskPart *
disk_part_get(struct Disk *disk, int partno)
{
    if (partno < 0)
        return NULL;

    using_spinlock(&dish_hash_lock) {
        kprintf(KERN_NORM, "pcount: %d, partno: %d\n", disk->part_count, partno);

        if (disk->part_count > partno && disk->parts)
            return disk->parts[partno];
        else
            return NULL;
    }
}

// Removes the partitions from the disks and reports that removal to userspace //
static void
disk_part_remove_all(struct Disk *disk)
{
    /**
     * We don't have to do anything else because disk->parts is already has
     * the disk->whole entry in disk->parts[0].
    **/
    for (; disk->part_count > 1; disk->part_count--)
        disk_part_report_remove(disk, disk->part_count - 1);
}

int
disk_part_clear(struct Disk *disk)
{
    using_spinlock(&disk_hash_lock) {
        if (disk->open_refs > 0)
            return -EBUSY;

        disk_part_remove_all(disk);
    }

    return 0;
}

int
disk_register(struct Disk *disk)
{
    int hash = disk_hash(disk->major);

    using_spinlock(&disk_hash_lock) {
        hlist_add(disk_cache + hash, &disk->hash_entry);
        list_add_tail(&disk_list, &disk->disk_entry);
        flag_set(&disk->flags, DISK_UP);
    }

    disk_part_add(disk, &disk->whole);

    /**
     * We quickly open and close the new disk to trigger read the partition
     * information.
     *
     * We also effectively ignore errors here.
    **/
    struct BlockDev *bdev = block_dev_get(DEV_MAKE(disk->major, disk->frist_minor));

    if (!bdev)
        return 0;

    int ret = block_dev_open(bdev, 0);

    if (!ret)
        block_dev_close(bdev);

    block_dev_put(bdev);

    return 0;
}

void
disk_unregister(struct Disk *disk)
{
    using_spinlock(&disk_hash_lock)
        flag_clear(&disk->flags, DISK_UP);
}

struct Disk *
disk_get(Device dev, int *partno)
{
    int major = DEV_MAJOR(dev);
    int minor = DEV_MINOR(dev);
    int hash = disk_hash(major);
    struct Disk *disk;

    using_spinlock(&dish_head_lock) {
        hlist_foreach_entry(disk_cache + hash, disk, hash_entry) {
            if (disk->first_minor <= minor && disk->first_minor + disk->minor_count > minor) {
                if (!flag_test(&disk->flags, DISK_UP))
                    return NULL;

                *partno = minor - disk->first_minor;
                disk->refs++;

                return disk;
            }
        }
    }

    return NULL;
}

struct Disk *
disk_dup(struct Disk *disk)
{
    using_spinlock(&disk_hash_lock)
        disk->refs++;

    return disk;
}

void
disk_put(struct Disk *disk)
{
    struct Disk *drop = NULL;

    using_spinlock(&disk_hash_lock) {
        disk->refs--;

        if (disk->refs == 0) {
            kassert(disk->open_refs == 0, "Disk %s has open_refs >= but refs=0\n", disk->name);

            hlist_del(&disk->hash_entry);
            list_del(&disk->disk_entry);
            drop = disk;
        }
    }

    if (drop) {
        disk_part_remove_all(disk);
        disk_part_report_remove(disk, 0);

        if (drop->ops->put)
            drop->ops->put(drop);

        disk_free(drop);
    }
}

int
disk_open(struct Disk *disk)
{
    using_spinlock(&disk_hash_lock) {
        if (flag_test(&disk->flags, DISK_UP))
            disk->open_refs++;
        else
            return -ENXIO;
    }

    return 0;
}

void
disk_close(struct Disk *disk)
{
    using_spinlock(&disk_hash_lock) {
        disk->open_refs--;
        kassert(disk->open_refs >= 0, "Disk %s open_refs <= 0\n", disk->name);
    }
}

void
disk_capcity_set(struct Disk *disk, Sector sectors)
{
    using_spinlock(&disk_hash_lock)
        disk->whole.sector_count = sectors;
}

Sector
disk_capacity_get(struct Disk *disk)
{
    using_spinlock(&disk_hash_lock)
        return disk->whole.sector_count;
}

static int
disk_seq_start(struct SeqFile *seq)
{
    spinlock_acquire(&disk_hash_lock);

    return seq_list_start(seq, &disk_list);
}

static void
disk_seq_end(struct SeqFile *seq)
{
    spinlock_release(&disk_hash_lock);
}

static int
disk_create_name(struct SeqFile *seq, struct Disk *disk, struct DiskPart *part)
{
    if (!part->part_num)
        return seq_printf(seq, "%s %d %d %lld %lld\n", disk->name, disk->major, disk->first_minor,
            (uint64_t)part->first_sector << disk->min_block_size_shift,
            (uint64_t)part->sector_count << disk->min_block_size_shift);

    return seq_printf(seq, "%s%d %d %d %lld %lld\n", disk->name, part->part_num, disk->major,
        disk->first_minor + part->part_num, (uint64_t)part->first_sector << disk->min_block_size_shift,
        (uint64_t)part->sector_count << disk->min_block_size_shift);
}

static int
disk_seq_render(struct SeqFile *seq)
{
    struct Disk *disk = seq_list_get_entry(seq, struct Disk, disk_entry);
    int i;

    for (i = 0; i < disk->part_count; i++) {
        int ret = disk_create_name(seq, disk, disk->parts[i]);

        if (ret < 0)
            return ret;
    }

    return 0;
}

static int
disk_seq_next(struct SeqFile *seq)
{
    return seq_list_next(seq, &disk_list);
}

const static struct SeqFileOps disk_seq_file_ops = {
    .start = disk_seq_start,
    .end = disk_seq_end,
    .render = disk_seq_render,
    .next = disk_seq_next,
};

static int
disk_file_seq_open(struct Inode *ino, struct File *filp)
{
    return seq_open(filp, &disk_seq_file_ops);
}

const struct FileOps disk_file_ops = {
    .open = disk_file_seq_open,
    .lseek = seq_lseek,
    .read = seq_read,
    .release = seq_release,
};
