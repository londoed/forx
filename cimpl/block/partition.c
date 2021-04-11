/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { block/partition.c }.
 * Copyright (C) 2020, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/dump_mem.h>
#include <libctl/string.h>
#include <forx/sched.h>
#include <forx/mm/kmalloc.h>
#include <forx/wait.h>

#include <forx/arch/spinlock.h>
#include <forx/block/bdev.h>
#include <forx/block/disk.h>
#include <forx/block/bcache.h>

struct MbrPart {
    uint8_t attr;
    uint8_t cylinder_s;
    uint8_t head_s;
    uint8_t sector_s;
    uint8_t system_id;
    uint8_t cylinder_e;
    uint8_t head_e;
    uint8_t sector_e;

    // This is the only real useful part, the CHS addresses are irrevelant //
    uint32_t lba_start;
    uint32_t lba_length;
} __packed;

static int
mbr_add_parititions(struct BlockDev *dev)
{
    struct Block *b;
    struct Page *block_dup;
    size_t i;
    struct Disk *disk = dev->disk;
    int part_count = 0;

    const int mbr_part_offsets[] = {
        0x1BE,
        0x1CE,
        0x1DE,
        0x1EE,
    };

    block_dup = page_alloc(0, PAL_KERNEL);

    using_block_locked(dev, 0, b)
        memcpy(block_dup->virt, b->data, b->block_size);

    uint8_t *blk = block_dup->virt;

    // Check for the marker indicating an MBR is present //
    if (blk[510] != 0x55 || blk[511] != 0xAA)
        goto release_copy;

    for (i = 0; i < ARRAY_SIZE(mbr_part_offsets); i++) {
        struct MbrPart *p = (struct MbrPart *)(block_dup->virt + mbr_part_offsets[i]);

        if (p->lba_length) {
            struct DiskPart *part = disk_part_alloc();
            part->first_sector = p->lba_start;
            part->sector_count = p->lba_length;

            kprintf(KERN_NORM, "Partition for device %d:%d: start %d, len: %d\n",
                DEV_MAJOR(dev->dev), DEV_MINOR(dev->dev), part->first_sector, part->sector_count);
            disk_part_add(disk, part);
            part_count++;
        }
    }

release_copy:
    page_free(block_dup, 0);

    return part_count;
}

int
block_dev_repartition(struct BlockDev *bdev)
{
    return mbr_add_partitions(bdev);
}
