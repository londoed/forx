/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { block/bcache.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/libctl/string.h>
#include <forx/list.h>
#include <forx/sched.h>
#include <forx/mm/kmalloc.h>
#include <forx/crc.h>

#include <forx/arch/spinlock.h>
#include <forx/arch/tast.h>
#include <forx/arch/cpu.h>
#include <forx/block/disk.h>
#include <forx/block/bdev.h>
#include <forx/block/bcache.h>

#define BLOCK_HASH_TABLE_SIZE CONFIG_BLOCK_HASH_TABLE_SIZE

static struct BlockCache {
    Spinlock lock;

    /**
     * List of cached blocks ready to be checked-out.
     *
     * NOTE: Some of the cached blocks may be currently locked
     * by another process.
    **/
    size_t cache_size;
    struct hlist_head_cache[BLOCK_HASH_TABLE_SIZE];
    ListHead lru;
} block_cache = {
    .lock = SPINLOCK_INIT(),
    .cache_size = 0,
    .cache = { { NULL }, },
    .lru = LIST_HEAD_INIT(block_cache.lry),
};

static inline int
block_hash(Device dev, Sector sector)
{
    int hash = ((DEV_MAJOR(dev) + DEV_MINOR(dev)) ^ (sector)) % BLOCK_HASH_TABLE_SIZE;

    return hash;
}

static void
__block_uncache(struct Block *b)
{
    block_cache.cache_size -= b->block_size;

    // Remove this block from the cache //
    hlist_del(&b->cache);
    list_del(&b->block_lru_node);
    list_del(&b->bdev_blocks_entry);
}

static void
__block_cache(struct Block *b)
{
    int hash = block_hash(b->bdev->dev, b->sector);

    hlist_add(block_cache.cache + hash, &b->cache);
    block_cache.cache_size += b->block_size;
    list_add(&b->bdev->blocks, &b->bdev_blocks_entry);
}

static void
block_delete(struct Block *b)
{
    if (b->block_size == PAGE_SIZE)
        page_free_va(b->data, 0);
    else
        kfree(b->data);

    kfree(b);
}

static struct Block *
block_new(void)
{
    struct Block *b = kzalloc(sizeof(*b), PAL_KERNEL);

    spinlock_init(&b->flags_lock);
    wait_queue_init(&b->flags_queue);

    list_node_init(&b->block_list_node);
    list_node_init(&b->block_lru_node);
    list_node_init(&b->bdev_blocks_entry);
    list_node_init(&b->block_sync_node);
    atomic_init(&b->refs, 0);

    return b;
}

static void
__block_cache_shrink(void)
{
    size_t freed_space = 0;
    int already_synced = 0;
    struct Block *b, *next;

    kprintf(KERN_NORM, "Shrinking block cache...\n");

again:
    list_foreach_entry_safe(&block_cache.lru, b, next, block_lru_node) {
        if (block_try_lock(b) != SUCCESS)
            continue;

        if (atomic_get(&b->refs) != 0) {
            block_unlock(b);
            continue;
        }

        // Don't need the spinlock, there's no existing references //
        if (flag_test(&b->flags, BLOCK_DIRTY)) {
            block_unlock(b);
            continue;
        }

        freed_space += b->block_size;

        // Remove this block from the cache //
        __block_uncache(b);
        block_delete(b);

        if (freed_space >= CONFIG_BLOCK_CACHE_SHRINK_SIZE)
            break;
    }

    // We could be stuck due to too many dirty blocks, sync them and try again //
    if (!already_synced && freed_space < CONFIG_BLOCK_CACHE_SHRINK_SIZE) {
        spinlock_release(&block_cache.lock);

        /**
         * We could potentially be more optimal and only sync the LRU blocks.
         * The only potential problem with that approach is that if someone
         * grabs a referenece during the sync they may no longer be in the
         * LRU after the sync() and we'll still have no blocks to free.
        **/
        block_sync_all(1);
        spinlock_acquire(&block_cache.lock);
        already_synced = 1;
        goto again;
    }

    kprintf(KERN_NORMAL, "Block cache shrunk, free'd bytes: %d\n", freed_space);
}

void
bcache_oom(void)
{
    using_spinlock(&block_cache.lock)
        __block_cache_shrink();
}

void
block_wait_for_sync(struct Block *b)
{
    using_spinlock(&b->flags_lock)
        wait_queue_event_spinlock(&b->flags_queue, !flag_test(&b->flags,
            BLOCK_LOCKED), &b->flags_lock);
}

static struct Block *
__find_block(Device dev, Sector sector)
{
    struct Block *b;
    int hash = block_hash(dev, sector);

    hlist_foreach_entry(block_cache.cache + hash, b, cache) {
        if (b->bdev->dev == dev && b->sector == sector)
            return b;
    }

    return NULL;
}

/**
 * This function returns the Block for the given device and sector,
 * but does not sync it, so it may be completely fresh and not
 * actually read off the disk.
**/
struct Block *
block_get_nosync(struct BlockDev *bdev, Sector sector)
{
    struct Block *b = NULL, *new = NULL;
    size_t block_size = block_dev_block_size_get(bdev);

    spinlock_acquire(&block_cache.lock);
    b = __find_block(bdev->dev, sector);

    if (b)
        goto inc_and_return;

    /**
     * We do the shrink __before__ we allocate a new block if it is
     * necessary. This is to ensure the shrink can't remove the block
     * we're about to add from the cache.
    **/
    if (block_cache.cache_size >= CONFIG_BLOCK_CACHE_MAX_SIZE)
        __block_cache_shrink();

    spinlock_release(&block_cache.lock);
    new = block_new();
    new->block_size = block_size;

    if (block_size != PAGE_SIZE)
        new->data = kzalloc(block_size, PAL_KERNEL);
    else
        new->data = page_alloc_va(0, PAL_KERNEL);

    new->sector = sector;
    new->bdev = bdev;
    spinlock_acquire(&block_cache.lock);

    /**
     * We had to drop the lock because allocating the memory may sleep.
     * If there is a race and a second allocation happens for the same
     * block then the block we just make might already be in the hash
     * list. In that situation we simply delete the one we just made
     * and return the existing one.
    **/
    b = __find_block(bdev->dev, sector);

    if (b) {
        block_delete(new);
        goto inc_and_return;
    }

    // Insert our new block into the cache //
    __block_cache(new);
    b = new;

inc_and_return:
    atomic_inc(&b->refs);

    // Refresh the LRU entry for this block //
    if (list_node_is_in_list(&b->block_lru_node))
        list_del(&b->block_lru_node);

    list_add_tail(&block_cache.lru, &b->block_lru_node);
    spinlock_release(&block_cache.lock);

    return 0;
}

struct Block *
block_get(struct BlockDev *dev, Sector sector)
{
    struct Block *b;

    if (!dev)
        return NULL;

    b = block_get_nosync(dev, sector);

    if (!b)
        return NULL;

    /**
     * We can check this without the lock because BLOCK_VALID is never
     * removed once set, and syncing an extra time isn't a big deal.
    **/
    if (!flag_test(&b->flags, BLOCK_VALID)) {
        int should_sync = 0, should_wait = 0;

        /**
         * If the block is already LOCKED, then it will become VALID once
         * that is done and we don't need to submit it ourselves.
        **/
        using_spinlock(&b->flags_lock) {
            if (flag_test(&b->flags, BLOCK_LOCKED))
                should_wait = 1;
            else if (!flag_test(&b->flags, BLOCK_VALID))
                should_sync = 1;
        }

        if (should_sync) {
            block_lock(b);
            block_submit(b);
        }

        if (should_wait || should_sync)
            block_wait_for_sync(b);
    }

    return b;
}

void
block_put(struct Block *b)
{
    atomic_dec(&b->refs);
}

/**
 * Protects the b->block_sync_node entries.
 * Ordering:
 *    sync_lock
 *    block_cache.lock
**/
static Mutex sync_lock = MUTEX_INIT(sync_lock);

void
block_dev_clear(struct BlockDev *bdev)
{
    struct Block *b;

    block_dev_sync(bdev, 1);

    using_spinlock(&block_cache.lock) {
        list_foreach_take_entry(&bdev->blocks, b, bdev_blocks_entry) {
            if (b->bdev != bdev)
                continue;

            if (block_try_lock(b) != SUCCESS || atomic_get(&b->refs) != 0) {
                kprintf(KERN_WARN, "Block: Reference to block %d:%d held when "
                    "block_dev_clear() was called\n", b->bdev->dev, b->sector);
                continue;
            }

            if (flag_test(&b->flags, BLOCK_DIRTY)) {
                kprintf(KERN_WARN, "Block: block %d:%d was still dirty when block_dev_clear() "
                    "was called\n", b->bdev->dev, b->sector);
                continue;
            }

            __block_uncache(b);
            block_delete(b);
        }
    }
}

void
block_dev_sync(struct BlockDev *bdev, int wait)
{
    ListHead sync_list = LIST_HEAD_INIT(sync_list);
    struct Block *b, *next;

    using_mutex(&sync_lock) {
        using_spinlock(&block_cache.lock) {
            list_foreach_entry(&bdev->blocks, b, bdev_blocks_entry) {
                if (b->bdev != bdev)
                    continue;

                using_spinlock(&b->flags_lock) {
                    if (flag_test(&b->flags, BLOCK_VALID) && flag_test(&b->flags, BLOCK_DIRTY)) {
                        atomic_inc(&b->refs);
                        list_add_tail(&sync_list, &b->block_sync_node);
                    }
                }
            }
        }

        /**
         * It's better to simply hold the block_cache.lock spinlock the
         * whole time and them submit all the blocks down here.
         *
         * Safe is used because if we're not waiting we need to drop the
         * reference here too.
        **/
        list_foreach_entry_safe(&sync_list, b, next, block_sync_node) {
            block_lock(b);
            block_submit(b);

            if (!wait)
                block_put(b);
        }

        if (!wait)
            return;

        while (!list_empty(&sync_list)) {
            b = list_take_first(&sync_list, struct Block, block_sync_node);

            // Wait for block to be synced, and then drop reference //
            block_wait_for_sync(b);
            atomic_dec(&b->refs);
        }
    }
}

void
block_sync_all(int wait)
{
    ListHead sync_list = LIST_HEAD_INIT(sync_list);
    struct Block *b, *next;

    using_mutex(&sync_lock) {
        using_spinlock(&block_cache.lock) {
            int hash;

            for (hash = 0; hash < BLOCK_HASH_TABLE_SIZE; hash++) {
                hlist_foreach_entry(block_cache.cache + hash, b, cache) {
                    using_spinlock(&b->flags_lock) {
                        if (flag_test(&b->flags, BLOCK_VALID) && flag_test(&b->flags, BLOCK_DIRTY)) {
                            atomic_inc(&b->refs);
                            list_add_tail(&sync_list, &b->block_sync_node);
                        }
                    }
                }
            }
        }

        /**
         * It's better to simply hold the block_cache.lock spinlock
         * the whole time and then submit all the blocks down here.
         *
         * Safe is used because if we're not waiting we need to drop the
         * reference here too.
        **/
        list_foreach_entry_safe(&sync_list, b, next, block_sync_node) {
            block_lock(b);

            if (!flag_test(&b->flags, BLOCK_VALID) || !flag_test(&b->flags, BLOCK_DIRTY)) {
                block_unlockput(b);
                continue;
            }

            block_submit(b);

            if (!wait)
                block_put(b);
        }

        if (!wait)
            return;

        while (!list_empty(&sync_list)) {
            b = list_take_first(&sync_list, struct Block, block_sync_node);

            // Wait for block to be synced, and then drop reference //
            block_wait_for_sync(b);
            block_put(b);
        }
    }
}
