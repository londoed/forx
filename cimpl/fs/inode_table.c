/**
 * FORX: An open and collaborative operating system kernel for the research community.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { fs/inode_table.c }.
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
#include <forx/arch/spinlock.h>
#include <forx/mutex.h>
#include <forx/atomic.h>
#include <forx/mm/kmalloc.h>
#include <forx/arch/task.h>

#include <forx/block/bcache.h>
#include <forx/block/bdev.h>
#include <forx/fs/super.h>
#include <forx/fs/file.h>
#include <forx/fs/stat.h>
#include <forx/fs/inode.h>
#include <forx/fs/vfs.h>

#define INO_HASH_SIZE 512

/**
 * Protects inode_hashes, inode->hash_entry, inode_freeing_queue.
 * inode->flags_lock nests inside of this lock.
**/
static Spinlock inode_hashes_lock;
static HListHead inode_hashes[INO_HASH_SIZE];

/**
 * This queue is used when an inode is in INO_FREEZING.
 *
 * We cannot wait on the inode's queue because the inode will be free'd out
 * from under us. This single queue is for every inode, hopefully there's
 * not too many in INO_FREEZING at any given time that are also being 
 * requested.
**/
static struct WaitQueue inode_freeing_queue = WAIT_QUEUE_INIT(inode_freeing_queue);
static Atomic inode_count;

/**
 * Use the pointer and inode number for the hash.
**/
static inline int
inode_hash_get(struct SuperBlock *sb, Inode ino)
{
    /**
     * XOR the top and bottom of the pointer so that there's a bit more
     * mixing before we do the mod.
    **/
    uintptr_t sb_ptr = (uintptr_t)sb;
    sb_ptr ^= ((sb_ptr >> 16) | (sb_ptr << 16));

    return (ino ^ sb_ptr) % INO_HASH_SIZE;
}

static void
__inode_hash_add(struct Inode *new)
{
    int hash = inode_hash_get(new->sb, new->ino);

    hlist_add(inode_hashes + hash, &new->hash_entry);
    atomic_inc(&inode_count);
}

// Allocates a completely empty inode //
struct Inode *
inode_create(struct SuperBlock *sb)
{
    struct Inode *new = sb->ops->inode_alloc(sb);

    new->sb = sb;
    atomic_inc(&new->ref);

    return new;
}

static void
inode_deallocate(struct Inode *i)
{
    if (i->bdev)
        block_dev_put(i->bdev);

    i->sb->ops->inode_dealloc(i->sb, i);
}

static void
__inode_uncache(struct Inode *i)
{
    hlist_del(&i->hash_entry);
    list_del(&i->sb_entry);
    list_del(&i->sb_dirty_entry);
}

static void
__inode_wait_for_write(struct Inode *ino)
{
    wait_queue_event_spinlock(&ino->flags_queue, !flag_test(&ino->flags, INO_SYNC),
        &ino->flags_lock);
}

void
inode_wait_for_write(struct Inode *ino)
{
    using_spinlock(&ino->flags_lock)
        __inode_wait_for_write(ino);
}

int
inode_write_to_disk(struct Inode *ino, int wait)
{
    using_spinlock(&ino->flags_lock) {
        if (!flag_test(&ino->flags, INO_DIRTY))
            return 0;

        if (flag_test(&ino->flags, INO_SYNC)) {
            /**
             * Currently syncing, wait for sync to complete if passed
             * `wait`, otherwise just exit.
            **/
            if (wait)
                __inode_wait_for_write(ino);

            return 0;
        }

        flag_set(&ino->flags, INO_SYNC);
    }

    int ret;

    using_inode_lock_read(ino)
        ret = ino->sb->opts->inode_write(ino->sb, ino);

    using_spinlock(&inode_hashes_lock) {
        using_spinlock(&ino->flags_lock) {
            flag_clear(&ino->flags, INO_SYNC);
            flag_clear(&ino->flags, INO_DIRTY);
            list_del(&ino->sb_dirty_entry);
        }
    }

    wait_queue_wake(&ino->flags_queue);

    return ret;
}

static void
inode_evict(struct Inode *ino)
{
    if (ino->sb->ops->inode_delete) {
        int err = ino->sb->ops->inode_delete(ino->sb, ino);

        if (err)
            kprintf(KERN_WARN, "Error when deleting inode "PRinode" "
                "Error: %d\n", Pinode(ino), err);
    }

    // All done here, get rid of it //
    using_spinlock(&inode_hashes_lock)
        __inode_uncache(ino);

    inode_deallocate(ino);

    // Notify anybody waiting for this inode to be freed //
    wait_queue_wake(&inode_freeing_queue);
}

void
inode_put(struct Inode *ino)
{
    spinlock_acquire(&inode_hashes_lock);
    spinlock_acquire(&ino->flags_lock);

    /**
     * Check if the inode is completely gone, and remove it if so. If
     * we're already INO_FREEING, then we don't do this--this could
     * happen if a INO_SYNC is currently happening.
    **/
    if (atomic_dec_and_test(&ino->ref) && !atomic_get(&ino->nlinks) &&
        !flag_test(&ino->flags, INO_FREEING)) {

        kassert(!flag_test(&ino->flags, INO_SYNC), "INO_SYNC should not be set if inode->ref == 0\n");
        flag_set(&ino->flags, INO_FREEING);
        spinlock_release(&ino->flags_lock);
        spinlock_release(&inode_hashes_lock);
        inode_evict(ino);

        return;
    }

    // Add to proper dirty list if it's dirty //
    if (flag_test(&ino->flags, INO_DIRTY) && !list_node_is_in_list(&ino->sb_dirty_entry))
        list_add_tail(&ino->sb->dirty_inodes, &ino->sb_dirty_entry);

    spinlock_release(&ino->flags_lock);
    spinlock_release(&inode_hashes_lock);
}

struct Inode *
inode_dup(struct Inode *ino)
{
    atomic_inc(&ino->ref);

    return ino;
}

/**
 * NOTE: Requires inode_hashes_lock and inode to be locked. Returns with only
 * inode_hashes_lock locked.
**/
static void
wait_for_freeing(struct Inode *ino)
{
    struct Task *current = cpu_to_local()->current;

    sched_set_sleeping();
    wait_queue_register(&inode_freeing_queue, &current->wait);

    /**
     * NOTE: The release order is actually important. After the inode_hashes_lock
     * is released, `ino` may no longer be vaild and flags_lock cannot be held
     * when the ino is deallocated.
    **/
    spinlock_release(&ino->flags_lock);
    spinlock_release(&inode_hashes_lock);
    sched_task_yield();

    /**
     * Don't grab ino->flags_lock--we're not checking the flags here, and
     * the inode was presumably freed while we were waiting.
    **/
    spinlock_acquire(&inode_hashes_lock);
    wait_queue_unregister(&current->wait);
    sched_set_running();
}

void
inode_mark_valid(struct Inode *new)
{
    using_spinlock(&new->flags_lock)
        flag_set(&new->flags, INO_VALID);

    wait_queue_wake(&new->flags_queue);
}

void
inode_mark_bad(struct Inode *new)
{
    struct Inode *drop = NULL;

    using_spinlock(&inode_hashes_lock) {
        spinlock_acquire(&new->flags_lock);

        // Don't bother signalling INO_BAD if there are not other references //
        if (atomic_dec_and_test(&new->ref)) {
            spinlock_release(&new->flags_lock);
            __inode_uncache(new);
            drop = new;
        } else {
            flag_set(&new->flags, INO_BAD);
            wait_queue_wake(&new->flags_queue);
            spinlock_release(&new->flags_lock);
        }
    }

    if (drop)
        inode_deallocate(drop);
}

/**
 * Waits for an inode to become either valid or bad.
 *
 * If bad, it decrements the count, handles cleanup, and returns NULL.
 * If valid, return the inode.
**/
static struct Inode *
inode_wait_for_valid_or_bad(struct Inode *ino)
{
    using_spinlock(&ino->flags_lock)
        wait_queue_event_spinlock(&ino->flags_queue, ino->flags &
            F(INO_VALID, INO_BAD), &ino->flags_lock);

    // We need inode_hashes_lock to be able to __inode_uncache //
    spinlock_acquire(&inode_hashes_lock);
    spinlock_acquire(&ino->flags_lock);

    if (flag_test(&ino->flags, INO_BAD)) {
        int drop = atomic_dec_and_test(&ino->ref);
        spinlock_release(&ino->flags_lock);

        if (drop)
            __inode_uncache(ino);

        spinlock_release(&inode_hashes_lock);
        inode_deallocate(ino);
        ino = NULL;
    } else {
        spinlock_release(&ino->flags_lock);
        spinlock_release(&inode_hashes_lock);
    }

    return ino;
}

struct Inode *
inode_get_invalid(struct SuperBlock *sb, Inode ino)
{
    int hash = inode_hash_get(sb, ino);
    struct Inode *inode, *new = NULL, *found = NULL;

again:
    using_spinlock(&inode_hashes_lock) {

again_no_acquire:
        hlist_foreach_entry(&inode_hashes[hash], inode, hash_entry) {
            if (inode->ino == ino && inode->sb == sb) {
                spinlock_acquire(&inode->flags_lock);

                if (flag_test(&inode->flags, INO_FREEING)) {
                    wait_for_freeing(inode);
                    goto again_no_acquire;
                }

                spinlock_release(&inode->flags_lock);
                atomic_inc(&inode->ref);
                found = inode;
                break;
            }
        }

        /**
         * We have an allocated inode and did not find the one we were
         * looking for--add the new one to the hash table and continue
         * on to set it up.
        **/
        if (!found && new) {
            __inode_hash_add(new);
            list_add_tail(&sb->inodes, &new->sb_entry);
            found = new;
        }
    }

    // Didn't find the inode, allocate a new one and try again //
    if (!found && !new) {
        new = inode_create(sb);
        new->ino = ino;
        goto again;
    }

    // Found an inode and it was not the one we allocated--deallocate if NULL //
    if (new && found != new)
        inode_deallocate(new);

    if (found && found == new)
        return found;

    // Found an inode, did not create it--wait for INO_VALID or INO_BAD //
    if (found && found != new)
        found = inode_wait_for_valid_or_bad(found);

    /**
     * The case of adding a new inode falls through to here--we return it
     * with the INO_VALID flag not set.
    **/
    return found;
}

struct Inode *
inode_get(struct SuperBlock *sb, Inode ino)
{
    struct Inode *inode = inode_get_invalid(sb, ino);

    if (!inode)
        return NULL;

    /**
     * No locking necessary because INO_VALID is never unset after being set.
     * This case is hit if inode_get_invalid created a fresh inode.
    **/
    if (flag_test(&inode->flags, INO_VALID))
        return inode;

    // If we added the new inode allocated by us, then fill it in and mark it valid //
    int ret = sb->ops->inode_read(sb, inode);

    if (ret) {
        kprintf(KERN_WARN, "Error reading inode "PRinode\n", Pinode(inode)");
        inode_mark_bad(inode);

        return NULL;
    }

    inode_mark_valid(inode);

    return inode;
}

/**
 * Protects the `inode->sync_entry` members. Those are used to easily create
 * lists of inodes currently being written out or deleted, so that we can
 * queue them all up at once and then wait on them afterward.
**/
static Mutex sync_lock = MUTEX_INIT(sync_lock);

void
inode_sync(struct SuperBlock *sb, int wait)
{
    ListHead sync_list = LIST_HEAD_INIT(sync_list);
    struct Inode *ino;

    using_mutex(&sync_lock) {
        using_spinlock(&inode_hashes_lock) {
            int hash;

            for (hash = 0; hash < INO_HASH_SIZE; hash++) {
                hlist_foreach_entry(inode_hashes + hash, ino, hash_entry) {
                    if (sb && ino->sb != sb)
                        continue;

                    spinlock_acquire(&ino->flags_lock);

                    // Check if we should actually be syncing this one before grabbing a reference //
                    if (flag_test(&ino->flags, INO_FREEING) || !flag_test(&ino->flags,
                        INO_VALID) || !flag_test(&ino->flags, INO_DIRTY)) {

                        spinlock_release(&ino->flags_lock);

                        // NOTE: `wait` flag should trigger some waiting on INO_FREEING maybe? //
                        continue;
                    }

                    spinlock_release(&ino->flags_lock);
                    atomic_inc(&ino->ref);
                    list_add_tail(&sync_list, &ino->sync_entry);
                }
            }
        }

        while (!list_empty(&sync_list)) {
            ino = list_take_first(&sync_list, struct Inode, sync_entry);
            inode_write_to_disk(ino, wait);
            inode_put(ino);
        }
    }
}

void
inode_sync_all(int wait)
{
    return inode_sync(NULL, wait);
}

static void
inode_finish_list(ListHead *head)
{
    while (!list_empty(head)) {
        struct Inode *ino = list_take_first(head, struct Inode, sync_entry);
        inode_finish(ino);
    }
}

/**
 * Removes all the inodes associated with a SuperBlock that has no existing
 * references.
 *
 * The root inode gets some special handling--if we manage to remove every
 * inode from the SuperBlock, then we check if we're holding the only root
 * inode reference and drop it if so.
**/
int
inode_clear_super(struct SuperBlock *sb, struct Inode *root)
{
    struct Inode *ino;

again:
    spinlock_acquire(&inode_hashes_lock);

again_locked:
    list_foreach_entry(&sb->inodes, ino, sb_entry) {
        // Skip any inodes with active references--should always include root //
        if (atomic_get(&ino->flags_lock))
            continue;

        spinlock_acquire(&ino->flags_lock);

        /**
         * If an inode is currently being freed, wait for the signal and
         * start over, so that when inode_clear_super() returns the inode
         * is actually gone.
        **/
        if (flag_test(&ino->flags, INO_FREEING)) {
            wait_for_freeing(ino);

            // wait_for_freeing drops the ino->flag_lock for us //
            goto again_locked;
        }

        /**
         * Can't happen--non-INO_VALID or INO_SYNC require at least one
         * reference to exist.
        **/
        kassert(flag_test(&ino->flags, INO_VALID), "Inode "PRinode" has no "
            "references, but is not marked INO_VALID\n", Pinode(ino));
        kassert(!flag_test(&ino->flags, INO_SYNC), "Inode "PRinode" has no "
            "references, but is marked INO_SYNC\n", Pinode(ino));

        // Nothing is using this inode, mark it and get rid of it //
        flag_set(&ino->flags, INO_FREEING);
        spinlock_release(&ino->flags_lock);
        spinlock_release(&inode_hashes_lock);

        inode_finish(ino);

        // We dropped inode_hashes_lock and modified sb->inode, so just start over //
        goto again;
    }

    // If there is more than one entry, the super was still in use //
    if (sb->inodes.next->next != &sb->inodes)
        goto release_hashes_lock;

    // The case that root is the only reference still held, in which case ref > 1 //
    if (atomic_get(&root->ref) != 1)
        goto release_hashes_lock;

    // Verify sb->inodes only has one entry for the root inode left //
    if (list_empty(&sb->inodes)) {
        kprintf(KERN_WARN, "SuperBlock has no inodes despite still having a "
            "reference to root\n");
        goto release_hashes_lock;
    }

    if (sb->inodes.next != &root->sb_entry) {
        kprintf(KERN_WARN, "SuperBlock's last inode is not a reference to root\n");
        goto release_hashes_lock;
    }

    if (!atomic_get(&root->ref)) {
        kprintf(KERN_WARN, "Root's ref count is zero\n");
        atomic_inc(&root->ref);
    }

    /**
     * Drop root reference.
     *
     * We actually have a guarantee that the reference cannot be acquired
     * again, even when we drop hashes lock--the associated vfs_mount
     * currently has VFS_MOUNT_UNMOUNTING set. While that is set, the
     * vfs_mount_cannot be used, and that is the only direct way to gain
     * a reference to the SuperBlock's root.
     *
     * Thus, we drop it here, and then the caller will finish up the rest
     * of the umount.
    **/
    using_spinlock(&root->flags_lock) {
        atomic_dec(&root->ref);
        flag_set(&root->flags, INO_FREEING);
    }

    spinlock_release(&inode_hashes_lock);
    inode_finish(root);

    return 0;

release_hashes_lock:
    spinlock_release(&inode_hashes_lock);

    return -EBUSY;
}

void
inode_oom(void)
{
    ListHead *finish_list = LIST_HEAD_INIT(finish_list);
    struct Inode *ino;

    using_mutex(&sync_lock) {
        using_spinlock(&inode_hashes_lock) {
            int hash;

            for (hash = 0; hash < INO_HASH_SIZE; hash++) {
                hlist_foreach_entry(inode_hashes + hash, ino, hash_entry) {
                    // Skip any inodes with active references //
                    if (atomic_get(&ino->ref))
                        continue;

                    spinlock_acquire(&ino->flags_lock);

                    if (!flag_test(&ino->flags, INO_VALID) ||
                        flag_test(&ino->flags, INO_FREEING)) {

                        spinlock_release(&ino->flags_lock);
                        continue;
                    }

                    kassert(flag_test(&ino->flags, INO_VALID), "Inode "PRinode" has "
                        "no references, but is not marked INO_VALID", Pinode(ino));
                    kassert(!flag_test(&ino->flags, INO_SYNC), "Inode "PRinode" has no "
                        "references, but is marked INO_SYNC\n", Pinode(ino));

                    flag_set(&ino->flags, INO_FREEING);
                    spinlock_release(&ino->flags_lock);
                    list_add_tail(&finish_list, &ino->sync_entry);
                }
            }
        }

        inode_finish_list(&finish_list);
    }
}

#ifdef CONFIG_KERNEL_TESTS
#include "inode_table_test.c"
#endif
