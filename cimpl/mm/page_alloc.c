/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { mm/page_alloc.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <libctl/bits.h>
#include <libctl/list.h>
#include <forx/spinlock.h>
#include <forx/sched.h>
#include <forx/wait.h>
#include <forx/mm/kmalloc.h>
#include <forx/fs/inode.h>
#include <forx/block/bcache.h>
#include <forx/backtrace.h>
#include <forx/mm/bootmem.h>
#include <forx/mm/page_alloc.h>

extern char kern_end, kern_start;

struct PageBuddyMap {
    ListHead free_pages;
    int free_count;
    struct WaitQueue wait_for_free;
};

struct PageBuddyAlloc {
    Spinlock lock;
    struct Page *pages;
    int page_count;
    struct PageBuddyMap *maps;
    int map_count;
    int free_pages;
};

#define PALLOC_MAPS 6

static struct PageBuddyMap buddy_maps[PALLOC_MAPS];

static struct PageBuddyAlloc buddy_allocator = {
    .lock = SPINLOCK_INIT(),
    .pages = NULL,
    .page_count = 0,
    .maps = buddy_maps,
    .map_count = PALLOC_MAPS,
    .free_pages = 0,
};

/**
 * Called of page_alloc() runs out of memory to hand out. Call the `oom`
 * routines, which attempt to free memory being used by various caches.
 *
 * Note that a call to __oom() doesn't necessarily mean we're completely
 * out of memory. Reserve pages may still be available. The `oom`
 * routines will make use of these pages if they need to do allocation
 * (which is not impossible).
**/
void
__oom(void)
{
    kmalloc_oom();
    inode_oom();
    bcache_oom();
}

struct Page *
page_from_pn(PageNum page_num)
{
    return buddy_allocator.pages + page_num;
}

/**
 * We swap the bit in the `order` position to get this pages buddy.
 * This works because the buddy is always `2 ^ order` pages away.
**/
static inline PageNum
get_buddy_pn(PageNum pn, int order)
{
    return pn ^ (1 << order);
}

void
__pfree_add_pages(struct PageBuddyAlloc *alloc, PageNum cur_page, int order)
{
    int orig_order = order;
    struct Page *p, *buddy;

    while (order < PALLOC_MAPS - 1) {
        buddy = page_from_pn(get_buddy_pn(cur_page, order));

        if (buddy->order != order || bit_test(&buddy->flags, PG_INVALID))
            break;

        /**
         * Remove our buddy from it's current free list, then use the
         * lower of our two pages as our new higher-order page, and clear
         * the `order` value of the other page.
        **/
        list_del(&buddy->page_list_node);
        alloc->maps[order].free_count--;
        cur_page &= ~(1 << order);

        p = page_from_pn(get_buddy_pn(cur_page, order));
        p->order = -1;
        order++;
    }

    p = page_from_pn(cur_page);
    p->order = order;
    list_add(&alloc->maps[order].free_pages, &p->page_list_node);
    alloc->maps[order].free_count++;
    alloc->free_pages += 1 << orig_order;
}

void
__mark_page_free(PhysAddr pa)
{
    if (pa >= V2P(&kern_start) && pa < V2P(&kern_end)) {
        kprintf(KERN_ERR, "Marking a page free that's part of kernel memory\n");

        return;
    }

    __pfree_add_pages(&buddy_allocator, __PA_TO_PN(pa), 0);
}

void
pfree(struct Page *p, int order)
{
    int i;

    if (!p) {
        kprintf(KERN_ERR, "ERROR: pfree: %p\n", p);

        return;
    }

    PhysAddr pa = page_to_pa(p);

    if (pa >= V2P(&kern_start) && pa < V2P(&kern_end)) {
        kprintf(KERN_ERR, "pfree() called on page that's part of the kernel. "
            "Page was: %p\n", p->virt);
        dump_stack(KERN_ERR);

        return;
    }

    if (!atomic_dec_and_test(&p->use_count))
        return;

    using_spinlock(&buddy_allocator.lock) {
        __pfree_add_pages(&buddy_allocator, p->page_num, order);

         for (i = 0; i <= order; i++)
            wait_queue_wake(&buddy_allocator.maps[i].wait_for_free);
    }
}

void
page_free_unordered(ListHead *head)
{
    struct Page *p;

    list_foreach_take_entry(head, p, page_list_node)
        page_free(p, 0);
}

// Breaks apart a page of `order` size into two pages of `order - 1` size //
static void
break_page(struct PageBuddyAlloc *alloc, int order, unsigned int flags)
{
    struct Page *p, *buddy;

    if (order >= PALLOC_MAPS || order < 0) {
        kprintf(KERN_ERR, "page_alloc: break_page() failed\n");

        return;
    }

    if (alloc->maps[order].free_count == 0) {
        break_page(alloc, order + 1, flags);

        // It's possible `break_page()` failed //
        if (alloc->maps[order].free_count == 0)
            return;
    }

    p = list_take_last(&alloc->maps[order].free_pages, struct Page page, page_list_node);
    alloc->maps[order].free_count--;
    order--;

    buddy = page_from_pn(get_buddy_pn(p->page_num, order));
    p->order = order;
    buddy->order = order;

    list_add(&alloc->maps[order].free_pages, &p->page_list_node);
    list_add(&alloc->maps[order].free_pages, &buddy->page_list_node);
    alloc->maps[order].free_count += 2;
}

static void
__page_alloc_sleep_for_enough_pages(struct PageBuddyAlloc *alloc, int order, unsigned int flags)
{
    if (alloc->free_pages < (1 << order)) {
        kprintf(KERN_WARN, "Out of memory: Attempting to free some\n");
        __oom();
    }

    wait_queue_event_spinlock(&alloc->maps[order].wait_for_free,
        alloc->free_pages >= (1 << order), &alloc->lock);
}

static struct Page *
__page_alloc_phys_multiple(struct PageBuddyAlloc *alloc, int order, unsigned int flags)
{
    struct Page *p;

    if (!(flags & __PAL_NOWAIT))
        __page_alloc_sleep_for_enough_pages(&buddy_allocator, order, flags);

    if (alloc->maps[order].free_count == 0) {
        break_page(alloc, order + 1, flags);

        if (alloc->maps[order].free_count == 0) {
            p = NULL;
            goto return_page;
        }
    }

    p = list_take_last(&alloc->maps[order].free_pages, struct Page, page_list_node);
    alloc->maps[order].free_count--;

    /**
     * Sanity check--if somehow the page array was corrupted, this could catch
     * it and fail us early.
    **/
    if (p->page_num != (p - alloc->pages))
        panic("Error: page=%p, %d, %p\n", p, p->page_num, p->virt);

    p->order = -1;
    buddy_allocator.free_pages -= 1 << order;

return_page:
    if (p)
        atomic_inc(&p->use_count);

    return p;
}

struct Page *
page_alloc(int order, unsigned int flags)
{
    struct Page *p;

    using_spinlock(&buddy_allocator.lock)
        p = __page_alloc_phys_multiple(&buddy_allocator, order, flags);

    PhysAddr pa = page_to_pa(p);

    if (pa >= V2P(&kern_start) && pa < V2P(&kern_end)) {
        kprintf(KERN_ERR, "page_alloc() is returning a page that's part of the kernel\n");
        dump_stack(KERN_ERR)
    }

    return p;
}

int
page_alloc_unordered(ListHead *head, int count, unsigned int flags)
{
    using_spinlock(&buddy_allocator.lock) {
        struct Page *p;
        int i;

        for (i = 0; i < count; i++) {
            p = __page_alloc_phys_multiple(&buddy_allocator, 0, flags);
            list_add_tail(head, &p->page_list_node);

            if (!p)
                panic("OOM\n");
        }
    }

    return 0;
}

int
page_alloc_free_page_count(void)
{
    return buddy_allocator.free_pages;
}

void
page_alloc_init(int pages)
{
    struct Page *p;
    int i;

    kprintf(KERN_DEBUG, "Initializing buddy allocator\n");
    buddy_allocator.page_count = pages;
    buddy_allocator.pages = bootmem_alloc(pages * sizeof(struct Page), PAGE_SIZE);

    kprintf(KERN_DEBUG, "Pages: %d, array: %p\n", pages, buddy_allocator.pages);
    memset(buddy_allocator.pages, 0, pages * sizeof(struct Page));

    /**
     * All pages start as INVALID. As the arch init code goes, it will call
     * `free` on any pages which are valid to use.
    **/
    p = buddy_allocator.pages + pages;

    while (p-- >= buddy_allocator.pages) {
        p->order = -1;
        p->page_num = (int)(p - buddy_allocator.pages);

        list_node_init(&p->page_list_node);
        bit_set(&p->flags, PAGE_INVALID);
        p->virt = P2V((p->page_num) << PAGE_SHIFT);
    }

    for (i = 0; i < PALLOC_MAPS; i++) {
        list_head_init(&buddy_allocator.maps[i].free_pages);
        wait_queue_init(&buddy_allocator.maps[i].wait_for_free);
        buddy_allocator.maps[i].free_count = 0;
    }
}
