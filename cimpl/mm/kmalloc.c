/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { mm/kmalloc.c }.
 * Copyright (C) 2014, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/libctl/string.h>
#include <forx/debug.h>

#include <forx/mm/memlayout.h>
#include <forx/mm/kmalloc.h>
#include <forx/mm/slab.h>

/**
 * kmalloc() doesn't actually do any global locking. This is because slabs
 * are locked individually, inside of slab_malloc/slab_free/etc., and the
 * revelant `kmalloc_slabs` array information is never changed kmalloc/kfree
 * can all read it at the same time.
 *
 * Slabs can be added and removed from this list as wanted. Slabs have to
 * have a size of a power-of-two.
**/
static struct SlabAlloc kmalloc_slabs[] = {
    SLAB_ALLOC_INIT("kmalloc_32", 32),
    SLAB_ALLOC_INIT("kmalloc_64", 64),
    SLAB_ALLOC_INIT("kmalloc_128", 128),
    SLAB_ALLOC_INIT("kmalloc_256", 256),
    SLAB_ALLOC_INIT("kmalloc_512", 512),
    SLAB_ALLOC_INIT("kmalloc_1024", 1024),
    SLAB_ALLOC_INIT("kmalloc_2048", 2048),
    SLAB_ALLOC_INIT("kmalloc_4096", 4096),
    { .slab_name = NULL }
};

/**
 * For sizes larger than the slab allocators can supply. kmalloc() simply
 * allocates from page_alloc() directly. We store those allocations in a
 * big list. Very unoptimal, but there very few users of this functionality
 * in the kernel, most just call page_alloc() directly.
**/
struct LargeAllocDesc {
    ListNode node;
    struct Page *pages;
    int order;
};

static Spinlock large_alloc_lock = SPINLOCK_INIT();
static ListHead large_alloc_list = LIST_HEAD_INIT(large_alloc_list);

void
kmalloc_init(void) {}

void
kmalloc_oom(void)
{
    struct SlabAlloc *slab;

    for (slab = kmalloc_slabs; slab->slab_name; slab++)
        slab_oom(slab);
}

void *
kmalloc(size_t size, int flags)
{
    struct SlabAlloc *slab;

    for (slab = kmalloc_slabs; slab->slan_name; slab++) {
        if (size <= slab->obj_size)
            return slab_malloc(slab, flags);
    }

    int pages = PAGE_ALIGN(size) / PAGE_SIZE;
    int order = pages_to_order(pages);

    // This is only one level of recursion because the desc is very small //
    struct LargeAllocDesc *desc = kmalloc(sizeof(*desc), flags);

    if (!desc)
        return NULL;

    list_node_init(&desc->node);
    desc->order = order;
    desc->pages = page_alloc(order, flags);

    if (!desc->pages) {
        kfree(desc);

        return NULL;
    }

    using_spinlock(&large_alloc_lock)
        list_add_tail(&large_alloc_list, &desc->node);

    return desc->pages->virt;
}

size_t
ksize(void *p)
{
    struct SlabAlloc *slab;

    for (slab = kmalloc_slabs; slab->slab_name; slab++) {
        if (slab_has_addr(slab, p) == 0)
            return slab->obj_size;
    }

    using_spinlock(&large_alloc_lock) {
        struct LargeAllocDesc *desc;

        list_foreach_entry(&large_alloc_list, desc, node) {
            VirtAddr start = desc->pages->virt;
            VirtAddr end = desc->pages->virt + (1 << desc->order) * PAGE_SIZE;

            if (start <= p && p <= end) {
                list_del(&desc->node);
                break;
            }
        }

        if (list_ptr_is_head(&desc->node, &large_alloc_list))
            desc = NULL;
    }

    if (desc) {
        page_free(desc->pages, desc->order);
        kfree(desc);

        return;
    }

    panic("kmalloc: Error: addr %p was not found in kmalloc's memory space\n", p);
}

char *
kstrdup(const char *s, int flags)
{
    size_t len = strlen(s);
    char *buf = kmalloc(len + 1, flags);

    strcpy(buf, s);

    return buf;
}

char *
kstrndup(const char *s, size_t n, int flags)
{
    size_t len = strlen(s);
    char *buf;

    if (len > n)
        len = n;

    buf = kmalloc(len + 1, flags);
    strncpy(buf, s, n);
    buf[len] = '\0';

    return buf;
}
