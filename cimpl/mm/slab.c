/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { mm/slab.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/libctl/string.h>
#include <forx/libctl/snprintf.h>
#include <forx/debug.h>
#include <forx/bits.h>
#include <forx/libctl/limits.h>
#include <forx/mm/memlayout.h>
#include <forx/mm/page_alloc.h>
#include <forx/backtrace.h>
#include <forx/kparam.h>

#include <forx/arch/spinlock.h>
#include <forx/arch/paging.h>
#include <forx/mm/slab.h>

static int slab_max_log_level = CONFIG_SLAP_LOG_LEVEL;
KPARAM("slab.loglevel", &slab_max_log_level, KPARAM_LOGLEVEL);

#define kb_slab_check_level(lvl, slab, str, ...) \
    kp_check_level((lvl), slab_max_log_level, "slab %s: ", str,
        ((slab)->slab_name), ##__VA_ARGS__)

#define kslab_trace(slab, str, ...) kslab_check_level(KERN_TRACE, slab, str, ##__VA_ARGS__)
#define kslab_debug(slab, str, ...) kslab_check_level(KERN_DEBUG, slab, str, ##__VA_ARGS__)
#define kslab(slab, str, ...)       kslab_check_level(KERN_NORM, slab, str, ##__VA_ARGS__)
#define kslab_warning(slab, str, ...) kslab_check_level(KERN_WARN, slab, str, ##__VA_ARGS__)
#define kslab_error(slab, str, ...) kslab_check_level(KERN_ERROR, slab, str, ##__VA_ARGS__)

#define SLAB_POISON(0xDEADBEAF)

struct PageFrameEmpty {
    struct PageFrameEntry *next;
};

struct SlabPageFrame {
    struct SlabPageFrame *next;
    void *first_addr;
    void *last_addr;
    int page_index_size;
    int obj_count;
    int free_obj_count;
    struct PageFrameEmpty *free_list;
};

void
__slab_info(struct SlabAlloc *slab, char *buf, size_t buf_size)
{
    struct SlabPageFrame *frame;

    snprintf(buf, buf_size, "slab %s:\n", slab->slab_name);

    for (frame = slab->first_frame; frame != NULL; frame = frame->next)
        snprintf(buf, buf_size, "  frame (%p): %d objects\n", frame, frame->obj_count);
}

static int
__slab_frame_add_new(struct SlabAlloc *slab, unsigned int flags)
{
    char *obj;
    struct PageFrameEmpty **current;
    struct SlabPageFrame *new_frame;
    int i, page_index = CONFIG_KERNEL_SLAB_ORDER;

    /**
     * We drop the lock before callinc page_alloc_va(). It creates a potential
     * (but mostly harmless) race where we could end up creating an extra slab
     * frame.
     *
     * The alloc logic will retry instead of using this frame directly, so
     * any extra frames should be left unused unless all the previous frames
     * are filled, which leaves the extra frames in a position to get cleared
     * on an OOM.
    **/
    spinlock_release(&slab->lock);
    kslab_debug(slab, "Calling page_alloc() with %d, %d\n", flags, page_index);
    new_frame = page_alloc_va(page_index, flags);
    kslab_debug(slab, "New frame for slab: %p\n", new_frame);
    spinlock_acquire(&slab->lock);

    if (!new_frame)
        return -ENOMEM;

    new_frame->page_index_size = page_index;
    new_frame->next = NULL;

    new_frame->first_addr = ALIGN_2(((char *)new_frame) + sizeof(*new_frame),
        slab->obj_size);
    new_frame->obj_count = (((char *)new_frame + PAGE_SIZE * (1 << new_frame->page_index_size))
        - (char *)new_frame->first_addr) / slab->obj_size;
    new_frame->last_addr = new_frame->first_addr + new_frame->obj_count * slab->obj_size;
    new_frame->free_obj_count = new_frame->obj_count;

    current = &new_frame->free_list;
    obj = new_frame->first_addr;
    int count;

    for (i = 0; i < new_frame->obj_count; i++, obk = ALIGN_2(obj + slab->obj_size,
        slab->obj_size), current = &((*current)->next)) {

        uint32_t *poison = (uint32_t *)obj;
        int k = 0;

        for (; k < slab->obj_size / 4; k++)
            poison[k] = SLAB_POISON;

        *current = (struct PageFrameEmpty *)obj;
        count++;
    }

    *current = NULL;

    /**
     * Loop until we hit the last entry. The double pointer just remove the special case
     * for slab->first_frame.
    **/
    struct SlabPageFrame **current_frame = &slab->first_frame;

    for (; *current_frame; current_frame = &((*current_frame)->next))
        ;

    *current_frame = new_frame;

    return 0;
}

static void
__slab_frame_free(struct SlabAlloc *slab, struct SlabPageFrame *frame)
{
    kslab_debug(slab, "Calling page_free() with %p, %d\n", frame, frame->page_index_size);
    page_free_va(frame, frame->page_index_size);
}

void
__slab_oom(struct SlabAlloc *slab)
{
    struct SlabPageFrame **prev = &slab->first_frame, *frame, *next;

    for (frame = slab->first_frame; frame; frame = next) {
        next = frame->next;

        if (frame->free_obj_count == frame->obj_count) {
            __slab_frame_free(slab, frame);
            *prev = next;
        } else {
            prev = &frame->next;
        }
    }
}

static void *
__slab_frame_object_alloc(struct SlabAlloc *slab, struct SlabPageFrame *frame)
{
    struct PageFrameEmpty *obj, *next;

try_again:
    if (!frame->free_list)
        return NULL;

    obj = frame->free_list;

    /**
     * Skip the valid PageFrameEntry, and verify the rest of the entry is
     * equal to the poison value.
    **/
    uint32_t *poison = (uint32_t *)(obj + 1);
    size_t poison_count = (slab->obj_size - sizeof(*obj)) / 4;
    int k = 0;

    for (; k < poison_count; k++) {
        if (poison[k] != SLAB_POISON) {
            kslab_error(slab, "%p: POISON IS INVALID, offset: %zd\n", obj,
                k * 4 + sizeof(*obj));
            dump_stack(KERN_ERROR);

            /**
             * Skip the invalid entry (it is effectively lost forever. Though,
             * in a double-free situation, the `second` free may insert it
             * back into kfree()).
             *
             * NOTE: Perhaps we should mark these bad forever, even if freed again?
            **/
            frame->free_list = frame->free_list->next;
            kslab_error(slab, "Skipping invalid to next: %p\n", frame->free_list);
            goto try_again;
        }
    }

    next = frame->free_list->next;
    frame->free_list = next;
    frame->free_obj_count--;
    kslab_debug(slab, "__slab_frame_object_alloc: %p\n", obj);

    return obj;
}

static void
__slab_frame_object_free(struct SlabAlloc *slab, struct SlabPageFrame *frame, void *obj)
{
    struct PageFrameEmpty *new = obj, *current;

    for (current = &frame->free_list; current; current = &(*current)->next) {
        if (obj >= (void *)(*current) && obj < (void *)(*current) + slab->obj_size) {
            kprintf(KERN_ERROR, "slab %s: Double free detected, pointer %p was freed, but "
                "already in free list, current: %p\n", slab->slab_name, obj, *current);
            dump_stack(KERN_ERROR);

            return;
        }

        if (obj <= (void *)(*current) || !*current) {
            uint32_t *poison = (uint32_t *)new;
            int k = 0;

            for (; k < slab->obj_size / 4; k++)
                poison[k] = SLAB_POISON;

            new->next = *current;
            *current = new;
            frame->free_obj_count++;

            /**
             * If this frame is unused, then run the OOM logic to get rid of it.
             *
             * We can't just remove it here because we don't have easy access to
             * the previous frame.
            **/
            if (frame->free_obj_count == frame->obj_count)
                __slab_oom(slab);

            return;
        }
    }

    kprintf(KERN_ERROR, "%p was freed, but is not in frame %p\n", obj, frame);
}

void *
__slab_malloc(struct SlabAlloc *slab, unsigned int flags)
{
    struct SlabPageFrame **frame = &slab->first_fame;

try_again:
    for (frame = &slab->first_frame; *frame; frame = &((*frame)->next)) {
        if ((*frame)->free_obj_count && !(*frame)->free_list) {
            kprintf(KERN_ERROR, "free_object_count and free_list do not agree: "
                "%s, %d, %p\n", slab->slab_name, (*frame)->free_obj_count.
                (*frame)->frame_list);
            continue;
        }

        if ((*frame)->free_obj_count)
            return __slab_frame_object_alloc(slab, *frame);
    }

    int err = __slab_frame_add_new(slab, flags);

    if (err)
        return NULL;

    goto try_again;
}

int
__slab_has_addr(struct SlabAlloc *slab, void *addr)
{
    struct SlabPageFrame *frame;

    for (frame = slab->first_frame; frame; frame = frame->next) {
        if (addr >= frame->first_addr && addr < frame->last_addr)
            return 0;
    }

    return 1;
}

void
__slab_free(struct SlabAlloc *slab, void *obj)
{
    struct SlabPageFrame *frame;

    for (frame = slab->first_frame; frame; frame = frame->next) {
        if (obj >= frame->first_addr && obj < frame->last_addr)
            return __slab_frame_object_free(slab, frame, obj);
    }

    panic("slab: Error: attempted to free address %p, not in slab %s\n", obj,
        slab->slab_name);
}

void
__slab_clear(struct SlabAlloc *slab)
{
    struct SlabPageFrame *frame, *next;

    for (frame = slab->first_frame; frame; frame = next) {
        next = frame->next;
        __slab_frame_free(slab, frame);
    }
}

void
*slab_malloc(struct SlabAlloc *slab, unsigned int flags)
{
    void *ret;

    using_spinlock(&slab->lock)
        ret = __slab_malloc(slab, flags);

    kslab_debug(slab, "malloc new: %p\n", ret);

    return ret;
}

int
slab_has_addr(struct SlabAlloc *slab, void *addr)
{
    int ret;

    using_spinlock(&slab->lock)
        ret = __slab_has_addr(slab, addr);

    return ret;
}

void
slab_free(struct SlabAlloc *slab, void *obj)
{
    using_spinlock(&slab->lock)
        __slab_free(slab, obj);
}

void
slab_clear(struct SlabAlloc *slab)
{
    using_spinlock(&slab->lock)
        __slab_clear(slab);
}

void
slab_oom(struct SlabAlloc *slab)
{
    using_spinlock(&slab->lock)
        __slab_oom(slab);
}

#ifdef CONFIG_KERNEL_TESTS
#include "slab_test.c"
#endif
