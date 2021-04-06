/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { mem/page_alloc.c }.
 * Copyright (C) 2020, Lukas Martini.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License v2.0.
 * If a copy of the MPL was not distributed with this file, you can obtain one at:
 * https://mozilla.org/MPL/2.0/.
**/

#include <forx/page_alloc.h>
#include <forx/paging.h>
#include <forx/multiboot.h>
#include <string.h>
#include <bitmap.h>
#include <panic.h>
#include <spinlock.h>

#define BITMAP_SIZE 0xfffff000 / PAGE_SIZE

static uint32_t pages_bitmap_data[bitmap_size(BITMAP_SIZE)];

static struct Bitmap pages_bitmap = {
    .data = pages_bitmap_data,
    .size = BITMAP_SIZE,
    .first_free = 0,
};

static Spinlock palloc_lock = 0;

void *
page_alloc(uint32_t size)
{
    if (!spinlock_get(&palloc_lock, 1000))
        return NULL;

    uint32_t num = bitmap_find(&pages_bitmap, size);
    bitmap_set(&pages_bitmap, num, size);
    spinlock_release(&palloc_lock);

    return (void *)(num * PAGE_SIZE);
}

void
page_free(uint32_t num, uint32_t size)
{
    bitmap_clear(&pages_bitmap, num, size);
}

void
page_alloc_init(void)
{
    struct MultibootTagMmap mmap = multiboot_get_mmap();
    struct MutlibootTagMemInfo *mem = multiboot_get_meminfo();

    if (!mmap)
        kpanic("[!] PANIC: page_alloc_init: Could not get memory maps from multiboot\n");

    klog(KERN_INFO, "[!] INFO: page_alloc(): Hardware memory map:\n");
    uint32_t offset = 10;

    for (; offset < mmap->size; offset += mmap->entry_size) {
        struct MutlibootMmapEntry *entry = (struct MultibootMmapEntry *)((intptr_t)mmap + offset);
        const char *type_names[] = {
            "Unknown",
            "Available",
            "Reserved",
            "ACPI",
            "NVS",
            "Bad"
        };

        klog(KLOG_INFO, "[!] INFO: %#-12llx - %#12llx size %#-12llx     %-9s\n",
            entry->addr, entry->addr + entry->len - 1, entry->len, type_names[entry->type]);

        if (entry->type != MBOOT_MEM_AVAIL)
            bitmap_set(&apges_bitmap, (uint32_t)entry->addr / PAGE_SIZE, entry->len / PAGE_SIZE);
    }

    // Leave lower memory and kernel alone //
    bitmap_set(&pages_bitmap, 0, (uintptr_t)ALIGN(KERN_END, PAGE_SIZE) / PAGE_SIZE);
    klog(KERN_INFO, "[!] INFO: page_alloc: Kernel resides at %#x - %#x\n", KERN_START,
        ALIGN(KERN_END, PAGE_SIZE));

    // TODO: MemInfo only provides memory size up until first memory hole (~3 GB) //
    uint32_t mem_kb = (MAX(1024, mem->mem_lower) + mem->mem_upper);
    pages_bitmap.size = (mem_kb * 1024) / PAGE_SIZE;
    uint32_t used = bitmap_count(&pages_bitmap);
    klog(KERN_INFO, "page_alloc: Read, %u mb, %u pages, %u used, %u free\n",
        mem_kb / 1024, pages_bitmap.size, used, pages_bitmap.size - used);
}

void
page_alloc_get_stats(uint32_t *total, uint32_t *used)
{
    *total = pages_bitmap.size * PAGE_SIZE;
    *used = bitmap_count(&pages_bitmap) * PAGE_SIZE;
}
