/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { mm/mmap.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/libctl/string.h>
#include <forx/list.h>
#include <forx/libctl/snprintf.h>
#include <forx/task.h>
#include <forx/mm/page_alloc.h>
#include <forx/mm/kmalloc.h>
#include <forx/mm/memlayout.h>
#include <forx/mm/vm.h>
#include <forx/fs/vfs.h>

static int
mmap_file_fill_page(struct VmMap *map, VirtAddr addr)
{
    struct Page *p = page_alloc(0, PAL_KERNEL);

    if (!p)
        return -ENOSPC;

    addr = PAGE_ALIGN_DOWN(addr);
    off_t mem_offset = addr - map->addr.start;
    off_t offset = mem_offset + map->file_page_offset;
    struct UserBuffer read_buf = make_kernel_buffer(p->virt);
    int err = vfs_pread(map->filp, read_buf, PAGE_SIZE, offset);

    if (err < 0)
        return err;

    page_table_map_entry(map->owner->page_dir, addr, page_to_pa(p), map->flags,
        PCM_CACHED);

    return 0;
}

const struct VmMapOps mmap_file_ops = {
    .fill_page = mmap_file_fill_page,
};
