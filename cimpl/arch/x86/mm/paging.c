/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { arch/x86/mm/paging.c }.
 * Copyright (C) 2014, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/multiboot.h>
#include <libctl/snprintf.h>
#include <forx/debug.h>
#include <forx/mm/memlayout.h>
#include <forx/mm/page_alloc.h>
#include <forx/mm/vm.h>
#include <forx/mm/vm_area.h>
#include <forx/task.h>
#include <forx/fs/fs.h>
#include <forx/fs/sys.h>
#include <forx/drivers/tty.h>
#include <forx/symbols.h>
#include <forx/mm/bootmem.h>

#include <forx/arch/asm.h>
#include <forx/arch/cpu.h>
#include <forx/arch/idt.h>
#include <forx/arch/cpuid.h>
#include <forx/arch/msr.h>
#include <forx/arch/pat.h>
#include <forx/arch/task.h>
#include <forx/arch/paging.h>
#include <forx/arch/backtrace.h>

#define PG_ERR_FLAG_TYPE 0
#define PG_ERR_FLAG_ACCESS_TYPE 1
#define PG_ERR_FLAG_PRIV 2
#define PG_ERR_FLAG_RESERVE_BITS 3

#define PG_ERR_TYPE_NON_PRESENT
#define PG_ERR_TYPE_PROTECTION 0x01

#define PG_ERR_ACCESS_TYPE_WRITE 0x02
#define PG_ERR_ACCESS_TYPE_READ 0x00

#define PG_ERR_PRIV_USER 0x04
#define PG_ERR_PRIV_KERNEL 0x00

#define PG_ERR_RESERVE_BITS_WRONG 0x08
#define PG_ERR_RESERVE_BITS_RIGHT 0x00

#define pg_err_non_present_page(err) \
    (((err) & F(PG_ERR_FLAG_TYPE)) == PG_ERR_TYPE_NON_PRESENT)

#define pg_err_protection_fault(err) \
    (((err) & F(PG_ERR_FLAG_TYPE)) == PG_ERR_TYPE_PROTECTION)

#define pg_err_was_user(err) \
    (((err) & F(PG_ERR_FLAG_PRIV)) == PG_ERR_PRIV_USER)

#define pg_err_was_kernel(err) \
    (((err) & F(PG_ERR_FLAG_PRIV)) == PG_ERR_PRIV_KERNEL)

#define pg_err_was_read(err) \
    (((err) & F(PG_ERR_FLAG_ACCESS_TYPE)) == PG_ERR_ACCESS_TYPE_READ)

#define pg_err_was_write(err) \
    (((err) & F(PG_ERR_FLAG_ACCESS_TYPE)) == PG_ERR_ACCESS_TYPE_WRITE)

static void
paging_dump_stack(struct IrqFrame *frame, uintptr_t p)
{
    int log_level = KERN_ERR;

    /**
     * Unhandled userspace page faults produce similar logging, but they
     * do not crash the kernel and are not logged as an error, but
     * just a warning.
    **/
    if (pg_err_was_user(frame->err))
        log_level = KERN_WARN;

    kprintf(log_level, "Page fault at: %p, addr: %p, err: 0x%08x\n",
        (void *)frame->eip, (void *)p, frame->err);

    kprintf(log_level, "Type: %s, access: %p, priv: %s\n",
        pg_err_non_present_page(frame->err) ? "non-present page" : "protection fault",
        pg_err_was_read(frame->err) ? "read" : "write",
        pg_err_was_user(frame->err) ? "user" : "kernel");

    struct Task *current = cpu_get_local()->current;

    if (!pg_err_was_user(frame->err)) {
        kprintf(log_level, "eax: 0x%08x, ebx: 0x%08x, edx: 0x%08x\n",
            frame->eax, frame->ebx, frame->ecx, frame->edx);
        kprintf(log_level, "esi: 0x%08x, edi: 0x%08x, esp: 0x%08x, ebp: 0x%08x\n",
            frame->esi, frame->edi, frame->esp, frame->ebp);

        kprintf(log_level, "Stack backtrace:\n");
        const struct Symbol *sym = ksym_lookup(frame->uip);
        kprintf(log_level, "eip: [0x%08x] %s\n", frame->eip, symbol ?
            symbol->name : "");
        dump_stack_ptr((void *)frame->ebp, log_level);
    }

    if (current && !flag_test(&current->flags, TASK_FLAG_KERNEL)) {
        kprintf(log_level, "Current running program: %s\n", current->name);

        if (current->context.frame) {
            kprintf(log_level, "eax: 0x%08x, ebx: 0x%08x, esp: 0x%08x, ebp: 0x%08x\n",
                current->context.frame->esi,
                current->context.frame->edi,
                current->context.frame->esp,
                current->context.frame->ebp);
            kprintf(log_level, "User stack dump:\n");
            dump_stack_ptr((void *)current->context.fram->ebp, log_level);
        } else {
            kprintf(log_level, "Context frame: null\n");
        }
    }

    kprintf(log_level, "End of backtrace\n");
}

static void
halt_and_dump_stack(struct IrqFrame *frame, uintptr_t p)
{
    paging_dump_stack(frame, p);
    panic_notrace("Kernel page fault\n");
}

static void
page_fault_handler(struct IrqFrame *frame, void *param)
{
    uintptr_t p;

    // cr2 contains the address that we faulted on //
    asm("movl %%cr2, %0" : "=r" (p));
    struct Task *current = cpu_get_local()->current;

    if (!current)
        halt_and_dump_stack(frame, p);

    if (current->in_page_fault)
        halt_and_dump_stack(frame, p);

    current->in_page_fault = 1;

    // Check if this page was a fault we can handle //
    int ret = address_space_handle_pagefault(current->addrspc, (VirtAddr)p);

    if (!ret)
        goto clear_in_page_fault;

    /**
     * If we're currently doing a read/write to a user pointer from the
     * kernel, then this flag will be set.
     *
     * To resolve the fault, we set the `return` to the provided address,
     * which will handle the fault.
    **/
    if (flag_test(&current->flags, TASK_FLAG_RW_USER) && current->user_check_jmp_addr) {
        frame->eip = (uint32_t)current->user_check_jmp_addr;
        goto clear_in_page_fault;
    }

    /**
     * We had a page fault and it was not part of a read/write to userspace.
     * Something is likely on fire...
    **/
    if (pg_err_was_kernel(frame->err))
        halt_and_dump_stack(frame, p);

    paging_dump_stack(frame, p);

    /**
     * Program seg-faulted and we couldn't handle it--attempt to display
     * message and exit.
    **/
    if (current->tty) {
        char buf[32];
        snprintf(buf, sizeof(buf), "Seg-Fault -- %d terminated\n", current->pid);
        tty_write_buf(current->tty, buf, strlen(buf));
    }

    flag_set(&current->flags, TASK_FLAG_KILLED);

clear_in_page_fault:
    current->in_page_fault = 0;

    return;
}

/**
 * These are readonly except during very early setup when we enable the PAT
 * if the processor supports it. It maps the page cache modes to the x86
 * PTR flags. These are `best effort` settings which are compatible, but
 * not necessarily as performant, which will be replaced with PAT-based
 * settings if possible.
**/
static uint32_t pcm_to_pte_flags[] = {
    [PCM_CHACHED] = 0,
    [PCM_UNCACHED] = PTE_CACHE_DISABLE,
    [PCM_UNCACHED_WEAK] = PTE_CACHE_DISABLE,
    [PCM_WRITE_COMBINED] = PTE_CACHE_DISABLE,
    [PCM_WRITE_THROUGH] = PTE_WRITE_THROUGH,
};

void
ptr_set_pcm(PageTableEntry *pte, int pcm)
{
    pte->write_through = 0;
    pte->cache_disabled = 0;
    pte->pat = 0;
    pte->entry |= pcm_to_pte_flags[pcm];
}

static void
setup_pat(void)
{
    if (!cpuid_has_pat())
        return;

    kprintf(KERN_NORM, "CPU supports PAT\n");

    uint64_t new_pat = PAT_ENT(0, PAT_MEM_WRITE_BACK) | PAT_ENT(1, PAT_MEM_UNCACHED) |
        PAT_ENT(2, PAT_MEM_UNCACHED_WEAK) | PAT_ENT(3, PAT_MEM_WRITE_COMBINED) |
        PAT_ENT(4, PAT_MEM_WRITE_THROUGH);

    x86_write_msr(MSR_PAT, new_pat);
    pcm_to_pte_flags[PCM_CHACHED] = 0;
    pcm_to_pte_flags[PCM_UNCACHED] = PTE_PAT_BIT_1;
    pcm_to_pte_flags[PCM_UNCACHED_WEAK] = PTE_PAT_BIT_2;
    pcm_to_pte_flags[PCM_WRITE_COMBINED] = PTE_PAT_BIT_1 | PTE_PAT_BIT_2;
    pcm_to_pte_flags[PCM_WRITE_THROUGH] = PTE_PAT_BIT_3;
}

/**
 * All of the kernel-space virtual memory directly maps onto the lowest part
 * of physical memory (or all of physical memory, if there is less physical
 * memory then the kernel's virtual mem space). This code sets up the kernel's
 * page directory to map all of the addresses in kernel-space in this way.
 *
 * NOTE: If we have PSE, we just use that and map all of kernel-space using
 * 4MB pages, and thus avoid ever having to allocate page-tables.
 *
 * Since every processes's page directory will have the kernel's memory mapped,
 * we can make all of these pages as global, if the processor supports it.
**/
static void
setup_kernel_pagedir(void)
{
    int cur_table, cur_page;
    PhysAddr new_page;
    struct PageDir *page_dir = &kernel_dir;
    struct PageTable *page_tbl;
    int table_start = KMEM_KPAGE;
    int tbl_gbl_bit = (cpuid_has_pge()) ? PTE_GLOBAL : 0;
    int dir_gbl_bit = (cpuid_has_pge()) ? PTE_GLOBAL : 0;
    VirtAddr kmap_start = (VirtAddr)CONFIG_KERNEL_KMAP_START;
    int kmap_dir_start = PAGING_DIR_INDEX(kmap_start);

    kprintf(KERN_NORM, "kmap_end: %p, dir: 0x%03x\n", kmap_start, kmap_dir_start);
    setup_pat();

    /**
     * We start at the last table from low-memory.
     * We use 4MB pages if we're able to, since they're nicer and we're never
     * going to be editing this map again.
    **/
    if (!cpuid_has_pse()) {
        for (cur_table = table_start; cur_table < kmap_dir_start; cur_table++) {
            page_tbl = bootmem_alloc(PAGE_SIZE, PAGE_SIZE);
            new_page = V2P(page_tbl);

            for (cur_page = 0; cur_page < 1024; cur_page++)
                page_tbl->entries[cur_page].entry = (PAGING_MAKE_DIR_INDEX(cur_table -
                    table_start) + PAGING_MAKE_TABLE_INDEX(cur_page)) | PTE_PRESENT |
                    PTE_WRITEABLE | tbl_gbl_bit);

            page_dir->entries[cur_table].entry = new_page | PDE_PRESENT | PDE_WRITABLE;
        }
    } else {
        for (cur_table = table_start; cur_table < kmap_dir_start; cur_table++)
            page_dir->entries[cur_table].entry = PAGING_MAKE_DIR_INDEX(cur_table -
                table_start) | PDE_PRESENT | PDE_WRITABLE | PDE_PAGE_SIZE |
                dir_gbl_bit;
    }

    // Setup directories for kmap //
    for (cur_table = kmap_dir_start; cur_table < 0x400; cur_table++) {
        page_tbl = bootmem_alloc(PAGE_SIZE, PAGE_SIZE);
        new_page = V2P(page_tbl);
        memset(page_tbl, 0, sizeof(PAGE_SIZE));
        page_dir->entries[cur_table].entry = new_page | PDE_PRESENT | PDE_WRITABLE |
            dir_gbl_bit;
    }
}

static struct IrqHandler page_fault_irq_handler = IRQ_HANDLER_INIT(page_fault_irq_handler,
    "Page fault handler", page_fault_handler, NULL, IRQ_SYSCALL, 0);

void
paging_setup_kernelspace(void)
{
    uint32_t pse, pge;

    // We make use of both PSE and PGE if the CPU support them //
    pse = (cpuid_has_pse()) ? CR4_PSE : 0;
    pge = (cpuid_has_pge()) ? CR4_GLOBAL : 0;

    if (pse || pge) {
        uint32_t cr4 = cpu_get_cr4();
        cr4 |= pse | pge;
        cpu_set_cr4(cr4);
    }

    kprintf(KERN_NORM, "Setting up initial kernel page dir, PSE: %s, PGE: %s\n",
        pse ? "yes" : "no", pge ? "yes" : "no");
    setup_kernel_pagedir();
    set_current_page_dir(v_to_p(&kernel_dir));
    int err = cpu_exeception_register_callback(14, &page_fault_irq_handler);

    if (err)
        panic("Unable to register page fault handler\n");

    return;
}

void
paging_dump_dir(PhysAddr page_dir)
{
    struct PageDir *cur_dir;
    int32_t table_off, page_off;
    struct PageTable *cur_page_table;

    cur_dir = P2V(page_dir);

    for (table_off = 0; table_off != 1024; table_off++) {
        if (cur_dir->entries[table_off].entry & PDE_PRESENT) {
            kprintf(KERN_NORM, "Dir %d: %x\n", table_off, cur_dir->entries[table_off].entry);
            cur_page_table = (struct PageTable *)P2V(cur_dir->entries[table_off].entry & ~0x3FF);

            for (page_off = 0; page_off != 1024; page_off++) {
                if (cur_page_table->entries[page_off].entry & PTE_PRESENT)
                    kprintf(KERN_NORM, "Page: %d: %x\n", page_off,
                        cur_page_table->entries[page_off].entry);
            }
        }
    }
}

uintptr_t
paging_get_phys(VirtAddr virt)
{
    struct PageDir *cur_dir;
    struct PageTable *cur_page_table;
    int32_t table_off, page_off;
    uintptr_t virt_addr = (uintptr_t)virt;

    table_off = PAGING_DIR_INDEX(virt_addr);
    page_off = PAGING_TABLE_INDEX(virt_addr);
    cur_dir = P2V(get_current_page_dir());

    if (!(cur_dir->entries[table_off].entry & PDE_PRESENT))
        return 0;

    cur_page_table = (struct PageTable *)P2V(cur_dir->entries[table_off].entry &
        0xFFFFF000);

    if (!(cur_page_table->entries[page_off].entry & PDE_PRESENT))
        return 0;

    return cur_page_table->entries[page_off].entry & 0xFFFFF000;
}

void
vm_area_map(VirtAddr va, PhysAddr addr, Flags vm_flags, int pcm)
{
    PageDir *dir;
    PageTable *table;
    uint32_t table_off, page_off;
    uintptr_t table_entry = addr | PTE_PRESENT;

    if (flag_test(&vm_flags, VM_MAP_WRITE))
        table_entry |= PTE_WRITEABLE;

    table_entry |= pcm_to_pte_flags[pcm];
    table_off = PAGING_DIR_INDEX(va);
    page_off = PAGING_TABLE_INDEX(va);

    dir = P2V(get_current_page_dir());
    table = P2V(PAGING_FRAME(dir->entries[table_off].entry));
    table->entries[page_off].entry = table_entry;
}

void
vm_area_unmap(VirtAddr va)
{
    PageDir *dir;
    PageTable *table;
    uint32_t table_off, page_off;

    table_off = PAGING_DIR_INDEX(va);
    page_off = PAGING_TABLE_INDEX(va);

    dir = P2V(get_current_page_dir());
    table = P2V(PAGING_FRAME(dir->entries[table_off].entry));
    table->entries[page_off].entry = 0;

    flush_tib_single(PAGE_ALIGN_DOWN(va));
}
