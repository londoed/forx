/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { arch/kernel/cpu.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional detials.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <libctl/snprintf.h>
#include <forx/sched.h>
#include <forx/mm/page_alloc.h>
#include <forx/mm/kmalloc.h>

#include <forx/arch/task.h>
#include <forx/arch/memlayout.h>
#include <forx/arch/memlayout.h>
#include <forx/arch/asm.h>
#include <forx/arch/gdt.h>
#include <forx/arch/cpuid.h>
#include <forx/arch/cpu.h>

static struct CpuInfo cpu;

void
cpu_setup_fpu(struct CpuInfo *c)
{
    if (cpuid_has_sse()) {
        kprintf(KERN_NORM, "CPU has SSE support\n");

        // Turn SSE on //
        uint32_t cr0 = cpu_get_cr0();
        cr0 &= ~CR0_EM;
        cr0 |= CR0_MP;
        cpu_set_cr0(cr0);

        uint32_t cr4 = cpu_get_cr4();
        cr4 |= CR4_OSFXSR | CR4_OSXMMEXCPT;
        cpu_set_cr4(cr4);
    } else {
        kprintf(KERN_NORM, "CPU does not support SSE\n");
    }
}

static void
cpu_gdt(struct CpuInfo *c)
{
    c->gdt_entries[_GDT_NULL] = (struct GdtEntry){ 0 };
    c->gdt_entries[_KERNEL_CS_N] = GDT_ENTRY(GDT_TYPE_EXECUTABLE | GDT_TYPE_READABLE, 0,
        0xFFFFFFFF, GDT_DPL_KERNEL);
    c->gdt_entries[_KERNEL_DS_N] = GDT_ENTRY(GDT_TYPE_WRITABLE, 0, 0xFFFFFFFF, GDT_DPL_KERNEL);
    c->gdt_entries[_USER_CS_N] = GDT_ENTRY(GDT_TYPE_EXECUTABLE | GDT_TYPE_READABLE, 0,
        0xFFFFFFFF, GDT_DPL_USER);
    c->gdt_entries[_USER_DS_N] = GDT_ENTRY(GDT_TYPE_WRITABLE, 0, 0xFFFFFFFF, GDT_DPL_USER);

    // Setup CPU-local variable //
    c->gdt_entries[_CPU_VAR_N] = GDT_ENTRY(GDT_TYPE_WRITABLE, (uintptr_t)&c->cpu,
        sizeof(&c->cpu) - 1, GDT_DPL_KERNEL);

    // Setyp CPU-tss //
    c->gdt_entries[_GDT_TSS_N] = GDT_ENTRY16(GDT_STS_T32A, (uintptr_t)&c->tss,
        sizeof(c->tss) - 1, GDT_DPL_KERNEL);
    c->gdt_entries[_GDT_TSS_N].des_type = 0;
    gdt_flush(c->gdt_entries, sizeof(c->gdt_entries));

    // Reload CS and IP //
    asm volatile(
        "jmpl $" Q(_KERNEL_CS)", $if\n"
        "1:\n"
        : : : "memory"
    );

    // Reset the segment registers to use the new GDT //
    asm volatile(
        "movw %w0, %%ss\n"
        "movw %w0, %%ds\n"
        "movw %w0, %%es\n"
        "movw %w0, %%fs\n"
        "movw %w1, %%gs\n"
        : : "r" (_KERNEL_DS), "r" (_CPU_VAR)
        : "memory"
    );
}

static void
cpu_tss(struct CpuInfo *c)
{
    memset(&c->tss, 0, sizeof(c->tss));
    c->tss.iomb = sizeof(c->tss);
}

void
cpu_set_kernel_stack(struct CpuInfo *c, void *kstack)
{
    /**
     * We rewrite this GDT entry since old TSS will have a type of `TSS busy`.
     * We just overwrite it with a new TSS segment to make sure it's right
     * again.
    **/
    c->gdt_entries[_GDT_TSS_N] = GDT_ENTRY16(GDT_STS_T32A, (uintptr_t)&c->tss,
        sizeof(c->tss) - 1, GDT_DPL_KERNEL);
    c->gdt_entries[_GDT_TSS_N].des_type = 0;

    c->tss.ss0 = _KERNEL_DS;
    c->tss.esp0 = kstack;
    ltr(_GDT_TSS);
}

// Dumb cpu idle loop--used when we have no tasks to execute on this cpu //
static int
cpu_idle_loop(void *cpuid)
{
    kprintf(KERN_DEBUG, "kidle: %d\n", (int)cpuid);

    for (;;)
        asm volatile("hlt" ::: "memory");

    return 0;
}

void
cpu_setup_idle(void)
{
    char name[20];
    struct CpuInfo *c = cpu_get_local();

    snprintf(name, sizeof(name), "kidle %d", c->cpu_id);
    struct Task *t = kmalloc(sizeof(*t), PAL_KERNEL | PAL_ATOMIC);

    if (!t)
        panic("Unable to allocate cpu idle task\n");

    task_init(t);
    task_kernel_init(t, name, cpu_idle_loop, (void *)c->cpu_id);

    c->kidle = t;
    c->intr_count = 0;
}

void
cpu_start_sched(void)
{
    schedule();
}

void
cpu_init_early(void)
{
    cpu_gdt(&cpu);
}

void
cpu_info_init(void)
{
    cpu_tss(&cpu);
    cpu_setup_fpu(&cpu);

    cpu.cpu = &cpu;
    cpu.cpu_id = 0;
    cpu.intr_count = 1;
    cpu.reschedule = 0;
}
