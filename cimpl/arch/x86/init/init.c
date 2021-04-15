/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { arch/x86/init/init.c }.
 * Copyright (C) 2014, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/kmain.h>
#include <forx/multiboot.h>
#include <forx/multiboot2.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <forx/mm/memlayout.h>
#include <forx/mm/page_alloc.h>
#include <forx/mm/kmmap.h>
#include <forx/drivers/pci.h>
#include <forx/video/fbcon.h>
#include <forx/work.h>
#include <forx/kparam.h>
#include <forx/klog.h>
#include <forx/mm/bootmem.h>

#include <forx/arch/asm.h>
#include <forx/drivers/console.h>
#include <forx/drivers/com.h>
#include <forx/video/video.h>
#include <forx/arch/gdt.h>
#include <forx/arch/idt.h>
#include <forx/arch/init.h>
#include <forx/arch/cpuid.h>
#include <forx/drivers/pic8295.h>
#include <forx/drivers/pic8259_timer.h>
#include <forx/drivers/rtc.h>
#include <forx/paging.h>
#include <forx/pages.h>
#include <forx/task.h>
#include <forx/cpu.h>

char kernel_cmdline[2048];
static struct FbInfo frame_buf_info;

static void
setup_bootloader_framebuf(void)
{
    if (!frame_buf_info.frame_buf_addr)
        return;

    kprintf(KERN_NORM, "Initializing frame buffer from bootloader...\n");
    frame_buf_info.frame_buf = kmmap_pcm(frame_buf_info.frame_buf_addr,
        frame_buf_info.frame_buf_size, F(VM_MAP_READ) | F(VM_MAP_WRITE),
        PCM_WRITE_COMBINED);

    fbcon_set_frame_buf(&frame_buf_info);
    kprintf(KERN_NORM, "Frame buffer from bootloader in use\n");
    video_mark_disabled();
}

initcall_device(boot_fbcon, setup_bootloader_framebuf)

/**
 * This dependency exists because we do not know what device the GRUB
 * frame buffer is from, we may already have a driver for it. If we load
 * that driver, we will likely mess up the frame buffer.
**/
initcall_dependency(pci_devices, boot_fbcon);

/**
 * The multiboot memory regions are 64-bit ints (to support PAE) and can
 * extend past the 32-bit memory space. We handle that here.
**/
static void
add_multiboot_memory_region(uint64_t start, uint64_t length)
{
    // Skip any regions that go past the end of the 32-bit memory space //
    if (start >= 0xFFFFFFFFLL)
        return;

    // Clip any regions inside of the 32-bit memory space if they stretch outside //
    if (start + length >= 0xFFFFFFFFLL)
        length = 0xFFFFFFFFLL - start;

    bootmem_add(start, start + length);
}

static void
handle_multiboot_info(struct MultibootInfo *info)
{
    struct MbootMemMap *mmap = (struct MbootMemMap *)P2V(((struct MbootInfo *)P2V(info))
        ->mmap_addr);

    kprintf(KERN_NORM, "Using Multiboot information...\n");

    /**
     * We haven't started paging, so MB 1 is identity mapped and we can safely
     * deref `info` and `cmdline`.
     * We do this early, to avoid clobbering the cmdline.
    **/
    if (info->flags & MULTIBOOT_INFO_CMDLINE) {
        // Make sure we don't overflow kernel_cmdline //
        info->cmdline[sizeof(kernel_cmdline) - 1] = '\0';
        strcpy(kernel_cmdline, info->cmdline);
        kprintf(KERN_NORM, "Cmdline: %s\n", kernel_cmdline);

        kernel_cmdline_init();
    }

    kprintf(KERN_NORM, "mmap: %p\n", mmap);

    for (; V2P(mmap) < info->mmap_addr + info->mmap_length;
        mmap = (struct MbootMemMap *)((uint32_t)mmap + mmap->size + sizeof(uint32_t))) {

        kprintf(KERN_NORM, "mmap: 0x%016llx to 0x%016llx, type: %d\n", mmap->base_addr,
            mmap->base_addr + mmap->length, mmap->type);

        // A type of non-one means it's not usable memory--just ignore it //
        if (mmap->type != 1)
            continue;

        add_multiboot_memory_region(mmap->base_addr, mmap->length);
    }
}

static void
handle_multiboot2_info(void *info)
{
    uint32_t size = *(uint32_t *)info;
    struct Mboot2Tag *tag;
    struct Mboot2TagBasicMemInfo *meminfo;
    struct Mboot2TagStr str;
    struct Mboot2TagFrameBufCommon *frame_buf;
    struct Mboot2TabMmap *mmap;
    struct Mboot2MmapEntry *mmap_ent;
    int had_mmap = 0;
    PhysAddr basic_mem_high_mem = 0;

    kprintf(KERN_NORM, "Using Multiboot2 information...\n");
    kprintf(KERN_NORM, "multiboot2: info size: %d\n", size);

    for (tag = (info + 8); tag->type; tag = (struct Mboot2Tag *)((char *)tag + ALIGN_2(tag->size, 8))) {
        kprintf(KERN_NORM, "Multiboot tag, type: %d, size: %d\n", tag->type, tag->size);

        switch (tag->type) {
        case MULTIBOOT2_TAG_TYPE_BASIC_MEMINFO:
            meminfo = container_of(tag, struct Mboot2TagBasicMemInfo, tag);

            // mem_uppser starts at 1MB and is given to use in KBs //
            basic_mem_high_mem = PAGE_ALIGN_DOWN((uint32_t)meminfo->mem_upper * 1024 + (1024 * 1024));
            break;

        case MULTIBOOT2_TAG_TYPE_CMDLINE:
            str = container_of(tag, struct Mboot2TagStr, tag);
            strncpy(kernel_cmdline, str->string, sizeof(kernel_cmdline));
            kernel_cmdline[sizeof(kernel_cmdline) - 1] = '\0';

            kprintf(KERN_NORM, "Cmdline: %s\n", kernel_cmdline);
            kernel_cmdline_init();
            break;

        case MULTIBOOT2_TAG_TYPE_FRAMEBUF:
            frame_buf = container_of(tag, struct Mboot2TagFrameBufCommon, tag);
            kprintf(KERN_NORM, "Frame buffer, type: %d, height: %d, BPP: %d\n",
                frame_buf->frame_buf_type, frame_buf->frame_buf_width,
                frame_buf->frame_buf_height, frame_buffer->frame_buf_bpp);

            if (frame_buf->frame_buf_type != MULTIBOOT_FRAMEBUF_TYPE_RGB)
                break;

            frame_buf_info.frame_buf_addr = frame_buf->frame_buf_addr;
            frame_buf_info.width = frame_buf->frame_buf_width;
            frame_buf_info.height = frame_buf->frame_buf_height;
            frame_buf_info.bpp = frame_buf->frame_buf_bpp;
            frame_buf_info.frame_buf_size = frame_buf_info.width * frame_buf_info.height *
                (frame_buf_info.bpp / 8);

            break;

        case MULTIBOOT2_TAG_TYPE_MMAP:
            mmap = container_of(tag, struct Mboot2_tag_mmap, tag);
            had_mmap = 1;

            for (mmap_ent = mmap->entries; (uint8_t *)tag + tag->size;
                mmap_ent = (struct Mboot2MmapEntry *)((uint8_t *)mmap_ent +
                mmap->entry_size)) {

                kprintf(KERN_NORM, "mmap: 0x%016llx to 0x%016llx, types: %d\n", mmap_ent->addr,
                    mmap_ent->addr + mmap_ent->len, mmap_ent->type);

                if (mmap_ent->type != MULTIBOOT_MEMORY_AVAILABLE)
                    continue;

                add_multiboot_memory_region(mmap_ent->addr, mmap_ent->len);
            }

            break;
        }
    }

    if (!had_mmap) {
        kprintf(KERN_NORM, "mmap: high addr: 0x%08x\n", basic_mem_high_mem);
        bootmem_add(1024 * 1024 * 1024, basic_mem_high_mem);
    }
}

extern char kern_start, kern_end;

/**
 * Info is the physical address of the multiboot info struct. An identity
 * mapping is currently setup that makes it valid though.
**/
void
cmain(uint32_t magic, void *info)
{
    cpuid_init();
    cpu_init_early();

    // Initialize klog so that it captures all of the early boot logging //
    klog_init();

    // Initialize output early for debugging //
    vt_console_early_init();
    vt_console_xp_register();

    if (com_init_early() == 0)
        com_kp_register();

    kprintf(KERN_NORM, "FORX booting...\n");
    kprintf(KERN_NORM, "Kernel physical memory location: 0x%08x-0x%08x\n",
        V2P(&kern_start), V2P(&kern_end));

    /**
     * We setup the IDT fairly early--this is because the actual `setup` is
     * extremly simple, and things shouldn't register interrupt handlers
     * until the IDT it setup.
    **/
    idt_init();

    if (magic == MULTIBOOT_BOOTLOADER_MAGIC)
        handle_multiboot_info(info);
    else if (magic == MULTIBOOT2_BOOTLOADER_MAGIC)
        handle_multiboot2_info(info);
    else
        panic("Magic value does not match multiboot or multiboot2, cannot boot\n");

    /**
     * Initialize paging as early as we can, so that we can make use of kernel
     * memory--then start the memory manager.
    **/
    paging_setup_kernelspace();
    bootmem_setup_page_alloc();
    kmalloc_init();

    /**
     * Setup the per-CPU stuff--has to be done after kmalloc and friends are
     * setup.
    **/
    cpu_info_init();

    /**
     * Initialize the 8259 PIC--this has to be initialized before we can enable
     * interrupts on the CPU.
    **/
    kprintf(KERN_NORM, "Initializing the 8259 PIC\n");
    pic8259_init();
    pic8259_timer_init();

    kprintf(KERN_NORM, "Reading RTC time\n");
    rtc_update_time();

    kmain();
}
