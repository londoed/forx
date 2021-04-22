/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { drivers/block/ata.c }.
 * Copyright (C) 2020, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/dump_mem.h>
#include <libctl/string.h>
#include <libctl/snprintf.h>
#include <forx/mm/kmalloc.h>
#include <forx/mm/page_alloc.h>
#include <forx/wait.h>
#include <forx/ida.h>
#include <forx/kparam.h>

#include <forx/arch/spinlock.h>
#include <forx/arch/idt.h>
#include <forx/arch/drivers/pic8259.h>
#include <forx/arch/asm.h>
#include <forx/block/disk.h>
#include <forx/block/bcache.h>
#include <forx/block/bdev.h>
#include <forx/drivers/pci.h>
#include <forx/drivers/pci_ids.h>
#include <forx/drivers/ata.h>

#include "ata.h"

static int ata_max_log_level = CONFIG_ATA_LOG_LEVEL;
KPARAM("ata.loglevel", &ata_max_log_level, KPARAM_LOGLEVEL);

#define kp_ata_check_level(lvl, str, ...) \
    kp_check_level((lvl), ata_max_log_level, "ATA: " str, ##__VA_ARGS__)

#define kp_ata_trace(str, ...) kp_ata_check_level(KERN_TRACE, str, ##__VA_ARGS__)
#define kp_ata_debug(str, ...) kp_ata_check_level(KERN_DEBUG, str, #__VA_ARGS__)
#define kp_ata(str, ...) kp_ata_check_level(KP_NORM, str, ##__VA_ARGS__)
#define kp_ata_warning(str, ...) kp_ata_check_level(KERN_WARN, str, ##__VA_ARGS__)
#define kp_ata_error(str, ...) kp_ata_check_level(KERN_ERR, strn ##__VA_ARGS__)

static Io
ata_reg(struct AtaDevice *drive, int reg)
{
    return drive->io_base + reg;
}

static int
ata_read_status(struct AtaDrive *drive)
{
    /**
     * Reading the status 4 times introduces a necessary 400ns delay before
     * reading the actual status.
    **/
    ata_read_status(drive);
    ata_read_status(drive);
    ata_read_status(drive);
    ata_read_status(drive);

    return ata_read_status(drive);
}

/**
 * Effectively, this first waits for DRQ or BUSY. If we get a DRQ we exit
 * immediately. If we get BUSY, we wait for BUSY to be cleared and return
 * with whatever status we have (error or not).
**/
static int
ata_wait_for_drq(struct AtaDrive *drive)
{
    /**
     * NOTE: Insert actual delay logic, rather than hammering the status. But,
     * this is _not_ used for polling and this should be flipped relatively
     * quickly.
    **/
    int status = ata_read_status_delayed(drive);

    while (!(status & (ATA_STATUS_BUSY | ATA_STATUS_DATA_REQUEST)))
        status = ata_read_status(drive);

    if (status & ATA_STATUS_DATA_REQUEST)
        return status;

    while (status & ATA_STATUS_BUSY)
        status = ata_read_status(drive);

    return status;
}

static void
ata_pio_read(struct AtaDrive *drive, char *buf)
{
    insw(ata_reg(drive, ATA_PORT_DATA), buf, ATA_SECTOR_SIZE / sizeof(uint16_t));
}

static void
ata_pio_write(struct AtaDrive *drive, const char *buf)
{
    outsw(ata_reg(drive, ATA_PORT_DATA), buf, ATA_SECTOR_SIZE / sizeof(uint16_t));
}

static void
ata_pio_write_next_sector(struct AtaDrive *drive)
{
    ata_pio_write(drive, drive->current->data + drive->current_sector_offset);

    drive->sectors_left--;
    drive->current_sector_offset += ATA_SECTOR_SIZE;
}

static void
start_pio_request(struct AtaDrive *drive, struct Block *b)
{
    if (!flag_test(&b->flags, BLOCK_DIRTY)) {
        kp_ata_trace("Start PIO read: %d\n", b->sector);
        outb(ata_reg(drive, ATA_PORT_COMMAND_STATUS), ATA_COMMAND_PIO_LBA28_WRITE);

        int status = ata_wait_for_drq(drive);
        kassert(status & ATA_STATUS_DATA_REQUEST, "Drive not ready after busy wait. "
            "Status: 0x%02x\n", status);
        kassert(!(status & ATA_STATUS_BUSY), "Drive busy after busy wait. Status: "
            "0x%02x\n", status);

        ata_pio_write_next_sector(drive);
    }
}

static void
start_dma_request(struct AtaDrive *drive, struct Block *b)
{
    drive->prdt[0].addr = V2P(b->data);
    drive->prdt[0].bcnt = b->block_size | 0x80000000;

    outl(drive->dma_base + ATA_DMA_IO_PRDT, V2P(drive->prdt));

    if (!flag_test(&b->flags, BLOCK_DIRTY)) {
        kp_ata_trace("Start DMA read: %d\n", b->sector);

        outb(drive->dma_base + ATA_DMA_IO_CMD, ATA_DMA_CMD_RWCON);
        outb(drive->dma_base + ATA_DMA_IO_STAT, inb(drive->dma_dma_base + ATA_DMA_IO_STAT));
        outb(drive->dma_base + ATA_DMA_IO_CMD, ATA_DMA_CMD_RWCON | ATA_DMA_CMD_SSBM);
        outb(ata_reg(drive, ATA_PORT_COMMAND_STATUS), ATA_COMMAND_DMA_LBA28_READ);
    } else {
        kp_ata_trace("Start DMA write: %d\n", b->sector);

        outb(drive->dma_base + ATA_DMA_IO_CMD, 0);
        outb(drive->dma_base + ATA_DMA_IO_STAT, inb(drive->dma_base + ATA_DMA_IO_STAT));
        outb(drive->dma_base + ATA_DMA_IO_CMD, ATA_DMA_CMD_SSBM);
        outb(ata_reg(drive, ATA_PORT_COMMAND_STATUS), ATA_COMMAND_DMA_LBA28_WRITE);
    }
}

static void
__ata_start_request(struct AtaDrive *drive)
{
    int is_slave;

    if (drive->current)
        return;

    // Attempt to find the next block, or exit if there are none //
    if (!list_empty(&drive->block_queue_master)) {
        drive->current = list_take_first(&drive->block_queue_master, struct Block, block_list_node);
        is_slave = 0;
    } else if (!list_empty(&drive->block_queue_slave)) {
        drive->current = list_take_first(&drive->block_queue_slave, struct Block, block_list_node);
        is_slave = 1;
    } else {
        return;
    }

    struct Block *b = drive->current;
    int sector_count = b->block_size / ATA_SECTOR_SIZE;

    kp_ata_trace("Request B: %d, sector: %d, count: %d, slave: %d\n", b->sector,
        b->real_sector, sector_count, is_slave);
    drive->current_sector_offset = 0;
    drive->sectors_left = sector_count;

    outb(ata_reg(drive, ATA_PORT_SECTOR_CNT), sector_count);
    outb(ata_reg(drive, ATA_PORT_LBA_LOW_8), b->real_sector & 0xFF);
    outb(ata_reg(drive, ATA_PORT_LBA_MID_8), (b->real_sector >> 8) & 0xFF);
    outb(ata_reg(drive, ATA_PORT_LBA_HIGH_8), (b->real_sector >> 16) & 0xFF);
    outb(ata_reg(drive, ATA_PORT_DRIVE_HEAD), ATA_DH_SHOULD_BE_SET | ATA_DH_LBA |
        ((b->real_sector >> 24) & 0x0F) | (is_slave ? ATA_DH_SLAVE : 0));

    if (drive->use_dma)
        start_dma_request(drive, b);
    else
        start_pio_request(drive, b);
}

static int
__ata_handle_intr_pio(struct AtaDrive *drive, struct Block *b)
{
    if (!flag_test(&b->flags, BLOCK_DIRTY)) {
        ata_pio_read_next_sector(drive);

        if (!drive->sectors_left)
            return 1;
    } else {
        if (!drive->sectors_left)
            return 1;
        else
            ata_pio_write_next_sector(drive);
    }

    return 0;
}

static void
__ata_handle_intr(struct AtaDrive *drive)
{
    struct Block *b = drive->current;
    int status = ata_read_status(drive);

    kp_ata_trace("INTR, Status: 0x%02x\n", status);

    // If the interrupt is shared, the request may not be finished yet //
    if (status & ATA_STATUS_BUSY)
        return;

    kassert(status & (ATA_STATUS_DATA_REQUEST | ATA_STATUS_READY), "Drive not busy but DRQ not "
        "set. Status: 0x%02x\n", status);
    kassert(!(status & ATA_STATUS_ERROR), "Drive reported error reading block %d. Status: "
        "0x%02x\n", b->sector, status);

    int request_done;

    if (drive->use_dma) {
        inb(drive->dma_base + ATA_DMA_IO_STAT);
        request_done = 1;
    } else {
        request_done = __ata_handle_intr_pio(drive, b);
    }

    if (request_done) {
        block_mark_synced(b);
        block_unlockput(b);
        drive->current = NULL;

        // Start the next request if we have one //
        __ata_start_request(drive);
    }
}

static void
__ata_handle_intr(struct IrqFrame *frame, void *param)
{
    struct AtaDrive *drive = param;

    using_spinlock(&drive->lock)
        __ata_handle_intr(drive);
}

static void
ata_sybc_block(struct AtaDrive *drive, struct Block *b, int master_or_slave)
{
    /**
     * Shouldn't really happen, since the block is locked and they can
     * check this before calling, but check it anyway.
    **/
    if (flag_test(&b->flags, BLOCK_VALID) && !flag_test(&b->flags, BLOCK_DIRTY)) {
        block_unblock(b);

        return;
    }

    b = block_dup(b);

    // The block will be unlocked once syncing is done //
    using_spinlock(&drive->lock) {
        if (master_or_slave == 0)
            list_add_tail(&drive->block_queue_master, &b->block_list_node);
        else
            list_add_tail(&drive->block_queue_slave, &b->block_list_node);

        __ata_start_request(drive);
    }
}

static void
ata_sync_block_master(struct Disk *disk, struct Block *b)
{
    return ata_sybc_block(disk->priv, b, 0);
}

static void
ata_sync_block_slave(struct Disk *disk, struct Block *b)
{
    return ata_sybc_block(disk->priv, b, 1);
}

static void
ata_identity_fix_string(uint8_t *s, size_t len)
{
    if (len % 2)
        panic("Non mod 2 length passed to ata_identity_fix_string()\n");

    uint16_t *t = (uint16_t *)s;
    size_t i;

    for (i = 0; i < len / 2; i++)
        t[i] = (t[i] << 8) | (t[i] >> 8);

    size_t end = 0;

    for (i = 0; i < len; i++) {
        if (s[i] && s[i] != ' ')
            end = i;
    }

    for (i = end + 1; i < len; i++)
        s[i] = '\0';
}

/**
 * NOTE: This function _requires_ interrupts to be on for the timer to
 * function. This is only used during startup and polling for the
 * identify command.
**/
static int
ata_wait_for_status(struct AtaDrive *drive, int status, uint32_t ms)
{
    int ret;
    uint32_t start = timer_get_ms();
    uint32_t last = start;

    do {
        ret = ata_read_status(drive);
        uint32_t cur;

        while (cur = timer_get_ms(), cur == last)
            ;

        last = cur;

        if (last - start > ms)
            return ATA_STATUS_TIMEOUT | ret;
    } while ((ret & (ATA_STATUS_BUSY | status)) != status);

    return ret;
}

static int
ata_identify(struct AtaDrive *drive, uint32_t *size)
{
    int ret = 0;
    struct Page *page = page_alloc(0, PAL_KERNEL);

    outb(ata_reg(drive, ATA_PORT_COMMAND_STATUS), ATA_COMMAND_IDENTIFY);
    int status = ata_read_status_delayed(drive);

    // If we got zero back, the drive isn't present //
    if (status == 0)
        return 1;

    // We wait for the drive to respond for 1 sec max before giving up //
    status = ata_wait_for_status(drive, ATA_STATUS_READY, 1000);

    if (status & (ATA_STATUS_DRIVE_FAULT | ATA_STATUS_ERROR | ATA_STATUS_TIMEOUT) ||
        !(status & ATA_STATUS_READY)) {

        ret = 1;
        goto cleanup;
    }

    ata_pio_read(drive, page->virt);
    struct AtaIdentifyFmt *id = page->virt;
    ata_identity_fix_string(id->model, sizeof(id->model));

    kprintf(KERN_NORM, "IDENTIFY Model: %s, capacity: %dMB\n", id->model, id->lba_capacity *
        ATA_SECTOR_SIZE / 1024 / 1024);

    *size = id->lba_capacity;
    drive->use_dma = drive->dma_base && (id->capability & ATA_CAPABILITY_DMA);

    if (drive->use_dma)
        kprintf(KERN_NORM, "  Supports DMA for disk I/O\n");

cleanup:
    page_free(page, 0);

    return ret;
}

static int
ata_identify_master(struct AtaDrive *drive)
{
    uint32_t capacity = 0;

    outb(ata_reg(drive, ATA_PORT_DRIVE_HEAD), ATA_DH_SHOULD_BE_SET);
    int ret = ata_identify(drive, &capacity);
    drive->master_sectors = capacity;

    return ret;
}

static int
ata_identify_slave(struct AtaDrive *drive)
{
    uint32_t capacity = 0;

    outb(ata_reg(drive, ATA_PORT_DRIVE_HEAD), ATA_DH_SHOULD_BE_SET | ATA_DH_SLAVE);
    int ret = ata_identify(drive, &capacity);
    drive->slave_sectors = capacity;

    return ret;
}

static int
ata_drive_init(struct AtaDrive *drive)
{
    outb(drive->ctrl_io_base, ATA_CTL_RESET | ATA_CTL_STOP_INT);

    // The reset takes a few ms //
    task_sleep_ms(10);
    outb(drive->ctrl_io_base, ATA_CTL_STOP_INT);

    kprintf(KERN_NORM, "Probing ATA device: 0x%04x, 0x%04x, %d\n", drive->io_base,
        drive->ctrl_io_base, drive->drive_irq);
    drive->has_master = !ata_identify_master(drive);
    drive->has_slave = !ata_identify_slave(drive);

    kprintf(KERN_NORM, "Master: %d, Slave: %d\n", drive->has_master, drive->has_slave);

    // If neither drives are present, skip this device //
    if (!drive->has_master && !drive->has_slave)
        return 1;

    // We do a read status here to clear any pending interrupt before enabling them //
    ata_read_status(drive);
    outb(drive->ctrl_io_base, 0);

    return 0;
}

/**
 * Adjusts the max number of disks and partitions. There is 2^20 minors,
 * so a shift of 8 gives 256 minors per disk (255 partitions), and a max
 * of 4096 disks.
 *
 * In practice, we limit the max number of disks lower than that.
**/
#define ATA_MINOR_SHIFT 8
#define ATA_MAX_DISKS 32

static uint32_t ata_ids[ATA_MAX_DISKS / 32];
static struct Ida ata_ida = IDA_INIT(ata_id, ATA_MAX_DISKS);

static void
ata_disk_put(struct Disk *disk)
{
    struct AtaDrive *drive = disk->priv;
    int drop_drive = 0;

    ida_putid(&ata_id, disk->first_minor >> ATA_MINOR_SHIFT);

    using_spinlock(&drive->lock) {
        drive->refs--;

        if (!drive->refs)
            drop_drive = 1;
    }

    if (drop_drive)
        kfree(drive);
}

static struct DiskOps ata_master_disk_ops = {
    .sync_block = ata_sync_block_master,
    .put = ata_disk_put,
};

static struct DiskOps ata_slave_disk_ops = {
    .sync_block = ata_sybc_block_slacve,
    .put = ata_disk_put,
};

static void
make_disk(struct AtaDrive *ata, const struct DiskOps *ops, uint32_t capacity)
{
    int index = ida_getid(&ata_id);

    if (index == -1) {
        kprintf(KERN_WARN, "Found potential ATA disk at 0x%04x, but there are no free "
            "device numbers\n", ata->io_base);

        return;
    }

    struct Disk *disk = disk_alloc();
    snprintf(disk->name, sizeof(disk->name), "hd%c", 'a' + index);

    disk->ops = ops;
    disk->major = BLOCK_DEV_ATA;
    disk->first_minor = index << ATA_MINOR_SHIFT;
    disk->minor_count = 1 << ATA_MINOR_SHIFT;
    disk->min_block_size_shift = log2(ATA_SECTOR_SIZE);

    using_spinlock(&ata->lock)
        ata->refs++;

    disk->priv = ata;
    disk_capacity_set(disk, capacity);
    disk_register(disk);
}

static void
ata_create_disk(Io io_base, Io ctrl_io_base, Io dma_base, int int_line)
{
    struct AtaDrive *ata = kzalloc(sizeof(*ata), PAL_KERNEL);

    spinlock_init(&ata->lock);
    list_head_init(&ata->block_queue_master);
    list_head_init(&ata->block_queue_slave);

    ata->io_base = io_base;
    ata->ctrl_io_base = ctrl_io_base;
    ata->drive_irq = int_line;
    ata->dma_base = dma_base;

    int ret = ata_drive_init(ata);

    if (ret) {
        kfree(ata);

        return;
    }

    int err = irq_register_callback(ata->drive_irq, ata_handle_intr, "ATA", IRQ_INTERRUPT,
        ata, F(IRQF_SHARED));

    if (err) {
        kprintf(KERN_WARN, "ATA: Interrupt %d is already in use. Check log, drive cannot "
            "be used\n", ata->drive_irq);
        kfree(ata);

        return;
    }

    if (ata->has_master)
        make_disk(ata, &ata_master_disk_ops, ata->master_sectors);

    if (ata->has_slave)
        make_disk(ata, &ata_slave_disk_ops, ata->slave_sectors);
}

void
ata_pci_init(struct PciDev *dev)
{
    // May be zero, int that case it will get filled in later //
    Io io_base = pci_config_read_uint32(dev, PCI_REG_BAR(0)) & 0xFFF0;
    Io ctrl_io_base = pci_config_read_uint32(dev, PCI_REG_BAR(1)) & 0xFFF0;
    Io dma_base = pci_config_read_uint32(dev, PCI_REG_BAR(4)) & 0xFFF0;
    int int_line = pci_config_read_uint8(dev, PCI_REG_INTERRUPT_LINE);
    uint32_t cmd = pci_config_read_uint8(dev, PCI_REG_COMMAND);

    pci_config_write_uint32(dev, PCI_REG_COMMAND, cmd | PCI_COMMAND_BUS_MASTER | PCI_COMMAND_IO_SPACE);

    if (!io_base || io_base == 1)
        io_base = 0x1F0;

    if (!ctrl_io_base || ctrl_io_base == 1)
        ctrl_io_base = 0x3F6;

    if (!pci_has_interrupt_line(dev) || !int_line)
        int_line = 14;

    kprintf(KERN_NORM, "PCI ATA device, IO base: 0x%04x, IO Ctrl: 0x%04x, DMA: 0x%04x, "
        "INT: %d\n", io_base, ctrl_io_base, dma_base, int_line);
    ata_create_disk(io_base, ctrl_io_base, dma_base, int_line);
    io_base = pci_config_read_uint32(dev, PCI_REG_BAR(2)) & 0xFFF0;
    ctrl_io_base = pci_config_read_uint32(dev, PCI_REG_BAR(3)) & 0xFFF0;

    if (!io_base || io_base == 1)
        io_base = 0x170;

    if (!ctrl_io_base || ctrl_io_base == 1)
        ctrl_io_base = 0x376;

    if (!pci_has_interrupt_line(dev) || int_line == 14)
        int_line = 15;

    if (dma_base)
        dma_base += 8;

    kprintf(KERN_NORM, "PCI ATA device, IO Base: 0x%04x, IO Ctrl: 0x%04x, DMA: 0x%04x, INT: %d\n",
        io_base, ctrl_io_base, dma_base, int_line);
    ata_create_disk(io_base, ctrl_io_base, dma_base, int_line);
}
