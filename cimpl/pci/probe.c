/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { pci/probe.c }.
 * Copyright (C) 2017, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <forx/mm/kmalloc.h>
#include <libctl/snprintf.h>
#include <forx/arch/asm.h>

#include <forx/fs/procfs.h>
#include <forx/drivers/ata.h>
#include <forx/drivers/e1000.h>
#include <forx/drivers/rtl.h>
#include <forx/drivers/pci.h>
#include <forx/drivers/pci_ids.h>
#include <forx/video/bga.h>

#include "internal.h"

static const struct PciDriver pci_drivers[] = {
#ifdef CONFIG_NET_RTL8139_DRIVER
    {
        .name = "RealTek RTL8139 Fast Ethernet",
        .vendor = PCI_VENDOR_ID_REALTEK,
        .device = PCI_DEVICE_ID_RTL8139_NET,
        .device_init = rtl_device_init,
    },
#endif
#ifdef CONFIG_NET_E1000_DRIVER
    {
        .name = "Intel E1000 Fast Ethernet",
        .vendor = PCI_VENDOR_ID_INTEL,
        .device = PCI_DEVICE_ID_E1000_NET,
        .device_list = e1000_device_init,
    },
#endif
    {
        .name = "Bochs Graphic Adaptor",
        .vendor = 0x1234,
        .device = 0x1111,
        .device_init = bga_device_list,
    },
    {
        .name = "Generic ATA/IDE Interface",
        .class = 1,
        .subclass = 1,
        .device_init = ata_pci_init,
    },
    {
        .name = NULL,
        .vendor = 0,
        .device = 0,
    }
};

ListHead pci_dev_list = LIST_HEAD_INIT(pci_dev_list);

#define PCI_CLASS_X \
    X(NONE, "No PCI Class"), \
    X(NETWORK, "Network Controller"), \
    X(DISPLAY, "Display Controller"), \
    X(MULTIMEDIA, "Multimedia Controller")m \
    X(MEMORY, "Memory Controller"), \
    X(BRIDGE, "PCI Bridge Device"), \
    X(SIMPLE_COMM, "Simple Communications Controller"), \
    X(BASE_SYSTEM, "Base System Peripherals"), \
    X(INPUT, "Input Device"), \
    X(DOCKING, "Docking Station"), \
    X(PROCESSOR, "Processor"), \
    X(SERIAL_BUS, "Serial Bus"), \
    X(WIRELESS, "WIreless Controller"), \
    X(INTELLIGENT_IO, "Intelligent I/O Controller"), \
    X(SATELITE, "Satelite Communications Controller"), \
    X(ENCRYPT_DECRYPT, "Encryption/Decryption Controller"), \
    X(SINGAL_PROC, "Data Acquisition and Signal Processing Controller")

#define PCI_CLASS_STORAGE_X \
    X(SCSI, 0, "SCSI Storage Controller"), \
    X(IDE, 1, "IDE Interface"), \
    X(FLOPPY, 2, "Floppy Disk Controller"), \
    X(IPI, 3, "IPI Bus Controller"), \
    X(RAID, 4, "RAID Bus Controller"), \
    X(ATA, 5, "ATA Controller"), \
    X(SATA, 6, "SATA Controller"), \
    X(SERIAL_SCSI, 7, "Serial Attached SCSI Controller"), \
    X(NON_VOLATILE, 8, "Non-Volatile Memory Controller"), \
    X(PASS_STORAGE, 80, "Nass Storage Controller")

enum {
#define X(en, ...) PCI_CLASS_##en
    PCI_CLASS_X
#undef X
    PCI_CLASS_UNKNOWN = 0xFF,
};

enum {
#define X(en, val, ...) PCI_CLASS_STORAGE_##en = val
    PCI_CLASS_STORAGE_X
#undef X
};

static const char *pci_class_storage_names[] = {
#define X(en, val, name) [PCI_CLASS_STORAGE_##en] = name
    PCI_CLASS_STORAGE_X
#undef X
};

static const char *pci_class_names[] = {
#define X(en, name) [PCI_CLASS_##en] = name
    PCI_CLASS_X,
#undef X
    [PCI_CLASS_UNKNOWN] = "PCI Class Unknown",
};

static const char **pci_class_device_names[PCI_CLASS_UNKNOWN] = {
    [PCI_CLASS_MASS_STORAGE] = pci_class_storage_names,
};

#define PCI_SUBCLASS_BRIDGE_PCI 0x04

struct PciAddr {
    union {
        uint32_t addr;
        struct {
            uint32_t regno: 8;
            uint32_t funcno: 3;
            uint32_t slotno: 5;
            uint32_t busno: 8;
            uint32_t reserved: 7;
            uint32_t enabled: 1;
        };
    };
};

#define PCI_IO_CONFIG_ADDR (0xCF8)
#define PCI_IO_CONFIG_DATA (0xCFC)

#define PCI_ADDR_CREATE(dev, reg) \
    { \
        .enabled = 1, \
        .busno = ((dev)->bus), \
        .slotno = ((dev)->slot), \
        .funcno = ((dev)->func), \
        .regno = ((reg) & 0xFC), \
    }

uint32_t
pci_config_read_uint32(struct PciDev *dev, uint8_t regno)
{
    struct PciAddr addr = PCI_ADDR_CREATE(dev, regno);
    outl(PCI_IO_CONFIG_ADDR, addr.addr);

    return inl(PCI_IO_CONFIG_DATA);
}

uint16_t
pci_config_read_uint16(struct PciDev *dev, uint8_t regno)
{
    struct PciAddr addr = PCI_ADDR_CREATE(dev, regno);
    outl(PCI_IO_CONFIG_ADDR, addr.addr);

    return inw(PCI_IO_CONFIG_DATA + (regno & 3));
}

uint8_t
pci_config_read_uint8(struct PciDev *dev, uint8_t regno)
{
    struct PciAddr addr = PCI_ADDR_CREATE(dev, regno);
    outl(PCI_IO_CONFIG_ADDR, addr.addr);

    return inb(PCI_IO_CONFIG_DATA + (regno & 3));
}

void
pci_config_write_uint32(struct PciDev *dev, uint8_t regno, uint32_t value)
{
    struct PciAddr addr = PCI_ADDR_CREATE(dev, regno);

    outl(PCI_IO_CONFIG_ADDR, addr.addr);
    outl(PCI_IO_CONFIG_DATA, value);
}

void
pci_config_write_uint16(struct PciDev *dev, uint8_t regno, uint16_t value)
{
    struct PciAddr addr = PCI_ADDR_CREATE(dev, regno);

    outl(PCI_IO_CONFIG_ADDR, addr.addr);
    outw(PCI_IO_CONFIG_DATA + (regno & 3), value);
}

void
pci_config_write_uint8(struct PciDev *dev, uint8_t regno, uint8_t value)
{
    struct PciAddr addr = PCI_ADDR_CREATE(dev, regno);

    outl(PCI_IO_CONFIG_ADDR, addr.addr);
    outb(PCI_IO_CONFIG_DATA + (regno & 3), value);
}

static void
pci_get_device_vendor(struct PciDev *dec, uint16_t *vendor, uint16_t *dev)
{
    uint32_t devven = pci_config_read_uint32(dev, 0);

    *device = (devven >> 16);
    *vendor = (devven & 0xFFFF);
}

static uint32_t
pci_get_class(struct PciDev *dev)
{
    return pci_config_read_uint8(dev, PCI_REG_CLASS);
}

static uint32_t
pci_get_subclass(struct PciDev *dev)
{
    return pci_config_read_uint8(dev, PCI_REG_SUBCLASS);
}

static uint32_t
pci_get_procif(struct PciDev *dev)
{
    return pci_config_read_uint8(dev, PCI_REG_PROG_IF);
}

static uint32_t
pci_get_revision(struct PciDev *dev)
{
    return pci_config_read_uint8(dev, PCI_REG_REVISION_ID);
}

static uint32_t
pci_get_header_type(struct PciDev *dev)
{
    return pci_config_read_uint8(dev, PCI_REG_HEADER_TYPE);
}

static uint32_t
pci_get_secondary_bus(struct PciDev *dev)
{
    return pci_config_read_uint8(dev, PCI_REG_SECONDARY_BUS);
}

void
pci_get_class_name(uint8_t class, uint8_t subclass, const char **class_name, const char **subclass_name)
{
    *class_name = NULL;
    *subclass_name = NULL;

    if (class < ARRAY_SIZE(pci_class_names) && class > 0) {
        if (pci_class_names[class]) {
            *class_name = pci_class_names[class];

            if (pci_class_device_names[class]) {
                if (pci_class_device_names[class][subclass])
                    *subclass_name = pci_class_device_names[class][subclass];
            }
        }
    }
}

static void pci_enumerate_bus(int bus);

/**
 * Add's a device to the main list of devices.
 * NOTE: We keep this list sorted by bus, slot, and func number.
**/
static void
pci_add_dev_entry(struct PciDevEntry *new_entry)
{
    struct PciDevEntry *ent;

    list_foreach_entry(&pci_dev_list, ent, pci_dev_node) {
        if (new_entry->info.id.bus < ent->info.id.bus ||
            (new_entry->info.id.bus == ent->info.id.bus && new_entry->info.id.slot < ent->info.id.slot) ||
            (new_entry->info.id.bus == ent->info.id.bus && new_entry->info.id.slot == ent->info.id.slot &&
            new_entry->info.id.func < ent->info.id.func)) {

            list_add_tail(&ent->pci_dev_node, &new_entry->pci_dev_node);

            return;
        }
    }

    list_add_tail(&pci_dev_list, &new_entry->pci_dev_node);
}

static void
pci_dev_info_populate(struct PciDevInfo *info)
{
    pci_get_device_vendor(&info->id, &info->vendor, &info->device);

    if (info->vendor == 0xFFF)
        return;

    info->header_type = pci_get_header_type(&info->id);
    info->class = pci_get_class(&info->id);
    info->subclass = pci_get_subclass(&info->id);
    info->procif = pci_get_procif(&info->id);
    info->revision = pci_get_revision(&info->id);
}

static void
pci_check_dev(struct PciDevInfo *dev)
{
    struct PciDevEntry *entry = kzalloc(sizeof(*entry), PAL_KERNEL);
    const char *cla = NULL, *sub = NULL;

    list_node_init(&entry->pci_dev_node);
    entry->info = *dev;

    kprintf(KERN_NORM, "PCI %d:%d:%d - 0x%04x:0x%04x\n", dev->id.bus, dev->id.slot, dev->id.func,
        entry->info.vendor, entry->info.device);
    pci_get_class_name(entry->info.class, entry->info.subclass, &cla, &sub);

    if (cla && sub)
        kprintf(KERN_NORM, "  - %s, %s\n", cla, sub);
    else if (cla)
        kprintf(KERN_NORM, "  - %s\n", cla);

    pci_add_dev_entry(entry);

    if (dev->header_type & PCI_HEADER_IS_BRIDGE) {
        int new_bus = pci_get_secondary_bus(&dev->id);
        pci_enumerate_bus(new_bus);
    }
}

static void
pci_check_slot(int bus, int slot)
{
    struct PciDevInfor info = {
        .id.bus = bus,
        .id.slot = slot,
    };

    pci_dev_info_populate(&info);

    if (info.vendor == 0xFFFF)
        return;

    pci_check_dev(&info);

    if (info.header_type & PCI_HEADER_IS_MULTIFUNCTION) {
        for (info.id.func = 1l info.id.func < 8; info.id.func++) {
            pci_dev_info_populate(&info);

            if (info.vendor == 0xFFFF)
                continue;

            pci_check_dev(&info);
        }
    }
}

static void
pci_enumerate_bus(int bus)
{
    int slot;

    for (slot = 0; slot < 32; slot++)
        pci_check_slot(bus, slot);
}

static void
enum_pci(void)
{
    pci_enumerate_bus(0);
}

/**
 * A simple helper function--if `target` is zero, then the check isn't performed.
**/
static int
pci_eq(int target, int actual)
{
    return !target || (target == actual);
}

static void
pci_load_device(struct PciDev *dev, uint16_t vendor, uint16_t dev, uint16_t class,
    uint16_t subclass)
{
    const struct PciDriver *driver;

    for (driver = pci_drivers; driver->name; driver++) {
        if (pci_eq(driver->vendor, vendor) && pci_eq(driver->device, dev) &&
            pci_eq(driver->class, class) && pci_eq(driver->subclass, subclass)) {

            kprintf(KERN_NORM, "Initializing device: %s\n", driver->name);
            (driver->device_init)(dev);

            return;
        }
    }
}

static void
load_pci_devices(void)
{
    struct PciDevEntry *entry;

    list_foreach_entry(&pci_dev_list, entry, pci_dev_node)
        pci_load_device(&entry->info.id, entry->info.vendor, entry->info.device, entry->info.class,
            entry->info.subclass)
}

static void
pci_init(void)
{
    enum_pci();
    load_pci_devices();
}

initcall_device(pci_devices, pci_init);

size_t
pci_bar_size(struct PciDev *dev, uint8_t bar_reg)
{
    uint32_t bar = pci_config_read_uint32(dev, bar_reg);
    size_t size;

    pci_config_write_uint32(dev, bar_reg, 0xFFFFFFFF);
    size = pci_config_read_uint32(dev, bar_reg);
    pci_config_write_uint32(dev, bar_reg, bar);

    return (~size) + 1;
}

int
pci_has_interrupt_line(struct PciDev *dev)
{
    uint8_t int_line = pci_config_read_uint8(dev, PCI_REG_INTERRUPT_LINE);
    uint8_t result;

    pci_config_write_uint8(dev, PCI_REG_INTERRUPT_LINE, 0xFE);
    result = pci_config_read_uint8(dev, PCI_REG_INTERRUPT_LINE);
    pci_config_write_uint8(dev, PCI_REG_INTERRUPT_LINE, int_line);

    return result == 0xFE;
}
