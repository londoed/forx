/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { pci/internal.h }.
 * Copyright (C) 2020, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#ifndef FORX_PCI_INTERNAL_H
#define FORX_PCI_INTERNAL_H

#include <forx/list.h>
#include <forx/mutex.h>
#include <forx/drivers/pci.h>

struct PciDevInfo {
    struct PciDev id;
    uint8_t class, subclass, procif, revision, header_type;
    uint16_t vendor, device;
};

struct PciDevEntry {
    struct PciDevInfo info;
    ListNode pci_dev_node;
};

// Currently readonly after initialization //
extern ListHead pci_dev_list;

void pci_get_class_name(uint8_t class, uint8_t subclass, const char **class_name, const char **subclass_name);

#endif
