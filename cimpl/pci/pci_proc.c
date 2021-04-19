/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { pci/pci_proc.c }.
 * Copyright (C) 2021, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <libctl/snprintf.h>

#include <forx/fs/procfs.h>
#include <forx/fs/seq_file.h>
#include <forx/drivers/pci.h>

#include "internal.h"

static int
proc_seq_start(struct SeqFile *seq)
{
    return seq_list_start(seq, &pci_dev_list);
}

static int
proc_seq_render(struct SeqFile *seq)
{
    struct  PciDevEntry *entry = seq_list_get_entry(seq, struct PciDevEntry, pci_dev_node);
    const char *cla = NULL, *sub = NULL;

    pci_get_class_name(entry->info.class, entry->info.subclass, &cla, &sub);

    if (sub)
        return seq_printf(seq, "%02d:%02d.%d: 0x%04x:0x%04x: %s, %s\n",
            entry->info.id.bus, entry->info.id.slot,
            entry->info.id.func, entry->info.vendor,
            entry->info.device, cla, sub);
    else
        return seq_printf(seq, "%02d:%02d.%d: 0x%04x:0x%04x: %s\n",
            entry->info.id.bus, entry->info.id.slot,
            entry->info.id.func, entry->info.vendor,
            entry->info.device, cla);
}

static int
proc_seq_next(struct SeqFile *seq)
{
    return seq_list_next(seq, &pci_dev_list);
}

const static struct SeqFileOps pci_seq_file_ops = {
    .start = proc_seq_start,
    .render = proc_seq_render,
    .next = proc_seq_next,
};

static int
pci_file_seq_open(struct Inode *ino, struct File *filp)
{
    return seq_open(filp, &pci_seq_file_ops);
}

const struct FileOps pci_file_ops = {
    .open = pci_file_seq_open,
    .lseek = seq_lseek,
    .read = seq_read,
    .release = seq_release,
};
