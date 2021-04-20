/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { drivers/net/rtl8139/rtl8139.c }.
 * Copyright (C) 2017, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <forx/dump_mem.h>
#include <forx/mm/kmalloc.h>
#include <libctl/snprintf.h>
#include <forx/arch/paging.h>
#include <forx/arch/asm.h>
#include <forx/arch/irq.h>
#include <forx/arch/idt.h>
#include <forx/arch/drivers/pic8259.h>

#include <forx/fs/procfs.h>
#include <forx/drivers/pci.h>
#include <forx/drivers/pci_ids.h>
#include <forx/net/arphrd.h>
#include <forx/net.h>
#include <forx/drivers/rtl.h>
#include <forx/net/arp.h>
#include <forx/net/linklayer.h>

#include "internal.h"

/**
 * Defines the functions rtl_outb, rtl_outw, rtl_outl, rtl_inb, etc...
**/
DEFINE_REG_ACCESS_FUNCTIONS(rtl, struct NetInterfaceRtl *rtl, rtl->io_base);

static struct RtlRxPacket *
rtl_iter_next_rx_buf(struct NetInterfaceRtl *rtl, struct RtlRxPacket *prev_rx_buf)
{
    /**
     * Add the packet length and the length of the header, and 3 is used to align
     * the offset to 4 bytes.
    **/
    rtl->rx_cur_offset = ALIGN_2(rtl->rx_cur_offset + prev_rx_buf->len +
        sizeof(struct RtlRxPacket), 4);
    rtl->rx_cur_offset %= 8192;

    // Subtraction avoids overflow issues //
    rtl_outw(rtl, REG_CAPR, rtl->rx_cur_offset - 0x10);

    return rtl->rx_buffer->virt + rtl->rx_cur_offset;
}

static int
rtl_has_rx_buf(struct NetInterfaceRtl *rtl)
{
    return !(rtl_inb(rtl, REG_CR) & REG_CR_BUFE);
}

static struct RtlRxPacket *
rtl_cur_rx_buf(struct NetInterfaceRtl *rtl)
{
    return rtl->rx_buffer->virt + rtl->rx_cur_offset;
}

#define foreach_rx_buf(rtl, buf) \
    for (buf = rtl_cur_rx_buf((rtl)); \
        rtl_has_rx_buf(rtl); \
        buf = rtl_iter_next_rx_buf(rtl, buf))

static void
rtl_handle_rx(struct NetInterfaceRtl *rtl)
{
    struct RtlRxPacket *rx_buf;

    foreach_rx_buf(rtl, rx_buf) {
        struct Packet *packet;

        if ((rx_buf->status & RSR_ROK) && rx_buf->len > 0 && rx_buf->len < PAGE_SIZE) {
            packet = packet_new(PAL_KERNEL | PAL_ATOMIC);
            memcpy(packet->start, rx_buf->packet, rx_buf->len);
            packet->head = packet->start;
            packet->tail = packet->head + rx_buf->len;

            packet->iface_rx = netdev_dup(&rtl->net);
            net_packet_receive(packet);
        } else {
            kprintf(KERN_NORM, "rtl8139: Ignoring packet with length %d\n",
                rx_buf->len);
        }
    }
}

static void
__rtl_send_packet(struct NetInterfaceRtl *rtl, struct Packet *packet, size_t len)
{
    packet_to_buffer(packet, rtl->tx_buffer[rtl->tx_cur_buffer]->virt, PAGE_SIZE);

    rtl_outl(rtl, REG_TSD(rtl->tx_cur_buffer), len);
    rtl->tx_cur_buffer = (rtl->tx_cur_buffer + 1) % 4;
}

static void
rtl_process_tx_queue(struct NetInterface *iface)
{
    struct NetInterfaceRtl *rtl = container_of(iface, struct NetInterfaceRtl, net);

    using_spinlock(&rtl->net.tx_lock) {
        while (__net_iface_has_tx_packet(&rtl->net)) {
            int i, own = 0;

            /**
             * We loop up to 10 times checking for the current buffer to
             * become usable.
            **/
            for (i = 0; i < 10 && !own; i++)
                own = rtl_inl(rtl, REG_TSD(rtl->tx_cur_buffer)) & REG_TSD_OWN;

            if (!own)
                return;

            struct Packet *packet = __net_iface_tx_packet_pop(iface);
            __rtl_send_packet(rtl, packet, packet_len(packet));
            packet_free(packet);
        }
    }
}

static void
rtl_rx_interrupt(struct IrqFrame *frame, void *param)
{
    struct NetInterfaceRtl *rtl = param;
    uint16_t isr = rtl_inw(rtl, REG_ISR);

    if (isr & REG_ISR_ROK)
        rtl_handle_rx(rtl);

    if (isr & REG_ISR_TOK)
        rtl_process_tx_queue(&rtl->net);

    // ACK Interrupt //
    rtl_outw(rtl, REG_ISR, isr);
}

void
rtl_device_init_rx(struct NetInterfaceRtl *rtl)
{
    rtl->rx_buffer = page_alloc(3, PAL_KERNEL);

    rtl_outl(rtl, REG_RCR, REG_RCR_AB | REG_RCR_AM | REG_RCR_APM | REG_RCR_AAP | REG_RCR_WRAP);
    rtl_outl(rtl, REG_RESTART, page_to_pa(rtl->tx_buffer));
}

void
rtl_device_init_tx(struct NetInterfaceRtl *rtl)
{
    int i;

    for (i = 0; i < 4; i++)
        rtl->tx_buffer[i] = page_alloc(0, PAL_KERNEL);

    rtl_outl(rtl, REG_TSAD0, (uintptr_t)page_to_pa(rtl->tx_buffer[0]));
    rtl_outl(rtl, REG_TSAD1, (uintptr_t)page_to_pa(rtl->tx_buffer[1]));
    rtl_outl(rtl, REG_TSAD2, (uintptr_t)page_to_pa(rtl->tx_buffer[2]));
    rtl_outl(rtl, REG_TSAD3, (uintptr_t)page_to_pa(rtl->tx_buffer[3]));

    rtl_outl(rtl, REG_TCR, REG_TCR_CRC);
}

void
rtl_device_init(struct PciDev *dev)
{
    struct NetInterfaceRtl *rtl = kzalloc(sizeof(*rtl), PAL_KERNEL);
    uint16_t command_reg;
    int int_line;

    net_interface_init(&rtl->net);
    rtl->next.process_tx_queue = rtl_process_tx_queue;
    rtl->net.linklayer_tx = arp_tx;

    kprintf(KERN_NORM, "Found RealTek RTL8139 Fast Ethernet: "PRpci_dev"\n", Ppci_dev(dev));
    rtl->next.name = "eth";
    rtl->dev = *dev;

    command_reg = pci_config_read_uint16(dev, PCI_REG_COMMAND);
    pci_config_write_uint16(dev, PCI_REG_COMMAND, command_reg | PCI_COMMAND_BUS_MASTER |
        PCI_COMMAND_IO_SPACE);
    int_line = pci_config_read_uint8(dev, PCI_REG_INTERRUPT_LINE);
    kprintf(KERN_NORM, "  Interrupt: %d\n", int_line);
    rtl->io_base = pci_config_read_uint32(dev, PCI_REG_BAR(0)) & 0xFFFE;

    // Turn the RT18139 on //
    rtl_outb(rtl, REG_CONFIG0, 0);

    /**
     * Perform a software reset.
     * REG_CR_RST will go low when reset is complete.
    **/
    rtl_outb(rtl, REG_CR, REG_CR_RST);

    while (rtl_inb(rtl, REG_CR) & REG_CR_RST)
        ;

    // Read MAC address //
    rtl->net.mac[0] = rtl_inb(rtl, REG_MAC0);
    rtl->net.mac[1] = rtl_inb(rtl, REG_MAC1);
    rtl->net.mac[2] = rtl_inb(rtl, REG_MAC2);
    rtl->net.mac[3] = rtl_inb(rtl, REG_MAC3);
    rtl->net.mac[4] = rtl_inb(rtl, REG_MAC4);
    rtl->net.mac[5] = rtl_inb(rtl, REG_MAC5);
    rtl->net.hwtype = ARPHRD_ETHER;

    kprintf(KERN_NORM, "  MAC: "PRmac"\n", Pmac(rtl->net.mac));

    rtl_device_init_rx(rtl);
    rtl_device_init_tx(rtl);
    int err = irq_register_callback(int_line, rtl_rx_interrupt, "RealTek RTL8239", IRQ_INTERRUPT,
        rtl, F(IRQF_SHARED));

    if (err) {
        kprintf(KERN_WARN, "rtl8129: Interrupt %d already taken and not shared\n", PIC8295_IRQ0 + int_line);

        return;
    }

    rtl_outw(rtl, REG_IMR, REG_IMR_TOK | REG_IMR_ROK);
    rtl_outb(rtl, REG_CR, REG_CR_TE | REG_CR_RE);
    net_interface_register(&rtl->net);
}
