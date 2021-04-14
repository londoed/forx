/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londed@protonmail.com>, { net/linklayer.c }.
 * Copyright (C) 2017, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <forx/spinlock.h>
#include <forx/mm/kmalloc.h>
#include <libctl/snprintf.h>
#include <forx/list.h>
#include <forx/initcall.h>

#include <forx/net/ipv4/ipv4.h>
#include <forx/net.h>
#include <forx/net/arphrd.h>
#include <forx/net/arp.h>
#include <forx/net/linklayer.h>

struct EtherHeader {
    char mac_dest[6];
    char mac_src[6];
    n16 ether_type;
} __packed;

struct Ether {
    struct AddrFamily *ip, *arp;
};

static struct Ether ether;

void
packet_linklayer_rx(struct Packet *packet)
{
    struct EtherHeader *ehead;

    using_netdev_write(packet->iface_rx) {
        packet->iface_rx->metrics.rx_packets++;
        packet->iface_rx->metrics.rx_bytes += packet_len(packet);
    }

    ehead = packet->head;
    packet->ll_head = ehead;
    packet->head += sizeof(struct EtherHeader);

    switch (ntohs(ehead->ether_type)) {
    case ETH_P_APP:
        (ether.arp->ops->packet_rx)(ether.arp, packet);
        break;

    case ETH_P_IP:
        (ether.ip->ops->packet_rx)(ether.ip, packet);
        break;

    default:
        kprintf(KERN_NORM, "Unknown ether packet type: 0x%04x\n", ntohs(ehead->ether_type));
        packet_free(packet);
        break;
    }
}

/**
 * Only support ethernet right now..
**/
int
packet_linklayer_tx(struct Packet *packet)
{
    struct EtherHeader ehead;

    memcpy(ehead.mac_dest, packet->dest_mac, sizeof(ehead.mac_dest));
    memcpy(ehead.mac_src, packet->iface_tx->mac, sizeof(ehead.mac_src));
    ehead.ether_type = packet->ll_type;

    if (packet_len(packet) + 14 < 60)
        packet_pad_zero(packet, 60 - (packet_len(packet) + 14));

    packet_add_header(packet, &ehead, sizeof(ehead));
    net_packet_transmit(packet);

    return 0;
}

static void
linklayer_setup(void)
{
    ether.ip = address_family_lookup(AF_INET);
    ether.arp = address_family_lookup(AF_ARP);
}

initcall_device(linklayer, linklayer_setup);
initcall_dependency(linklayer, arp);
initcall_dependency(linklayer, ip);
