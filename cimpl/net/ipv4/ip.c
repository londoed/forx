/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { net/ipv4/ip.c }.
 * Copyright (C) 2017. Matt Kilgore.
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
#include <forx/list.h>
#include <forx/arch/asm.h>
#include <forx/initcall.h>

#include <forx/net/socket.h>
#include <forx/net/proto.h>
#include <forx/net/netdev.h>
#include <forx/net/arphrd.h>
#include <forx/net/ipv4/ipv4.h>
#include <forx/net/ipv4/ip_route.h>
#include <forx/net/linklayer.h>
#include <forx/net.h>

#include "ipv4.h"

static struct AddrFamily ip_addr_family_ops;

struct AddrFamilyIp ip_addr_family = {
    .af = ADDRESS_FAMILY_INIT(ip_addr_family.af, AF_INET, &ip_addr_family_ops),
    .lock = MUTEX_INIT(ip_addr_family.lock),
    .raw_sockets = LIST_HEAD_INIT(ip_addr_family.raw_sockets),
    .sockets = LIST_HEAD_INIT(ip_addr_family.sockets),
};

InAddr
inet_addr(const char *ip)
{
    int vals[4];
    int i;

    for (i = 0; i < 4; i++) {
        int new_val = 0;

        while (*ip >= '0' && *ip <= '9') {
            new_val = new_val * 10 + (*ip - '0');
            ip++;
        }

        vals[i] = new_val;
        ip++;
    }

    return n32_make((vals[3] << 24) + (vals[2] << 16) + (vals[1] << 8) + vals[0]);
}

n16
ip_chksum(uint16_t *head, size_t byte_count)
{
    size_t i;
    uint32_t sum = 0;

    for (i = 0; i < byte_count / 2; i++)
        sum += head[i];

    if (byte_count % 2)
        sum += head[byte_count];

    while (sum & 0xFFFF0000)
        sum = (sum & 0xFFFF) + ((sum & 0xFFFF0000) >> 16);

    return n16_make(~sum);
}

static uint16_t next_ip_id = 0;
void
ip_rx(struct AddrFamily *afamily, struct Packet *packet)
{
    struct AddrFamilyIp *af = container_of(afamily, struct AddrFamilyIp, af);
    struct IpHeader *header = packet->head;
    struct SockAddrIn *in;
    int packet_handled = 0;

    packet->af_head = packet->head;
    packet->head += header->ihl * 4;
    packet->tail = packet->head + ntohs(header->total_length) - header->ihl * 4;

    kp_ip_trace("  Packet: "PRin_addr" -> "PRin_addr"\n", Pin_addr(header->source_ip),
        Pin_addr(header->dest_ip));
    kp_ip_trace("  af_head: %p, start: %p, offset: %ld\n", packet->af_head, packet->start,
        packet->af_head - packet->start);
    kp_ip_trace("  Version: %d, HL: %d, %d bytes\n", header->version, header->ihl, header->ifl * 4);
    kp_ip_trace("  Protocol: 0x%2x, ID: 0x%04x, Len: 0x%04x\n", header->protocol,
        ntohs(header->id), ntohs(header->total_length) - header->ihl * 4);
    kp_ip_trace("  Checksum: 0x%04x\n", ntohs(header->csum));
    header->csum = htons(0);
    kp_ip_trace("  Calculated: 0x%04x\n", ntohs(ip_chksum((uint16_t *)header, header->ihl * 4)));

    in = (struct SockAddrIn *)&packet->src_addr;
    in->sin_family = AF_INET;
    in->sin_addr.s_addr = header->source_ip;
    packet->src_len = sizeof(*in);

    // First, route a copy to any raw sockets //
    using_mutex(&af->lock) {
        struct Socket *raw;

        list_foreach_entry(&af->raw_sockets, raw, socket_entry) {
            if (raw->protocol == header->protocol) {
                struct Packet *copy = packet_copy(packet, PAL_KERNEL);
                copy->sock = socket_dup(raw);
                (raw->proto->ops->packet_rx)(raw->proto, raw, copy);
                packet_handled = 1;
            }
        }
    }

    struct Socket *sock = NULL;
    struct IpLookup lookup = {
        .proto = header->protocol,
        .src_addr = header->dest_ip,
        .dest_addr = header->source_ip,
    };

    int maxscore = 2;
    struct Protocol *proto = NULL;

    switch (header->protocol) {
    case IPPROTO_TCP:
        proto = tcp_get_proto();
        tcp_lookup_fill(&lookup, packet);
        maxscore = 1;

        break;

    case IPPROTO_UDP:
        proto = udp_get_proto();
        udp_lookup_fill(&lookup, packet);
        maxscore = 4;

        break;

    default:
        break;
    }

    using_mutex(&af->lock)
        sock = __ipaf_find_socket(af, &lookup, maxscore);

    packet->sock = sock;

    if (proto) {
        (proto->ops->packet_rx)(proto, sock, packet);
    } else {
        if (!packet_handled)
            kp_ip_trace("  Packet dropped: %p\n", packet);

        packet_free(packet);
    }
}

void
ip_tx(struct Packet *packet)
{
    struct IpHeader *header;
    struct SockAddrIn *in = (struct SockAddrIn *)&packet->dest_addr;
    size_t data_len = packet_len(packet);

    packet->head -= sizeof(struct IpHeader);
    header = packet->head;
    memset(header, 0, sizeof(*header));

    header->version = 4;
    header->ihl = 5;
    header->tos = 0;
    header->id = htons(next_ip_id++);
    header->frag_off = htons(0);
    header->ttl = 30;
    header->protocol = packet->protocol_type;
    header->total_length = htons(data_len + sizeof(*header));

    using_netdev_read(packet->iface_tx)
        header->source_ip = packet->iface_tx->in_addr;

    header->dest_ip = in->sin_addr.s_addr;
    header->csum = htons(0);
    header->csum = ip_chksum((uint16_t *)header, header->ihl * 4);

    kp_ip_trace("Ip route: "PRin_addr", len: %d, csum: 0x%04x, DestIP: "PRin_addr"\n",
        Pin_addr(packet->route_addr), data_len, ntohs(header->csum), Pin_addr(header->dest_ip));

    return (packet->iface_tx->linklayer_tx)(packet);
}
