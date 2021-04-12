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

int
ip_packet_fill_route(struct Socket *sock, struct Packet *packet)
{
    return ip_packet_fill_route_addr(sock, packet, NULL, 0);
}

int
ip_packet_fill_route_addr(struct Socket *sock, struct Packet *packet, const struct SockAddr *addr,
    socklen_t len)
{
    struct Ipv4SocketPrivate *ip_priv = &sock->af_private.ipv4;
    enum SocketState cur_state = socket_state_get(sock);

    if (cur_state == SOCKET_CONNECTING || cur_state == SOCKET_CONNECTED) {
        sockaddr_in_assign_addr(&packet->dest_addr, ip_priv->dest_addr);

        packet->iface_tx = netdev_dup(ip_priv->route.iface);
        packet->ll_type = htons(ETH_P_IP);
        packet->route_addr = ip_route_get_ip(&ip_priv->route);

        return 0;
    }

    // Else we attempt to lookup the route //
    if (addr) {
        const struct SockAddrIn *in;

        if (sizeof(*in) > len)
            return -EFAULT;

        if (addr->sa_family != AF_INET)
            return -EINVAL;

        in = (const struct SockAddrIn *)addr;
        sockaddr_in_assign_addr(&packet->dest_addr, in->sin_addr.s_addr);
    } else {
        return -EDESTADDRREQ;
    }

    struct SockAddrIn *in = (struct SockAddrIn *)&packet->dest_addr;
    struct IpRouteEntry route;
    int ret = ip_route_get(in->sin_addr.s_addr, &route);

    if (ret)
        return -EACCES;

    packet->iface_tx = route.iface;
    packet->ll_type = htons(ETH_P_IP);
    packet->route_addr = ip_route_get_ip(&route);

    return 0;
}

int
ip_packet_fill_raw(struct Packet *packet, InAddr dest_addr)
{
    struct IpRouteEntry route;
    int ret = ip_route_get(dest_addr, &route);

    if (ret)
        return -EACCES;

    sockaddr_in_assign_addr(&packet->dest_addr, dest_addr);

    packet->iface_tx = route.iface;
    packet->ll_type = htons(ETH_P_IP);
    packet->route_addr = ip_route_get_ip(&route);

    return 0;
}

static int
ip_create(struct AddrFamily *family, struct Socket *socket)
{
    if (socket->sock_type == SOCK_DGRAM && (socket->protocol == 0 ||
        socter->protocol == IPPROTO_UDP)) {

        kp_ip_trace("Looking up UDP protocol\n");
        socket->proto = udp_get_proto();
        socket->af_private.ipv4.proto = IPPROTO_UDP;
    } else if (socket->sock_type == SOCK_STREAM && (socket->protocol == 0) ||
        socket->protocol == IPPROTO_TCP) {

        kp_ip_trace("Looking up TCP protocol\n");
        socket->proto = tcp_get_proto();
        socket->af_private.sock_type == SOCK_RAW;
    } else if (socket->sock_type == SOCK_RAW) {
        if (socket->protocol > 255 || socket->protocol < 0)
            return -EINVAL;

        socket->proto = ip_raw_get_proto();
        socket->af_private.ipv4.proto = socket->protocol;
    } else {
        return -EINVAL;
    }

    return 0;
}

void
ip_release(struct AddrFamily *family, struct Socket *sock)
{
    struct Ipv4SocketPrivate *priv = &sock->af_private.ipv4;

    ip_route_clear(&priv->route);
}

static struct AddrFamilyOps ip_addr_family_ops = {
    .create = ip_create,
    .packet_rx = ip_rx,
};

struct ProcfsDir *ipv4_dir_procfs;

static void
ip_init(void)
{
    addr_family_register(&ip_addr_family.af);
}

initcall_device(ip, ip_init);

static void
ip_procfs_init(void)
{
    ipv4_dir_procfs = procfs_register_dir(net_dir_procfs, "ipv4");

    procfs_register_entry_ops(ipv4_dir_procfs, "route", &ipv4_route_ops);
    procfs_register_entry(ipv4_dir_procfs, "udp", &udp_proc_file_ops);
    procfs_register_entry(ipv4_dir_profcs, "ip-raw", &ip_raw_proc_file_ops);
    procfs_register_entry(ipv4_dir_procfs, "tcp", &tcp_proc_file_ops);
}

initcall_device(ip_procfs, ip_procfs_init);
initcall_dependency(ip_procfs, ip);
initcall_dependency(ip_procfs, net_procfs);
