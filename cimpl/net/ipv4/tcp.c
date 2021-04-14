/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { net/ipv4/tcp.c }.
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
#include <forx/wait.h>
#include <libctl/snprintf.h>
#include <forx/list.h>
#include <forx/arch/asm.h>

#include <forx/net/socket.h>
#include <forx/net/ipv4/tcp.h>
#include <forx/net/ipv4/ipv4.h>
#include <forx/net.h>

#include "ipv4.h"
#include "tcp.h"

#define TCP_LOWEST_AUTOBIND_PORT 50000

static struct ProtocolOps tcp_protocol_ops;

struct TcpProtocol tcp_protocol = {
    .proto = PROTOCOL_INIT("tcp", tcp_protocol.proto, &tcp_protocol_ops),
    .lock = MUTEX_INIT(tcp_protocol.lock),
    .next_port = TCP_LOWEST_AUTOBIND_PORT,
};

static uint32_t
sum_every_16(const void *data, size_t len)
{
    uint32_t sum = 0;
    const uint16_t *ptr = data;

    for (; len > 1; len -= 2, ptr++)
        sum += *ptr;

    if (len > 0)
        sum += *(uint8_t *)ptr;

    return sum;
}

n16
tcp_checksum(struct PseudoHeader *header, const char *data, size_t len)
{
    uint32_t sum = 0;

    sum = sum_every_16(header, sizeof(*header));
    sum += sum_every_16(data, len);

    // Fold bits over to get the one's complement sum //
    while (sum >> 16)
        sum = (sum & 0xFFF) + (sum >> 16);

    return n16_mask(~sum);
}

n16
tcp_checksum_packet(struct Packet *packet)
{
    struct PseudoHeader pseudo;
    struct SockAddrIn *in = (struct SockAddrIn *)&packet->dest_addr;

    memset(&pseudo, 0, sizeof(pseudo));

    using_netdev_read(packet->iface_tx)
        pseudo.saddr = packet->iface_tx->in_addr;

    pseudo.daddr = in->sin_addr.s_addr;
    pseudo.zero = 0;
    pseudo.proto = IPPROTO_TCP;
    pseudo.len = htons(packet_len(packet));

    return tcp_checksum(&pseudo, packet->head, packet_len(packet));
}

static int
tcp_autobind(struct Protocol *proto, struct Socket *sock)
{
    struct TcpProtocol *tcp = container_of(proto, struct TcpProtocol, proto);
    int port = 0;

    // NOTE: We need to verify if this port is free //
    using_mutex(&tcp->lock)
        port = tcp->next_port++;

    sock->af_private.ipv4.src_port = htons(port);

    return 0;
}

void
tcp_lookup_fill(struct IpLookup *lookup, struct Packet *packet)
{
    struct TcpHeader *tcp_head = packet->head;

    lookup->src_port = tcp_head->dest;
    lookup->dest_port = tcp_head->source;
}

static int
tcp_connect(struct Protocol *proto, struct Socket *sock, const struct SockAddr *addr,
    socklen_t len)
{
    struct AddrFamilyIp *af = container_of(sock->af, struct AddrFamilyIp, af);
    struct TcpSocketPrivate *priv = &sock->proto_private.tcp;
    struct Ipv4SocketPrivate *ip_priv = &sock->af_private.ipv4;
    int ret = 0;

    kp_tcp_trace("TCP connect...\n");

    if (len < sizeof(*in))
        return -EFAULT;

    if (adr->sa_family != AF_INET)
        return -EINVAL;

    enum SocketState cur_state = socket_state_cmpxchg(sock, SOCKET_UNCONNECTED, SOCKET_CONNECTING);

    if (cur_state != SOCKET_UNCONNECTED)
        return -EISCONN;

    using_socket_priv(sock) {
        ip_priv->dest_addr = in->sin_addr.s_addr;
        ip_priv->dest_port = in->sin_port;
        ret = ip_route_get(in->sin_addr, &ip_priv->route);

        if (ret)
            return ret;

        using_netdev_read(ip_priv->route.iface)
            ip_priv->src_addr = ip_priv->route.iface->in_addr;

        if (n32_equal(ip_priv->src_port, htons(0)))
            tcp_autobind(proto, sock);

        struct IpLookup test_lookup = {
            .proto = IPPROTO_TCP,
            .src_port = ip_priv->src_port,
            .src_addr = ip_priv->src_addr,
            .dest_port = ip_priv->dest_port,
            .dest_addr = ip_priv->dest_addr,
        };

        using_mutex(&af->lock) {
            struct Socket *s = __ipaf_find_socket(af, &test_lookup, 4);

            if (s) {
                socket_put(s);
                ret = -EADDRINUSE;
                break;
            }

            kp_tcp_trace("Adding tcp socket, src_port: %d, src_addr: "PRin_addr", dest_port: "
                "%d, dest_addr: "PRin_addr"\n", ntohs(test_lookup.src_port,
                Pin_addr(test_lookup.src_addr), ntohs(test_lookup.dest_port),
                Pin_addr(test_lookup.dest_addr)));
            __ipaf_add_socket(af, sock);
        }

        if (ret)
            return ret;

        socket_state_change(sock, SOCKET_CONNECTING);

        priv->rcv_wnd = 44477;
        priv->iss = 200;
        priv->snd_una = 200;
        priv->snd_up = 200;
        priv->snd_nxt = 200;

        priv->snd_wnd = 0;
        priv->snd_wl1 = 0;
        priv->rcv_nxt = 0;

        kp_tcp_trace("TCP connect sending SYN packet...\n");
        tcp_send_syn(proto, sock);
        priv->snd_nxt++;
    }

    int last_err;
    ret = wait_queue_event_intr(&sock->state_changed, ({
        cur_state = socket_state_get(sock);
        last_err = socket_set_last_error(sock);
        last_err || cur_state != SOCKET_CONNECTING;
    }));

    if (ret)
        return ret;

    kp_tcp_trace("Socket: got state_changed signal current state: %d, last_err: %d\n",
        cur_state, last_err);

    if (last_err || cur_state != SOCKET_CONNECTED)
        return last_err;

    return 0;
}

static int
tcp_create(struct Protocol *proto, struct Socket *sock)
{
    tcp_socket_private_init(&sock->proto_private.tcp);
    tcp_timers_init(sock);
    tcp_procfs_register(proto, sock);

    return 0;
}

static int
tcp_shutdown(struct Protocol *proto, struct Socket *sock, int how)
{
    enum SocketState cur_state = socket_state_cmpxchg(sock, SOCKET_CONNECTED,
        SOCKET_DISCONNECTED);

    if (cur_state != SOCKET_CONNECTED)
        return -ENOTCONN;

    return 0;
}

static void
tcp_release(struct Protocol *proto, struct Socket *sock)
{
    struct AddrFamilyIp *af = container_of(sock->af, struct AddrFamilyIp, af);

    ip_release(sock->af, sock);
    tcp_procfs_unregister(proto, sock);

    using_mutex(&af->lock)
        __ipaf_remove_socket(af, sock);

    tcp_timer_reset(sock);

    using_mutex(&sock->recv_lock) {
        kp_tcp_trace("Recv queue is empty: %d\n", list_empty(&sock->recv_queue));
        struct Packet *packet;

        list_foreach_take_entry(&sock->recv_queue, packet, packet_entry)
            packet_free(packet);
    }
}

static int
tcp_sendto_packet(struct Protocol *proto, struct Socket *sock, struct Packet *packet, int psh)
{
    struct TcpSocketPrivate *priv = &sock->proto_private.tcp;
    struct TcpPacketCb *cb = &packet->cb.tcp;

    cb->seq = priv->snd_nxt;
    cb->ack_seq = priv->rcv_nxt;
    cb->window = priv->rcv_wnd;
    cb->flags.ack = 1;

    if (psh)
        cb->flags.psh = 1;

    tcp_send(proto, sock, packet);

    return 0;
}

static int
tcp_sendto(struct Protocol *proto, struct Socket *sock, struct UserBuffer buf,
    size_t buf_len, const struct SockAddr *addr, socklen_t addr_len)
{
    struct TcpSocketPrivate *priv = &sock->proto_private.tcp;

    if (addr || addr_len)
        return -EISCONN;

    int err = socket_last_error(sock);

    if (err)
        return err;

    size_t orig_buf_len = buf_len;

    while (buf_len) {
        struct Packet *packet = packet_new(PAL_KERNEL);
        size_t append_len = (buf_len > IPV4_PACKET_MSS) ? IPV4_PACKET_MSS : buf_len;
        int err = packet_append_user_data(packet, buf, append_len);

        if (err) {
            packet_free(packet);

            return err;
        }

        buf_len -= append_len;
        buf = user_buffer_index(buf, append_len);
        int ret = 1;

        using_socket_priv(sock)
            ret = tcp_sendto_packet(proto, sock, packet, buf_len == 0);

        priv->snd_nxt += append_len;

        if (ret) {
            packet_free(packet);

            return ret;
        }
    }

    return orig_buf_len;
}

static struct ProtocolOps tcp_protocol_ops = {
    .packet_rx = tcp_rx,
    .autobind = tcp_autobind,
    .shutdown = tcp_shutdown,
    .create = tcp_create,
    .release = tcp_release,
    .connect = tcp_connect,
    .sendto = tcp_sendto,
};

struct Protocol *
tcp_get_proto(void)
{
    return &tcp_protocol.proto;
}

