/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { net/ipv4/udp.c }.
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
#include <forx/list.h>
#include <forx/fs/seq_file.h>
#include <forx/arch/asm.h>

#include <forx/net/socket.h>
#include <forx/net.h>

#include "ipv4.h"

struct UdpHeader {
    n16 source_port;
    n16 dest_port;
    n16 length;
    n16 checksum;
} __packed;

#define UDP_HASH_SIZE 128
#define UDP_LOWEST_AUTOBIND_PORT 50000

struct UdpProtocol {
    struct Protocol proto;
    Mutex lock;
    uint16_t next_port;
};

static struct ProtocolOps udp_protocol_ops;

static struct UdpProtocol udp_protocol = {
    .proto = PROTOCOL_INIT("udp", udp_protocol.proto, &udp_protocol_ops),
    .lock = MUTEX_INIT(udp_protocol.lock),
    .next_port = UDP_LOWEST_AUTOBIND_PORT,
};

static n16
udp_find_port(struct UdpProtocol *proto)
{
    n16 port;
    int found = 0;

    using_mutex(&proto->lock) {
        do {
            port = htons(proto->next_port++);

            if (proto->next_port == 65536)
                proto->next_port = UDP_LOWEST_AUTOBIND_PORT;

            // NOTE: Check this against the AddrFamilyIp socket table //
            found = 1;
        } while (!found);
    }

    kp_udp_trace("Autobind port: %d\n", ntohs(port));

    return port;
}

static int
udp_register_sock(struct UdpProtocol *proto, struct Socket *sock)
{
    int ret = 0;
    struct AddrFamilyIp *af = container_of(sock->af, struct AddrFamilyIp, af);

    struct IpLookup test_lookup = {
        .proto = IPPROTO_UDP,
        .src_port = sock->af_private.ipv4.src_port,
        .src_addr = sock->af_private.ipv4.src_addr,
        .dest_port = sock->af_private.ipv4.dest_port,
        .dest_addr = sock->af_private.ipv4.dest_addr,
    };

    using_mutex(&af->lock) {
        struct Socket *s = __ipaf_find_socket(af, &test_lookup, 4);

        if (s) {
            socket_put(s);
            ret = -EADDORINUSE;
            break;
        }

        kp_udp("Adding socket, src_port: %d, src_addr: "PRin_addr", dest_addr: "PRin_addr"\n",
            ntohs(test_lookup.src_port), Pin_addr(test_lookup.src_addr), ntohs(test_lookup.dest_port),
            Pin_addr(test_lookup.dest_addr));
        __ipaf_add_socket(af, sock);
    }

    return ret;
}

void
udp_rx(struct Protocol *proto, struct Socket *sock, struct Packet *packet)
{
    struct UdpHeader *header = packet->head;
    struct SockAddrIn *in;

    in = (struct SockAddrIn *)&packet->src_addr;
    in->sin_port = header->source_port;

    kp_udp_trace(" %d -> %d, %d bytes\n", ntohs(header->source_port), ntohs(header->dest_port),
        ntohs(header->length));

    if (!sock) {
        kp_udp_trace("  Packet dropped: %p\n", packet);

        return;
    }

    // Manually set the length according to the UDP length field //
    packet->tail = packet->head + ntohs(header->length);
    packet->head += sizeof(*header);

    using_mutex(&sock->recv_lock) {
        list_add_tail(&sock->recv_queue, &packet->packet_entry);
        wait_queue_wake(&sock->recv_wait_queue);
    }
}

void
udp_tx(struct Packet *packet)
{
    const struct SockAddrin *in;
    size_t plen;
    struct UdpHeader *header;

    packet->head -= sizeof(*header);
    header = packet->head;
    plen = packet_len(packet);
    in = (struct SockAddrIn *)&packet->src_addr;

    header->source_port = in->sin_port;
    in = (struct SockAddrIn *)&packet->dest_addr;
    header->dest_port = in->sin_port;

    header->length = htons(plen);
    header->checksum = htons(0);

    packet->protocol_type IPPROTO_UDP;
    ip_tx(packet);
}

static int
udp_process_sockaddr(struct Socket *sock, struct Packet *packet, const struct SockAddr *addr,
    socklen_t len)
{
    if (addr) {
        const struct SockAddrIn *in;

        if (sizeof(*in) > len)
            return -EFAULT;

        if (addr->sa_family != AF_INET)
            return -EINVAL;

        in = (const struct SockAddrIn *)addr;
        sockaddr_in_assign_port(&packet->dest_addr, in->sin_port);
    } else if (socket_state_get(sock) == SOCKET_CONNECTED) {
        sockaddr_in_assign_port(&packet->dest_addr, sock->af_private.ipv4.dest_port);
    } else {
        return -EDESTADDRREQ;
    }

    return 0;
}

static int
__udp_autobind(struct Protocol *protocol, struct Socket *sock)
{
    int ret;
    struct UdpProtocol *udp = container_of(protocol, struct UdpProtocol, proto);

    sock->af_private.ipv4.src_addr = INADDR_ANY;
    sock->af_private.ipv4.src_port = udp_find_port(udp);
    ret = udp_register_sock(udp, sock);

    if (ret) {
        sock->af_private.ipv4.src_port = htons(0);

        return ret;
    }

    return 0;
}

static int
udp_autobind(struct Protocol *protocol, struct Socket *sock)
{
    using_socket_priv(sock)
        return __udp_autobind(protocol, sock);
}

static int
udp_sendto_packet(struct Protocol *protocol, struct Socket *sock, struct Packet *packet,
    const struct SockAddr *addr, socklen_t len)
{
    kp_udp_trace("Processing sockaddr: %p\n", addr);
    int ret = udp_process_sockaddr(sock, packet, addr, len);

    if (ret)
        return ret;

    if (n32_equal(sock->af_private.ipv4.src_port, htons(0))) {
        ret = __udp_autobind(protocol, sock);

        if (ret)
            return ret;
    }

    kp_udp_trace("Assigning packet src_port\n");
    ret = ip_packet_fill_route_addr(sock, packet, addr, len);

    if (ret)
        return ret;

    packet->sock = socket_dup(sock);
    kp_udp_trace("Packet Tx\n");
    udp_tx(packet);

    return 0;
}

static int
udp_sendto(struct Protocol *proto, struct Socket *sock, struct UserBuffer buf, size_t buf_len,
    const struct SockAddr *addr, socklen_t len)
{
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
            ret = udp_sendto_packet(proto, sock, packet, addr, len);

        if (ret) {
            packet_free(packet);

            return ret;
        }
    }

    return orig_buf_len;
}

static int
udp_bind(struct Protocol *protocol, struct Socket *sock, const struct SockAddr *addr, socklen_t len)
{
    struct UdpProtocol *udp = container_of(protocol, struct UdpProtocol, proto);
    const struct SockAddrIn *in = (const struct SockAddrIn *)addr;
    int ret;

    if (len < sizeof(*in))
        return -EFAULT;

    if (addr->sa_family != AF_INET)
        return -EINVAL;

    using_socket_priv(sock) {
        sock->af_private.ipv4.src_addr = in->sin_addr.s_addr;
        sock->af_private.ipv4.src_port = in->sin_port;
        ret = udp_register_sock(udp, sock);

        if (ret) {
            sock->af_private.ipv4.src_port = htons(0);

            return ret;
        }
    }

    return 0;
}

static int
udp_connect(struct Protocol *protocol, struct Socket *socket, const struct SockAddr *addr,
    socklen_t len)
{
    struct Ipv4SocketPrivate *ip_priv = &socket->af_private.ipv4;
    const struct SockAddrIn *in = (const struct SockAddrIn *)addr;

    if (len < sizeof(*in))
        return -EFAULT;

    if (addr->sa_family != AF_INET)
        return -EINVAL;

    using_socket_priv(socket) {
        socket->af_private.ipv4.dest_addr = in->sin_addr.s_addr;
        socket->af_private.ipv4.dest_port = in->sin_port;
        int ret = ip_route_get(in->sin_addr.s_addr, &ip_priv->route);

        if (ret)
            return ret;
    }

    socket_state_change(socket, SOCKET_CONNECTED);

    return 0;
}

static int
udp_create(struct Protocol *proto, struct Socket *sock)
{
    using_mutex(&proto->lock) {
        sock = socket_dup(sock);
        list_add_tail(&proto->socket_list, &sock->proto_entry);
    }

    return 0;
}

static int
udp_shutdown(struct Protocol *proto, struct Socket *sock, int how)
{
    return -ENOTCONN;
}

static void
udp_release(struct Protocol *proto, struct Socket *sock)
{
    struct AddrFamilyIp *af = container_of(sock->af, struct AddrFamilyIp, af);

    ip_release(sock->af, sock);

    using_socket_priv(sock) {
        if (n32_nonzero(sock->af_private.ipv4.src_port)) {
            using_mutex(&af->lock)
                __ipaf_remove_socket(af, sock);
        }
    }

    using_mutex(&proto->lock) {
        list_del(&sock->proto_entry);
        socket_put(sock);
    }

    socket_state_change(sock, SOCKET_UNCONNECTED);
}

static int
udp_getsockname(struct Protocol *protocol, struct Socket *sock, struct SockAddr *addr, socklen_t *len)
{
    struct SockAddrIn *in = (struct SockAddrIn *)addr;

    if (*len < sizeof(*in))
        return -EFAULT;

    in->sin_port = sock->af_private.ipv4.src_port;
    *len = sizeof(*in);

    return 0;
}

void
udp_lookup_fill(struct IpLookup *lookup, struct Packet *packet)
{
    struct UdpHeader *header = packet->head;

    lookup->src_port = header->dest_port;
    lookup->dest_port = header->source_port;
}

static struct ProtocolOps udp_protocol_ops = {
    .packet_rx = udp_rx,
    .sendto = udp_sendto,
    .connect = udp_connect,
    .bind = udp_bind,
    .autobind = udp_autobind,
    .getsockname = udp_getsockname,
    .shutdown = udp_shutdown,
    .create = udp_create,
    .release = udp_release,
};

struct Protocol *
udp_get_proto(void)
{
    return &udp_protocol.proto;
}

static int
udp_seq_start(struct SeqFile *seq)
{
    return proto_seq_start(seq, &udp_protocol.proto);
}

static int
udp_seq_render(struct SeqFile *seq)
{
    struct Socket *s = proto_seq_get_socket(seq);

    if (!s)
        return seq_printf(seq, "LocalAddr LocalPort RemoteAddr RemotePort\n");

    struct Ipv4SocketPrivate *private = &s->af_private.ipv4;

    using_socket_priv(s)
        return seq_printf(seq, PRin_addr" %d "PRin_addr" %d\n",
            Pin_addr(private->src_addr), private->src_port,
            Pin_addr(private->dest_addr), private->dest-port);
}

static const struct SeqFileOps udp_seq_file_ops = {
    .start = udp_seq_start,
    .render = udp_seq_render,
    .next = proto_seq_next,
    .end = proto_seq_end,
};

static int
udp_file_seq_open(struct Inode *ino, struct File *filp)
{
    return seq_open(filp, &udp_seq_file_ops);
}

struct FileOps udp_proc_file_ops = {
    .open = udp_file_seq_open,
    .lseek = seq_lseek,
    .read = seq_read,
    .release = seq_release,
};
