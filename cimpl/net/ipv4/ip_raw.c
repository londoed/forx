/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { net/ipv4/ip_raw.c }.
 * Copyright (C) 2019, Matt Kilgore.
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

#include <forx/net/socket.h>
#include <forx/net/proto.h>
#include <forx/net/netdev.h>
#include <forx/net/arphrd.h>
#include <forx/net/ipv4/ipv4.h>
#include <forx/net/ipv4/ip_route.h>
#include <forx/net/linklayer.h>
#include <forx/net.h>

#include "ipv4.h"

static struct ProtocolOps ip_raw_protocol_ops;
static struct Protocol ip_raw_proto = PROTOCOL_INIT("ip-raw", ip_raw_proto, &ip_raw_protocol_ops);

static void
ip_raw_rx(struct Protocol *proto, struct Socket *sock, struct Packet *packet)
{
    using_mutex(&sock->recv_lock) {
        list_add_tail(&sock->recv_queue, &packet->packet_entry);
        wait_queue_wake(&sock->recv_wait_queue);
    }
}

static int
ip_raw_sendto(struct Protocol *proto, struct Socket *sock, struct UserBuffer buf,
    size_t buf_len, const struct SockAddr *addr, socklen_t len)
{
    int err = socket_last_error(sock);

    if (err)
        return err;

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
        packet->sock = socket_dup(sock);
        int ret = ip_packet_fill_route_addr(sock, packet, addr, len);

        if (ret) {
            packet_free(packet);

            return ret;
        }

        packet->protocol_type = sock->protocol;

        using_socket_priv(sock)
            ip_tx(packet);
    }

    return 0;
}

static int
ip_raw_bind(struct Protocol *proto, struct Socket *sock, const struct SockAddr *addr,
    socklen_t len)
{
    const struct SockAddrIn *in = (const struct SockAddrIn *)addr;

    if (sizeof(*in) > len)
        return -EFAULT;

    using_socket_priv(sock)
        sock->af_private.ipv4.src_addr = in->sin_addr.s_addr;

    return 0;
}

static int
ip_raw_autobind(struct Protocol *proto, struct Socket *sock)
{
    using_socket_priv(sock)
        sock->af_private.ipv4.src_addr = htoni(0);

    return 0;
}

static int
ip_raw_getsockname(struct Protocol *proto, struct Socket *sock, struct SockAddr *addr, socklen_t *len)
{
    struct SockAddrIn *in = (struct SockAddrIn *)addr;

    if (*len < sizeof(*in))
        return -EFAULT;

    using_socket_priv(sock)
        in->sin_addr.s_addr = sock->af_private.ipv4.src_addr;

    *len = sizeof(*in);

    return 0;
}

static int
ip_raw_create(struct Protocol *proto, struct Socket *sock)
{
    struct AddrFamilyIp *af = container_of(sock->af, struct AddrFamilyIp, af);

    using_mutex(&proto->lock) {
        sock = socket_dup(sock);
        list_add_tail(&proto->socket_list, &sock->proto_entry);
    }

    using_mutex(&af->lock) {
        sock = socket_dup(sock);
        list_add_tail(&af->raw_sockets, &sock->socket_entry);
    }

    return 0;
}

static int
ip_raw_shutdown(struct Protocol *proto, struct Socket *sock, int how)
{
    return -ENOTCONN;
}

static void
ip_raw_release(struct Protocol *proto, struct Socket *sock)
{
    struct AddrFamilyIp *af = container_of(sock->af, struct AddrFamilyIp, af);

    ip_release(sock->af, sock);

    using_mutex(&proto->lock) {
        list_del(&sock->proto_entry);
        socket_put(sock);
    }

    using_mutex(&af->lock) {
        list_del(&sock->socket_entry);
        socket_put(sock);
    }

    socket_state_change(sock, SOCKET_UNCONNECTED);
}

static struct ProtocolOps ip_raw_protocol_ops = {
    .packet_rx = ip_raw_rx,
    .sendto = ip_raw_sendto,
    .create = ip_raw_create,
    .release = ip_raw_release,
    .bind = ip_raw_bind,
    .autobind = ip_raw_autobind,
    .getsockname = ip_raw_getsockname,
    .shutdown = ip_raw_shutdown,
};

struct Protocol *
ip_raw_get_proto(void)
{
    return &ip_raw_proto;
}

static int
ip_raw_seq_start(struct SeqFile *seq)
{
    return proto_seq_start(seq, &ip_raw_proto);
}

static int
ip_raw_seq_render(struct SeqFile *seq)
{
    struct Socket *s = proto_seq_get_socket(seq);

    if (!s)
        return seq_printf(seq, "LocalAddr RemoteAddr\n");

    struct Ipv4SocketPrivate *private = &s->af_private.ipv4;

    return seq_printf(seq, PRin_addr" "PRin_addr"\n",
        Pin_addr(private->src_addr), Pin_addr(private->dest_addr));
}

static const struct SeqFileOps ip_raw_seq_file_ops = {
    .start = ip_raw_seq_start,
    .render = ip_raw_seq_render,
    .next = proto_seq_next,
    .end = proto_seq_end,
};

static int
ip_raw_file_seq_open(struct Inode *ino, struct File *filp)
{
    return seq_open(filp, &ip_raw_seq_file_ops);
}

struct FileOps ip_raw_proc_file_ops = {
    .open = ip_raw_file_seq_open,
    .lseek = seq_lseek,
    .read = seq_read,
    .release = seq_release,
};
