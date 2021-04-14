/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { net/ipv4/tcp_output.c }.
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
#include <forx/net/ipv4/icp.h>
#include <forx/net/ipv4/ipv4.h>
#include <forx/net.h>

#include "ipv4.h"
#include "tcp.h"

static void
tcp_send_inner(struct Protocol *proto, struct Packet *packet)
{
    struct TcpPacketCb *cb = &packet->cb.tcp;
    struct TcpHeader *head;

    packet->head -= sizeof(*head);
    head = packet->head;
    packet->proto_head = head;

    memset(head, 0, sizeof(*head));

    head->hl = sizeof(*head) / 4;
    head->source = sockaddr_in_get_port(&packet->src_addr);
    head->dest = sockaddr_in_get_port(&packet->dest_addr);
    head->flags = cb->flags;
    head->seq = htonl(cb->seq);

    head->ack_seq = htonl(cb->ack_seq);
    head->window = htons(cb->window);
    head->urg_ptr = htons(0);

    kp_tcp_trace("TCP send packet, flags: 0x%02x, seq: %u, ack_seq: %u, len: %d\n",
        cb->flags.flags, cb->seq, cb->ack_seq, packet_len(packet));

    packet->protocol_type = IPPROTO_TCP;
    head->check = htons(0);
    head->check = tcp_checksum_packet(packet);
    ip_tx(packet);
}

void
tcp_send_raw(struct Protocol *proto, struct Packet *packet, n16 src_port, n32 dest_addr,
    n16 dest_port)
{
    int ret = ip_packet_fill_raw(packet, dest_addr);

    kp_tcp_trace("TCP send packet, ip route ret: %d\n");

    if (ret) {
        packet_free(packet);

        return;
    }

    sockaddr_in_assign_port(&packet->src_addr, src_port);
    sockaddr_in_assign_port(&packet->dest_addr, dest_port);
    tcp_send_inner(proto, packet);
}

void
tcp_send(struct Protocol *proto, struct Socket *sock, struct Packet *packet)
{
    struct Ipv4SocketPrivate *ip_priv = &sock->af_private.ipv4;
    int ret = ip_packet_fill_route(sock, packet);

    kp_tcp_trace("TCP send packet, ip route ret: %d\n", ret);

    if (ret) {
        packet_free(packet);

        return;
    }

    sockaddr_in_assign_port(&packet->src_addr, ip_priv->src_port);
    sockaddr_in_assign_port(&packet->dest_addr, ip_priv->dest_port);
    packet->sock = socket_dup(sock);
    tcp_send_inner(proto, packet);
}

void
tcp_send_syn(struct Protocol *proto, struct Socket *sock)
{
    struct TcpSocketPrivate *priv = &sock->proto_private.tcp;
    struct Packet *packet = packet_new(PAL_KERNEL);
    struct TcpPacketCb *cb = &packet->cb.tcp;

    cb->seq = priv->snd_nxt;
    cb->ack_seq = priv->rcv_nxt;
    cb->window = priv->rcv_wnd;
    cb->flags.syn = 1;

    tcb_send(proto, sock, packet);
    sock->proto_private.tcp.tcp_state = TCP_SYN_SENT;
}

void
tcp_send_ack(struct Protocol *proto, struct Socket *sock)
{
    struct TcpSocketPrivate *priv = &sock->proto_private.tcp;
    struct Packet *packet = packet_new(PAL_KERNEL);
    struct TcpPacketCb *cb = &packet->cb.tcp;

    cb->seq = priv->snd_nxt;
    cb->ack_seq = priv->rcv_nxt;
    cb->window = priv->rcv_wnd;
    cb->flags.ack = 1;

    tcp_delack_timer_stop(sock);
    tcp_send(proto, sock, packet);
}

void
tcp_send_reset(struct Protocol *proto, struct Packet *old_packet)
{
    struct TcpPacketCb *old_cb = &old_packet->cb.tcp;
    struct TcpHeader *tcp_head = old_packet->proto_head;
    struct IpHeader *ip_head = old_packet->af_head;
    struct Packet *packet = packet_new(PAL_KERNEL);
    struct TcpPacketCb *cb = &packet->cb.tcp;

    // If the received packet is an RST, don't send one in response //
    if (old_cb->flags.rst)
        goto release_old_packet;

    /**
     * If we're responding to an ACK, we make it look like an acceptible
     * ACK. If not, we just use sequence number 0.
    **/
    if (!old_cb->flags.ack) {
        cb->seq = 0;
        cb->ack_seq = old_cb->seq + packet_len(old_packet);
        cb->flags.rst = 1;
        cb->flags.ack = 1;

        if (old_cb->flags.syn)
            cb->ack_seq++;
    } else {
        cb->seq = old_cb->ack_seq;
        cb->flags.rst = 1;
    }

    kp_tcp_trace("RESET SrcIP: "PRin_addr", DestIP: "PRin_addr"\n", Pin_addr(ip_head->source_ip),
        Pin_addr(ip_head->dest_ip));
    tcp_send_raw(proto, packet, tcp_head->dest, ip_head->source_ip, tcp_head->source);

release_old_packet:
    // Consume the old packet //
    packet_free(old_packet);
}
