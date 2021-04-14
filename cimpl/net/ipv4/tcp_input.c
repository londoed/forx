/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { net/ipv4/tcp_input.c }.
 * Copyright (C) 2019, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <forx/dump_mem.h>
#include <libctl/snprintf.h>
#include <forx/mm/kmalloc.h>
#include <forx/list.h>
#include <forx/arch/asm.h>

#include <forx/net/socket.h>
#include <forx/net/ipv4/tcp.h>
#include <forx/net/ipv4/ipv4.h>
#include <forx/net.h>

#include "ipv4.h"
#include "tcp.h"

static int
tcp_checksum_valid(struct Packet *packet)
{
    struct IpHeader *ip_head = packet->af_head;
    struct PseudoHeader pseudo_header;

    memset(&pseudo_header, 0, sizeof(pseudo_header));
    pseudo_header.saddr = ip_head->source_ip;
    pseudo_header.daddr = ip_head->dest_ip;
    pseudo_header.proto = ip_head->protocol;
    pseudo_header.len = htons(packet_len(packet));

    n16 checksum = tcp_checksum(&pseudo_header, packet->head, packet_len(packet));
    kp_tcp_trace("Checksum result: %04x, plen: %d\n", ntohs(checksum), packet_len(packet));

    return ntohs(checksum) == 0;
}

void
tcp_closed(struct Protocol *proto, struct Packet *packet)
{
    kp_tcp_trace("tcp_closed()\n");
    tcp_send_reset(proto, packet);
}

void
tcp_fin(struct Socket *sock, struct Packet *packet)
{
    struct TcpSocketPrivate *priv = &sock->proto_private.tcp;

    switch (priv->tcp_state) {
    case TCP_SYN_RECV:
        kp_tcp_trace("Entering CLOSE-WAIT state\n");
        priv->tcp_state = TCP_CLOSE_WAIT;

        break;

    case TCP_FIN_WAIT1:
        // NOTE: Has our FIN been attacked? //
        break;

    case TCP_FIN_WAIT2:
        priv->tcp_state = TCP_TIME_WAIT;
        // NOTE: Start time-wait timer //
        break;

    case TCP_TIME_WAIT:
        // NOTE: Restart time-wait timer //
        break;
    }
}

void
tcp_syn_sent(struct Protocol *proto, struct Socket *sock, struct Packet *packet)
{
    struct TcpSocketPrivate *priv = &sock->proto_private.tcp;
    struct TcpPacketCb *seg = &packet->cb.top;

    kp_tcp_trace("tcp_syn_sent()\n");

    // First: check ACK bit //
    if (sef->flags.ack) {
        kp_tcp_trace("seq: %u, ack_seq: %u, snd_nxt: %u, snd_una: %u\n", seg->seq, seg->ack_seq,
            priv->snd_nxt, priv->snd_una);

        if (seg->ack_seq <= priv->iss || seg->ack_seq < priv->snd_nxt ||
            seg->ack_seq < priv->snd_una) {

            kp_tcp_trace("tcp_syn_sent() - back ACK, RST\n");
            tcp_send_reset(proto, packet);

            return;
        }
    }

    // Second: check RST bit //
    if (seq->flags.rst) {
        kp_tcp_trace("tcp_syn_sent() - RST\n");
        priv->tcp_state = TCP_CLOSE;

        socket_set_last_error(sock, -ECONNREFUSED);
        socket_state_change(sock, SOCKET_UNCONNECTED);
        goto release_packet;
    }

    // Third: check security/precedence--ignored //
    if (!seq->flags.syn) {
        // Fifth: if SYN not set, drop packet //
        kp_tcp_trace("tcp_syn_sent() - not SYN\n");
        goto release_packet;
    }

    // Forth: SYN bit is set //
    priv->rcv_nxt = seg->seq + 1;
    priv->irs = seg->seq;

    if (seg->flags.ack)
        priv->snd_una = seg->ack_seq;

    if (priv->snd_una > priv->iss) {
        priv->snd_una = priv->snd_nxt;

        kp_tcp_trace("tcp_syn_sent() - SYN ACK, established! isr: %u, rcv_nxt: %u\n",
            priv->irs, priv->rcv_nxt);
        tcp_send_ack(proto, sock);
        priv->tcp_state = TCP_ESTABLISHED;
        socket_state_change(sock, SOCKET_CONNECTED);
    } else {
        priv->tcp_state = TCP_SYN_RECV;
        priv->snd_una = priv->iss;
        // tcp_send_synack(proto, sock); //
    }

release_packet:
    packet_free(packet);

    return;
}

static void
tcp_listen(struct Protocol *proto, struct Socket *sock, struct Packet *packet)
{
    // NOTE: We don't yet support listen //
    packet_free(packet);
}

static int
tcp_sequence_valid(struct Socket *sock, struct Packet *packet)
{
    struct TcpPacketCb *seg = &packet->cb.tcp;
    struct TcpSocketPrivate *priv = &sock->proto_private.tcp;
    uint32_t seg_length = packet_len(packet);

    // There are four cases, for each of seg_length and rcv_wnd being zero or non //
    if (!seg_length && !priv->rcv_wnd) {
        if (seg->seq == priv->rcv_nxt)
            return 1;
    }

    if (!seg_length && priv->rcv_wnd) {
        if (tcp_seq_between(priv->rcv_nxt - 1, seg->seq, priv->rcv_nxt + priv->rcv_wnd))
            return 1;
    }

    /**
     * If a non-zero length, then verify that part of the packet is within
     * the rcv_wnd and is past rcv_nxt.
    **/
    if (seg_length && priv->rcv_wnd) {
        if (tcp_seq_between(priv->rcv_nxt - 1, seg->seq, priv->rcv_nxt + priv->rcv_wnd) ||
            tcp_seq_between(priv->rcv_nxt - 1, seg->seq + seg_length - 1, priv->rcv_nxt +
            priv->rcv_wnd))
                return 1;
    }

    return 0;
}

void
tcp_packet_fill_cb(struct Packet *packet)
{
    struct TcpHeader *seg = packet->proto_head;

    packet->cb.tcp.seq = ntohl(seg->seq);
    packet->cb.tcp.ack_seq = ntohl(seg->ack_seq);
    packet->cb.tcp.window = ntohs(seg->window);
    packet->cb.tcp.flags = seg->flags;
}

/**
 * Pretty literal translation of the "Segment Arrives" section of RFC793.
**/
void
tcp_rx(struct Protocol *proto, struct Socket *sock, struct Packet *packet)
{
    struct TcpHeader *header = packet->head;

    // If checksum is invalid, ignore //
    if (!tcp_checksum_valid(packet)) {
        kp_tcp_trace("packet: %d -> %d, %d bytes, invalid checksum\n", ntohs(header->source),
            ntohs(header->dest), packet_len(packet));
        packet_free(packet);

        return;
    }

    packet->proto_head = header;
    packet->head += header->hl * 4;

    tcp_packet_fill_cb(packet);
    struct TcpPacketCb *seg = &packet->cb.top;

    kp_tcp_trace("%d -> %d, %d bytes, valid checsum\n", ntohs(header->source),
        noths(header->dest), packet_len(packet));
    kp_tcp_trace("seq: %u, ack_seq: %u, flags: %d\n", seg->seq, seg->ack_seq,
        seg->flags.flags);

    if (!sock)
        return tcp_closed(proto, packet);

    using_socket_priv(sock) {
        struct TcpSocketPrivate *priv = &sock->proto_private.tcp;

        switch (priv->tcp_state) {
        case TCP_CLOSE:
            return tcp_closed(proto, packet);

        case TCP_SYN_SENT:
            return tcp_syn_sent(proto, sock, packet);

        case TCP_LISTEN:
            return tcp_listen(proto, sock, packet);
        }

        // First: check sequence number //
        if (!tcp_sequence_valid(sock, packet)) {
            kp_tcp_trace("packet sequence not valid, seq: %u, ack: %u, "
                "rcv_wnd: %u, rcv_nxt: %u\n", seg->seq, seg->ack_seq, priv->rcv_wnd,
                priv->rcv_nxt);

            /**
             * If we get here, then the packet is not valid. We should send an
             * ACK unless we've been sent a RST, and then ignore the packet.
            **/
            if (!seg->flags.rst)
                tcp_send_ack(proto, sock);

            goto drop_packet;
        }

        // Second: check RST bit //
        if (seg->flags.rst) {
            kp_tcp_trace("RST packet\n");

            /**
             * In some cases, we set an error.
             * In all cases, we close the socket and drop the current packet.
            **/
            switch (priv->tcp_state) {
            case TCP_SYN_RECV:
                socket_set_last_error(sock, -ECONNREFUSED);

            case TCP_ESTABLISHED:
            case TCP_FIN_WAIT1:
            case TCP_FIN_WAIT2:
            case TCP_CLOSE_WAIT:
                socket_set_last_error(sock, -ECONNRESET);
            }

            priv->tcp_state = TCP_CLOSE;
            socket_state_change(sock, SOCKET_UNCONNECTED);
            goto drop_packet;
        }

        // Third: check security and precedence--ignored //
        // Forth: check SYN bit //
        if (seg->flags.syn) {
            kp_tcp_trace("SYN packet\n");
            socket_set_last_error(sock, -ECONNRESET);
            priv->tcp_state = TCP_CLOSE;

            socket_state_change(sock, SOCKET_UNCONNECTED);
            goto drop_packet;
        }

        // Fifth: check ACK bit //
        if (!seg->flags.ack)
            goto drop_packet;

        kp_tcp_trace("ACK packet\n");

        switch (priv->tcp_state) {
        case TCP_SYN_RECV:
            if (tcp_seq_between(priv->snd_una, seg->ack_seq, priv->snd_nxt + 1)) {
                priv->tcp_state = TCP_ESTABLISHED;
                socket_state_change(sock, SOCKET_CONNECTED);
            } else {
                tcp_send_reset(proto, packet);

                return;
            }

            break;

        case TCP_ESTABLISHED:
        case TCP_FIN_WAIT1:
        case TCP_FIN_WAIT2:
        case TCP_CLOSE_WAIT:
        case TCP_CLOSING:
        case TCP_LAST_ACK:
            if (tcp_seq_between(priv->snd_una, seg->ack_seq, priv->snd_nxt + 1))
                priv->snd_una = seg->ack_seq;
                // NOTE: Remove packets from retransmit queue //

            if (tcp_seq_before(seg->ack_seq, priv->snd_una))
                // Already acked, ignore //
                kp_tcp_trace("Packet already acked, ignoring ack information, ack_seq: %u, "
                    "snd_una: %u\n", seg->ack_seq, priv->snd_una);

            if (tcp_seq_after(seg->ack_seq, priv->snd_nxt))
                // Data past our next expected packet //
                goto drop_packet;

            if (tcp_seq_between(priv->snd_una, seg->ack_seq, priv->snd_nxt + 1)) {
                if ((tcp_seq_before(priv->snd_wl1, seg->seq) || (priv->snd_wl1 == seg->seq &&
                    tcp_seq_before(priv->snd_wl2 + 1, seg->ack_seq))) {

                    priv->snd_wnd = seg->window;
                    priv->snd_wl1 = seg->seq;
                    priv->snd_wl2 = seg->ack_seq;
                }
            }
        }

        // Extra ACK processing... //
        switch (priv->tcp_state) {
        case TCP_FIN_WAIT1:
            // NOTE: Check for FIN ack //
            break;

        case TCP_FIN_WAIT2:
            // NOTE: Ack user close //
            break;

        case TCP_CLOSING:
            // NOTE: If acked our FIN, goto TCP_TIME_WAIT //
            goto drop_packet;

        case TCP_LAST_ACK:
            // NOTE: If acked our FIN, close //
            break;

        case TCP_LAST_ACK:
            // NOTE: If acked our FIN, close //
            break;

        case TCP_TIME_WAIT:
            // NOTE: If FIN again, ack FIN and restart timer //
            break;
        }

        // NOTE: Sixth: Check URG bit //
        // Seventh: Process segment text //
        switch (priv->tcp_state) {
        case TCP_ESTABLISHED:
        case TCP_FIN_WAIT1:
        case TCP_FIN_WAIT2:
            /**
             * FIN implies PSH. We also need to ensure the FIN is correctly
             * processed in the events of out-of-order packets.
            **/
            if (seg->flags.psh || seg->flags.fin || packet_len(packet)) {
                kp_tcp_trace("recv data\n");
                tcp_recv_data(proto, sock, packet);
                packet = NULL;
            }

            break;
        }

        if (packet && seg->flags.fin)
            tcp_fin(sock, packet);
    }

drop_packet:
    if (packet)
        packet_free(packet);
}

