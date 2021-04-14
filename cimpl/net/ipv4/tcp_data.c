/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { net/ipv4/tcp_data.c }.
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
#include <forx/net/ipv4/tcp.h>
#include <forx/net/ipv4/ipv4.h>
#include <forx/net.h>

#include "ipv4.h"
#include "tcp.h"

#define TCP_DELACK_TIMER_MS 100

/**
 * Out-of-order packets should be added to the queue in order of their segment.
**/
static void
add_to_ooo_queue(struct Socket *sock, struct Packet *packet)
{
    struct TcpPacketCb *seg = &packet->cb.tcp;
    struct Packet *cur, *tmp;

    kp_tcp_trace("Adding packet to OOO queue...\n");

    /**
     * NOTE: It may be unlikely, but segments could contain overlapping
     * data, and we should make sure we don't duplicate that data back
     * back to caller.
    **/
    list_foreach_entry_safe(&sock->out_of_order_queue, cur, tmp, packet_entry) {
        struct TcpPacketCb *cur_seg = &cur->cb.tcp;

        if (tcp_seq_before(seg->seq, cur_seg->seq)) {
            kp_tcp_trace("Adding packet %u before packet %u\n", seg->seq, cur_seg->seq);

            // list_add_tail places it before the current segment //
            list_add_tail(&cur->packet_entry, &packet->packet_entry);

            return;
        }
    }

    kp_tcp_trace("Adding packet %u at the end\n", seg->seq);

    // The packet is past every entry in the queue //
    list_add_tail(&sock->out_of_order_queue, &packet->packet_entry);
}

static void
socket_recv_packet(struct Socket *sock, struct Packet *packet)
{
    struct TcpSocketPrivate *priv = &sock->proto_private.tcp;
    struct TopPacketCb *cur_seg = &packet->cb.top;

    priv->rcv_nxt += packet_len(packet);

    if (cur_seg->flags.fin) {
        priv->rcv_nxt++;
        tcp_fin(sock, packet);
    }

    kp_tcp_trace("Recv packet seq: %u, len: %d, new rcv_nxt: %u\n", cur_seg->seq,
        packet_len(packet), priv->rcv_nxt);
    list_add_tail(&sock->recv_queue, &packet->packet_entry);
}

/**
 * Checks the out-of-order queue and adds any pending packets to the
 * recv queue if they come next.
**/
static void
consolidate_ooo_queue(struct Socket *sock)
{
    struct TcpSocketPrivate *priv = &sock->proto_private.tcp;
    struct Packet *cur, *tmp;

    kp_tcp_trace("OOO consolidation...\n");

    list_foreach_entry_safe(&sock->out_of_order_queue, cur, tmp, packet_entry) {
        struct TcpPacketCb *cur_seg = &cur->cb.top;

        kp_tcp_trace("OOO packet seq: %u, rcv_nxt: %u...\n", cur_seg->seq, priv->rcv_nxt);

        if (cur_seg->seq == priv->rcv_nxt) {
            list_del(&cur->packet_entry);
            socket_recv_packet(sock, cur);
        }
    }
}

void
tcp_recv_data(struct Protocol *proto, struct Socket *sock, struct Packet *packet)
{
    struct TcpSocketPrivate *priv = &sock->proto_private.tcp;
    struct TcpPacketCb *seg = &packet->cb.top;

    if (!priv->rcv_wnd) {
        packet_free(packet);

        return;
    }

    kp_tcp_trace("seq: %u, rcv_nxt: %u\n", seg->seq, priv->rcv_nxt);

    if (seg->seq == priv->rcv_nxt) {
        using_mutex(&sock->recv_lock) {
            socket_recv_packet(sock, packet);
            consolidate_ooo_queue(sock);
            wait_queue_wake(&sock->recv_wait_queue);
        }

        tcp_delack_timer_start(sock, TCP_DELACK_TIMER_MS);
    } else {
        /**
         * Packet is in window, but not the next one in line.
         * Add it to the out-of-order queue.
        **/
        using_mutex(&sock->recv_lock)
            add_to_ooo_queue(sock, packet);

        // Send a dup ack when we get an OOO packet //
        tcp_send_ack(proto, sock);
    }
}
