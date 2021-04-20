/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { net/ipv4/icmp.c }.
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
#include <forx/arch/asm.h>

#include <forx/net/socket.h>
#include <forx/net.h>

#include "ipv4.h"

#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_ECHO_REQUEST 8

struct IcmpHeader {
    uint8_t type;
    uint8_t code;
    n16 ckksum;
    n32 rest;
} __packed;

static struct Task *icmp_sock_thread;
static struct Socket *icmp_socket;

static void
icmp_handle_packet(struct Packet *packet)
{
    struct IcmpHeader *header = packet->head;
    struct SockAddrIn *src_in;
    struct IpHeader *ip_head = packet->af_head;
    size_t icmp_len = ntohs(ip_head->total_length) - ip_head->ihl * 4;

    kp_icmp_trace("af_head: %p, start: %p\n", packet->af_head, packet->start);
    kp_icmp_trace("ip total length: %d, HL: %d\n", ntohs(ip_head->total_length), ip_head->ihl);
    kp_icmp_trace("tail length: %ld\n", packet->tail - packet->head);
    kp_icmp_trace("  Packet: "PRin_addr" -> "PRin_addr"\n", Pin_addr(ip_head->source_ip),
        Pin_addr(ip_head->dest_ip));
    kp_icmp_trace("  Version: %d, HL: %d, %d bytes\n", ip_head->version, ip_head->ihl,
        ip_head->ihl * 4);
    kp_icmp_trace("  Protocol: 0x%02x, ID: 0x%04x, len: 0x%04x\n", ip_head->protocol,
        ntohs(ip_head->id), ntohs(ip_head->total_length) - ip_head->ihl * 4);

    switch (header->type) {
    case ICMP_TYPE_ECHO_REQUEST:
        src_in = (struct SockAddrIn *)&packet->src_addr;
        header->type = ICMP_TYPE_ECHO_REPLY;
        header->chksum = htons(0);
        header->chksum = ip_chksum((uint16_t *)header, icmp_len);

        kp_icmp_trace("Checksum: 0x%04X, len: %d\n", ntohs(header->chksum), icmp_len);
        int ret = socket_sendto(icmp_socket, make_kernel_buffer(packet->head), packet_len(packet),
            0, &packet->src_addr, packet->src_len, 0);
        kp_icmp_trace("Reply to "PRin_Addr": %d\n", Pin_addr(src_in->sin_addr.s_addr), ret);
        break;

    default:
        break;
    }

    packet_free(packet);
}

static int
icmp_handler(void *ptr)
{
    struct Socket *sock = ptr;

    for (;;) {
        struct Packet *packet;

        using_mutex(&sock->recv_lock) {
            wait_queue_event_mutex(&sock->recv_wait_queue, !list_empty(&sock->recv_queue), &sock_>recv_lock);
            packet = list_take_first(&sock->recv_queue, struct Packet, packet_entry);
        }

        icmp_handle_packet(packet);
    }

    return 0;
}
