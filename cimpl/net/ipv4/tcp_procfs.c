/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { net/ipv4/tcp_procfs.c }.
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

void
tcp_procfs_register(struct Protocol *proto, struct Socket *sock)
{
    using_mutex(&proto->lock) {
        sock = socket_dup(sock);
        list_add_tail(&proto->socket_list, &sock->proto_entry);
    }
}

void
tcp_procfs_unregister(struct Protocol *proto, struct Socket *sock)
{
    using_mutex(&proto->lock) {
        list_del(&sock->proto_entry);
        socket_put(sock);
    }
}

static int
tcp_seq_start(struct SeqFile *seq)
{
    return proto_seq_start(seq, &tcp_protocol.proto);
}

static const char *tcp_state_str[] = {
    [0]                    = "NONE",
    [TCP_ESTABLISHED]      = "ESTABLISHED",
    [TCP_SYN_SENT]         = "SYN-SENT",
    [TCP_SYN_RECV]         = "SYN-RECV",
    [TCP_FIN_WAIT1]        = "FIN-WAIT1",
    [TCP_FIN_WAIT2]        = "FIN-WAIT2",
    [TCP_TIME_WAIT]        = "TIME-WAIT",
    [TCP_CLOSE]            = "CLOSE",
    [TCP_CLOSE_WAIT]       = "CLOSE-WAIT",
    [TCP_LAST_ACK]         = "LAST-ACK",
    [TCP_LISTEN]           = "LISTEN",
    [TCP_CLOSING]          = "CLOSING",
};

static int
tcp_seq_render(struct SeqFile *seq)
{
    struct Socket *s = proto_seq_get_socket(seq);

    if (!s)
        return seq_printf(seq, "LocalAddr\t"
            "LocalPort\t"
            "RemodeAddr\t"
            "RemotePort\t"
            "STATE\t"
            "ISS\t"
            "IRS\t"
            "RCV.NXT\t"
            "RCV.UP\t"
            "RVC.WND\t"
            "SND.NXT\t"
            "SND.UNA\t"
            "SND.UP\t"
            "SND.WND\t"
            "SND.WL1\n"
            "SND.WL2\n");

    struct Ipv4SocketPrivate *ip_priv = &s->af_private.ipv4;
    struct TcpSocketPrivate *tcp_priv = &s->proto_private.tcp;

    using_socket_priv(s)
        return seq_printf(seq, PRin_addr"\t"
            "%d\t"
            PRin_addr"\t"
            "%d\t"
            "%s\t"
            "%u\t"
            "%u\t"
            "%u\t"
            "%u\t"
            "%u\t"
            "%u\t"
            "%u\t"
            "%u\t"
            "%u\t"
            "%u\n",
            Pin_addr(ip_priv->src_addr),
            ntohs(ip_priv->src_port),
            Pin_addr(ip_priv->dest_addr),
            ntohs(ip_priv->dest_port),
            tcp_state_str[tcp_priv->tcp_state],
            tcp_priv->iss,
            tcp_priv->irs,
            tcp_priv->rcv_nxt,
            tcp_priv->rcv_up,
            tcp_priv->snd_nxt,
            tcp_priv->snd_una,
            tcp_priv->snd_up,
            tcp_priv->snd_wnd,
            tcp_priv->snd_wl1,
            tcp_priv->snd_wl2);
}

static const struct SeqFileOps tcp_seq_file_ops = {
    .start = tcp_seq_start,
    .render = tcp_seq_render,
    .next = proto_seq_next,
    .end = proto_seq_end,
};

static int
tcp_file_seq_open(struct Inode *ino, struct File *filp)
{
    return seq_open(filp, &tcp_seq_file_ops);
}

struct FileOps tcp_proc_file_ops = {
    .open = tcp_file_seq_open,
    .lseek = seq_lseek,
    .read = seq_read,
    .release = seq_release,
};
