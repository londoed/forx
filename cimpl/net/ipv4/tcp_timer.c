/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { net/ipv4/tcp_timer.c }.
 * Copyright (C) 2019, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <libctl/snprintf.h>
#include <forx/list.h>
#include <forx/ktimer.h>

#include <forx/net/socket.h>
#include <forx/net/ipv4/tcp.h>
#include <forx/net/ipv4/ipv4.h>
#include <forx/net.h>

#include "ipv4.h"
#include "tcp.h"

static void
delack_callback(struct Work *work)
{
    struct Socket *sock = container_of(work, struct Socket, proto_private.tcp.delack.work);

    using_socket_priv(sock)
        tcp_send_ack(sock->proto, sock);

    socket_put(sock);
}

void
tcp_timers_init(struct Socket *sock)
{
    struct Work *delack_work = &sock->proto_private.tcp.delack.work;

    work_init_kwork(delack_work, delack_callback);
    flag_set(&delack_work->flags, WORK_ONESHOT);
}

void
tcp_delack_timer_stop(struct Socket *sock)
{
    struct DelayWork *dwork = &sock->proto_private.tcp.delack;

    if (kwork_delay_unschedule(dwork) == 0)
        socket_put(sock);
}

void
tcp_delack_timer_start(struct Socket *sock, uint32_t ms)
{
    if (kwork_delay_schedule(&sock->proto_private.tcp.delack, ms) == 0)
        socket_dup(sock);
}

void
tcp_timers_reset(struct Socket *sock)
{
    using_socket_priv(sock)
        tcp_delack_timer_stop(sock);
}
