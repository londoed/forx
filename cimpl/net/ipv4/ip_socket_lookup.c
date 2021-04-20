/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { net/ipv4/ip_socket_lookup.c }.
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

void
__ipaf_add_socket(struct AddrFamilyIp *af, struct Socket *sock)
{
    socket_dup(sock);
    list_add_tail(&af->sockets, &sock->socket_entry);
}

void
__ipaf_remove_socket(struct AddrFamilyIp *af, struct Socket *sock)
{
    if (list_node_is_in_list(&sock->socket_entry)) {
        list_del(&sock->socket_entry);
        socket_put(sock);
    }
}

__must_check
struct Socket *
__ipaf_find_socket(struct AddrFamilyIp *af, struct IpLookup *addr, int total_max_score)
{
    struct Socket *sock;
    struct Socket *ret = NULL;
    int max_score = 0;

    /**
     * This looks complicated, but is actually pretty simple.
     *
     * When an IP packet comes in, we have to match it to a corresponding
     * socket, which is marked with a protocol, source/dest port, and
     * source/dest IP addr.
     *
     * In the case of a listening socket, those source/dest values may be 0,
     * representing a bind to _any_ value, so we skip checking those.
     * Otherwise, the values have to match exactly what we were passed.
     *
     * Beyond that, if we have, say, a socket listening for INADDR_ANY (zero)
     * on port X, and a socket with a direct connection to some specific IP on
     * port X, we want to send the packet to the direct connection and not to
     * the listening socket. To achieve that, we keep a "score" of how many
     * details of the connection matched, and then select the socket with the
     * highest score at the end (4 is highest score possible, so we return
     * right away if we hit that).
    **/
    list_foreach_entry(&af->sockets, sock, socket_entry) {
        /**
         * NOTE: We do not lock the sock private here. This is important to
         * avoid deadlocks, since this can be called with a socket already
         * locked.
         *
         * This is okay because all of this information should be read-only
         * after the socket is added to the IP lookup list.
        **/
        struct Ipv4SocketPrivate *sock_route = &sock->af_private.ipv4;
        int score = 0;

        if (sock_route->proto != addr->proto)
            continue;

        if (n16_nonzero(sock_route->src_port)) {
            if (!n16_equal(sock_route->src_port, addr->src_port))
                continue;

            score++;
        }

        if (n32_nonzero(sock_route->src_addr)) {
            if (!n32_equal(sock_route->src_addr, addr->src_addr))
                continue;

            score++;
        }

        if (n16_nonzero(sock_route->dest_port)) {
            if (!n16_equal(sock_route->dest_port, addr->dest_port))
                continue;

            score++;
        }

        if (n32_nonzero(sock_route->dest_addr)) {
            if (!n32_equal(sock_route->dest_addr, addr->dest_addr))
                continue;

            score++;
        }

        if (score == total_max_score)
            return socket_dup(sock);

        if (max_score >= score)
            continue;

        max_score = score;
        ret = sock;
    }

    if (ret)
        ret = socket_dup(ret);

    return ret;
}
