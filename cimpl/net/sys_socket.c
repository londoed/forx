/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { net/sys_socket.c }.
 * Copyright (C) 2017, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <forx/mm/kmalloc.h>
#include <libctl/snprintf.h>
#include <forx/list.h>

#include <forx/fs/file.h>
#include <forx/fs/stat.h>
#include <forx/fs/inode.h>
#include <forx/fs/vfs.h>
#include <forx/net/ipv4/ip_route.h>
#include <forx/net/ipv4/ipv4.h>
#include <forx/net/linklayer.h>
#include <forx/net/socket.h>
#include <forx/sys.h>
#include <forx/net.h>

int
socket_open(int domain, int type, int protocol, struct Socket **sock_ret)
{
    struct Socket *socket;
    int ret;

    socket = socket_alloc();
    kprintf(KERN_NORM, "Socket alloc: %p, domain: %d, type: %d, proto: %d\n", socket, domain, type,
        protocol);

    socket->address_family = domain;
    socket->sock_type = type;
    socket->protocol = protocol;
    socket->af = address_family_lookup(domain);
    kprintf(KERN_NORM, "Socket AF: %p\n", socket->af);

    ret = (socket->af->ops->create)(socket->af, socket);

    if (ret || !socket->proto)
        goto release_socket;

    if (socket->proto->ops->create) {
        ret = (socket->proto->ops->create)(socket->proto, socket);

        if (ret)
            goto release_socket;
    }

    kprintf(KERN_NORM, "Socket ret: %p, refs: %d\n", socket, atomic_get(&socket->refs));
    *sock_ret = socket;

    return ret;

release_socket:
    socket_put(socket);

    return ret;
}

int
socket_sendto(struct Socket *socket, struct UserBuffer buf, size_t len, int flags,
    const struct SockAddr *dest, socklen_t addr_len, int nonblock)
{
    kprintf(KERN_NORM, "Socket: %p, socklen: %d, dest: %p\n", socket, addr_len, dest);
    kprintf(KERN_NORM, "Proto: %p\n", socket->proto);
    kprintf(KERN_NORM, "Ops: %p\n", socket->proto->ops);
    kprintf(KERN_NORM, "Sendto: %p\n", socket->proto->ops->sendto);

    if (socket->proto->ops->sendto)
        return socket->proto->ops->sendto(socket->proto, socket, buf, len, dest, addr_len);
    else
        return -ENOTSUP;
}

int
socket_send(struct Socket *socket, struct UserBuffer buf, size_t len, int flags)
{
    return socket_sendto(socket, buf, len, flags, NULL, 0, 0);
}

int
socket_recvfrom(struct Socket *socket, struct UserBuffer buf, size_t len, int flags)
{
    int ret = 0;
    struct Packet *packet = NULL;

    using_mutex(&socket->recv_lock) {
        if (list_empty(&socket->recv_queue)) {
            if (!nonblock)
                ret = wait_queue_event_intr_mutex(&socket->recv_wait_queue,
                    !list_empty(&socket->recv_queue), &socket->recv_lock);
            else
                ret = -EAGAIN;
        }

        if (!ret) {
            /**
             * We may request less data than is in this packet. In that case,
             * we remove that data from the packet, but keep it in the queue.
            **/
            packet = list_first(&socket->recv_queue, struct Packet, packet_entry);
            size_t plen = packet_len(packet);
            int drop_packet = 0;

            if (plen <= len) {
                ret = user_memcpy_from_kernel(buf, packet->head, plen);

                if (ret)
                    return ret;

                ret = plen;
                drop_packet = 1;
            } else {
                ret = user_memcpy_from_kernel(buf, packet->head, len);

                if (ret)
                    return ret;

                ret = len;

                // Move the head past the read data //
                packet->head += len;
            }

            if (addr && *addr_len >= packet->src_len) {
                memcpy(addr, &packet->src_addr, packet->src_len);
                *addr_len = packet->src_len;
            } else if (addr) {
                memcpy(addr, &packet->src_addr, *addr_len);
                *addr_len = packet->src_len;
            }

            if (drop_packet) {
                list_del(&packet->packet_entry);
                packet_free(packet);
            }
        }
    }

    return ret;
}

int
socket_recv(struct Socket *socket, struct UserBuffer *buf, size_t len, int flags)
{
    return socket_recvfrom(socket, buf, len, flags, NULL, NULL, 0);
}

int
socket_bind(struct Socket *socket, const struct SockAddr *addr, socklen_t addr_len)
{
    int ret;

    if (flag_test(&socket->flags, SOCKET_IS_BOUND))
        return -EINVAL;

    ret = socket->proto->ops->bind(socket->proto, socket, add, addr_len);

    if (ret)
        return ret;

    flag_set(&socket->flags, SOCKET_IS_BOUND);

    return 0;
}

int
socket_getsockname(struct Socket *socket, struct SockAddr *addr, socklen_t *addr_len)
{
    int ret;

    if (!flag_test(&socket->flags, SOCKET_IS_BOUND))
        return -EINVAL;

    ret = socket->proto->ops->getsockname(socket->proto, socket, addr, addr_len);

    if (ret)
        return ret;

    return 0;
}

int
socket_setsockopt(struct Socket *socket, int level, int optname, struct UserBuffer optval, socklen_t optlen)
{
    return -ENOTSUP;
}

int
socket_getsockopt(struct Socket *socket, int level, int optname, struct UserBuffer optval,
    struct UserBuffer optlen)
{
    return -ENOTSUP;
}

int
socket_accept(struct Socket *socket, struct SockAddr *addr, socklen_t *addr_len, struct Socket **new_socket)
{
    return -ENOTSUP;
}

int
socket_connect(struct Socket *socket, const struct SockAddr *addr, socklen_t addr_len)
{
    int ret;

    if (!socket->proto->ops->connect)
        return -ENOTSUP;

    ret = socket->proto->ops->connect(socket->proto, socket, addr, addr_len);

    if (ret)
        return ret;

    return 0;
}

int
socket_listen(struct Socket *socket, int backlog)
{
    return -ENOTSUP;
}

int
socket_shutdown(struct Socket *socket, int how)
{
    if (socket->proto->ops->shutdown)
        return (socket->proto->ops->shutdown)(socket->proto, socket, how);
    else
        return -ENOTSUP;

    return 0;
}

void
socket_release(struct Socket *socket)
{
    if (socket->proto->ops->release)
        (socket->proto->ops->release)(socket->proto, socket);
}

