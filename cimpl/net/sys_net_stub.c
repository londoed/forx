/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { net/sys_net_stub.c }.
 * Copyright (C) 2018, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <forx/kassert.h>
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
#include <forx/net/sys.h>
#include <forx/net.h>

#include "sys_common.h"

/**
 * This file is used when net support is disabled. It provides stubs for the
 * syscalls normally handled by the net subsystem.
**/
int
sys_bind(int sockfd, const struct SockAddr *addr, SockLen addrlen)
{
    return -ENOTSUP;
}

int
sys_getsockname(int sockfd, struct SockAddr *addr, SockLen *addrlen)
{
    return -ENOTSUP;
}

int
sys_setsockopt(int sockfd, int level, int optname, const void *optval, SockLen optlen)
{
    return -ENOTSUP;
}

int
sys_getsockopt(int sockfd, int level, int optname, void *optval, SockLen *optlen)
{
    return -ENOTSUP;
}

int
__sys_sendto(struct File *filp, const void *buf, size_t len, int flags, const struct SockAddr *dest,
    SockLen addrlen)
{
    return -ENOTSUP;
}

int
sys_sendto(int sockfd, const void *buf, size_t len, int flags, const struct SockAddr *dest,
    SockLen addrlen)
{
    return -ENOTSUP;
}

int
sys_send(int sockfd, const void *buf, size_t len, int flags)
{
    return -ENOTSUP;
}

int
__sys_recvfrom(struct File *filp, void *buf, size_t len, int flags, struct SockAddr *addr,
    SockLen *addrlen)
{
    return -ENOTSUP;
}

int
sys_recvfrom(int sockfd, void *buf, size_t len, int flags, struct SockAddr *addr,
    SockLen *addrlen)
{
    return -ENOTSUP;
}

int
sys_recv(int sockfd, void *buf, size_t len, int flags)
{
    return -ENOTSUP;
}

int
sys_shutdown(int sockfd, int how)
{
    return -ENOTSUP;
}

int
sys_socket(int afamily, int type, int protocol)
{
    return -ENOTSUP;
}
