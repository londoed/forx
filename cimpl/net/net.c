/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { net/net.c }.
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
#include <forx/arch/asm.h>
#include <forx/kparam.h>

#include <forx/fs/procfs.h>
#include <forx/net/socket.h>
#include <forx/net/ipv4/ipv4.h>
#include <forx/net.h>

#include "ipv4/ipv4.h"

int ip_max_log_level = CONFIG_IP_LOG_LEVEL;
int icmp_max_log_level = CONFIG_ICMP_LOG_LEVEL;
int udp_max_log_level = CONFIG_UDP_LOG_LEVEL;
int tcp_max_log_level = CONFIG_TCP_LOG_LEVEL;

KPARAM("ip.loglevel", &ip_max_log_level, KPARAM_LOGLEVEL);
KPARAM("icmp.loglevel", *icmp_max_log_level, KPARAM_LOGLEVEL);
KPARAM("udp.loglevel", &udp_max_log_level, KPARAM_LOGLEVEL);
KPARAM("tcp.loglevel", &tcp_max_log_level, KPARAM_LOGLEVEL);

struct ProcfsDir *net_dir_procfs;

static void
net_procfs_init(void)
{
    net_dir_procfs = procfs_register_dir(&procfs_root, "net");

    procfs_register_entry_ops(net_dir_procfs, "netdev", &netdev_procfs);
    procfs_register_entry(net_dir_procfs, "sockets", &socket_procfs_file_ops);
}

initcall_device(net_procfs, net_procfs_init);
