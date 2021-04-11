/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { net/addr_family.c }.
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
#include <forx/net/socket.h>
#include <forx/net/sys.h>
#include <forx/net.h>

static Mutex af_list_lock = MUTEX_INIT(af_list_lock);
static ListHead af_list = LIST_HEAD_INIT(af_list);

void
address_family_register(struct AddrFamily *af)
{
    using_mutex(&af_list_lock)
        list_add(&af_list, &af->af_entry);
}

struct AddrFamily *
address_family_lookup(int af)
{
    struct AddrFamily *af, *ret = NULL;

    using_mutex(&af_list_lock) {
        list_foreach_entry(&af_list, af, af_entry) {
            if (af->af_type == af) {
                ret = af;
                break;
            }
        }
    }

    return ret;
}
