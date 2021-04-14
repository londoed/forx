/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { net/protocol.c }.
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
#include <forx/fs/seq_file.h>
#include <forx/fs/vfs.h>
#include <forx/net/socket.h>
#include <forx/net/sys.h>
#include <forx/net.h>

static Mutex proto_list_lock = MUTEX_INIT(proto_list_lock);
static ListHead proto_list = LIST_HEAD_INIT(proto_list);

struct ProtoState {
    struct Protocol *proto;
    ListNode *cur_sock;
};

int
proto_seq_start(struct SeqFile *seq, struct Protocol *proto)
{
    struct ProtoState *state = kmalloc(sizeof(*state), PAL_KERNEL);

    mutex_lock(&proto->lock);
    state->proto = proto;
    state->cur_lock = seq_list_start_header_node(seq, &proto->socket_list);
    seq->priv = state;

    return 0;
}

struct Socket *
proto_seq_get_socket(struct SeqFile *seq)
{
    struct ProtoState *state = seq->priv;

    if (!state->cur_sock)
        return NULL;

    return container_of(state->cur_sock, struct Socket, proto_entry);
}

int
proto_seq_next(struct SeqFile *seq)
{
    struct ProtoState *state = seq->priv;

    state->cur_sock = seq_list_next_node(seq, state->cur_sock, &state->proto->socket_list);

    return 0;
}

void
proto_seq_end(struct SeqFile *seq)
{
    struct ProtoState *state = seq->priv;

    mutex_unlock(&state->proto->lock);
    kfree(state);
}
