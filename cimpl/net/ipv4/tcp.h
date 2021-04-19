/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { net/ipv4/tcp.h }.
 * Copyright (C) 2017, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/net/proto.h>

struct PseudoHeader {
    n32 saddr;
    n32 daddr;
    uint8_t zero;
    uint8_t proto;
    n16 len;
} __packed;

void tcp_rx(struct Protocol *proto, struct Socket *sock, struct Packet *packet);
void tcp_send_reset(struct Protocol *proto, struct Packet *old_packet);
void tcp_send_syn(struct Protocol *proto, struct Socket *sock);
void tcp_send_ack(struct Protocol *proto, struct Socket *sock);
void tcp_send(struct Protocol *proto, struct Socket *sock, struct Packet *packet);
void tcp_send_raw(struct Protocol *proto, struct Packet *packet, n16 src_port,
    n32 dest_addr, n16 dest_port);

void tcp_recv_data(struct Protocol *proto, struct Socket *sock, struct Packet *packet);
void tcp_fin(struct Socket *, struct Packet *);

void tcp_timers_init(struct Socket *sock);
void tcp_timers_reset(struct Socket *sock);
void tcp_delack_timer_start(struct Socket *sock);
void tcp_delack_timer_stop(struct Socket *sock);

void tcp_procfs_register(struct Protocol *proto, struct Socket *sock);
void tcp_profcs_unregister(struct Protocol *proto, struct Socket *sock);
n16 tcp_checksum(struct PseudoHeader *header, const char *data, size_t len);
n16 tcp_checksum_packet(struct Packet *packet);

static inline int
tcp_seq_before(uint32_t seq1, uint32_t seq2)
{
    return ((int32_t)(seq1 - seq2)) < 0;
}

static inline int
tcp_seq_after(uint32_t seq1, uint32_t seq2)
{
    return ((int32_t)(seq1 - seq2)) > 0;
}

// Checks that seq1 < seq2 < seq3 //
static inline int
tcp_seq_between(uint32_t seq1, uint32_t seq2, uint32_t seq3)
{
    return tcp_seq_before(seq1, seq2) && tcp_seq_before(seq2, seq3);
}

struct TcpProtocol {
    struct Protocol proto;
    Mutex lock;
    uint16_t next_port;
};

extern struct TcpProtocol tcp_protocol;

#endif
