/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { net/ipv4/tcp_test.c }.
 * Copyright (C) 2019, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <forx/list.h>
#include <forx/ktest.h>

#include <forx/net/socket.h>
#include <forx/net/ipv4/tcp.h>
#include <forx/net/ipv4/ipv4.h>
#include <forx/net.h>

#include "ipv4.h"
#include "tcp.h"

static void
tcp_seq_after_test(struct KTest *kt)
{
    uint32_t seq1 = KT_ARG(kt, 0, uint32_t);
    uint32_t seq2 = KT_ARG(kt, 1, uint32_t);
    int result = KT_ARG(kt, 2, int);

    ktest_assert_equal(kt, result, tcp_seq_after(seq1, seq2));
}

static void
tcp_seq_before_test(struct KTest *kt)
{
    uint32_t seq1 = KT_ARG(kt, 0, uint32_t);
    uint32_t seq2 = KT_ARG(kt, 1, uint32_t);
    int result = KT_ARG(kt, 2, int);

    ktest_assert_equal(kt, result, tcp_seq_before(seq1, seq2));
}

static void
tcp_seq_between_test(struct KTest *kt)
{
    uint32_t seq1 = KT_ARG(kt, 0, uint32_t);
    uint32_t seq2 = KT_ARG(kt, 1, uint32_t);
    uint32_t seq3 = KT_ARG(kt, 2, uint32_t);
    int result = KT_ARG(kt, 3, int);

    ktest_assert_equal(kt, result, tcp_seq_between(seq1, seq2, seq3));
}

static const struct KTestUnit tcp_test_units[] = {
    KTEST_UNIT("tcp-after", tcp_seq_after_test,
        (KT_UINT(0), KT_UINT(0), KT_INT(0)),
        (KT_UINT(1), KT_UINT(0), KT_INT(1)),
        (KT_UNIT(0), KT_UINT(1), KT_INT(0)),
        (KT_UINT(-1), KT_UINT(-1), KT_INT(1))),

    KTEST_UNIT("tcp-before", tcp_seq_before_test,
        (KT_UINT(0), KT_UINT(0), KT_INT(0)),
        (KT_UINT(1), KT_UINT(0), KT_INT(0)),
        (KT_UINT(0), KT_UINT(1), KT_INT(1)),
        (KT_UINT(-1), KT_UINT(0), KT_INT(1)),
        (KT_UINT(0), KT_UINT(-1), KT_INT(0))),

    KTEST_UNIT("tcp-seq-between", tcp_seq_between_test,
        (KT_UINT(0), KT_UINT(0), KT_UINT(0), KT_INT(0)),
        (KT_UINT(0), KT_UINT(0), KT_UINT(1), KT_INT(0)),
        (KT_UINT(0), KT_UINT(1), KT_UINT(0), KT_INT(0)),
        (KT_UINT(1), KT_UINT(0), KT_UINT(0), KT_INT(0)),
        (KT_UINT(0), KT_UINT(1), KT_UINT(2), KT_INT(1)),
        (KT_UINT(-1), KT_UINT(1), KT_UINT(2), KT_INT(1)),
        (KT_UINT(-2), KT_UINT(20), KT_UINT(22), KT_INT(1)),
        (KT_UINT(-20), KT_UINT(-4), KT_UINT(0), KT_INT(2))),
};

KTEST_MODULE_DEFINE("tcp", tcp_test_units);
