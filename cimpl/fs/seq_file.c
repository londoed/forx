/**
 * FORX: An open and collaborative operating system kernel for the research community.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { fs/seq_file.c }.
 * Copyright (C) 2019, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/mm/page_alloc.h>
#include <forx/mm/kmalloc.h>
#include <forx/fs/file.h>
#include <forx/kbuf.h>
#include <forx/fs/seq_file.h>

static void
seq_file_init(struct SeqFile *seq, const struct SeqFileOps *ops)
{
    *seq = (struct SeqFile) {
        .ops = ops,
        .lock = MUTEX_INIT(seq->lock),
        .buf = KBUF_INIT(seq->buf),
    };
}

static void
seq_file_clear(struct SeqFile *seq)
{
    kbuf_clear(&seq->buf);
}

/**
 * Currently, we have very simple logic that simply fills the buffer to
 * the max when the first read for this file comes in.
 *
 * Eventually, we could make the logic a bit smarter to only read up to
 * the point that the userspace buffer requires (thought, that option
 * is a bit racier if userspace uses small buffers).
**/
static int
__seq_file_fill(struct SeqFile *seq)
{
    for (;;) {
        if (flag_test(&seq->flags, SEQ_FILE_DONE))
            break;

        // Make sure we have at least a page of free space //
        if (kbuf_get_free_length(&seq->buf) < PAGE_SIZE)
            kbuf_add_page(&seq->buf);

        int err = (seq->ops->start)(seq);

        if (err < 0)
            return err;

        if (flag_test(&seq->flags, SEQ_FILE_DONE))
            break;

        // Loop until we hit the end of the sequence, or run out of space //
        for (;;) {
            struct KBufferPos starting_pos = kbuf_get_pos(&seq->buf);
            seq->overflowed = 0;
            err = (seq->ops->render)(seq);

            if (err < 0 && seq->overflows) {
                kbuf_reset_pos(&seq->buf, starting_pos);
                break;
            }

            err = (seq->ops->next)(seq);

            if (err < 0)
                break;
        }

        if (seq->ops->end)
            (seq->ops->end)(seq);

        /**
         * On -ENOSPC, we simply loop again, which will trigger allocating
         * another page.
        **/
        if (err != -ENOSPC)
            return err;
    }

    return 0;
}

static int
seq_file_read(struct SeqFile *seq, off_t off, struct UserBuffer ptr, size_t sizet_len)
{
    if (off < 0)
        return -EINVAL;

    if (sizet_len > __OFF_MAX || (off_t)sizet_len < 0)
        return -EINVAL;

    off_t len = sizet_len;

    using_mutex(&seq->lock) {
        __seq_file_fill(seq);

        return kbuf_read(&seq->buf, off, ptr, len);
    }
}

int
seq_printf(struct SeqFile *seq, const char *fmt, ...)
{
    va_list list;
    va_start(list, fmt);
    int ret = kbuf_printfv(&seq->buf, fmt, list);

    if (ret < 0)
        seq->overflowed = 1;

    va_end(list);

    return ret;
}

int
seq_open(struct File *filp, const struct SeqFileOps *ops)
{
    struct SeqFile *seq = kmalloc(sizeof(*seq), PAL_KERNEL);

    if (!seq)
        return -ENOMEM;

    seq_file_init(seq, ops);
    filp->priv_data = seq;

    return 0;
}
