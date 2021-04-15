/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { include/kbuf.h }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#ifndef FORX_KBUF_H
#define FORX_KBUF_H

#include <forx/types.h>
#include <libctl/stddef.h>
#include <forx/list.h>

/**
 * Kbuf implements a simple buffer interface that allows writing to the end,
 * and reading from any location. The buffer size can be expanded by
 * requesting a new page be added. You can also reset the write location
 * (in situations of things like a partial write that you want to roll back).
**/

struct KbufPos {
    size_t offset;
};

struct Kbuf {
    ListHead pages;
    size_t page_count;
    struct KbufPos cur_pos;
};

#define KBUF_INIT(kb) \
    { \
       .pages = LIST_HEAD_INIT((kb).pages, ) \
    }

static inline void
kbuf_init(struct Kbuf *kbuf)
{
    *kbuf = (struct Kbuf)KBUF_INIT(*kbuf);
}

int kbuf_add_page(struct Kbuf *);
void kbuf_clear(struct Kbuf *);

size_t kbuf_get_free_length(struct Kbuf *);
size_t kbuf_get_length(struct Kbuf *);
struct KbufPos kbuf_get_pos(struct Kbuf *);
void kbuf_reset_pos(struct Kbuf *, struct KbufPos);

int kbuf_read(struct Kbuf *, size_t loc, struct UserBuffer, size_t len);
int kbuf_write(struct Kbuf *, const struct UserBuffer, size_t);

// NOTE: On an overflow, these return -ENOSPC //
int kbuf_printfv(struct Kbuf *, const char *, va_list args);
int kbuf_printf(struct Kbuf *, const char *, ...) __printf(2, 3);

#endif
