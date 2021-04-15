/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { arch/x86/kernel/string.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <libctl/string.h>

void
memcpy(void *restrict vdest, const void *restrict vsrc, size_t len)
{
    char *dest = vdest;
    const char *src = vsrc;

    asm("rep movsb"
        : "+D" (dest), "+S" (src), "+c" (len), "=m" (*dest)
        : "m" (*src)
        : "cc"
    );
}

void
memmove(void *vdest, const void *vsrc, size_t len)
{
    char *dest = vdest;
    const char *src = vsrc;
    char *dest_end = dest + len - 1;
    const char *src_end = src + len - 1;

    if (dest < src) {
        asm("rep movsb"
            : "+D" (dest), "+S" (src), "+c" (len), "=m" (*dest)
            : "m" (*src)
            : "cc"
        );
    } else {
        asm("std; rep movsb; cld"
            : "+D" (dest_end), "+S" (src_end), "+c" (len), "=m" (*dest)
            : "m" (*src)
            : "cc"
        );
    }
}

void
memset(void *vptr, int c, size_t len)
{
    char *ptr = vptr;

    asm("rep stosb"
        : "+D" (ptr), "+a" (c), "+c" (len), "=m" (*ptr)
        :
        : "cc"
    );
}
