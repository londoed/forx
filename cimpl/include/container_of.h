/**
 * FORX: An open and collaborative operating system kernel for the research community.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { include/container_of.h }.
 * Copyright (C) 2020, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#ifndef __FORX_CONTAINER_OF_H
#define __FORX_CONTAINER_OF_H

#include <forx/stddef.h>

// We only use the fancy version that requires typeof() if we're using gcc //
#ifdef __GNUC__
#define container_of(ptr, type, member) ({ \
    const __typeof__(((type *)0)->member)*__mptr = (ptr); \
    (type *)((char *)__mptr - __koffsetof(type, member)); \
})

#else
#define container_of(ptr, type, member) \
    ((type *)((char *)ptr - __koffsetof(type, member)))
#endif

#endif
