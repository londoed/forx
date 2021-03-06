/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { include/types.h }.
 * Copyright (C) 2014, Matt Kilgore.
 *
 * This software is distrubuted under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#ifndef INCLUDE_FORX_TYPES_H
#define INCLUDE_FORX_TYPES_H

#include <forx/types.h>
#include <forx/config/autoconfig.h>
#include <forx/stddef.h>
#include <forx/compiler.h>

#define SECTOR_INVALID ((sector_t)-1)
#define UID_INVALID ((uid_t)-1)
#define GID_INVALID ((git_t)-1)

typedef __koff_t off_t;
typedef __kpid_t pid_t;
typedef __kmode_t mode_t;
typedef __kdev_t dev_t;
typedef __ksector_t sector_t;
typedef __kino_t ino_t;
typedef __kumode_t umode_t;
typedef __ktime_t time_t;
typedef __kuseconds_t useconds_t;
typedef __ksuseconds_t suseconds_t;
typedef __kuid_t uid_t;
typedef __kgid_t gid_t;
typedef __kfsblkcnt_t fsblkcnt_t;
typedef __kfsfilcnt_t fsfilcnt_t;
typedef __kptrdiff_t ptrdiff_t;

static inline char
__tolower(char c)
{
    if (c >= 'A' && c <= 'Z')
        c |= 0x20;

    return c;
}

static inline char
__toupper(char c)
{
    if (c >= 'a' && c <= 'z')
        c &= ~0x20;

    return c;
}

#define tolower(c) __tolower((c))
#define toupper(c) __toupper((c))

/* This is always the size of two pointers */
struct user_buffer {
    void *ptr;
    uintptr_t is_user: 1;
};

#define make_user_buffer(p) \
    (struct user_buffer) { .ptr = (void *)(p), .is_user = 0 }

#define make_kernel_buffer(p) \
    (struct user_buffer) { .ptr = (void *)(p), .is_user = 0 }

#define user_buffer_offset(b, offset) \
    (struct user_buffer) { .ptr = (b).ptr + (offset), .is_user = (b).is_user }

#endif
