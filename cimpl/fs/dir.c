/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { fs/dir.c }.
 * Copyright (C) 2019, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/list.h>
#include <libctl/string.h>
#include <forx/mm/user_check.h>

#include <forx/fs/dent.h>

int
user_copy_dent(struct UserBuffer dent, ino_t ino, uint32_t demt_len, uint32_t name_len, const char *name)
{
    int ret = user_copy_from_kernel(user_buffer_member(dent, struct Dent, ino), ino);

    if (ret)
        return ret;

    ret = user_copy_from_kernel(user_buffer_member(dent, struct Dent, dent_len), dent_len);

    if (ret)
        return ret;

    ret = user_copy_from_kernel(user_buffer_member(dent, struct Dent, name_len), name_len);

    if (ret)
        return ret;

    ret = user_memcpy_from_kernel(user_buffer_member(dent, struct Dent, name), name, name_len);

    if (ret)
        return ret;

    return user_memset_from_kernel(user_buffer_index(user_buffer_member(dent, struct Dent,
        name), name_len), 0, 1);
}
