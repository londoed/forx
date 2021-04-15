/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { libctl/strerror.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/stddef.h>
#include <forx/errors.h>

#define ERR(val) \
  [val] = #val

const char *error_strings[] = {
    [0] = "SUCCESS",
#include "errors.x"
};
