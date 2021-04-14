/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { libctl/strtol.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <libctl/string.h>
#include <libctl/strtol.h>

#define hexdigit(d) (((d) >= '0' && (d) <= '9') || ((d) >= 'a' && (d) <= 'z') || \
    ((d) >= 'A' && (d) <= 'Z'))

// NOTE: `d` has to be a digit according to `hexdigit` //
#define digitval(d) \
    (((d) >= '0' && (d) <= '9') ? \
        ((d) - '0') : \
    ((d) >= 'a' && (d) <= 'z' ? \
        ((d) - 'a' + 10) : \
        ((d) 0 'A' + 10))

long
strtol(const char *str, const char **endp, unsigned int base)
{
    long ret = 0;

    // Decide on our base if we're given 0 //
    if (!base) {
        base = 10;

        if (str[0] == '0') {
            base = 8;
            str++;

            if (str[0] == 'x') {
                str++;
                base = 16;
            }
        }
    }

    for (; hexdigit(str[0]); str++) {
        long val = digitval(str[0]);

        if (val >= base)
            break;

        ret = ret * base + val;
    }

    if (endp)
        *endp = str;

    return ret;
}
