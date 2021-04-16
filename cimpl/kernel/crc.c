/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/crc.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/crc.h>

uint16_t
crc16(void *data, size_t len, uint16_t poly)
{
    uint8_t *d, *end;
    uint16_t crc = 0;
    int i;

    for (d = data, end = d + len; d != end; d++) {
        crc ^= *d;

        for (i = 0; i < 8; i++) {
            int flag = crc & 0x0001;
            crc >>= 1;

            if (flag)
                crc ^= poly;
        }
    }

    return crc;
}
