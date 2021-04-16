/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { libctl/sprintf.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <libctl/stdarg.h>
#include <libctl/limits.h>
#include <libctl/basic_printf.h>

struct PrintfBackboneStr {
    struct PrintfBackboneStr backbone;
    char *buf;
    size_t left;
};

static void
str_putchar(struct PrintfBackbone *b, char ch)
{
    struct PrintfBackboneStr *str = container_of(b, struct PrintfBackboneStr, backbone);

    if (str->left <= 0)
        return;

    *str->buf = ch;
    str->buf++;
    str->left--;
}

static void
str_putnstr(struct PrintfBackbone *b, const char *s, size_t len)
{
    struct PrintfBackboneStr *str = container_of(b, struct PrintfBackboneStr, backbone);
    size_t l;

    if (str->left >= len) {
        for (l = 0; l < len; l++)
            str->buf[l] = s[l];

        str->buf += len;
        str->left -= len;
    } else {
        for (l = 0; l < str->left; l++)
            str->buf[l] = s[l];

        str->buf += str->left;
        str->left = 0;
    }
}

int
snprintfv(char *buf, size_t len, const char *fmt, va_list lst)
{
    struct PrintfBackboneStr str = {
        .backbone = {
            .putchar = str_putchar,
            .putnstr = str_putnstr,
        },
        .buf = buf,
        .left = len - 1,
    };

    basic_printfv(&str.backbone, fmt, lst);
    *str.buf = '\0';

    return len - str.left - 1;
}

int
snprintf(char *buf, size_t len, const char *fmt, ...)
{
    int ret;
    va_list lst;
    va_start(lst, fmt);

    ret = snprintfv(buf, len, fmt, lst);
    va_end(lst);

    return ret;
}

#ifdef CONFIG_KERNEL_TESTS
#include "snprintf_test.c"
#endif
