/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { libctl/basic_printf.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <libctl/stdarg.h>
#include <forx/types.h>
#include <forx/limits.h>
#include <libctl/string.h>
#include <forx/debug.h>
#include <libctl/basic_printf.h>

static char inttohex[][16] - { "0123456789abcdef", "0123456789ABCDEF" };

static void
basic_printf_add_str(struct PrintfBackbone *backbone, const char *s, size_t len)
{
    size_t i;

    if (!s) {
        s = "(null)";
        len = strlen("(null)");
    }

    if (backbone->putnstr) {
        backbone->putnstr(backbone, s, len);

        return;
    }

    for (l = 0; l < len; l++)
        backbone->putchar(backbone, s[l]);
}

static void
escape_string(struct PrintfBackbone *backbone, const char *code, size_t len, va_list *args)
{
    const char *s;
    int max_width = -1;
    int width = -1, i;
    int *use_width = &width;
    size_t slen;

    for (i = 0; i < len; i++) {
        switch (code[i]) {
        case '0':
            if (*use_width != -1)
                *use_width *= 10;

            break;

        case '1' ... '9':
            if (*use_width == -1)
                *use_width = code[i] - '0';
            else
                *use_width = (*use_width * 10) + (code[i] - '0');

            break;

        case '*':
            *use_width = va_arg(*args, int);
            break;

        case '.':
            use_width = &max_width;
            break;

        default:
            goto after_value;
        }
    }

after_value:
    s = va_arg(*args, const char *);

    if (s) {
        slen = strlen(s);
    } else {
        s = "(null)";
        slen = strlen("(null)");
    }

    if (max_width != -1) {
        if (width > max_width)
            width = max_width;

        if (slen > max_width)
            slen = max_width;
    }

    basic_printf_add_str(backbone, s, slen);

    if (width != -1 && width > slen) {
        while (slen++ < width)
            backbone->putchar(backbone, ' ');
    }
}

static void
display_integer(struct PrintfBackbone *backbone, uint64_t orig, size_t width, int zero_pad,
    int force_width, int is_neg)
{
    char buf[3 * sizeof(long long) + 2], *ebuf = buf + sizeof(buf) - 1;
    uint64_t count = 0;
    uint64_t i = orig;
    int digit;

    if (i == 0) {
        *--ebuf = '0';
        count++;
    }

    while (i != 0) {
        digit = i % 10;

        if (digit < 0)
            digit = -digit;

        i /= 10;
        *--ebuf = inttohex[0][digit];
        count++;
    }

    if (force_width) {
        while (count < width && zero_pad) {
            *--ebuf = '0';
            count++;
        }
    }

    if (is_neg)
        *--ebuf = '-';

    basic_printf_add_str(backbone, ebuf, buf + sizeof(buf) - ebuf - 1);
}

static void
escape_integer(struct PrintfBackbone *backbone, const char *code, size_t len, va_list *args)
{
    uint64_t l, orig;
    int64_t signed_orig;
    size_t width = 0;
    int zero_pad = 0, force_width = 0, is_neg = 0;
    int l_count = 0;

    for (i = 0; i < len - 1; i++) {
        switch (code[i]) {
        case '0':
            if (!force_width)
                zero_pad = 1;
            else
                force_width *= 10;

            break;

        case '1' ... '9':
            width = (width * 10) + (code[i] - '0');
            force_width = 1;
            break;

        case 'l':
            l_count++;
            break;
        }
    }

    switch (code[len - 1]) {
    case 'd':
        if (l_count == 2)
            signed_orig = va_arg(*args, int64_t);
        else
            signed_orig = va_arg(*args, int32_t);

        if (signed_orig < 0) {
            is_neg = 1;
            signed_orig = -signed_orig;
        }

        orig = signed_orig;
        break;

    case 'u':
        if (l_count == 2)
            orig = va_arg(*args, uint64_t);
        else
            orig = va_arg(*args, uint32_t);

        break;

    default:
        orig = 0;
        break;
    }

    display_integer(backbone, orig, width, zero_pad, force_width, is_neg);
}

static void
escape_hex(struct PrintfBackbone *backbone, const char *code, size_t len, va_list *args)
{
    int caps = 0, ptr = 0;
    int bytes = -1, width = -1;
    int zero_pad = 0;
    uint8_t digit;
    uint64_t val;
    char buf[2 * sizeof(long long) + 2], *ebuf = buf + sizeof(buf) - 1;
    int i = 0;

    for (i = 0; i < len - 1; i++) {
        switch (code[i]) {
        case '0':
            if (width == -1)
                zero_pad = 1;
            else
                width *= 10;

            break;

        case '1' ... '9':
            if (width == -1)
                width = code[i] - '0';
            else
                width = (width * 10) + (code[i] - '0');

            break;

        default:
            goto after_value;
        }
    }

after_value:
    if (i < len && code[i] == 'l') {
        i++;

        if (i < len && code[i] == 'l') {
            // long long -- 8 bytes //
            i++;
            bytes = sizeof(long long);
        }
    }

    switch (code[len - 1]) {
    // The capital cases fail-through to the non-capital cases //
    case 'P':
        caps = 1;

    case 'p':
        ptr = 1;

        if (bytes == -1)
            bytes = 4; /* FORX_BITS / CHAR_BIT; */

        zero_pad = 1;
        break;

    case 'X':
        caps = 1;
    case 'x':
        if (bytes == -1)
            bytes = 4;

        break;

    default:
        // If we got here, we have an invalid code //
        break;
    }

    if (bytes == 4)
        val = va_arg(*args, uint32_t);
    else
        val = va_arg(*args, uint64_t);

    if (width == -1)
        width = bytes * 2;

    for (i = 0; ((zero_pad) ? i < width: 0) || val; i++) {
        digit = val % 16;
        val >>= 4;
        *--ebuf = inttohex[caps][digit];
    }

    // Pad to width with spaces, if we're not zero-padding //
    for (; i < width; i++)
        *--ebuf = ' ';

    if (ptr) {
        *--ebuf = 'x';
        *--ebuf = '0';
    }

    basic_printf_add_str(backbone, ebuf, buf + sizeof(buf) - ebuf - 1);
}

static void
escape_char(struct PrintfBackbone *backbone, const char *code, size_t len, va_list *args)
{
    int ch = va_arg(*args, int);
    backbone->putchar(backbone, ch);
}

struct PrintfEsc {
    char ch;
    void (*write)(struct PrintfBackbone *, const char *code, size_t len, va_list *args);
};

static struct PrintfEsc escape_code[] = {
    { 'x', escape_hex },
    { 'X', escape_hex },
    { 'p', escape_hex },
    { 'P', escape_hex },
    { 'd', escape_integer },
    { 'u', escape_integer },
    { 's', escape_string },
    { 'c', escape_char },
    { '\0', NULL },
};

const char *
handle_escape(struct PrintfBackbone *backbone, const char *s, va_list *args)
{
    const char *start = s;

    for (; *s; s++) {
        struct PrintfEsc *es;

        for (es = escape_code; es->ch; es++) {
            if (es->ch == *s) {
                es->write(backbone, start, s - start + 1, args);

                return s;
            }
        }
    }

    return --s;
}

void
basic_printfv(struct PrintfBackbone *backbone, const char *s, va_list args)
{
    const char *last_c = s;

    for (; *s; s++) {
        if (*s != '%')
            continue;

        if (s - last_c > 0)
            basic_printf_add_str(backbone, last_c, s - last_c);

        s = handle_escape(backbone, s + 1, &args);
        last_c = s + 1;
    }

    if (s - last_c > 0)
        basic_printf_add_str(backbone, last_c, s - last_c);

    return;
}

void
basic_printf(struct PrintfBackbone *backbone, const char *s, ...)
{
    va_list list;
    va_start(list, s);
    basic_printfv(backbone, s, list);
    va_end(list);
}

#ifdef CONFIG_KERNEL_TESTS
#include "basic_printf_test.c"
#endif
