/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { libctl/sort.c }.
 * Copyright (C) 2005, Matt Mackall <mpm@selenic.com>.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/kernel.h>
#include <forx/sort.h>
#include <forx/slab_alloc.h>

static void
u32_swap(void *a, void *b, int size)
{
    uint32_t t = *(uint32_t *)a;

    *(uint32_t *)a = *(uint32_t *)b;
    *(uint32_t *)b = t;
}

static void
generic_swap(void *a, void *b, int size)
{
    char t;

    do {
        t = *(char *)a;
        *(char *)a++ = *(char *)b;
        *(char *)b++ = t;
    } while (--size > 0);
}

void
sort(void *base, size_t num, size_t size, int (*cmp_fn)(const void *, const void *),
    void (*swap_fn)(void *, void *, int size))
{
    // Pre-scale counters for performance //
    int i = (num / 2 - 1) * size, n = num * size, c, r;

    if (!swap_fn)
        swap_fn = (size == 4 ? u32_swap : generic_swap);

    // Heapify //
    for (; i >= 0; i -= size) {
        for (r = i; r * 2 + size < n; r = c) {
            c = r * 2 + size;

            if (c < n - size && cmp_fn(base + c, base + c + size) < 0)
                c += size;

            if (cmp_fn(base + r, base + c) >= 0)
                break;

            swap_fn(base + r, base + c, size);
        }
    }

    // Sort //
    for (i = n - size; i > 0; i -= size) {
        swap_fn(base, base + i, size);

        for (r = 0; r * 2 + size < i; r = c) {
            c = r * 2 + size;

            if (c < i - size && cmp_fn(base + c, base + c + size) < 0)
                c += size;

            if (cmp_fn(base + r, base + c) >= 0)
                break;

            swap_fn(base + r, base + c, size);
        }
    }
}

int
cmpint(const void *a, const void *b)
{
    return *(int *)a - *(int *)b;
}

static int
sort_test(void)
{
    int *a, i, r = 1;

    a = kmalloc(1000 * sizeof(int), PAL_KERNEL);

    if (!a)
        return NULL;

    kprintf("Testing sort()\n");

    for (i = 0; i < 1000; i++) {
        r = (r * 725861) % 6599;
        a[i] = r;
    }

    sort(a, 1000, sizeof(int), cmpint, NULL);

    for (i = 0; i < 999; i++) {
        if (a[i] > a[i + 1]) {
            kprintf("sort() failed\n");
            break;
        }
    }

    kfree(a);

    return 0;
}
