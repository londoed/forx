/**
 * FORX: An open and collaborative operating system kernel for research operating system.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/char_buf_test.c }.
 * Copyright (C) 2019, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/char_buf.h>
#include <forx/mm/page_alloc.h>
#include <forx/ktest.h>

static void
char_buf_read_wrap_test(struct Ktest *kt)
{
    struct Page *page = page_alloc(0, PAL_KERNEL);
    struct CharBuf buf;

    char_buf_init(&buf, page->virt, PAGE_SIZE);
    char tmp[128];
    int i;

    for (i = 0; i < ARRAY_SIZE(tmp); i++)
        tmp[i] = i;

    buf.start_pos = PAGE_SIZE - 64;
    buf.buf_len = 128;

    memcpy(page->virt + PAGE_SIZE - 64, tmp, 64);
    memcpy(page->virt, tmp + 64, 64);

    char read_ret[128] = { 0 };
    size_t ret = char_buf_read(&buf, read_ret, sizeof(read_ret));

    ktest_assert_equal(kt, 128, ret);
    ktest_assert_equal(kt, 64, buf.start_pos);
    ktest_assert_equal(kt, 0, buf.buf_len);
    ktest_assert_equal_mem(kt, tmp, read_ret, 128);

    page_free(page, 0);
}

static void
char_buf_read_user_wrap_test(struct Ktest *kt)
{
    struct Page *page = page_alloc(0, PAL_KERNEL);
    struct CharBuf buf;

    char_buf_init(&buf, page->virt, PAGE_SIZE);
    char tmp[128];
    int i;

    for (i = 0; i < ARRAY_SIZE(tmp); i++)
        tmp[i] = i;

    buf.start_pos = PAGE_SIZE - 64;
    buf.buf_len = 128;

    memcpy(page->virt + PAGE_SIZE - 64, tmp, 64);
    memcpy(page->virt, tmp + 64, 64);

    char read_ret[128] = { 0 };
    size_t ret = char_buf_read_user(&buf, make_kernel_buffer(read_ret), sizeof(read_ret));

    ktest_assert_equal(kt, 128, ret);
    ktest_assert_equal(kt, 64, buf.start_pos);
    ktest_assert_equal(kt, 0, buf.buf_len);
    ktest_assert_equal_mem(kt, tmp, read_ret, 128);

    page_free(page, 0);
}

static void
char_buf_write_wrap_test(struct Ktest *kt)
{
    struct Page *page = page_alloc(0, PAL_KERNEL);
    struct CharBuf buf;

    char_buf_init(&buf, page->virt, PAGE_SIZE);
    char tmp[128];
    int i;

    for (i = 0; i < ARRAY_SIZE(tmp); i++)
        tmp[i] = i;

    buf.start_pos = PAGE_SIZE - 64;
    char_buf_write(&buf, tmp, sizeof(tmp));

    ktest_assert_equal(kt, PAGE_SIZE - 64, buf.start_pos);
    ktest_assert_equal(kt, sizeof(tmp), buf.buf_len);
    ktest_assert_equal_mem(kt, tmp, page->virt + PAGE_SIZE - 64, 64);
    ktest_assert_equal_mem(kt, tmp + 64, page->virt, 64);

    page_free(page, 0);
}

static void
char_buf_write_buf(struct Ktest *kt)
{
    struct Page *page = page_alloc(0, PAL_KERNEL);
    struct CharBuf buf;

    char_buf_init(&buf, page->virt, PAGE_SIZE);
    ktest_assert_equal(kt, 0, buf.start_pos);
    ktest_assert_equal(kt, 0, buf.buf_len);

    char tmp[128];
    int i;

    for (i = 0; i < ARRAY_SIZE(tmp); i++)
        tmp[i] = i;

    char_buf_write(&buf, tmp, sizeof(tmp));
    ktest_assert_equal(kt, 0, buf.start_pos);
    ktest_assert_equal(kt, sizeof(tmp), buf.buf_len);

    char_buf_write(&buf, tmp, sizeof(tmp));
    ktest_assert_equal(kt, 0, buf.start_pos);
    ktest_assert_equal(kt, sizeof(tmp) * 2, buf.buf_len);

    char_buf_write(&buf, tmp, sizeof(tmp));
    ktest_assert_equal(kt, 0, buf.start_pos);
    ktest_assert_equal(kt, sizeof(tmp) * 3, buf.buf_len);

    char_buf_write(&buf, tmp, sizeof(tmp));
    ktest_assert_equal(kt, 0, buf.start_pos);
    ktest_assert_equal(kt, sizeof(tmp) * 4, buf.buf_len);

    char_buf_write(&buf, tmp, sizeof(tmp));
    ktest_assert_equal(kt, 0, buf.start_pos);
    ktest_assert_equal(kt, sizeof(tmp) * 5, buf.buf_len);

    page_free(page, 0);
}

static void
char_buf_empty_read_test(struct Ktest *kt)
{
    struct Page *page = page_alloc(0, PAL_KERNEL);
    struct CharBuf buf;

    char_buf_init(&buf, page->virt, PAGE_SIZE);
    ktest_assert_equal(kt, 0, buf.start_pos);
    ktest_assert_equal(kt, 0, buf.buf_len);

    char tmp[10] = { 0 };
    size_t ret = char_buf_read(&buf, tmp, sizeof(tmp));

    ktest_assert_equal(kt, 0, ret);
    page_free(page, 0);
}

static const struct KtestUnit char_buf_test_units[] = {
    KTEST_UNIT("char-buf-read-wrap-test", char_buf_read_wrap_test),
    KTEST_UNIT("char-buf-read-user-wrap-test", char_buf_read_user_wrap_test),
    KTEST_UNIT("char-buf-write-wrap-test", char_buf_write_wrap_test),
    KTEST_UNIT("char-buf-write-test", char_buf_write_test),
    KTEST_UNIT("char-buf-empty-read-test", char_buf_empty_read_test),
};

KTEST_MODULE_DEFINE("char-buf", char_buf_test_units);
