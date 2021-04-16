/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/kbuf_test.c }.
 * Copyright (C) 2019, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
 *
 * Tests for kbuf.c -- included directly at the end of kbuf.c.
**/

#include <forx/types.h>
#include <forx/kbuf.h>
#include <forx/ktest.h>

static void
kbuf_get_free_length_test(struct Ktest *kt)
{
    struct Kbuf kbuf;

    kbuf_init(&kbuf);
    ktest_assert_equal(kt, 0, kbuf_get_free_length(&kbuf));

    kbuf_add_page(&kbuf);
    ktest_assert_equal(kt, PAGE_SIZE, kbuf_get_free_length(&kbuf));

    kbuf_add_page(&kbuf);
    ktest_assert_equal(kt, PAGE_SIZE * 2, kbuf_get_free_length(&kbuf));

    char buf[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    kbuf_write(&kbuf, make_kernel_buffer(buf), 10);
    ktest_assert_equal(kt, PAGE_SIZE * 2 - 10, kbuf_get_free_length(&kbuf));

    kbuf_clear(&kbuf);
}

static void
kbuf_printf_overflow_test(struct Ktest *kt)
{
    struct Kbuf kbuf;

    kbuf_init(&kbuf);
    kbuf_add_page(&kbuf);

    // Leave only 10 bytes left in the buffer //
    int i;

    for (i = 0; i < PAGE_SIZE - 10; i++)
        kbuf_write(&kbuf, make_kernel_buffer(&i), 1);

    int ret = kbuf_printf(&kbuf, "This is longer than 10 characters");

    /**
     * Truncation still occurs, so the buffer is completely filled, but we
     * also get -ENOSPC.
    **/
    ktest_assert_equal(kt, -ENOSPC, ret);
    ktest_assert_equal(kt, PAGE_SIZE, kbuf.cur_pos.offset);
    kbuf_clear(&kbuf);
}

static void
kbuf_printf_test(struct Ktest *kt)
{
    struct Kbuf kbuf;

    kbuf_init(&kbuf);
    kbuf_add_page(&kbuf);

    struct Page *page = list_first_entry(&kbuf.pages, struct Page, page_list_node);
    ktest_assert_equal(kt, 0, list_ptr_is_head(&kbuf.pages, &page->page_list_node));
    int ret = kbuf_printf(&kbuf, "This is a test: %d\n", 100);

    ktest_assert_equal(kt, 20, ret);
    ktest_assert_equal(kt, 20, kbuf.cur_pos.offset);
    ktest_assert_equal_mem(kt, "This is a test 100\n", page->virt, 20);

    kbuf_clear(&kbuf);
}

static void
kbuf_printf_empty_buf_test(struct Ktest *kt)
{
    struct Kbuf kbuf;

    kbuf_init(&kbuf);
    int ret = kbuf_printf(&kbuf, "This is a test: %d\n", 10);

    ktest_assert_equal(kt, -ENOSPC, ret);
    ktest_assert_equal(kt, 0, kbuf.cur_pos.offset);
    kbuf_clear(&kbuf);
}

static void
kbuf_multiread_test(struct Ktest *kt)
{
    int read_size = KT_ARG(kt, 0, int);
    struct Page *tmp_page = page_alloc(2, PAL_KERNEL);
    struct Kbuf kbuf;

    kbuf_init(&kbuf);
    kbuf_add_page(&kbuf);
    kbuf_add_page(&kbuf);
    kbuf_add_page(&kbuf);
    kbuf_add_page(&kbuf);

    memset(tmp_page->virt, 0, PAGE_SIZE * 4);
    struct Page *pages[4];

    pages[0] = list_first_entry(&kbuf.pages, struct Page, page_list_node);
    pages[1] = list_next_entry(pages[0], page_list_node);
    pages[2] = list_next_entry(pages[1], page_list_node);
    pages[3] = list_next_entry(pages[2], page_list_node);

    ktest_assert_equal(kt, 0, list_ptr_is_head(&kbuf.pages, &pages[0]->page_list_node));
    ktest_assert_equal(kt, 0, list_ptr_is_head(&kbuf.pages, &pages[1]->page_list_node));
    ktest_assert_equal(kt, 0, list_ptr_is_head(&kbuf.pages, &pages[2]->page_list_node));
    ktest_assert_equal(kt, 0, list_ptr_is_head(&kbuf.pages, &pages[3]->page_list_node));

    /**
     * We write uint16_t values and do some math to try to reduce patterns
     * in buffer.
    **/
    int i, k;

    for (k = 0; k < 4; k++) {
        for (i = 0; i < PAGE_SIZE / 2; i++)
            ((uint16_t *)pages[k]->virt)[i] = ((i + k * PAGE_SIZE / 2) * 7) & 0xFFFF;
    }

    kbuf.cur_pos.offset = PAGE_SIZE * 4;
    int total_reads = PAGE_SIZE * 4 / read_size;

    for (i = 0; i < total_reads; i++) {
        int err = kbuf_read(&kbuf, i * read_size, make_kernel_buffer(tmp_page->virt +
            i * read_size), read_size);
        ktest_assert_equal(kt, read_size, err);

        size_t total_read_len = (i + 1) * read_size;
        int pages_len[4];

        pages_len[0] = (total_read_len > PAGE_SIZE) ? PAGE_SIZE : total_read_len;
        pages_len[1] = (total_read_len > PAGE_SIZE * 2) ? PAGE_SIZE : total_read_len - PAGE_SIZE;
        pages_len[2] = (total_read_len > PAGE_SIZE * 3) ? PAGE_SIZE : total_read_len - PAGE_SIZE * 2;
        pages_len[3] = (total_read_len > PAGE_SIZE * 4) ? PAGE_SIZE : total_read_len - PAGE_SIZE * 3;

        for (k = 0; k < 4; k++) {
            if (pages_len[k] > 0)
                ktest_assert_equal_mem(kt, pages[k]->virt, tmp_page->virt +
                    k * PAGE_SIZE, pages_len[k]);
        }
    }

    /**
     * If our read_size doesn't divide the kbuf size evenly, then read the
     * last of the buffer and verify the partial read happened correctly.
    **/
    if ((PAGE_SIZE * 4) % read_size) {
        int left_over = (PAGE_SIZE * 4) % read_size;
        int err = kbuf_read(&kbuf, total_reads * read_size,
            make_kernel_buffer(tmp_page->virt + total_reads * read_size), read_size);

        ktest_assert_equal(kt, left_over, err);
    }

    // At this point, the whole buffer should be written, so verify the whole thing //
    for (k = 0; k < 4; k++)
        ktest_assert_equal_mem(kt, pages[k]->virt, tmp_page->virt + k * PAGE_SIZE, PAGE_SIZE);

    kbuf_clear(&kbuf);
    page_free(tmp_page, 2);
}

static void
kbuf_read_from_offset_test(struct Ktest *kt)
{
    size_t read_len = KT_ARG(kt, 0, int);
    struct Page *tmp_page = page_alloc(0, PAL_KERNEL);
    struct Kbuf kbuf;

    kbuf_init(&kbuf);
    kbuf_add_page(&kbuf);

    struct Page *cur_page = list_first_entry(&kbuf.pages, struct Page, page_list_node);
    ktest_assert_equal(kt, 0, list_ptr_is_head(&kbuf.pages, &cur_page->page_list_node));
    int i;

    for (i = 0; i < PAGE_SIZE / 2; i++)
        ((uint16_t *)tmp_page->virt)[i] = (i * 7) & 0xFFFF;

    kbuf.cur_pos.offset = PAGE_SIZE;

    for (i = 0; i < PAGE_SIZE - read_len; i++) {
        int err = kbuf_read(&kbuf, i, make_kernel_buffer(tmp_page->virt), read_len);

        ktest_assert_equal(kt, read_len, err);
        ktest_assert_equal_mem(kt, cur_page->virt + i, tmp_virt->virt, read_len);
    }

    kbuf_clear(&kbuf);
    page_free(tmp_page, 0);
}

static void
kbuf_read_from_start_test(struct Ktest *kt)
{
    size_t read_len = KT_ARG(kt, 0, int);
    struct Page *tmp_page = page_alloc(0, PAL_KERNEL);
    struct Kbuf kbuf;

    kbuf_init(&kbuf);
    kbuf_add_page(&kbuf);

    struct Page *cur_page = list_first_entry(&kbuf.pages, struct Page, page_list_node);
    ktest_assert_equal(kt, 0, list_ptr_is_head(&kbuf.pages, &cur_page->page_list_node));
    int i;

    for (i = 0; i < PAGE_SIZE / 2; i++)
        ((uint16_t *)tmp_page->virt)[i] = (i * 7) & 0xFFFF;

    kbuf.cur_pos.offset = PAGE_SIZE;
    memset(tmp_page->virt, 0, PAGE_SIZE);

    int err = kbuf_read(&kbuf, 0, make_kernel_buffer(tmp_page->virt), read_len);
    ktest_assert_equal(kt, read_len, err);
    ktest_assert_equal_mem(kt, cur_page->virt, tmp_page->virt, read_len);

    kbuf_clear(&kbuf);
    page_free(tmp_page, 0);
}

static void
kbuf_read_past_the_end_test(struct Ktest *kt)
{
    size_t length = KT_ARG(kt, 0, int);
    struct Page *tmp_page = page_alloc(0, PAL_KERNEL);
    struct Kbuf kbuf;

    kbuf_init(&kbuf);
    kbuf_add_page(&kbuf);

    struct Page *cur_page = list_first_entry(&kbuf.pages, struct Page, page_list_node);
    ktest_assert_equal(kt, 0, list_ptr_is_head(&kbuf.pages, &cur_page->page_list_node));
    int i;

    for (i = 0; i < PAGE_SIZE / 2; i++)
        ((uint16_t *)tmp_page->virt)[i] = (i * 7) & 0xFFFF;

    kbuf.cur_pos.offset = length;
    memset(tmp_page->virt, 0, PAGE_SIZE);

    int err = kbuf_read(&kbuf, 0, make_kernel_buffer(tmp_page->virt), PAGE_SIZE);
    ktest_assert_equal(kt, length, err);
    ktest_assert_equal_mem(kt, cur_page->virt, tmp_page->virt, length);

    kbuf_clear(&kbuf);
    page_free(tmp_page, 0);
}

static void
kbuf_multiwrite_test(struct Ktest *kt)
{
    int k;
    int write_size = KT_ARG(kt, 0, int);
    struct Page *tmp_page = page_alloc(2, PAL_KERNEL);
    struct Kbuf kbuf;

    kbuf_init(&kbuf);
    kbuf_add_page(&kbuf);
    kbuf_add_page(&kbuf);
    kbuf_add_page(&kbuf);
    kbuf_add_page(&kbuf);

    struct Page *pages[4];
    pages[0] = list_first_entry(&kbuf.pages, struct Page, page_list_node);
    pages[1] = list_next_entry(pages[0], page_list_node);
    pages[2] = list_next_entry(pages[1], page_list_node);
    pages[3] = list_next_entry(pages[2], page_list_node);

    ktest_assert_equal(kt, 0, list_ptr_is_head(&kbuf.pages, &pages[0]->page_list_node));
    ktest_assert_equal(kt, 0, list_ptr_is_head(&kbuf.pages, &pages[1]->page_list_node));
    ktest_assert_equal(kt, 0, list_ptr_is_head(&kbuf.pages, &pages[2]->page_list_node));
    ktest_assert_equal(kt, 0, list_ptr_is_head(&kbuf.pages, &pages[3]->page_list_node));

    /**
     * We write uint16_t values and do some math to try to reduce patterns
     * in buffer.
    **/
    int i;

    for (i = 0; i < PAGE_SIZE; i++)
        ((uint16_t *)tmp_pages->virt)[i] = (i * 7) & 0xFFFF;

    int total_writes = PAGE_SIZE * 4 / write_size;

    for (i = 0; i < total_writes; i++) {
        int err = kbuf_write(&kbuf, make_kernel_buffer(tmp_page->virt + i * write_size),
            write_size);
        ktest_assert_equal(kt, write_size, err);

        size_t total_write_len = (i + 1) * write_size;
        int pages_len[4];

        pages_len[0] = (total_write_len > PAGE_SIZE) ? PAGE_SIZE : total_write_len;
        pages_len[1] = (total_write_len > PAGE_SIZE * 2) ? PAGE_SIZE :
            total_write_len - PAGE_SIZE;
        pages_len[2] = (total_write_len > PAGE_SIZE * 3) ? PAGE_SIZE :
            total_write_len - PAGE_SIZE * 2;
        pages_len[3] = (total_write_len > PAGE_SIZE * 4) ? PAGE_SIZE :
            total_write_len - PAGE_SIZE * 3;

        for (k = 0; k < 4; k++) {
            if (pages_len[k] > 0)
                ktest_assert_equal_mem(kt, pages[k]->virt,
                    tmp_page->virt + k * PAGE_SIZE, pages_len[k]);
        }
    }

    /**
     * If our write_size doesn't divide the kbuf size evenly, the write
     * the last of the buffer and verify the partial write happened
     * correctly.
    **/
    if ((PAGE_SIZE * 4) % write_size) {
        int left_over = (PAGE_SIZE * 4) % write_size;
        int err = kbuf_write(&kbuf, make_kernel_buffer(tmp_page->virt + total_write *
            write_size), write_size);

        ktest_assert_equal(kt, left_over, err);
    }

    /**
     * At this point, the whole buffer should be written, so verify the
     * whole thing.
    **/
    for (k = 0; k < 4; k++)
        ktest_assert_equal_mem(kt, pages[k]->virt, tmp_page->virt + k * PAGE_SIZE,
            PAGE_SIZE);

    kbuf_clear(&kbuf);
    page_free(tmp_page, 2);
}

static void
kbuf_write_two_page_test(struct Ktest *kt)
{
    size_t length = KT_ARG(kt, 0, int);
    struct Page *tmp_page = page_alloc(1, PAL_KERNEL);
    struct Kbuf kbuf;

    kbuf_init(&kbuf);
    kbuf_add_page(&kbuf);
    kbuf_add_page(&kbuf);
    int i;

    for (i = 0; i < PAGE_SIZE * 2; i++)
        ((char *)tmp_page->virt)[i] = i % 256;

    int err = kbuf_write(&kbuf, make_kernel_buffer(tmp_page->virt), length + PAGE_SIZE);
    ktest_assert_equal(kt, length + PAGE_SIZE, err);

    struct Page *cur_page = list_first_entry(&kbuf.pages, struct Page, page_list_node);
    struct Page *next_page = list_next_entry(cur_page, page_list_node);

    ktest_assert_equal(kt, 0, list_ptr_is_head(&kbuf.pages, &cur_page->page_list_node));
    ktest_assert_equal(kt, 0, list_ptr_is_head(&kbuf.pages, &next_page->page_list_node));
    ktest_assert_equal_mem(kt, cur_page->virt, tmp_page->vurt, PAGE_SIZE);
    ktest_assert_equal_mem(kt, next_page->virt, tmp_page->virt, length);

    kbuf_clear(&kbuf);
    page_free(tmp_page, 0);
}

static void
kbuf_write_one_page_test(struct Ktest *kt)
{
    size_t length = KT_ARG(kt, 0, int);
    struct Page *tmp_page = page_alloc(0, PAL_KERNEL);
    struct Kbuf kbuf;

    kbuf_init(&kbuf);
    kbuf_add_page(&kbuf);
    int i;

    for (i = 0; i < PAGE_SIZE; i++)
        ((char *)tmp_page->virt)[i] = i % 256;

    int err = kbuf_write(&kbuf, make_kernel_buffer(tmp_page->virt), length);
    ktest_assert_equal(kt, length, err);

    struct Page *cur_page = list_first_entry(&kbuf.pages, struct Page, page_list_node);
    ktest_assert_equal(kt, 0, list_ptr_is_head(&kbuf.pages, &cur_page->page_list_node));
    ktest_assert_equal_mem(kt, cur_page->virt, tmp_page->virt, length);

    kbuf_clear(&kbuf);
    page_free(tmp_page, 0);
}

static void
kbuf_add_page_test(struct Ktest *kt)
{
    struct Kbuf kbuf;

    kbuf_init(&kbuf);
    kbuf_add_page(&kbuf);

    ktest_assert_equal(kt, 1, !list_empty(&kbuf.pages));
    ktest_assert_equal(kt, 1, kbuf.page_count);
    ktest_assert_equal(kt, 0, kbuf.cur_pos.offset);

    kbuf_add_page(&kbuf);
    ktest_assert_equal(kt, 1, !list_empty(&kbuf.pages));
    ktest_assert_equal(kt, 2, kbuf.page_count);
    ktest_assert_equal(kt, 0, kbuf.cur_pos.offset);

    kbuf_clear(&kbuf);
    ktest_assert_equal(kt, 1, list_empty(&kbuf.pages));
    ktest_assert_equal(kt, 0, kbuf.page_count);
    ktest_assert_equal(kt, 0, kbuf.cur_pos.offset);
}

static void
kbuf_init_test(struct Ktest *kt)
{
    struct Kbuf kbuf;

    kbuf_init(&kbuf);

    ktest_assert_equal(kt, 1, list_empty(&kbuf.pages));
    ktest_assert_equal(kt, 0, kbuf.page_count);
    ktest_assert_equal(kt, 0, kbuf.cur_pos.offset);

    kbuf_clear(&kbuf);
}

static const struct KtestUnit kbuf_test_units[] = {
    KTEST_UNIT("kbuf-init-test", kbuf_init_test),
    KTEST_UNIT("kbuf-add-page", kbuf_add_page_test);

    KTEST_UNIT("kbuf-write-one-page-test", kbuf_write_one_page_test,
        (KT_INT(0)),
        (KT_INT(1)),
        (KT_INT(256)),
        (KT_INT(PAGE_SIZE))),

    KTEST_UNIT("kbuf-write-two-page-test", kbuf_write_two_page_test,
        (KT_INT(0)),
        (KT_INT(1)),
        (KT_INT(256)),
        (KT_INT(PAGE_SIZE))),

    KTEST_UNIT("kbuf-multi-write-test", kbuf_multiwrite_test,
        (KT_INT(32)),
        (KT_INT(64)),
        (KT_INT(256)),
        (KT_INT(PAGE_SIZE)),
        (KT_INT(PAGE_SIZE * 2)),
        (KT_INT(PAGE_SIZE * 4)),
        (KT_INT(10)),
        (KT_INT(100)),
        (KT_INT(1000)),
        (KT_INT(10000))),

    KTEST_UNIT("kbuf-read-from-start-test", kbuf_read_from_start_test,
        (KT_INT(0)),
        (KT_INT(1)),
        (KT_INT(20)),
        (KT_INT(256)),
        (KT_INT(2048)),
        (KT_INT(3000)),
        (KT_INT(PAGE_SIZE))),

    KTEST_UNIT("kbuf-read-past-the-end-test", kbuf_read_past_the_end_test,
        (KT_INT(0)),
        (KT_INT(1)),
        (KT_INT(20)),
        (KT_INT(256)),
        (KT_INT(2048)),
        (KT_INT(3000)),
        (KT_INT(PAGE_SIZE - 1))),

    KTEST_UNIT("kbuf-read-from-offset-test", kbuf_read_from_offset_test,
        (KT_INT(1)),
        (KT_INT(20)),
        (KT_INT(256)),
        (KT_INT(2048)),
        (KT_INT(3000)),
        (KT_INT(PAGE_SIZE - 1))),

    KTEST_UNIT("kbuf-multi-read-test", kbuf_multiread_test,
        (KT_INT(32)),
        (KT_INT(64)),
        (KT_INT(256)),
        (KT_INT(PAGE_SIZE)),
        (KT_INT(PAGE_SIZE * 2)),
        (KT_INT(PAGE_SIZE * 4)),
        (KT_INT(10)),
        (KT_INT(100)),
        (KT_INT(1000)),
        (KT_INT(10000))),

    KTEST_UNIT("kbuf-printf-overflow-test", kbuf_printf_overflow_test),
    KTEST_UNIT("kbuf-printf-test", kbuf_printf_test),
    KTEST_UNIT("kbuf-printf-empty-buf-test", kbuf_printf_empty_buf_test),
    KTEST_UNIT("kbuf-get-free-length-test", kbuf_get_free_length_test),
};

KTEST_MODULE_DEFINE("kbuf", kbuf_test_units);
