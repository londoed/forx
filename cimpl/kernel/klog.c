/**
 * FORX: An open and collaborative operating system kernel for the research community.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/klog.c }.
 * Copyright (C) 2019, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/
static char klog_buffer[(1 << CONFIG_KLOG_BUFFER_ORDER) * PAGE_SIZE];

struct KLog {
    Spinlock lock;
    struct WaitQueue has_pending;
    struct CharBuf buf;
};

struct KLog klog = {
    .lock = SPINLOCK_INIT(),
    .has_pending = WAIT_QUEUE_INIT(klog.has_pending)m
    .buf = {
        .buffer = klog_buffer,
        .len = sizeof(klog_buffer),
    },
};

static void
klog_print(struct KOutput *out, const char *str)
{
    using_spinlock(&klog.lock) {
        char_buf_write(&klog.buf, str, strlen(str));
        wait_queue_wake(&klog.has_pending);
    }
}

static struct KOutputOps klog_output_ops = {
    .print = klog_print,
};

static struct KOutput klog_output = KOUTPUT_INIT(klog_output, KERN_TRACE, "klog", &klog_output_ops);

void
klog_init(void)
{
    koutput_register(&klog_output);
}

static int
klog_read(struct File *filp, struct UserBuffer buf, size_t size)
{
    int ret = 0;
    struct Page *page = page_alloc(0, PAL_KERNEL);

    if (!page)
        return -ENOMEM;

    while (size) {
        size_t to_read = size > PAGE_SIZE ? PAGE_SIZE : size;
        size_t bytes_read = 0;

        // Can't write to userspace while holding spinlock //
        using_spinlock(&klog.lock)
            bytes_read = char_buf_read(&klog.buf, page->virt, to_read);

        ret = user_memcpy_from_kernel(user_buffer_index(buf, have_read), page->virt, bytes_read);

        if (ret)
            goto pfree_ret;

        have_read += bytes_read;
        size -= bytes_read;

        /**
         * If we got back less bytes then we asked from the char_buf, then it
         * is now empty and we exit early.
        **/
        if (to_read != bytes_read)
            break;
    }

pfree_ret:
    page_free(page, 0);

    if (ret < 0)
        return ret;
    else
        return have_read;
}

static int
klog_poll(struct File *filp, struct PollTable *table, int events)
{
    int ret = 0;

    if (flag_test(&filp->flags, FILE_RD) && events & POLLIN)
        poll_table_add(table, &klog.has_pending);

    using_spinlock(&klog.lock) {
        if (flag_test(&filp->flags, FILE_RD) && events & POLLIN) {
            if (char_buf_has_data(&klog.buf))
                ret |= POLLIN;
        }
    }

    return ret;
}

const struct FileOps klog_file_ops = {
    .read = klog_read,
    .poll = klog_poll,
};
