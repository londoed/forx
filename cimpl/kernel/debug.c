/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/debug.c }.
 * Copyright (C) 2014, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <libctl/stdarg.h>
#include <forx/debug.h>
#include <libctl/snprintf.h>
#include <forx/spinlock.h>
#include <forx/drivers/console.h>
#include <forx/kparam.h>

#include <forx/arch/backtrace.h>
#include <forx/arch/reset.h>
#include <forx/arch/asm.h>

static Spinlock kprintf_lock = SPINLOCK_INIT();
static ListHead kp_output_list = LIST_HEAD_INIT(kp_output_list);
static int max_log_level = CONFIG_KERNEL_LOG_LEVEL;
KPARAM("kernel.loglevel", &max_log_level, KPARAM_LOGLEVEL);

void
kp_output_register(struct KpOutput *output)
{
    flag_clear(&output->flags, KP_OUTPUT_DEAD);

    using_spinlock(&kprintf_lock) {
        if (!list_node_is_in_list(&output->node))
            list_add_tail(&kp_output_list, &output->node);
    }
}

void
kp_output_unregister(struct KpOutput *rm_output)
{
    struct KpOutput *drop = NULL;

    using_spinlock(&kprintf_lock) {
        flag_set(&rm_output->flags, KP_OUTPUT_DEAD);

        if (rm_output->refs == 0) {
            list_del(&rm_output->node);
            drop = rm_output;
        }
    }

    if (drop && drop->ops->put)
        (drop->ops->put)(drop);
}

static void
kp_output_logline(int level, const char *line)
{
    struct KpOutput *output;
    struct KpOutput *tmp;
    ListHead drop_list = LIST_HEAD_INIT(drop_list);

    using_spinlock(&kprintf_lock) {
        /**
         * This iteration is safe even though we drop the lock, because
         * taking a ref ensures the output won't be removed while we're
         * writing to it.
        **/
        list_foreach_entry_safe(&kp_output_list, output, tmp, node) {
            if (flag_test(&output->flags, KP_OUTPUT_DEAD))
                continue;

            if (level != KERN_ERR && READ_ONCE(output->max_level) < level)
                continue;

            // Ensure this output doesn't get dropped while we're using it //
            output->refs++;

            not_using_spinlock(&kprintf_lock)
                (output->ops->print)(output, line);

            output->refs--;

            if (unlikely(flag_test(&output->flags, KP_OUTPUT_DEAD) && output->refs == 0)) {
                list_del(&output->node);
                list_add(&drop_list, &output->node);
            }
        }
    }

    if (unlikely(!list_empty(&drop_list))) {
        list_foreach_entry_safe(&drop_list, output, tmp, node) {
            if (output->ops->put)
                (output->ops->put)(output);
        }
    }
}

static const char *level_to_str[] = {
    [KERN_TRACE] = "[T]",
    [KERN_DEBUG] = "[D]",
    [KERN_NORM] = "[N]",
    [KERN_WARN] = "[W]",
    [KERN_ERR] = "[E]",
};

void
kpv_force(int level, const char *fmt, va_list list)
{
    // Max length of a kp line is 128 characters //
    char kp_buf[128];
    uint32_t kernel_time_ms = forx_uptime_get_ms();
    const char *prefix = "[!]";

    if (level >= 0 && level < 5)
        prefix = level_to_str[level];

    size_t prefix_len = snprintf(kp_buf, sizeof(kp_buf), "[%d.%03]%s: ", kernel_time_ms / 1000,
        kernel_time_ms % 1000, prefix);
    size_t end = snprintfv(kp_buf + prefix_len, sizeof(kp_buf) - prefix_len, fmt, list);

    // The line got cut-off--make sure a newline is still included, and add ~'s to let user know //
    if (prefix_len + end == sizeof(kp_buf) - 1) {
        kp_buf[sizeof(kp_buf) - 2] = '\n';
        kp_buf[sizeof(kp_buf) - 3] = '~';
        kp_buf[sizeof(kp_buf) - 4] = '~';
    }

    kp_output_logline(level, kp_buf);
}

void
kpv(int level, const char *fmt, va_list list)
{
    if (level > READ_ONCE(max_log_level))
        return;

    kpv_force(level, fmt, list);
}

void
kp(int level, const char *fmt, ...)
{
    va_list list;
    va_start(list, fmt);
    kpv(level, fmt, list);
    va_end(list);
}

void
kp_force(int level, const char *fmt, ...)
{
    va_list list;
    va_start(list, fmt);
    kpv_force(level, fmt, list);
    va_end(list);
}

int reboot_on_panic = 0;

static __noreturn void
__panicv_internal(const char *s, va_list list, int trace)
{
    // Switch VT to 0 so that the console is show to the user //
    console_switch_vt(0);
    cli();
    kvp(KERN_ERR, s, list);

    if (trace)
        dump_stack(KERN_ERR);

    if (reboot_on_panic)
        system_reboot();

    for (;;)
        hlt();
}

__noreturn void
__panicv_notrace(const char *s, va_list list)
{
    __panicv_internal(s, list, 0);
}

__noreturn void
__panic_notrace(const char *s, ...)
{
    va_list list;
    va_start(list, s);
    __panicv_notrace(s, list);
    va_end(list);
}

__noreturn void
__panicv(const char *s, va_list list)
{
    __panicv_internal(s, list, 1);
}

__noreturn void
__panic(const char *s, ...)
{
    va_list list;
    va_start(list, s);
    __panicv(s, list);
    va_end(list);
}
