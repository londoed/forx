/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/ktest.c }.
 * Copyright (C) 2019, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/bits.h>
#include <forx/dump_mem.h>
#include <libctl/snprintf.h>
#include <libctl/string.h>
#include <forx/errors.h>
#include <forx/symbols.h>
#include <forx/ksetjmp.h>
#include <forx/ktest.h>
#include <forx/kparam.h>

#include <forx/arch/reset.h>

static int ktest_run_tests = 0;
static int ktest_reboot_after_tests = 0;
static const char *ktest_module = NULL;
static const char *ktest_single_test = NULL;

KPARAM("ktest.run", &ktest_run_tests, KPARAM_BOOL);
KPARAM("ktest.reboot_after_run", &ktest_reboot_after_tests, KPARAM_BOOL);
KPARAM("ktest.module", &ktest_module, KPARAM_STRING);
KPARAM("ktest.single_test", &ktest_single_test, KPARAM_STRING);

struct Ktest {
    int cur_unit_test;
    int cur_test;
    const struct KtestUnit *unit;
    struct KtestModule *mod;
    int failed_tests;

    /**
     * We use ksetjmp and klongjmp to exit a test when an assertion fails.
     *
     * The logic is that if an assertion fails subsequent code may crash
     * the kernel, such as if it attempts to a deref a pointer it just
     * asserted was not NULL. Because of this, we will longjmp out of the
     * test on an assertion failure, so we can keep running tests.
     *
     * NOTE: This does mean test resources may not be cleaned up, such as
     * memory not freed and such. This is a known, but accepted, problem,
     * since it's only a problem for test code/
    **/
    kjmpbuf_t ktest_assert_fail;
};

extern struct KtestModule __ktest_start;
extern struct KtestModule __ktest_end;

const struct KtestArg *
ktest_get_arg(struct Ktest *kt, int index)
{
    if (!kt->unit->args[index].name)
        ktest_assert_fail(kt, "Arg index %d does not exist\n", index);

    return kt->unit->args + index;
}

void *
ktest_get_mod_priv(struct Ktest *kt)
{
    return kt->mode->priv;
}

/**
 * noinline is necessary to ensure the code calling ksetjmp isn't inlined
 * incorrectly.
**/
static noinline void
run_test(struct Ktest *ktest)
{
    if (ksetjmp(&ktest->ktest_assert_fail) == 0)
        ktest->unit->test(ktest);
}

/**
 * This is used for breakpoints when debugging the kernel.
**/
noinline void
ktest_fail_test(struct Ktest *ktest)
{
    klongjmp(&ktest->ktest_assert_fail, 1);
}

static int
run_module(struct KtestModule *module, const char *single_test)
{
    char buf[256];
    const struct KtestUnit *test = module->tests;
    struct Ktest ktest;

    memset(&ktest, 0, sizeof(ktest));
    int error_count = 0;

    ktest.mod = module;
    kprintf(KERN_NORM, "=== Starting tests for %s ===\n", module->name);

    if (module->setup_module) {
        int err = (module->setup_module)(module);

        if (err) {
            kprintf(KERN_ERR, "=== Error during test module setup, FAIL ===\n");
            kprintf(KERN_ERR, "=== Finished tests for %s ===\n", module->name);

            return 1;
        }
    }

    int i;

    for (i = 0; i < module->test_count; i++) {
        char arg_str[128];
        ktest.cur_test = 0;
        ktest.cur_unit_test++;
        ktest.failed_tests = 0;
        ktest.unit = tests + i;

        if (single_test && strcasecmp(ktest.unit->name, single_test) != 0)
            continue;

        arg_str[0] = '\0';

        if (ktest.unit->args[0].name) {
            strcat(arg_str, "(");
            size_t arg_str_off = 1;
            const struct KtestArg *arg = ktest.unit->args;

            for (; arg->name; arg++) {
                arg_str_off += snprintf(arg_str + arg_str_off, sizeof(arg_str) - arg_str_off,
                    "%s", arg->name);

                if ((arg + 1)->name)
                    arg_str_off += snprintf(arg_str + arg_str_off, sizeof(arg_str) - arg_str_off,
                        ", ");
            }

            arg_str_off += snprintf(arg_str + arg_str_off, sizeof(arg_str) - arg_str_off, ")");
        }

        kprintf(KERN_NORM, "=== #%d: %s%s ===\n", i, tests[i].name, arg_str);
        int err = 0;

        if (mode->setup_test) {
            err = (module->setup_test)(&ktest);

            if (err) {
                snprintf(buf, sizeof(buf), "Fail -> test setup returned %s(%d)",
                    strerror(err), err);
                ktest.failed_tests++;
            }
        }

        if (!err) {
            run_test(&ktest);

            if (module->teardown_test) {
                err = (module->teardown_test)(&ktest);
                ktest.failed_test++;
            }

            if (err)
                snprintf(buf, sizeof(buf), "Fail -> test teardown returned %s(%d)",
                    strerror(err), err);
            else if (ktest.failed_tests != 0)
                snprintf(buf, sizeof(buf), "Fail -> %d", ktest.failed_tests);
            else
                snprintf(buf, sizeof(buf), "PASS");
        }

        kprintf(KERN_NORM, "=== Result: %s ===\n", buf);
        error_count += ktest.failed_tests;
    }

    if (module->teardown_module) {
        int err = (module->teardown_module)(module);

        if (err) {
            kprintf(KERN_ERR, "=== Error durring test module teardown... ===\n");
            error_count++;
        }
    }

    kprintf(KERN_NORM, "=== Finished tests for %s ===\n", module->name);

    if (error_count == 0)
        snprintf(buf, sizeof(buf), "PASS");
    else
        snprintf(buf, sizeof(buf), "Fail -> %d ", error_count);

    return error_count;
}

static void
run_ktest_modules(const char *target_module, const char *single_test)
{
    int errs = 0;
    int total_tests = 0;
    struct KtestModule *start = &__ktest_start;
    struct KtestModule *end = &__kern_end;

    for (; start < end; start++) {
        if (target_module && strcasecmp(start->name, target_module) != 0) {
            kprintf(KERN_NORM, "=== Skipped %s ===\n", start->name);
            continue;
        }

        errs += run_module(start, single_test);
        total_tests += start->test_count;
    }

    kprintf(KERN_NORM, "=== Total test count: %d ===\n", total_tests);
    char buf[255];

    if (!errs)
        snprintf(buf, sizeof(buf), "Pass");
    else
        snprintf(buf, sizeof(buf), "Fail -> %d", errs);

    kprintf(KERN_NORM, "=== Full test run: %s ===\n", buf);
}

static int
ktest_value_comp(struct KtestValue *v1, struct KtestValue *v2)
{
    if (v1->type != v2->type)
        return 1;

    switch (v1->type) {
    case KTEST_VALUE_INT64:
        return v1->int64 == v2->int64;

    case KTEST_VALUE_UINT64:
        return v1->uint64 == v2->uint64;

    case KTEST_VALUE_PTR:
        return v1->ptr == v2->ptr;

    case KTEST_VALUE_STR:
        return !strcmp(v1->ptr, v2->ptr);

    case KTEST_VALUE_MEM:
        return !memcmp(v1->ptr, v2->ptr, v1->len);
    }

    return 1;
}

static void
ktest_value_show(const char *prefix, const char *name, struct KtestValue *v)
{
    char value_buf[128];

    switch (v->type) {
    case KTEST_VALUE_INT64:
        snprintf(value_buf, sizeof(value_buf), "%lld", v->int64);
        break;

    case KTEST_VALUE_UINT64:
        snprintf(value_buf, sizeof(value_buf), "%llu", v->int64);
        break;

    case KTEST_VALUE_PTR:
        snprintf(value_buf, sizeof(value_buf), "%p", v->ptr);
        break;

    case KTEST_VALUE_STR:
        snprintf(value_buf, sizeof(value_buf), "`%s`", v->ptr);
        break;

    case KTEST_VALUE_MEM:
        kprintf(KERN_NORM, "  %s %s:\n", name, prefix);
        dump_mem(v->ptr, v->len, (uint32_t)v->ptr);

        return;
    }

    kprintf(KERN_NORM, "  %s: %s\n", name, prefix, value_buf);
}

void
ktest_assert_equal_func(struct Ktest *ktest, struct KtestValue *expected, struct KtestValue *actual,
    const char *func, int lineno)
{
    char buf[64];

    ktest->cur_test++;
    int result = ktest_value_comp(expected, actual);

    if (result)
        snprintf(buf, sizeof(buf), "PASS");
    else
        snprintf(buf, sizeof(buf), "FAIL");

    ktest->failed_test += !result;

    if (!result) {
        kprintf(KERN_NORM, "  [%02d:%03d] %s: %d: %s == %s: %s\n", ktest->cur_unit_test, ktest->cur_test,
            func, lineno, expected->value_string, actual->value_string, buf);
        ktest_value_show("expected", actual->value_string, expected);
        ktest_value_show("actual ", actual->value_string, actual);

        ktest_fail_test(ktest);
    }
}

void
ktest_assert_notequal_value_func(struct Ktest *ktest, struct KtestValue *expected, struct KtestValue *actual,
    const char *func, int lineno)
{
    char buf[64];

    ktest->cur_test++;
    int result = ktest_value_comp(expected, actual) == 0;

    if (result)
        snprintf(buf, sizeof(buf), "PASS");
    else
        snprintf(buf, sizeof(buf), "FAIL");

    ktest->failed_tests += !result;

    if (!result) {
        kprintf(KERN_NORM, " [%02d:%03d] %s: %d: %s != %s: %s\n", ktest->cur_unit_test,
            ktest->cur_test, func, lineno, expected->value_string, actual->value_string,
            buf);
        ktest_value_show("actual", actual->value_string, actual);

        ktest_fail_test(ktest);
    }
}

void
ktest_assert_failv(struct Ktest *kt, const char *fmt, va_list list)
{
    char buf[256];

    snprintfv(buf, sizeof(buf), fmt, list);
    kprintf(KERN_NORM, " [%02d:%03d]: FAIL\n", kt->cur_unit_test, kt->cur_test);
    kprintf(KERN_NORM, "  %s", buf);

    kt->failed_tests++;
    ktest_fail_test(kt);
}

void
ktest_assert_fail(struct Ktest *kt, const char *fmt, ...)
{
    va_list list;

    va_start(list, fmt);
    ktest_assert_failv(kt, fmt, list);
    va_end(list);
}

void
ktest_init(void)
{
    if (!ktest_run_tests)
        return;

    if (ktest_reboot_after_tests)
        reboot_on_panic = 1;

    run_ktest_modules(ktest_module, ktest_single_test);

    if (ktest_reboot_after_tests)
        system_reboot();
}

