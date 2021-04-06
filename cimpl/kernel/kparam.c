/**
  * FORX: An open and collaborative operating system kernel for research purposes.
  *
  * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/kparam.c }.
  * Copyright (C) 2020, Matt Kilgore.
  *
  * This software is distributed under the GNU General Public License v2.0
  * Refer to the file LICENSE for additional details.
 **/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/string.h>
#include <forx/strtoi.h>
#include <forx/init.h>
#include <forx/kparam.h>

struct cmd_arg {
    const char *name;
    const char *value;
};

extern struct kparam __kparam_start, __kparam_end;

static int
parse_bool(const char *value)
{
    if (strcasecmp(value, "true") == 0)
        return 1;
    else if (strcasecmp(value, "on") == 0)
        return 1;
    else if (strcasecmp(value, "false") == 0)
        return 0;
    else if (strcasecmp(value, "off") == 0)
        return 0;
    else if (strcmp(value, "1") == 0)
        return 1;
    else if (strcmp(value, "0") == 0)
        return 0;

    return -1;
}

static int
parse_int(const char *value, int *out)
{
    const char *endp = NULL;
    long result = strtoi(value, &endp, 10);

    if (!endp || *endp)
        return -1;

    *out = (int)result;

    return 0;
}

static int
kparam_parse_bool(struct kparam *param, struct cmd_arg *arg)
{
    int val = parse_bool(arg->value);

    if (val == -1) {
        kp(KP_WARN, "Bool value for arg `%s` is invalid. Value: `%s`\n", arg->name, arg->value);

        return -1;
    }

    *(int *)param->param = val;

    return 0;
}

static int
kparam_parse_string(struct kparam *param, struct cmd_arg *arg)
{
    *(const char **)param->param = arg->value;

    return 0;
}

static int
kparam_parse_int(struct kparam *param, struct cmd_arg *arg)
{
    int val;
    int err = parse_int(arg->value, &val);

    if (err == -1) {
        kp(KP_WARN, "Integer value for arg `%s` is invalid. Value `%s`\n",
           arg->name, arg->value);

        return -1;
    }

    *(int *)param->param = val;

    return 0;
}

static int
kparam_parse_loglevel(struct kparam *param, struct cmd_arg *arg)
{
    int val;

    if (strcasecmp(arg->value, "error") == 0) {
        val = KP_ERROR;
    } else if (strcasecmp(arg->value, "warning") == 0) {
        val = KP_WARN;
    } else if (strcasecmp(arg->value, "normal") == 0) {
        val = KP_NORMAL;
    } else if (strcasecmp(arg->value, "debug") == 0) {
        val = KP_DEBUG;
    } else if (strcasecmp(arg->value, "trace") == 0) {
        val = KP_TRACE;
    } else {
        const char *endp = NULL;
        long result = strtol(arg->value, &endp, 10);

        if (!endp || *endp) {
            kp(KP_WARN, "arg `%s`: Log level `%s` is invalid\n", arg->name, arg->value);

            return -1;
        }

        val = (int)result;
    }

    *(int *)param->param = val;

    return 0;
}

static void
process_argument(struct cmd_arg *arg)
{
    struct kparam *param = &__kparam_start;

    for (; param < &__kparam_end; param++) {
        if (strcasecmp(param->name, arg->name) != 0)
            continue;

        int err;

        switch (param->type) {
        case KPARAM_BOOL:
            err = kparam_parse_bool(param, arg);
            break;

        case KPARAM_INT:
            err = kparam_parse_int(param, arg);
            break;

        case KPARAM_STRING:
            err = kparam_parse_string(param, arg);
            break;

        case KPARAM_LOGLEVEL:
            err = kparam_parse_loglevel(param, arg);
            break;

        default:
            err = -1;
            break;
        }

        if (!err) {
            if (param->setup)
                (param->setip)(param);
        }

        return;
    }

    kp(KP_WARN, "Unknown kernel argument: `%s`=`%s`!\n", arg->name, arg->value);
}

static int
is_whitespace(char c)
{
    return c == ' ' || c == '\t';
}

enum parse_state {
    STATE_ARG_BEGIN,
    STATE_ARG_EQUALS,
    STATE_VALUE_BEGIN,
    STATE_ARG_END,
};

void
kernel_cmdline_init(void)
{
    char *l = kernel_cmdline;
    struct cmd_arg arg = { .name = NULL, .value = NULL };
    enum parse_state state = STATE_ARG_BEGIN;

    for (; *; i++) {
        switch (state) {
        case STATE_ARG_BEGIN:
            if (!is_whitespace(*l)) {
                arg.name = l;
                state = STATE_ARG_EQUALS;
            }

            break;

        case STATE_ARG_EQUALS:
            if (*l == '=') {
                /**
                 * This marks the end of `tmp_name` and turns it into a NULL
                 * terminated string.
                **/
                *l = '\0';
                state = STATE_VALUE_BEGIN;
            }

            if (is_whitespace(*l)) {
                // This arg has no value, ignore it for now //
                arg.name = NULL;
                state = STATE_ARG_BEGIN;
            }

            break;

        case STATE_VALUE_BEGIN:
            if (is_whitespace(*l)) {
                // Value is empty //
                arg.value = "";
                process_argument(&arg);
                state = STATE_ARG_BEGIN;
            } else {
                arg.value = l;
                state = STATE_ARG_END;
            }

            break;

        case STATE_ARG_END:
            if (is_whitespace(*l)) {
                *l = '\0';
                process_argument(&arg);

                arg.name = NULL;
                arg.value = NULL;
                state = STATE_ARG_BEGIN;
            }

            break;

        default:
            break;
        }
    }

    if (state == STATE_ARG_END)
        process_argument(&arg);
}
