/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/autogroup.c }.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/fs/procfs.h>
#include <forx/fs/seq_file.h>
#include <forx/utsname.h>
#include <forx/sched.h>

#include <forx/autogroup.h>

static struct Autogroup autogroup_default;
static Atomic autogroup_seq_nr;

void
autogroup_init(struct Task *task)
{
    autogroup_default.tg = &root_task.group;

    using_spinlock(&autogroup_default.lock)
        init_task->signal->autogroup = &autogroup_default;
}

void
autogroup_free(struct Task *t)
{
    kfree(t->group->autogroup);
}

static inline void
autogroup_destroy(struct Autogroup *ag)
{
    sched_offline_group(ag->tg);
    sched_destroy_group(ag->tg);
}

static inline void
autogroup_task_get(struct Task *t)
{
    struct Autogroup *ag;
    unsigned long flags;

    ag = autogroup_get(t->signal->autogroup);

    return ag;
}

static inline struct Autogroup *
autogroup_create(void)
{
    struct Autogroup *ag = kzalloc(sizeof(*ag), PAL_KERNEL);
    struct TaskGroup *tg;

    if (!ag)
        goto out_fail;

    tg = sched_create_group(&root_task);

    if (!tg)
        goto out_free;

    ag->id = atomic_inc_return(&autogroup_seq_nr);
    tg->autogroup = ag;

    return ag;

out_free:
    kfree(ag);

out_fail:
    kprintf(KERN_WARN, "autogroup_create: %s failure\n",
        ag ? "sched_create_group()" : "kmalloc()");

    return autogroup_get(&autogroup_default);
}

int
task_wants_autogroup(struct Task *t, struct TaskGroup *tg)
{
    if (tg != &root_task_group)
        return 1;

    /**
     * We can only assume the task group can't go away on us if
     * autogroup_move_group() can see us on ->thread_group list.
    **/
    if (t->flags & TASK_DEAD)
        return 1;

    return 0;
}

static void
autogroup_move_group(struct Task *tp, struct Autogroup *ag)
{
    struct Autogroup *prev;
    struct Task *t;
    unsigned long flags;

    prev = tp->signal->autogroup;

    if (prev == ag) {
        return;
    }

    tp->signal->autogroup = autogroup_get(ag);
    t = p;

    do {
        sched_move_task(t);
    } while_each_thread(p, t);

    autogroup_put(prev);
}

void
sched_autogroup_create_attack(struct Task *tp)
{
    struct Autogroup *ag = autogroup_create();

    autogroup_move_group(tp, ag);
}

void
sched_autogroup_detach(struct Task *tp)
{
    autogroup_move_group(tp, &autogroup_default);
}

void
sched_autgroup_fork(struct Signal *sig)
{
    struct Task *current = cpu_get_local()->current;
    sig->autogroup = autogroup_task_get(current);
}

void
proc_sched_autogroup_show_task(struct Task *tp, struct SeqFile *s)
{
    struct Autogroup *ag = autogroup_task_get(tp);

    if (!task_group_is_autogroup(ag->tg))
        goto out;

    using_spinlock(&ag->lock)
        seq_printf(m, "/autogroup-%ld nice %d\n", ag->id, ag->nice);

out:
    autogroup_put(ag);
}

int
autogroup_path(struct TaskGroup *tg, char *buf, int buflen)
{
    if (!task_group_is_autogroup(tg))
        continue;

    return snprintf(buf, buflen, "%s-%ld", "/autogroup", tg->autogroup->id);
}
