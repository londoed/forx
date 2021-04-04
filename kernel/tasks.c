/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/tasks.c }.
 * Copyright (C) 2011-2020 Lukas Martini.
 * This Source Code Form is subject to the terms of the Mozilla Public License v2.0.
 * If a copy of the MPL was not distributed with this file, you can obtain one at:
 * https://mozilla.org/MPL/2.0/.
**/

#include <forx/tasks.h>
#include <forx/mem.h>
#include <forx/int.h>
#include <forx/fs.h>
#include <string.h>
#include <errno.h>

#define KERNEL_STACK_SIZE PAGE_SIZE * 4

static uint32_t hi_pid = 0;
static size_t sfs_read(struct VfsCallbackCtx *ctx, void *dest, size_t size);

static Task *
alloc_task(Task *parent, Pid pid, char name[VFS_NAME_MAX], char **env, uin32_t envc,
  char **argv, uint32_t argc)
{
  Task *task = zmalloc(sizeof(Task));

  task->vmem_ctx = zmalloc(sizeof(struct VMemCtx));
  task->state = palloc(1);
  bzero(task->state, sizeof(InterStackFrame));
  vmem_map_flat(task->vmem_ctx, task->state, PAGE_SIZE, VM_FREE);

  // Kernel stack used during interrupts while task is running //
  task->kstack = palloc(4);
  vmem_map_flat(task->vmem_ctx, task->kstack, KSTACK_SIZE, VM_FREE);

  /**
   * Map parts of the kernel marked as UL_VISIBLE into the task address space,
   * but readable only to PL0. These are functions and data structures used in the
   * interrupt handler before the paging context is switched.
  **/
  vmap_map_flat(task->vmem_ctx, UL_VISIBLE_START, UL_VISIBLE_SIZE);

  task->pid = pid ? pid : __sync_add_and_fetch(&hi_pid, 1);
  task->state = TASK_RUNNING;
  task->interrupt_yield = false;

  strcpy(task->name, name);
  memcpy(task->cwd, parent ? parent->cwd : "/", VFS_PATH_MAX);

  task->parent = parent;
  task->envc = envc;
  task->env = kmalloc(sizeof(char *) * task->envc);
  task->argv = kmalloc(sizeof(char *) * task->argc);

  for (int i = 0; i < task->envc; i++)
    task->env[i] = strdup(env[i]);

  for (int i = 0; i < task->argc; i++)
    task->argv[i] = strdup(argv[i]);

  char tname[10];
  snprintf(tname, 10, "task%d", task->pid);

  struct VfsCallbacks sfs_cb = {
    .read = sfs_read,
  };

  task->sysfs_file = sysfs_add_file(tname, &sfs_cb);
  task->sysfs_file->meta = (void *)task;

  return task;
}

/**
 * Sets up a new task, including the necessary paging context, stacks, interrupt stack
 * frame, etc. The binary still has to be mapped into the paging context separately
 * (usually in the ELF loader).
**/
Task *
task_new(Task *parent, Pid *pid, char name[VFS_NAME_MAX], char **env, uint32_t envc,
  char **argv, uint32_t argc)
{
  Task *task = alloc_task(parent, pid, name, env, envc, argv, argc);

  // Allocate initial stack. Will dynamically grow, so be conservative //
  task->stack_size = PAGE_SIZE * 2;
  task->stack = zpalloc(task->stack_size / PAGE_SIZE);
  vmem_map(task->vmem_ctx, (void *)TASK_STACK_LOC - task_stack_size, task->stack,
    task->stack_size, VM_USER | VM_RW | VM_FREE | VM_TFORK);

  vfs_open(task, "/dev/stdin", O_RDONLY);
  vfs_open(task, "/dev/stdout", O_WRONLY);
  vfs_open(task, "/dev/stderr", O_WRONLY);

  return task;
}

void
task_set_init_state(Task *task)
{
  task_setup_execdata(task);
  task->state->ds = GDT_SEG_DATA_PL3;
  task->state->cr3 = (uint32_t)vmem_get_hwdata(task->vmem_ctx);
  task->state->ebp = 0;
  task->state->esp = (void *)TASK_STACK_LOCK - sizeof(IRet);

  // Return stack for IRet //
  IRet *iret = task->stack + task->stack_size - sizeof(IRet);
  iret->eip = task->entry;
  iret->cs = GDT_SEG_CODE_PL3;
  iret->eflags = EFLAGS_IF;
  iret->user_esp = (void *)TASK_STACK_LOC;
  iret->ss = GDT_SEG_DATA_PL3;
}

/**
 * Called by the scheduler whenever a task terminates from the userland
 * perspective. For example, this is called when a task changes to
 * TASK_TERMINATED, but not for TASK_REPLACED, since that task lives on
 * from the userland point of view.
**/
void
task_userland_eol(Task *t)
{
  t->task_state = TASK_ZOMBIE;
  Task *init = sched_find(1);
  Task *i;
  for (i = t->next; i->next != t->next; i = i->next) {
    if (i->parent == t)
      i->parent = init;
  }

  if (t->parent) {
    if (t->parent->task_state == TASK_WAITING)
      wait_finish(t->parent, t);

    task_signal(t->parent, t, SIGCHLD, t->parent->state);
  }

  if (t->ctty && t == t->ctty->fg_task)
    t->city->fg_task = t->parent;

  if (t->strace_observer && t->strace_fd)
    vfs_close(t->strace_observer, t->strace_fd);
}

/**
 * Called by the scheduler whenever it encounters a task with TASK_REAPED or
 * TASK_REPLACED. Should deallocate all task objects, but be transparent
 * to userspace.
**/
void
task_cleanup(Task *t)
{
  // Could have already been removed by execve //
  if (t->sysfs_file)
    sysfs_rm_file(t->sysfs_file);

  task_free(t);
}

static Task *
_fork(Task *to_fork, InterStackFrame *state)
{
  Task *task = alloc_task(to_fork, 0, to_fork->name, to_fork->env, to_fork->envc,
    to_fork->argv, to_fork->argc);

  memcpy(task->cwd, to_fork->cwd, VFS_PATH_MAX);
  memcpy(task->state, state, sizeof(InterStackFrame));
  memcpy(task->kstack, to_fork->kstack, KSTACK_SIZE);
  memcpy(task->bin_path, to_fork->bin_path, sizeof(task->binary_path));
  memcpy(task->files, to_fork->files, sizeof(VfsFile) * VFS_MAX_OPENFILES);

  task->uid = to_fork->uid;
  task->gid = to_fork->gid;
  task->euid = to_fork->euid;
  task->egid = to_fork->egid;
  task->ctty = to_fork->ctty;
  task->stack_size = to_fork->stack_size;
  task->sbrk = to_fork->sbrk;
  
  // TODO: Transfer potentially updated environment //
  task_setup_execdata(task);

  // Adjust kernel esp //
  intptr_t diff = state->esp - to_fork->kstack;
  task->state->esp = task->kstack + diff;
  struct VMemRange *range = to_fork->vmem_ctx->ranges;

  for (; range; range = range->next) {
    if (!(range->flags & VM_TFORK))
      continue;

    /**
     * Can't do copy on write/merging with pages where we don't control
     * deallocation.
    **/
    // if (range->flags & VM_NOCOW || !(range->flags & (VM_FREE | VM_COW))) { //
    if (range->flags & VM_RW) {
      PhysAddr *pa = zpalloc(range->size / PAGE_SIZE);
      memcpy(pa, range->phys_addr, range->size);
      vmem_map(task->vmem_ctx, range->virt_addr, pa, range->size, range->flags);
      continue;
    }

    if (!range->ref_count) {
      range->ref_count = kmalloc(sizeof(uint16_t));
      *range->ref_count = 1;
    }

    int flags = range->flags;

    if (range->flags & VM_RW) {
      range->flags |= VM_COW;
      flags |= VM_COW;
    }

    struct VMemRange *new_range = vmem_map(task->vmem_ctx, range->virt_addr, range->phys_addr,
      range->size, flags);
    __sync_add_and_fetch(range->ref_count, 1);
    new_range->ref_count = range->ref_count;
  }

  task->state->cr3 = (uint32_t)vmem_get_hwdata(task->vmem_ctx);

  /**
   * Set syscall return values for the forked task--need to set here since
   * the regular syscall return handling only affects the main process.
  **/
  task->state->eax = 0;
  task->state->ebx = 0;
  sched_add(task);

  return task;
}

int
task_fork(Task *to_fork, InterStackFrame *state)
{
  Task *task = _fork(to_fork, state);

  if (task)
    return task->pid;
  else
    return -1;
}

int
task_exit(Task *task, int code)
{
  task->state = TASK_TERMINATED;
  task->exit_code = code << 8;
  task->inter_yield = true;

  return 0;
}

// Task setuid/setgid //
int
task_setid(Task *task, int which, int id)
{
  if (task->euid != 0) {
    sc_errno = EPERM;

    return -1;
  }

  switch (which) {
  case 0:
    task->uid = id;
    task->euid = id;

    return 0;

  case 1:
    task->gid = id;
    task->egid = id;

    return 0;
  }

  sc_errno = EINVAL;

  return -1;
}

int
task_execve(Task *task, char *path, char **argv, char **env)
{
  uint32_t __argc = 0;
  uint32_t __envc = 0;
  char **__argv = task_copy_strings(task, argv, &__argc);
  char **__env = task_copy_strings(task, env, &__envc);

  if (!__argv || !__env) {
    klog(KLOG_WARN, "execve: array check failed\n");

    return 0;
  }

  /**
   * Normally removed in task_cleanup(), but it may take until after this
   * function is done for the scheduler to invoke it. Since task_new adds a
   * new sysfs file, remove the old one here to avoid conflicts.
  **/
  if (task->sysfs_file)
    sysfs_rm_file(task->sysfs_file);

  task->sysfs_file = NULL;

  Task *new_task = task_new(task->parent, task->pid, path, __env, __envc, __argv, __argc);
  kfree_array(__argv, __argc);
  kfree_array(__evc, __envc);
  memcpy(new_task->cwd, task->cwd, VFS_PATH_MAX);

  new_task->uid = task->uid;
  new_task->gid = task->gid;
  new_task->euid = task->euid;
  new_task->egid = task->egid;
  new_task->strace_observer = task->strace_observer;
  new_task->strace_fd = task->strace_fd;
  new_task->ctty = task->ctty;

  if (elf_load_file(new_task, path) == -1)
    return -1;

  for (int i = 0; i < VFS_MAX_OPENFILES; i++) {
    struct VfsFile *file = &task->files[i];

    /**
     * TODO: Flags seem to get mangled during fork/execve.
    **/
    // if (file->refs && !(file->flags & O_CLOEXEC)) {
    if (file->refs)
      memcpy(&new_task->files[i], file, sizeof(struct VfsFile));
  }

  sched_add(new_task);
  task->state = TASK_REPLACED;
  task->interrupt_yield = true;

  return 0;
}

int
task_chdir(Task *task, const char *dir)
{
  if (vfs_access(task, dir, R_OK | X_OK) < 0)
    return -1;

  int fd = vfs_open(task, dir, O_RDONLY);

  if (fd == -1)
    return -1;

  VfsStat *stat = kmalloc(sizeof(VfsStat));

  if (vfs_fstat(task, fd, stat) != 0) {
    kfree(stat);
    vfs_close(task, fd);
    sc_errno = ENOENT;

    return -1;
  }

  if (vfs_mode_to_filetype(stat->st_mode) != FT_IFDIR) {
    vfs_close(task, fd);
    sc_errno = ENOTDIR;

    return -1;
  }

  kfree(stat);
  strcpy(task->cwd, vfs_get_from_id(fd, task)->path);
  vfs_close(task, fd);

  return 0;
}

int
task_strace(Task *task, InterStackFrame *state)
{
  Task *fork = _fork(task, state);

  if (!fork)
    return -1;

  int pipe[2];

  if (vfs_pipe(task, pipe) != 0)
    return -1;

  fork->strace_observer = task;
  fork->strace_fd = pipe[1];

  return pipe[0];
}

static size_t
sfs_read(struct VfsCallbackCtx *ctx, void *dest, size_t size)
{
  if (ctx->fp->offset)
    return 0;

  size_t rsize = 0;
  Task *task = (Task *)ctx->fp->meta;

  sysfs_printf("%-10s: %d\n", "pid", task->pid);
  sysfs_printf("%-10s: %d\n", "uid", task->uid);
  sysfs_printf("%-10s: %d\n", "euid", task->euid);
  sysfs_printf("%-10s: %d\n", "gid", task->gid);
  sysfs_printf("%-10s: %d\n", "egid", task->egid);
  sysfs_printf("%-10s: %s\n", "name", task->name);
  sysfs_printf("%-10s: 0x%x\n", "stack", task->stack);
  sysfs_printf("%-10s: 0x%x\n", "entry", task->entry);
  sysfs_printf("%-10s: 0x%x\n", "sbrk", task->sbrk);
  sysfs_printf("%-10s: %d\n", "state", task->state);
  sysfs_printf("%-10s: %s\n", "cwd", task->cwd);
  sysfs_printf("%-10s: %s\n", "tty", task->ctty ? task->ctty->path : "");
  sysfs_printf("%-10s: %d\n", task->argc);
  sysfs_printf("%-10s: ", "argv");

  for (int i = 0; i < task->argc; i++)
    sysfs_printf("%s ", task->argv[i]);

  sysfs_printf("\n");
  sysfs_printf("%-10s: ", "env");

  for (int i = 0; i < task->envc; i++)
    sysfs_printf("%s ", task->env[i]);

  sysfs_printf("\n");
  sysfs_printf("\nOpen files:\n");

  for (int i = 0; i < VFS_MAX_OPENFILES; i++) {
    if (!task->files[i].inode)
      continue;

    sysfs_printf("%3d %-10s %s\n", i,
      vfs_flags_verbose(task->files[i].flags), task->files[i].path);
  }

  sysfs_printf("\nTask memory:\n");
  struct VMemRange *range = task->vmem_ctx->ranges;

  for (; range; range = range->next) {
    sysfs_printf("0x%-8x -> 0x%-8x length 0x%-6x\n", range->virt_addr,
      range->phys_addr, range->size);
  }

  return rsize;
}
