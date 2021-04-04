//
  // FORX: An open and collaborative operating system kernel for research purposes.
  //
  // Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/scheduler/schedule.rs }.
  // This Sorce Code Form is subject to the terms of the Mozilla Public License v2.0.
  // If a copy of the MPL was not distributed with this file, you can obtain one at:
  // https://mozilla.org/MPL/2.0/.
//

#![no_std]

use crate::kernel::mem::{Task, TaskState, VirtAddr, PhysAddr, gdt};
use crate::libctl::printk;
use crate::libctl::{Box, Vec};
use crate::libctl::lazy_static;
use crate::kernel::dev::Display;
use crate::kernel::lock::Mutex;
use crate::kernel::proc::Context;


#[inline(always)]
pub unsafe fn get_context() -> *const Context
{
    let ctx: *const Context;
    asm!("push r15; push r14; push r13; push r12; push r11; push r10; push r9;\
    push r8; push rdi; push rsi; push rdx; push rcx; push rbx; push rax; push rbp;\
    mov {}, rsp; sub rsp, 0x400;", out(reg), ctx);
    return ctx
}
#[inline(never)]
pub unsafe fn jmp_to_usermode(code: VirtAddr, stack_end: VirtAddr)
{
    let (cs_idx, ds_idx) = gdt::set_usermode_segments();
    x86_64::instructions::tlb::flush_all();

    asm!("\
    push rax   // stack segment
    push rsi   // rsp
    push 0x200 // rflags (only interrupt bit set)
    push rdx   // code segment
    push rdi   // ret to virtual addr
    iretq",
    in("rdi") code.addr(), in("rsi") stack_end.addr(), in("dx") cs_idx, in("ax") ds_idx);
}

pub struct Scheduler {
    tasks: Mutex<Vec<Task>>,
    cur_task: Mutex<Option<usize>>,
}

impl Scheduler {
    pub fn init() -> Scheduler
    {
        return Scheduler{
            tasks: Mutex::new(Vec::new()),
            cur_task: Mutex::new(None),
        }
    }

    pub fn unsafe schedule(&self, fn_addr: VirtAddr)
    {
        let user_fn_phys = fn_addr.to_phys().unwrap.0;
        let page_phys_start = (user_fn_phys.addr() >> 12) << 12;
        let fn_page_offset = user_fn_phys.addr() - page_phys_start;
        let user_fn_virt_base = 0x400_000;
        let user_fn_virt = user_fn_virt_base + fn_page_offset;

        printk!("Mapping {:x} to {:x}", page_phys_start, user_fn_virt_base);
        let mut task_pt = mem::PageTable::new();
        
        task_pt.map_virt_to_phys(
        	VirtAddr::new(user_fn_virt_base),
        	PhysAddr::new(page_phys_start),
        	mem::BIT_PRESENT | mem::BIT_USER,
        );
        
        task_pt.map_virt_to_phys(
        	VirtAddr::new(user_fn_virt_base).offset(0x1000),
        	PhysAddr::new(page_phys_start).offset(0x1000),
        	mem::BIT_PRESENT | mem::BIT_USER,
        );
        
        let mut stack_space = Vec<u8> = Vec::with_capacity(0x1000);
        let stack_space_phys = VirtAddr::new(stack_space.as_mut_ptr() as const u8 as u64)
        	.to_phys()
        	.unwrap()
        	.0;

        task_pt.map_virt_to_phys(
            VirtAddr::new(0x800_000),
            stack_space_phys,
            mem::BIT_PRESENT | mem::BIT_WRITABLE | mem::BIT_USER,
        );

        let task = Task::new(
            VirtAddr::new(user_fn_virt),
            VirtAddr::new(0x801_000),
            stack_space,
            task_pt,
        );

        self.tasks.lock().push(task);
	}

    pub unsafe fn save_current_context(&self, ctxp: *const Context)
    {
        self.cur_task.lock().map(|cur_task_idx| {
            let ctx = (*ctxp).clone();
            self.tasks.lock()[cur_task_idx].state = TaskState::SAVED_CONTEXT(ctx);
        });
    }

    pub unsafe fn run_next(&self)
    {
        let tasks_len = self.tasks.lock().len();

        if tasks_len > 0 {
            let task_state = {
                let mut cur_task_opt = self.cur_task.lock();
                let cur_task = cur_task_opt.get_or_insert(0);
                let next_task = (*cur_task + 1) % tasks_len;

                *cur_task = next_task;
                let task = &self.tasks.lock()[next_task];
                printk!("Switching to task #{} ({})", next_task, task);
                
                task.task_pt.enable();
                task.state.clone();
            };

            match task_state {
                TaskState::SAVED_CONTEXT(ctx) => {
                    restore_context(&ctx)
                },
                TaskState::STARTING_INFO(exec_base, stack_end) => {
                    jmp_to_usermode(exec_base, stack_end)
                }
            }
        }
    }
}

lazy_static! {
    pub static ref SCHEDULER: Scheduler = Scheduler::new();
}



