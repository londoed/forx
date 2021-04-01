//
  // FORX: An open and collaborative operating system kernel for research purposes.
  //
  // Copyright (C) 2021, Eric Londo <londoed@comcast.net>, { kernel/scheduler/schedule.rs }.
  // This Sorce Code Form is subject to the terms of the Mozilla Public License v2.0.
  // If a copy of the MPL was not distributed with this file, you can obtain one at:
  // https://mozilla.org/MPL/2.0/.
//

#![no_std]

extern crate alloc;
extern crate apic;
extern crate task;
use crate::runqueue;
use crate::scheduler_priority::select_next_task;
use crate::scheduler_round_robin::select_next_task;

use crate::librs::ops::Deref;
use irq_safety::hold_interrupts;
use apic::get_my_apic_id;
use task::{Task, get_my_current_task, TaskRef};

pub fn schedule() -> bool
{
    let _held_interrupts = hold_interrupts();
    let current_mask: *mut Task;
    let next_task: *mut Task;
    let apic_id = get_my_apic_id();

    {
        if let Some(selected_next_task) = select_next_task(apic_id) {
            next_task = selected_next_task.lock().deref() as *const as *mut Task;
        } else {
            return false;
        }
    }

    if next_task as usize == 0 {
        return false;
    }

    {
        current_task = get_my_current_task().expect("schedule(): get_my_current_task() failed")
            .lock()
            .deref() as *const Task as *mut Task;
    }

    if current_task == next_task {
        return false;
    }

    let (curr, next) = unsafe {
        (&mut *current_task, &mut *next_task)
    };

    curr.task_switch(next, apic_id);

    return true
}

pub fn set_priority(_task: &TaskRef, _priority: u8) -> Result<(), &'static str>
{
    #[cfg(priority_scheduler)] {
        scheduler_priority::set_priority(_task, _priority)
    }

    #[cfg(not(priority_scheduler))] {
        Err("no scheduler that uses task priority is currently loaded")
    }
}

pub fn get_priority(_task: &TaskRef) -> Option<u8>
{
    #[cfg(priority_scheduler)] {
        scheduler::priority::get_priority(_task)
    }

    #[cfg(not(priority_scheduler))] {
        None
    }
}
