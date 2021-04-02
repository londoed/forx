//
  // FORX: An open and collaborative operating system kernel for research purposes.
  //
  // Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { libctl/syscalls/syscall.rs }.
  // This Sorce Code Form is subject to the terms of the Mozilla Public License v2.0.
  // If a copy of the MPL was not distributed with this file, you can obtain one at:
  // https://mozilla.org/MPL/2.0/.
//

use crate::printk;
use crate::structs::Vec;

const MSR_STAR: usize = 0xC0000081;
const MSR_LSTAR: usize = 0xC0000082;
const MSR_FMASK: usize = 0xC0000084;

pub unsafe fn syscall_init()
{
  let handler_addr = handle_syscall as *const () as u64;

  asm!("\
    xor rdx, rdx
    mov rax, 0x200
    wrmsr", in("rcx") MSR_FMASK, out("rdx") _);

  asm!("\
    mov rdx, rax
    shr rdx, 32
    wrmsr", in("rax") handler_addr, in("rcx") MSR_LSTAR, out("rdx") _);

  asm!("\
    xor rax, rax
    mov rdx, 0x230008 // use seg selectors 8, 16 for syscall and 43, 51 for sysret
    wrmsr", in("rcx") MSR_STAR, out("rax") _, out("rdx") _);
}

#[inline(never)]
fn sys0(a: u64, b: u64, c: u64, d: u64) -> i64
{
  printk!("sys0 {:x} {:x} {:x} {:x}", a, b, c, d);

  return 123
}

#[inline(never)]
fn sys1(a: u64, b: u64, c: u64, d: u64) -> i64
{
  printk("sys1 {:x} {:x} {:x} {:x}", a, b, c, d);

  return 456
}

#[naked]
fn handle_syscall()
{
  unsafe {
    asm!("\
      push rcx // backup registers for sysretq
      push r11
      push rbp // save callee-saved registers
      push rbx
      push r12
      push r13
      push r14
      push r15
      mov rbp, rsp // save rsp
      sub rsp, 0x400 // make some room in the stack
      push rax // backup syscall params while we get some stack space
      push rdi
      push rsi
      push rdx
      push r10"
    );
  }

  let syscall_stack: Vec<u64> = Vec::with_capacity(0x10000);
  let stack_ptr = syscall_stack.as_ptr();

  unsafe {
    asm!("\
      pop r10 // restore syscall params to their registers
      pop rdx
      pop rsi
      pop rdi
      pop rax
      mov rsp, rbx // move our stack to the newly allocated one
      sti // enable interrupts",
      inout("rbx") stack_ptr => _)
    );
  }

  let syscall: u64;
  let arg0: u64;
  let arg1: u64;
  let arg2: u64;
  let arg3: u64;

  unsafe {
    asm!("nop", out("rax") syscall, out("rdi") arg0, out("rsi") arg1, out("rdx") arg2, out("r10") arg3);
  }

  let ret: i64 = match syscall {
    0x595CA11A => sys0(arg0, arg1, arg2, arg3),
    0x595CA11B => sys1(arg0, arg1, arg2, arg3),
    _ => -1,
  };

  unsafe {
    asm!("\
      mov rbx, {} // save return value into rbx so that it's maintained through free
      cli", in(reg) ret
    );
  }

  drop(syscall_stack);

  unsafe {
    asm!("\
      mov rax, rbx // restore syscall return value from rbx to rax
      mov rsp, rbp // restore rsp from rbp
      pop r15 // restore callee-saved registers
      pop r14
      pop r13
      pop r12
      pop rbx
      pop rbp // restore stack and registers for sysretq
      pop r11
      pop rcx
      sysretq // back to userland",
      options(noreturn)
    );
  }
}


