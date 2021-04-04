//
  // FORX: An open and collaborative operating system kernel for research purposes.
  //
  // Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/heap/heap.rs }.
  // This Source Code Form is subject to the terms of the Mozilla Public License v2.0.
  // If a copy of the MPL was not distributed with this file, you can obtain one at:
  // https://mozilla.org/MPL/2.0/.
//

#![feature(const_fn)]
#![feature(alloc_api)]
#![no_std]

use crate::memory::alloc::{GlobalAlloc, MemLayout};
use crate::memory::EntryFlags;
use crate::kernel::mem::{KERNEL_HEAP_START, KERNEL_HEAP_INIT_SIZE};
use crate::kernel::lock::MutexIrqSafe;
use crate::kernel::Once;
use crate::libctl::structs::Box;
use crate::block::FixedSizeBlockAllocator;

#[global_allocator]
pub static GLOBAL_ALLOCATOR: Heap = Heap::empty();

#[cfg(direct_access_to_multi_heaps)]
pub static DEFAULT_ALLOCATOR: Once<Box<dyn GlobalAlloc + Send + Sync>> = Once::new();

#[cfg(not(direct_access_to_multi_heaps))]
static DEFAULT_ALLOCATOR: Once<Box<dyn GlobalAlloc + Send + Sync>> = Once::new();

pub const HEAP_FLAGS: EntryFlags = EntryFlags::WRITABLE;
const INIT_HEAP_END_ADDR: usize = KERNEL_HEAP_START + KERNEL_HEAP_INIT_SIZE;

pub fn init_single_heap(start_vaddr: usize, size_bytes: usize)
{
  unsafe {
    GLOBAL_ALLOCATOR.init_allocator.lock().init(start_vaddr, size_bytes)
  }
}

pub fn set_allocator(alloc: Box<dyn GlobalAlloc + Send + Sync>)
{
  DEFAULT_ALLOCATOR.call_once(|| alloc);
}

pub struct Heap {
  init_alloc: MutexIrqSafe<FizedSizeBlockAllocator>,
}

impl Heap {
  pub const fn empty() -> Heap
  {
    return Heap{
      init_allocator: MutexIrqSafe::new(FixedSizeBlockAllocator::new()),
    }
  }
}

unsafe impl GlobalAlloc for Heap {
  unsafe fn alloc(&self, layout: MemLayout) -> *mut u8
  {
    match DEFAULT_ALLOCATOR.get() {
      Some(allocator) => allocator.alloc(layout),
      None => self.init_allocator.lock().allocate(layout)
    }
  }

  unsafe fn dealloc(&self, ptr: *mut u8, layout: MemLayout)
  {
    if (ptr as usize) < INIT_HEAP_END_ADDR {
      self.init_allocator.lock().dealloc(ptr, layout);
    } else {
      DEFAULT_ALLOCATOR.get()
        .expect("[!] ERROR: Pointer passed to dealloc is not within the init allocators range")
        .dealloc(ptr, layout);
    }
  }
}
