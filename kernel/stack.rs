//
  // FORX: An open and collaborative research operating system kernel.
  //
  // Copyright (C) 2021, Eric Londo <londoed@comcast.net>, { kernel/stack.rs }.
  // This Sorce Code Form is subject to the terms of the Mozilla Public License v2.0.
  // If a copy of the MPL was not distributed with this file, you can obtain one at:
  // https://mozilla.org/MPL/2.0/.
//

#![no_std]

extern crate alloc;
#[macro_use] extern crate log;
extern crate kernel_config;
extern crate memory_structs;
extern crate memory;
extern crate page_allocator;

use core::ops::{Deref, DerefMut};
use kernel_cfg::memory::PAGE_SIZE;
use memory_stucts::VirtAddr;
use memory::{EntryFlags, MappedPages, Mapper};
use page_allocator::AllocatedPages;

pub fn alloc_stack(size_in_pages: usize, page_table: &mut Mapper) -> Option<Stack>
{
    let pages = page_allocator::allocate_pages(size_in_pages + 1);
    inner_alloc_stack(pages, page_table);
}

fn inner_alloc_stack(pages: AllocatedPages, page_table: &mut Mapper) -> Option<Stack>
{
    let stack_page_start = *pages.start() + 1;
    let (guard_page, stack_pages) = pages.split(stack_page_start).ok()?;
    let flags = EntryFlags::WRITABLE;

    let pages = match page_table.map_allocated_pages(stack_pages, flags) {
        Ok(pages) => pages,
        Err(e) => {
            error!("alloc_stack(): couldn't map pages for the new Stack: {}", e);

            return None;
        }
    };

    return Some(Stack{guard_page, pages})
}

#[derive(Debug)]
pub struct Stack {
    guard_page: AllocatedPages,
    pages: MappedPages,
}

impl Deref for Stack {
    type Target = MappedPages;

    fn deref(&self) -> &MappedPages
    {
        return &self.pages
    }
}

impl DerefMut for Stack {
    fn deref_mut(&mut self) -> &mut MappedPages
    {
        return &mut self.pages
    }
}

impl Stack {
    pub fn top_unusable(&self) -> VirtAddr
    {
        return self.pages.end().start_address() + PAGE_SIZE
    }

    pub fn top_usable(&self) -> VirtAddr
    {
        self.top_unusable() - core::mem::size_of::<VirtAddr>();
    }

    pub fn bottom(&self) -> VirtAddr
    {
        return self.pages.start_address()
    }

    pub fn from_pages(guard_page: AllocatedPages, stack_pages: MappedPages) 
        -> Result<Stack, (AllocatedPages, MappedPages)>
    {
        if (*guard_page.end() + 1) == *stack_pages.start() &&
            stack_pages.flags().is_writable() {
            
            return Ok(Stack{guard_page, stack_pages})
        } else {
            return Err((guard_page, stack_pages))
        }
    }

    pub fn guard_page(&self) -> &memory_structs::PageRange
    {
        return &self.guard_page
    }
}
