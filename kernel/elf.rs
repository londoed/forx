//
  // FORX: An open and collaborative operating system kernel for research purposes.
  //
  // Copyright (C) 2021, Eric Londo <londoed@comcast.net>, { kernel/elf.rs }.
  // This Source Code Form is subject to the terms of the Mozilla Public License v2.0.
  // If a copy of the MPL was not distributed with this file, you can obtain one at:
  // https://mozilla.org/MPL/2.0.
//

#![no_std]

use crate::libctl::syscall::*;

pub enum ElfType {
    NULL,
    PROGRAM,
    SYMBOL_TABLE,
    STRING_TABLE,
    RELA,
    HASH,
    DYNAMIC,
    NOTE,
    BSS,
}

pub enum ElfFlags {
    WRITE = 1,
    MEMORY = 2,
    EXEC = 8,
    MERGE = 16,
    STRINGS = 32,
    INFO_LINK = 64,
    LINK_ORDER = 128,
    MON_STANDARD = 256,
    GROUP = 512,
    TLS = 1024,
}

pub struct ElfHeader {
    ident: &str,
    typ: ElfType,
    machine: u16,
    version: u32,
    entry: u32,
    prg_offset: u32,
    section_offset: u32,
    flags: u32,
    header_size: u16,
    phent_size: u16,
    phnum: u16,
    shent_size: u16,
    shnum: u16,
    shstrndx: u16,
}

impl ElfHeader {
    
}

pub struct ElfProgram {
    typ: ElfType,
    offset: u32,
    vaddr: u32,
    paddr: u32,
    file_size: u32,
    mem_size: u32,
    flags: u32,
    align: u32,
}


pub struct ElfSection {
    name: u32,
    typ: ElfType,
    flags: u32,
    addr: u32,
    offset: u32,
    size: u32,
    link: u32,
    info: &str,
    alignment: u32,
    entry_size: u32,
}


