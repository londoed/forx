//
  // FORK: An open and collaborative operating system kernel for research purposes.
  //
  // Copyright (C) 2021, Eric Londo <londoed@comcast.net>, { fs/inode.rs }.
  // This Source Code Form is subject to the terms of the Mozilla Public License v2.0.
  // If a copy of the MPL was not distributed with this file, you can obtain one at:
  // https://mozilla.org/MPL/2.0/.
//

pub struct Inode {
    device: Device,
    ino_id: u32,
    ref_count: i32,
    lock: LockType,
    valid: bool,
    typ: InodeType,
    major: i16,
    minor: i16,
    nlink: i16,
    size: u32,
    addrs: Vec<u32>,
    writable: Permission,
    readable: Permission,
    executable: Permission,
}

pub enum InodeType {
   REGULAR,
   DIR,
   BLOCK,
   CHAR,
   FIFO,
   SYMLINK,
   SHADOW,
   ATTRDIR,
}

pub type InodeCache = Vec<Inode>;

impl Inode {
    pub fn new(&self, table: ProcTable, ino_id: u32, typ: InodeType, dev: Device, 
        cache: InodeCache, sb: SuperBlock) -> Self
    {
        mut i = 0;
        sb.lock_type.init();
        
        while i < NUM_INODES {
            cache[i].lock.init();
            i++;
        }

        sb.read(&dev);

        return Self{
            device: dev,
            ino_id: ino_id,
            ref_count: 0,
            lock: LockType,
            valid: true,
            typ: typ,
            major: None,
            minor: None,
            nlink: table.size(),
            size: 1024,
            addrs: None,
            writable: Process::NONE,
            readable: Process::NONE,
            executable: Process::NONE,
        }
    }

    pub fn device(&self) -> Device {
        return self.device
    }

    pub fn set_device(&mut self, dev: Device) {
        self.device = dev;
    }

    pub fn inode_id(&self) -> u32 {
        return self.ino_id
    }

    pub fn set_id(&self, id: u32) {
        self.ino_id = id;
    }

    pub fn ref_count(&self) -> i32 {
        return self.ref_count
    }

    pub fn set_ref_count(&mut self, ref_count: i32) {
        self.ref_count = ref_count;
    }

    pub fn lock_type(&self) -> LockType {
        return self.lock
    }

    pub fn set_lock(&mut self, lock: LockType)
    {
        self.lock = lock;
    }

    pub fn valid(&self) -> bool {
        return self.valid
    }

    pub fn set_valid(&mut self)
    {
        self.valid = !self.valid;
    }

    pub fn inode_type(&self) -> InodeType {
        return self.typ
    }

    pub fn set_inode_type(&mut self, ino_type: InodeType) {
        self.typ = ino_type;
    }

    pub fn nlink(&self) -> u64 {
        return self.nlink
    }

    pub fn size() -> u64 {
        return self.size
    }

    pub fn addrs(&self) -> Vec<VirtAddr> {
        return self.addrs
    }

    pub fn writeable(&self) -> Permission {
        return self.writable
    }

    pub fn set_write_perm(&mut self, perm: Permission) {
        self.writable = perms;
    }

    pub fn readable(&self) -> Permission {
        return self.readable
    }

    pub fn set_read_perm(&mut self, perm: Permission) {
        self.readable = perm;
    }

    pub fn executable(&self) -> Process {
        return self.executable
    }

    pub fn set_exec_perm(&mut self, perm: Permission) {
        self.executable = perm;
    }
}

