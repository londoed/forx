//
  // FORK: An open and collaborative operating system kernel for research purposes.
  //
  // Copyright (C) 2021, Eric Londo <londoed@comcast.net>, { fs/file.rs }.
  // This Source Code Form is subject to the terms of the Mozilla Public License v2.0.
  // If a copy of the MPL was not distributed with this file, you can obtain one at:
  // https://mozilla.org/MPL/2.0/.
//

pub struct File {
   type: FileType,
   ref: i32,
   readable: Permission,
   writable: Permission,
   executable: Permission,
   pipe: Pipe,
   ino: Inode,
   off: bool
}

pub struct FileType {
    FD_NONE,
    FD_PIPE,
    FD_INODE,
}
