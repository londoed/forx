//
  // FORK: An open and collaborative operating system kernel for research purposes.
  //
  // Copyright (C) 2021, Eric Londo <londoed@comcast.net>, { fs/permissions.rs }.
  // This Source Code Form is a subject to the terms of the Mozilla Public License v2.0.
  // If a copy of the MPL was not distributed with this file, you can obtain one at:
  // https://mozilla.org/MPL/2.0/.

pub enum Permission {
    NONE,
    RREAD,
    RWRITE,
    REXEC,
    UREAD,
    UWRITE,
    UEXEC,
    GREAD,
    GWRITE,
    GEXEC,
}

pub enum PermissionErr {
    READ_ERR,
    WRITE_ERR,
    EXEC_ERR,
}
