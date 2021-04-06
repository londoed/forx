/**
 * FORX: An open and collaborative operating system kernel for the research community.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { include/klog.h }.
 * Copyright (C) 2019, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#ifndef FORX_KLOG_H
#define FORX_KLOG_H

#include <forx/types.h>
#include <forx/file.h>

void klog_init(void);

extern const struct FileOps klog_file_ops;

#endif
