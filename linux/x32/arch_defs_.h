/*
 * Copyright (c) 2018-2019 The strace developers.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#define ARCH_TIMESIZE 8
#define HAVE_ARCH_OLD_MMAP 1
#define HAVE_ARCH_OLD_SELECT 1
#define HAVE_ARCH_UID16_SYSCALLS 1
#define HAVE_ARCH_OLD_TIME64_SYSCALLS 1
#define SUPPORTED_PERSONALITIES 2
#define PERSONALITY0_AUDIT_ARCH { AUDIT_ARCH_X86_64, __X32_SYSCALL_BIT }
#define PERSONALITY1_AUDIT_ARCH { AUDIT_ARCH_I386,   0 }
