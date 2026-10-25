/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_WASM_Z1_FUTEX_H
#define _ASM_WASM_Z1_FUTEX_H

#include <linux/compiler_types.h>
#include <linux/types.h>

struct mm_struct;

/* Z1 private-mm futex wake.  Called by mm_release() on clear_child_tid,
 * using the exiting address space rather than current->mm.
 * Does not replace the generic Linux do_futex() wake path.
 */
unsigned int z1_futex_wake_mm(struct mm_struct *mm, u32 __user *uaddr,
			      unsigned int nr_wake);

#endif /* _ASM_WASM_Z1_FUTEX_H */
