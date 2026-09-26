/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_WASM_FUTEX_H
#define _ASM_WASM_FUTEX_H

#include <asm-generic/futex.h>

#define futex_atomic_cmpxchg_inatomic(uval, uaddr, oldval, newval) \
	futex_atomic_cmpxchg_inatomic_local(uval, uaddr, oldval, newval)

#define arch_futex_atomic_op_inuser(op, oparg, oval, uaddr) \
	futex_atomic_op_inuser_local(op, oparg, oval, uaddr)

#endif /* _ASM_WASM_FUTEX_H */
