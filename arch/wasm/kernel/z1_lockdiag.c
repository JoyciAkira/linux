// SPDX-License-Identifier: GPL-2.0
/*
 * Z1-F11-C3-A: bounded lock-event ring buffer for lock-ownership attribution.
 *
 * Constraint (mandate C3-A): diagnostics must not use printk/console output
 * (the TTY path under investigation) — events go to a preallocated static
 * buffer that the host reads through the z1_ldiag_* exports.
 *
 * Event record: six u32 words
 *   [0] timestamp low,  [1] timestamp high
 *   [2] type | (lock_id << 8) | (site << 16)
 *   [3] task token
 *   [4] pid | (data16 << 16)
 *   [5] data (full 32-bit payload, e.g. spin iteration count)
 */
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/atomic.h>
#include <asm/current.h>
#include <asm/globals.h>
#include <asm/wasm_imports.h>

#define Z1_LD_EVENTS 256
#define Z1_LD_WORDS 6

static u32 z1_ld_buf[Z1_LD_EVENTS * Z1_LD_WORDS];
static atomic_t z1_ld_head = ATOMIC_INIT(0);

/* last holder per tracked lock id (reentrancy detection) */
static u32 z1_ld_holder[8];

void z1_llog(u32 type, u32 lock_id, u32 site, u32 token, u32 data)
{
	int i = atomic_inc_return(&z1_ld_head) - 1;
	u32 slot = (u32)i % Z1_LD_EVENTS;
	u64 t = wasm_kernel_get_now_nsec();
	u32 *e = &z1_ld_buf[slot * Z1_LD_WORDS];

	e[0] = (u32)t;
	e[1] = (u32)(t >> 32);
	e[2] = type | (lock_id << 8) | (site << 16);
	e[3] = token;
	e[4] = task_pid_nr(current) | ((data & 0xffff) << 16);
	e[5] = data;
}

/* track holder for reentrancy detection; returns previous holder token */
u32 z1_lhold(u32 lock_id, u32 token)
{
	u32 prev = z1_ld_holder[lock_id & 7];

	z1_ld_holder[lock_id & 7] = token;
	return prev;
}

__attribute__((export_name("z1_ldiag_ptr"))) u32 z1_ldiag_ptr(void)
{
	/* C3-A self-test: prove the host↔kernel buffer path end to end. */
	z1_ld_buf[0] = 0xDEADBEEF;
	return (u32)(uintptr_t)z1_ld_buf;
}

__attribute__((export_name("z1_ldiag_count"))) u32 z1_ldiag_count(void)
{
	return (u32)atomic_read(&z1_ld_head);
}

__attribute__((export_name("z1_ldiag_words"))) u32 z1_ldiag_words(void)
{
	return Z1_LD_WORDS;
}
