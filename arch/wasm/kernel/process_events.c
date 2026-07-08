/* SPDX-License-Identifier: GPL-2.0 */
/*
 * SR0.10 - Run Identity Management
 * Generate unique run ID for process telemetry anti-replay
 */

#include <linux/random.h>
#include <linux/types.h>
#include <asm/wasm_imports.h>
#include <asm/process_events.h>

/* Run identity - 128-bit UUID generated at kernel boot */
static u64 kernel_run_id_hi;
static u64 kernel_run_id_lo;

/* Global monotonic event sequence counter */
static atomic64_t global_event_seq = ATOMIC64_INIT(0);

/**
 * zn_init_run_identity - Initialize run identity at kernel boot
 *
 * Generates a 128-bit random UUID to identify this kernel run.
 * Called during early kernel initialization.
 */
void __init zn_init_run_identity(void)
{
	u8 uuid[16];

	get_random_bytes(uuid, sizeof(uuid));

	/* Convert UUID bytes to two 64-bit values */
	kernel_run_id_hi = *(u64 *)&uuid[0];
	kernel_run_id_lo = *(u64 *)&uuid[8];

	/* Emit RUN_START event */
	wasm_kernel_process_event(
		ZN_EVENT_RUN_START,
		kernel_run_id_hi,
		kernel_run_id_lo,
		atomic64_inc_return(&global_event_seq),
		0, 0, 0, 0,  /* no pid/tgid/ppid/worker for run start */
		0, 0,        /* no data0/data1 */
		"<run_start>", 12
	);
}

/**
 * zn_get_next_event_seq - Get next event sequence number
 *
 * Returns monotonically increasing sequence number for event ordering.
 */
u64 zn_get_next_event_seq(void)
{
	return atomic64_inc_return(&global_event_seq);
}

/**
 * zn_get_run_id - Get current run identity values
 * @hi: Output parameter for high 64 bits
 * @lo: Output parameter for low 64 bits
 */
void zn_get_run_id(u64 *hi, u64 *lo)
{
	*hi = kernel_run_id_hi;
	*lo = kernel_run_id_lo;
}
