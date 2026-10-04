/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _WASM_PROCESS_EVENTS_H
#define _WASM_PROCESS_EVENTS_H

/*
 * SR0.10 - Minimal Guest Process Observability Bridge
 * Event taxonomy v1 - semantically fail-closed event kinds
 */

/* Event kinds for wasm_kernel_process_event() */
#define ZN_EVENT_RUN_START                      1
#define ZN_EVENT_WASM_EXEC_COMMITTED            2
#define ZN_EVENT_CLONE_WORKER_REQUESTED         3  /* superseded by 8; kept for K0-K4 streams */
#define ZN_EVENT_TASK_DEAD                      4
#define ZN_EVENT_USER_SIGNAL_HANDLER_DISPATCH   5
#define ZN_EVENT_WAIT_REAP_COMMITTED            6
#define ZN_EVENT_RUN_END                        7
/* K5 real guest lifecycle + context evidence (encoder/decoder ABI frozen) */
#define ZN_EVENT_CLONE_COMMITTED                8  /* child pid allocated, parent emitted */
#define ZN_EVENT_TASK_RELEASE_COMMITTED         9  /* release_task ran for a live-pid task */
#define ZN_EVENT_PARENT_POST_WAIT_SYSCALL      10  /* wait4 returned -ECHILD post-reap */
#define ZN_EVENT_CTX_SUSPEND                   11  /* data0=sp, data1=cookie, worker_id=reason */
#define ZN_EVENT_CTX_RESUME                    12  /* same cookie read back after real resume */

/* Schema version for event format */
#define ZN_EVENT_SCHEMA_VERSION                 1

void zn_init_run_identity(void);
u64 zn_get_next_event_seq(void);
void zn_get_run_id(u64 *hi, u64 *lo);

#endif /* _WASM_PROCESS_EVENTS_H */
