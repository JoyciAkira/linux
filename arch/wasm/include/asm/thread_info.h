#ifndef _WASM_THREAD_INFO_H
#define _WASM_THREAD_INFO_H

#include <asm/page.h>
#include <linux/types.h>

/* THREAD_SIZE is the size of the task_struct + kernel stack
 * This is asserted in setup, but the stack should be 1 page,
 * and a task_struct should be *way* less than a page big. */
#define THREAD_SIZE_ORDER 1
#define THREAD_SIZE (PAGE_SIZE << THREAD_SIZE_ORDER)
#define THREAD_SHIFT (PAGE_SHIFT << THREAD_SIZE_ORDER)

struct wasm_process_args {
	int len, envc, argc;
	char **argv, **envp;
	char data[];
};

struct thread_info {
	unsigned long flags;
	unsigned long syscall_work; /* SYSCALL_WORK_ flags */
	int preempt_count;
	int cpu; // this is for the kernel
	atomic_t running_cpu; // negative means unscheduled
	unsigned long tp_value;
	struct wasm_process_args *args;
	/* K5 context ownership: k5_park_floor is the lowest C stack point parked
	 * by any continuation of this task; new syscall continuations start
	 * strictly below it so a parked lifecycle/exec frame is never clobbered.
	 * k5_flags carries the exec-commit marker (no Linux return for execve)
	 * and the post-wait marker (successful wait4-reap followed by a
	 * matching ECHILD wait, awaiting the certifying post-wait getpid).
	 * k5_reaped_child holds the pid consumed by that successful wait4. */
	unsigned long k5_park_floor;
	u32 k5_flags;
	int k5_reaped_child;
};

/* K5 flags */
#define K5_KF_EXEC_COMMITTED 0x1 /* new user image committed this task */
#define K5_KF_POSTWAIT_PENDING 0x2 /* reap+ECHILD seen, awaiting post-wait getpid */

#define INIT_THREAD_INFO(tsk)                        \
	{                                            \
		.flags = 0,                          \
		.preempt_count = INIT_PREEMPT_COUNT, \
		.cpu = 0,                            \
		.running_cpu = ATOMIC_INIT(0),       \
		.tp_value = U32_MAX,                 \
		.args = NULL,                        \
		.k5_park_floor = 0,                  \
		.k5_flags = 0,                       \
		.k5_reaped_child = 0,                \
	}

#define TIF_SYSCALL_TRACE 0 /* syscall trace active */
#define TIF_NOTIFY_RESUME 1 /* resumption notification requested */
#define TIF_SIGPENDING 2 /* signal pending */
#define TIF_NEED_RESCHED 3 /* rescheduling necessary */
#define TIF_NOTIFY_SIGNAL 7 /* signal notifications exist */
#define TIF_MEMDIE 17 /* OOM killer killed process */

#define _TIF_SYSCALL_TRACE (1 << TIF_SYSCALL_TRACE)
#define _TIF_NOTIFY_RESUME (1 << TIF_NOTIFY_RESUME)
#define _TIF_SIGPENDING (1 << TIF_SIGPENDING)
#define _TIF_NEED_RESCHED (1 << TIF_NEED_RESCHED)
#define _TIF_NOTIFY_SIGNAL (1 << TIF_NOTIFY_SIGNAL)

#endif
