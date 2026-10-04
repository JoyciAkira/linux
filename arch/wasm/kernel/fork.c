#include <asm/globals.h>
#include <asm/param.h>
#include <asm/process_events.h>
#include <asm/wasm_imports.h>
#include <linux/sched.h>
#include <linux/syscalls.h>

/* USER_FORK_RESUME copy-ack. Lives in kernel linear memory (shared across all
 * continuations on the authority instance). The cloning task parks through the
 * Linux scheduler (TASK_UNINTERRUPTIBLE + schedule_timeout, so the park is a
 * real __switch_to with context suspend/resume events); the host calls the
 * fork_copied export — via promising, on its own continuation — once the
 * child VAS snapshot is complete, which stores the pid and wakes the waiter. */
static int g_ufr_copy_pid;
static struct task_struct *g_ufr_waiter;

struct clone_fn {
	void *__user fn;
	void *__user arg;
};

int wasm_call_clone_fn(void *arg)
{
	struct clone_fn *clone_fn = arg;
	wasm_user_switch_entry((uintptr_t)clone_fn->fn,
			       (uintptr_t)clone_fn->arg);
	wasm_user_instantiate(false);
	kfree(clone_fn);
	return 0;
}

/* G12 fork-mode child: the guest resumes its parent's user state via the
 * host user.fork_user import (machine copy + ax=0 + child pid). */
static int wasm_fork_continue(void *arg)
{
	wasm_user_fork_user((u32)current->pid);
	return 0;
}

/* K5 event 8: CLONE_COMMITTED. Emitted only after kernel_clone() returned a
 * real allocated child pid — copy_thread runs before alloc_pid, so the old
 * in-copy_thread emission produced pid0 events the decoder must reject. */
static void wasm_emit_clone_committed(int child, unsigned long clone_flags)
{
	u64 run_id_hi, run_id_lo;

	zn_get_run_id(&run_id_hi, &run_id_lo);
	wasm_kernel_process_event(
		ZN_EVENT_CLONE_COMMITTED,
		run_id_hi,
		run_id_lo,
		zn_get_next_event_seq(),
		(u32)child,               /* authoritative allocated child pid */
		(clone_flags & CLONE_THREAD) ? (u32)current->tgid : (u32)child,
		(u32)current->pid,        /* cloning parent */
		0,                        /* worker_id unused */
		clone_flags,              /* data0: clone_flags */
		0,                        /* data1: reserved */
		current->comm,
		strnlen(current->comm, sizeof(current->comm))
	);
}

SYSCALL_DEFINE6(clone, void *__user, fn, void *__user, fn_arg, unsigned long,
		clone_flags, int __user *, parent_tidptr, int __user *,
		child_tidptr, unsigned long, tls)
{
	struct kernel_clone_args kargs = {
		.flags = (lower_32_bits(clone_flags) & ~CSIGNAL),
		.pidfd = parent_tidptr,
		.child_tid = child_tidptr,
		.parent_tid = parent_tidptr,
		.exit_signal = (lower_32_bits(clone_flags) & CSIGNAL),
		.tls = tls,
	};

	/* G12 fork-mode: fn == NULL → fork-style clone — the child continues
	 * the parent's user state (no guest entry function). */
	if (fn == NULL) {
		int child;
		kargs.fn = wasm_fork_continue;
		kargs.fn_arg = NULL;
		child = kernel_clone(&kargs);
		/* Park this task through the scheduler until the child's VAS
		 * snapshot is complete, so the child's copy is the exact
		 * fork-point state. Bounded: the host must answer via
		 * fork_copied; a missed wake cannot hang the kernel. */
		if (child > 0) {
			g_ufr_waiter = current;
			for (;;) {
				set_current_state(TASK_UNINTERRUPTIBLE);
				if (READ_ONCE(g_ufr_copy_pid) == child)
					break;
				if (!schedule_timeout(HZ / 10)) {
					pr_err("K5: fork copy-ack timeout waiting for child %d\n",
					       child);
					break;
				}
			}
			__set_current_state(TASK_RUNNING);
			g_ufr_waiter = NULL;
			g_ufr_copy_pid = 0;
			wasm_emit_clone_committed(child, clone_flags);
		}
		return child;
	}

	struct clone_fn *clone_fn = kmalloc(sizeof(*clone_fn), GFP_KERNEL);
	if (!clone_fn)
		return -ENOMEM;
	clone_fn->fn = fn;
	clone_fn->arg = fn_arg;

	kargs.fn = wasm_call_clone_fn;
	kargs.fn_arg = clone_fn;

	{
		int child = kernel_clone(&kargs);

		if (child > 0)
			wasm_emit_clone_committed(child, clone_flags);
		return child;
	}
}

/* Host fork_user calls this (via promising, on its own kernel continuation)
 * after copying the parent VAS into the child. Stores the pid and wakes the
 * scheduler-parked cloning task. */
__attribute__((export_name("fork_copied")))
void fork_copied(unsigned int pid)
{
	g_ufr_copy_pid = (int)pid;
	if (g_ufr_waiter)
		wake_up_process(g_ufr_waiter);
}
