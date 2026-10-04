#include <linux/entry-common.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <asm/globals.h>
#include <asm/process_events.h>
#include <asm/wasm_imports.h>

/* Bytes reserved below the park floor for each new syscall continuation. */
#define KWA_SYSCALL_STACK_HEADROOM 1024

#undef __SYSCALL
#define __SYSCALL(nr, sym) asmlinkage long sym(const struct pt_regs *regs);
#include <asm/unistd.h>

typedef asmlinkage long (*syscall_handler_t)(const struct pt_regs *regs);

#undef __SYSCALL
#define __SYSCALL(nr, sym) [nr] = (syscall_handler_t)sym,

syscall_handler_t syscall_table[__NR_syscalls] = {
	[0 ... __NR_syscalls - 1] = (syscall_handler_t)sys_ni_syscall,
#include <asm/unistd.h>
};

static void wasm_emit_wait4_reap_event(long ret, unsigned long stat_addr)
{
	u64 run_id_hi, run_id_lo;
	int status;

	/*
	 * wait4() returns the PID whose wait condition was consumed. Only emit
	 * an authoritative reap event when the caller supplied a status pointer
	 * and the raw Linux wait status can be read back successfully. A null
	 * or unreadable status pointer stays fail-closed: the host must not infer
	 * terminal status from shell conventions alone.
	 */
	if (ret <= 0 || !stat_addr)
		return;
	if (get_user(status, (int __user *)stat_addr))
		return;

	zn_get_run_id(&run_id_hi, &run_id_lo);
	wasm_kernel_process_event(
		ZN_EVENT_WAIT_REAP_COMMITTED,
		run_id_hi,
		run_id_lo,
		zn_get_next_event_seq(),
		(u32)ret,                    /* child PID returned by wait4 */
		0,                           /* tgid unavailable after reap */
		(u32)current->pid,           /* authoritative waiting parent */
		0,                           /* worker_id not assigned here */
		(u64)((u32)status & 0xffffU), /* raw Linux wait status */
		0,                           /* reserved */
		"<wait4-reap>",
		12
	);
}

static volatile long kwa_last_entry_nr;
static volatile unsigned long kwa_last_entry_a5;
static volatile unsigned int kwa_entry_count;
/* K2: kernel-authoritative task identity captured at syscall entry */
static volatile int kwa_last_pid;
static volatile int kwa_last_tgid;
static volatile unsigned int kwa_last_generation;
static unsigned int kwa_generation_counter;

__attribute__((export_name("kwa_get_last_entry_nr"))) long
wasm_kwa_get_last_entry_nr(void)
{
	return kwa_last_entry_nr;
}

__attribute__((export_name("kwa_get_last_entry_a5"))) unsigned long
wasm_kwa_get_last_entry_a5(void)
{
	return kwa_last_entry_a5;
}

__attribute__((export_name("kwa_get_entry_count"))) unsigned int
wasm_kwa_get_entry_count(void)
{
	return kwa_entry_count;
}
__attribute__((export_name("kwa_get_last_pid"))) int
wasm_kwa_get_last_pid(void)
{
	return kwa_last_pid;
}

__attribute__((export_name("kwa_get_last_tgid"))) int
wasm_kwa_get_last_tgid(void)
{
	return kwa_last_tgid;
}

__attribute__((export_name("kwa_get_last_generation"))) unsigned int
wasm_kwa_get_last_generation(void)
{
	return kwa_last_generation;
}

__attribute__((export_name("syscall"))) long
wasm_syscall(long nr, unsigned long arg0, unsigned long arg1,
	     unsigned long arg2, unsigned long arg3, unsigned long arg4,
	     unsigned long arg5)
{
	struct pt_regs *regs = current_pt_regs();
	long ret;

	/*
	 * KWA K1 witness: capture the complete broker ABI at the real Linux
	 * syscall entry, before Linux normalizes or dispatches the request.
	 * Getters below are diagnostic-only and do not participate in dispatch.
	 */
	kwa_last_entry_nr = nr;
	kwa_last_entry_a5 = arg5;
	kwa_entry_count++;
	/* K2: stamp real kernel task identity before any dispatch.
	 * During early boot or standalone probe, current may be NULL;
	 * fall back to init_task which is always valid and has pid=0/tgid=0.
	 * In normal operation, current points to the real executing task. */
	{
		struct task_struct *t = current ?: &init_task;
		kwa_last_pid = t->pid;
		kwa_last_tgid = t->tgid;
		kwa_last_generation = ++kwa_generation_counter;
	}

	regs->user_mode = 0;
	nr = syscall_enter_from_user_mode(regs, nr);

	if (nr < 0 || nr >= ARRAY_SIZE(syscall_table))
		return -ENOSYS;

	regs->syscall_nr = nr;
	regs->syscall_args[0] = arg0;
	regs->syscall_args[1] = arg1;
	regs->syscall_args[2] = arg2;
	regs->syscall_args[3] = arg3;
	regs->syscall_args[4] = arg4;
	regs->syscall_args[5] = arg5;

	ret = syscall_table[nr](regs);

/*
 * Observe wait4 only after Linux has returned from the real syscall path.
 * ret > 0 identifies the wait condition actually consumed; data0 is the
 * raw status Linux wrote to user memory. No event is emitted for WNOHANG
 * zero returns, errors, null status pointers, or failed status reads.
 */
	if (nr == __NR_wait4 && ret > 0)
		wasm_emit_wait4_reap_event(ret, arg1);

	syscall_exit_to_user_mode(regs);
	regs->user_mode = 1;

	return ret;
}

/* K5: inner syscall body. Called ONLY from the kwa_syscall_for_task
 * trampoline AFTER the task stack is adopted, so this entire C frame (and
 * the identity locals it carries) is allocated below the task's stack top —
 * never in a previous/parked task's stack region. */
static noinline long
kwa_syscall_inner(struct task_struct *task, struct thread_info *ti, long nr,
		  unsigned long arg0, unsigned long arg1, unsigned long arg2,
		  unsigned long arg3, unsigned long arg4, unsigned long arg5,
		  u32 dispatch_id)
{
	/* C-owned identity capture at actual entry (K2/K5A evidence). These
	 * locals live on the task's own kernel stack: immune to cross-task
	 * overwrites of the diagnostic kwa_get_last_* globals while this
	 * continuation parks inside a blocking clone/wait4. */
	int pid = task->pid;
	int tgid = task->tgid;
	u32 generation = ++kwa_generation_counter;
	long ret;

	set_current_cpu(atomic_read(&ti->running_cpu));
	set_current_task(task); /* publish: this task executes on cpu */

	ret = wasm_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);

	/* Post-wait certification (event 10): a successful wait4 records the
	 * real reaped child; the matching second wait4's ECHILD arms the
	 * pending marker; ONLY a subsequent successful getpid (ret ==
	 * own pid) certifies PARENT_POST_WAIT_SYSCALL. Bare ECHILD never
	 * certifies anything. Flags are cleared after the emit. */
	if (nr == __NR_wait4) {
		if (ret > 0)
			ti->k5_reaped_child = (int)ret;
		else if (ret == -ECHILD && ti->k5_reaped_child != 0)
			ti->k5_flags |= K5_KF_POSTWAIT_PENDING;
	}
	if (nr == __NR_getpid && ret == (long)task->pid &&
	    (ti->k5_flags & K5_KF_POSTWAIT_PENDING)) {
		u64 run_id_hi, run_id_lo;

		zn_get_run_id(&run_id_hi, &run_id_lo);
		wasm_kernel_process_event(
			ZN_EVENT_PARENT_POST_WAIT_SYSCALL,
			run_id_hi,
			run_id_lo,
			zn_get_next_event_seq(),
			(u32)task->pid,        /* surviving waiter */
			(u32)task->tgid,
			task->real_parent ?
				(u32)task->real_parent->pid : 0,
			0,                     /* worker_id unused */
			(u64)ret,              /* data0: post-wait getpid */
			(u64)(u32)ti->k5_reaped_child, /* data1: reaped child */
			"<post-wait>",
			10
		);
		ti->k5_flags &= ~K5_KF_POSTWAIT_PENDING;
		ti->k5_reaped_child = 0;
	}

	/* Image replacement ONLY for an actual successful execve/execveat
	 * request carrying a fresh commit: the request itself exec'd (binfmt
	 * set the flag during THIS dispatch) and returned success. Any other
	 * syscall (e.g. an ordinary getpid) must never re-enter the image,
	 * even if a stale flag existed. */
	if ((nr == __NR_execve || nr == __NR_execveat) && ret == 0 &&
	    (ti->k5_flags & K5_KF_EXEC_COMMITTED)) {
		/* Successful execve has no Linux return: wrap into the newly
		 * committed user image. No syscall_complete for this request —
		 * its slot stays claimed until finish_task cancels it. The
		 * new program inherits no post-wait state. */
		ti->k5_flags &= ~K5_KF_EXEC_COMMITTED;
		ti->k5_flags &= ~K5_KF_POSTWAIT_PENDING;
		ti->k5_reaped_child = 0;
		kwa_enter_user_image(task);
	}

	/* Completion identity comes from C locals stamped at entry, read after
	 * the actual return — never from the shared diagnostics globals. */
	wasm_kernel_syscall_complete(kwa_task_token(task), dispatch_id,
				     (u32)ret, pid, tgid, generation);
	return ret;
}

/* K5: per-task brokered syscall bridge. The host invokes this export via
 * WebAssembly.promising — one fresh continuation per broker request — so it
 * can park on the Linux scheduler (blocking clone/wait4) without occupying
 * the authority context.
 *
 * TRAMPOLINE DISCIPLINE: scalar locals only, no address-taken storage — the
 * compiler keeps them in wasm locals on THIS continuation's engine stack, so
 * nothing is pinned in the previous (parked) task's linear stack region while
 * we run or park. The stack is adopted BEFORE the noinline inner call, so the
 * inner body's whole C frame lands on the task's own kernel stack. */
__attribute__((export_name("kwa_syscall_for_task"))) long
kwa_syscall_for_task(u32 task_token, long nr, unsigned long arg0,
		     unsigned long arg1, unsigned long arg2,
		     unsigned long arg3, unsigned long arg4,
		     unsigned long arg5, u32 dispatch_id)
{
	struct task_struct *task;
	struct thread_info *ti;
	unsigned long old_floor, stack_top;
	long ret;

	task = kwa_task_validate_running(task_token, NULL);
	if (!task) {
		/* Fail closed and loud (also rejects unscheduled tasks:
		 * running_cpu < 0 is Linux-scheduler-owned, never claimed
		 * here). Return WITHOUT syscall_complete so the host cancels
		 * the claimed slot instead of binding a result. */
		pr_err("K5: kwa_syscall_for_task rejected token=%u nr=%ld\n",
		       task_token, nr);
		return -ENOSYS;
	}
	ti = task_thread_info(task);

	old_floor = ti->k5_park_floor;
	stack_top = old_floor - KWA_SYSCALL_STACK_HEADROOM;
	if (stack_top <
	    (unsigned long)task->stack + sizeof(struct pt_regs) + 512) {
		pr_emerg("K5: task %d kernel stack exhausted (floor=%lx)\n",
			 task->pid, ti->k5_park_floor);
		BUG();
	}
	ti->k5_park_floor = stack_top;
	set_stack_pointer((void *)stack_top);

	ret = kwa_syscall_inner(task, ti, nr, arg0, arg1, arg2, arg3, arg4,
				arg5, dispatch_id);

	/* Ordinary return: this continuation completed, its frames are dead —
	 * give the park floor back so sequential syscalls do not creep down
	 * the stack. Exec/exit never reach this line. */
	ti->k5_park_floor = old_floor;
	return ret;
}

SYSCALL_DEFINE1(set_thread_area, unsigned long, addr)
{
	struct thread_info *ti = task_thread_info(current);
	ti->tp_value = addr;
	return 0;
}

__attribute__((export_name("get_thread_area"))) unsigned long
wasm_get_thread_area(void)
{
	struct thread_info *ti = task_thread_info(current);
	return ti->tp_value;
}
