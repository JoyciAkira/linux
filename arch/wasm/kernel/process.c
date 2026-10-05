#include <asm/delay.h>
#include <asm/globals.h>
#include <asm/sysmem.h>
#include <asm/wasm_imports.h>
#include <asm/process_events.h>
#include <linux/entry-common.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/sched/task.h>

int arch_dup_task_struct(struct task_struct *dst, struct task_struct *src)
{
	*dst = *src;
	atomic_set(&task_thread_info(dst)->running_cpu, -1);
	return 0;
}

struct task_struct *__switch_to(struct task_struct *from,
				struct task_struct *to)
{
	struct thread_info *from_info = task_thread_info(from);
	struct thread_info *to_info = task_thread_info(to);
	struct kwa_exec_ctx ctx;
	struct task_struct *prev;
	int cpu, other;

	cpu = atomic_xchg(&from_info->running_cpu, -1);
	BUG_ON(cpu < 0); // current process must be scheduled to a cpu

	// give the current cpu to the new task
	other = atomic_cmpxchg(&to_info->running_cpu, -1, cpu);
	BUG_ON(other != -1); // new process should not have had a cpu

	// this is set to true in do_task_dead:
	if (wasm_get_thread_done()) {
		/* Terminal handoff (K5): the dying task never returns. The host
		 * cancels only its claimed broker slots (no invented result),
		 * rejects/unwinds only its parked guest/root/syscall
		 * continuations, retires its user worker, and starts/resumes
		 * the kernel-named next task. Authority is never self-closed. */
		kwa_task_retire(kwa_task_token(from));
		wasm_kernel_finish_task(kwa_task_token(from),
					kwa_task_token(to));
		/* non-returning: the host rejects this continuation and unwinds
		 * it; if a broken host ever resolved it, refuse to park a dead
		 * task (loud hang, never a silent fake resume). */
		for (;;)
			;
	}

	// K5: cooperative yield. The host suspends this continuation here and
	// resumes exactly `to`. On resume, kwa_context_suspend rebinds every
	// mutable execution global (sp, current_cpu, current_task, thread_done)
	// from C stack locals before we touch any scheduler state.
	kwa_context_suspend(&ctx, KWA_YIELD_SWITCH, 0, kwa_task_token(to));

	cpu = atomic_read(&from_info->running_cpu);
	BUG_ON(cpu < 0); // we should be given a new cpu
	set_current_cpu(cpu);
	prev = get_current_task_on(cpu); // BEFORE republishing current_tasks[]
	set_current_task(current);

	return prev;
}

/* K5: C-owned user-call wrapper. Records the task's kernel entry context on
 * the C stack, parks this continuation in user.call while the real guest
 * module runs on its pure user worker (broker syscalls re-enter through
 * kwa_syscall_for_task on their own continuations), and restores the context
 * after the actual return. A guest death never returns here: finish_task
 * rejection unwinds this frame on the host side. */
void kwa_enter_user_image(struct task_struct *task)
{
	struct kwa_exec_ctx entry;

	/* Consume the exec commit: whether we got here from the kernel-thread
	 * entry path (initial /init exec) or the bridge exec path, entering
	 * the image completes the commit. A lingering flag would make the
	 * next ordinary syscall (e.g. getpid) wrongly re-enter the image. */
	task_thread_info(task)->k5_flags &= ~K5_KF_EXEC_COMMITTED;

	kwa_ctx_save(&entry);
	/* wasm_user_call() never returns on two paths, both host-owned:
	 * - genuine exec re-entry: the host rejects the OLD image's pending
	 *   frame with USER_IMAGE_REPLACED; the JS exception unwinds this
	 *   entire continuation stack — kwa_ctx_restore_raw, the G12 check and
	 *   do_exit below are unreachable on that path BY DESIGN. The task
	 *   continues on the exec bridge continuation, so this must NEVER be
	 *   routed into halt_worker/do_exit (AUTHORITY_HALT_BLOCKED must not
	 *   fire for image replacement). The successor clears and re-arms the
	 *   exec flag itself (guarded to real execve/execveat dispatches).
	 * - terminal task death: finish_task cancellation unwinds here the
	 *   same way; real death is exclusively finish_task/TERMINAL_TASK_EXIT.
	 * Only a NORMAL return (user module ended without kernel-driven exit)
	 * reaches the code below. */
	int user_call_outcome = wasm_user_call();
	kwa_ctx_restore_raw(&entry);
	if (user_call_outcome == KWA_USER_CALL_TRAP) {
		do_exit(SIGSEGV);
	}

	/* G12 fix: if the task already exited through another path (execve
	 * handoff, signal death), never call do_exit() again from this
	 * continuation. Re-entry loops do_task_dead -> BUG and re-runs
	 * release_task. */
	if (READ_ONCE(task->exit_state) != 0) {
		pr_err("G12-FIX: user image returned with exit_state=%x; halting instead of do_exit\n",
		       task->exit_state);
		wasm_kernel_halt_worker();
		for (;;)
			;
	}

	// if we're here, either the thread returned from its entrypoint without exiting,
	// or its entrypoint threw an error (likely either an `unreachable` instruction being
	// executed, or an out of range memory access.)

	/* FIRST-LIFECYCLE-FIX: an entry that reached its end is a completed
	 * task role (fork-coalesce: this worker's exec branch already handed off
	 * to the real child). A completed task must exit with its own result — a
	 * fabricated SIGSEGV is the first invalid terminal transition, corrupting
	 * the exit status on the way to wait4 (STATUS_PROPAGATION). do_exit(0)
	 * keeps release_task / reap on the valid path. */
	do_exit(0);
}

/* K5: inner task body — called only AFTER the task stack is adopted, so its
 * whole C frame (schedule_tail, bootstrap call, user-image park) lives on the
 * task's own kernel stack, never on a foreign parked stack. */
static noinline void kwa_task_entry_inner(struct task_struct *task,
					  struct thread_info *ti,
					  struct kwa_task_slot *slot, int cpu)
{
	struct task_struct *prev;

	wasm_set_thread_done(0); // fresh continuation: per-task default
	set_current_cpu(cpu);
	prev = get_current_task_on(cpu); // BEFORE republishing current_tasks[]
	set_current_task(task);
	if (!(slot->flags & KWA_SF_AUTOSTART))
		schedule_tail(prev);

	BUG_ON(!slot->fn);

	// callback returns when the kernel thread execs a process
	slot->fn(slot->fn_arg);

	/* exec consumed the return: run the committed user image. The slot has
	 * served its purpose; the continuation now lives as this task's
	 * lifecycle park until guest death (finish_task) unwinds it. */
	kwa_enter_user_image(task);
}

/* K5: task continuation entry. The host starts/resumes exactly this export
 * (via WebAssembly.promising) when the kernel names the task. TRAMPOLINE
 * DISCIPLINE: scalar locals only, CPU/validation checks BEFORE adopting the
 * target stack, and the stack adopted (wasm ABI 16-byte aligned) BEFORE the
 * noinline inner call — no C automatic struct is ever allocated on a foreign
 * parked stack here. */
__attribute__((export_name("kwa_task_entry"))) void
kwa_task_entry(u32 task_token)
{
	struct kwa_task_slot *slot;
	struct task_struct *task;
	struct thread_info *ti;
	unsigned long stack_top;
	int cpu;

	slot = kwa_task_take(task_token);
	BUG_ON(!slot); // host must never start an unregistered/started task

	if (task_token == 0) {
		/* Boot: the known pristine root stack, outside any foreign
		 * frame; the boot entry is __noreturn (ends in the cpu0 idle
		 * loop), so this continuation becomes the preserved kernel
		 * root stack. */
		set_stack_pointer(kwa_boot_stack_top());
		slot->fn(slot->fn_arg);
		BUG(); // boot entry never returns
	}

	task = slot->task;
	BUG_ON(!task);
	ti = task_thread_info(task);

	// scalar-only validation BEFORE any stack adoption
	if (READ_ONCE(task->exit_state) != 0) {
		/* G12 thread-exit fix: a task whose exit already ran must
		 * never re-enter the scheduler path (re-entry reruns do_exit,
		 * double release_task and underflows the shared sighand
		 * refcount). Halt. */
		pr_err("G12-FIX: kwa_task_entry re-entry on dead task pid=%d exit_state=%x; halting worker\n",
		       task->pid, task->exit_state);
		wasm_kernel_halt_worker();
		for (;;)
			;
	}
	if (slot->flags & KWA_SF_AUTOSTART) {
		cpu = ti->cpu; // autostart owns its dedicated cpu
	} else {
		/* The host may start a task only after the scheduler handoff
		 * (kernel.yield next_task) — the cpu is already ours; there is
		 * no waiting loop. */
		cpu = atomic_read(&ti->running_cpu);
		BUG_ON(cpu < 0);
	}

	// adopt the task's kernel stack: ABI-aligned top with the pt_regs
	// region preserved above it
	stack_top = ALIGN_DOWN((unsigned long)task_pt_regs(task),
			       KWA_STACK_ALIGN);
	set_stack_pointer((void *)stack_top);
	WRITE_ONCE(ti->k5_park_floor, stack_top);

	kwa_task_entry_inner(task, ti, slot, cpu);
}

int wasm_call_clone_fn(void *arg);

int copy_thread(struct task_struct *p, const struct kernel_clone_args *args)
{
	struct pt_regs *childregs = task_pt_regs(p);
	struct kwa_task_slot *slot;
	char name[TASK_COMM_LEN + 16] = { 0 };
	int name_len;

	memset(childregs, 0, sizeof(struct pt_regs));

	atomic_set(&task_thread_info(p)->running_cpu, -1);

	// don't spawn a continuation for idle threads
	// this is probably a bad idea
	if (args->idle)
		return 0;

	name_len = snprintf(name, ARRAY_SIZE(name), "%s (%d)", p->comm,
			    p->pid);

	/* K5: register the task in the kernel-owned registry. The C entry
	 * (kwa_task_entry) reads fn/arg from here; the host only ever handles
	 * the opaque token. NOTE: p->pid is not allocated yet (copy_thread runs
	 * before alloc_pid); the CLONE_COMMITTED process event is emitted by
	 * the clone syscall callers after kernel_clone() returns the real
	 * child pid — no pid0 event ever reaches the decoder. */
	slot = kwa_task_register(p, args->fn, args->fn_arg, 0);
	if (!slot)
		return -ENOMEM;

	/* K6R1 ABI v2: dedicated spawn_flags (scheduling policy only). Fork
	 * children get 0 — the scheduler names them via wake_up_new_task/
	 * __switch_to (K5-proven); autostart here would run the child before
	 * alloc_pid, so wasm_fork_continue would see current->pid == 0. Only
	 * secondary idle tasks (smp.c) autostart. */
	wasm_kernel_spawn_worker(args->fn, args->fn_arg,
				 name, name_len,
				 args->fn == wasm_call_clone_fn,
				 kwa_task_token(p),
				 0);

	return 0;
}
