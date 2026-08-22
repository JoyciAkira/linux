#include <asm/wasm_imports.h>
#include <linux/syscalls.h>

/* USER_FORK_RESUME copy-ack. Lives in kernel linear memory (shared across all
 * worker instances), so the child worker can signal the parked parent. */
static int g_ufr_copy_pid;

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
		/* Park this CPU until the child worker has snapshotted the VAS,
		 * so the child's copy is the exact fork-point state. Bounded. */
		if (child > 0) {
			int spins;
			g_ufr_copy_pid = 0;
			for (spins = 0; spins < 50 && g_ufr_copy_pid != child; spins++)
				__builtin_wasm_memory_atomic_wait32(&g_ufr_copy_pid, 0,
								    100 * 1000 * 1000);
			g_ufr_copy_pid = 0;
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

	return kernel_clone(&kargs);
}

/* Host fork_user calls this after copying the parent VAS into the child.
 * Plain store: the parent polls via memory.atomic_wait32 timeouts, so no
 * explicit notify is required (shared linear memory ⇒ visible immediately). */
__attribute__((export_name("fork_copied")))
void fork_copied(unsigned int pid)
{
	g_ufr_copy_pid = (int)pid;
}
