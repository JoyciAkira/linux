#include <linux/entry-common.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <asm/process_events.h>
#include <asm/wasm_imports.h>

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

__attribute__((export_name("syscall"))) long
wasm_syscall(long nr, unsigned long arg0, unsigned long arg1,
	     unsigned long arg2, unsigned long arg3, unsigned long arg4,
	     unsigned long arg5)
{
	struct pt_regs *regs = current_pt_regs();
	long ret;

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
