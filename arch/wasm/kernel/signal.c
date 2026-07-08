#include <asm/wasm_imports.h>
#include <asm/process_events.h>
#include <linux/syscalls.h>

void arch_do_signal_or_restart(struct pt_regs *regs) {
	struct ksignal ksig;

	if (get_signal(&ksig)) {
		struct sigaction* sa = &ksig.ka.sa;
		if (sa->sa_flags&SA_SIGINFO)
			pr_warn("TODO: SA_SIGINFO in signal handler\n");

		/* SR0.10: Emit USER_SIGNAL_HANDLER_DISPATCH before calling handler */
		{
			u64 run_id_hi, run_id_lo;
			zn_get_run_id(&run_id_hi, &run_id_lo);
			wasm_kernel_process_event(
				ZN_EVENT_USER_SIGNAL_HANDLER_DISPATCH,
				run_id_hi,
				run_id_lo,
				zn_get_next_event_seq(),
				current->pid,
				current->tgid,
				current->parent->pid,
				0,                 /* worker_id: unused */
				ksig.sig,          /* data0: signal number */
				sa->sa_flags,      /* data1: signal action flags */
				current->comm,
				strnlen(current->comm, sizeof(current->comm))
			);
		}

		wasm_user_call_signal_handler((uintptr_t)sa->sa_handler, ksig.sig);
	}
}

