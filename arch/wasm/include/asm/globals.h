#ifndef _WASM_GLOBALS_H
#define _WASM_GLOBALS_H

#include <linux/types.h>

__asm__(".globaltype __stack_pointer, i32\n");
static inline void set_stack_pointer(void *ptr)
{
	__asm__ volatile("local.get %0\n"
			 "global.set __stack_pointer" ::"r"(ptr));
}
static inline void *get_stack_pointer(void)
{
	void* ptr;
	__asm__ volatile("global.get __stack_pointer\n"
			 "local.set %0"
			 : "=r"(ptr));
	return ptr;
}


void set_current_cpu(int cpu);
int get_current_cpu(void);

struct task_struct;
void set_current_task(struct task_struct *task);
struct task_struct *get_current_task(void);
struct task_struct *get_current_task_on(int cpu);

/* K5: raw execution-global writers used only by the C context restore path.
 * set_current_task() publishes current_tasks[cpu]; the raw setter must never
 * run before __switch_to has recovered prev from current_tasks[cpu]. */
void kwa_set_current_task_raw(struct task_struct *task);

void set_irq_enabled(u32 flags);
u32 get_irq_enabled(void);

void wasm_set_thread_done(int done);
int wasm_get_thread_done(void);

/* K5: opaque kernel-owned task token = task_struct linear address (wasm32). */
static inline u32 kwa_task_token(const struct task_struct *task)
{
	return (u32)(uintptr_t)task;
}

/* Wasm C ABI: __stack_pointer must stay 16-byte aligned; V8 additionally
 * rejects non-naturally-aligned i64 atomics, which any sp-anchored storage
 * can hold. All adopted stack tops use ALIGN_DOWN(ptr, KWA_STACK_ALIGN). */
#define KWA_STACK_ALIGN 16UL

/* K5: snapshot of every mutable module-level execution global actually used
 * by generated code. Audit of the generated vmlinux.wat: exactly four mutables
 * are live — __stack_pointer, current_cpu, current_task, thread_done. The
 * remaining mutables are constant-in-practice (__tls_base: never written, 0
 * writes in 28MB WAT; __tls_size/__tls_align immutable) and no SjLj
 * temp-return/longjmp globals are generated. The struct lives on the C stack
 * of the suspending continuation, so JSPI preserves it across park/resume. */
struct kwa_exec_ctx {
	void *sp;
	int cpu;
	struct task_struct *task;
	int thread_done;
};

void kwa_ctx_save(struct kwa_exec_ctx *ctx);
/* Restore raw globals only; current_tasks[cpu] publication stays with the
 * explicit set_current_task() call sites (switch prev must be read first). */
void kwa_ctx_restore_raw(const struct kwa_exec_ctx *ctx);

/* K5: suspend this continuation on kernel.yield and, after the host resumes
 * it, rebind every mutable execution global from C stack locals. Emits
 * CTX_SUSPEND before and CTX_RESUME after with the same kernel-authored
 * volatile stack cookie (pid>0 tasks only; boot/idle stays event-silent).
 * Records the parking sp into the task's park floor for stack ownership. */
u64 kwa_context_suspend(struct kwa_exec_ctx *ctx, u32 reason, u64 deadline_ns,
			u32 next_task);

/* K5: per-task user-image entry wrapper (task_entry + exec handoff). Records
 * the task's kernel entry context, parks the continuation in user.call while
 * the real guest module runs on its pure user worker, and restores context on
 * return. Never returns for a correctly-exiting guest (do_exit path). */
void kwa_enter_user_image(struct task_struct *task);

/* K5: kernel task registry — C-owned validation of host-supplied tokens. */
#define KWA_TASK_SLOTS 64
#define KWA_SF_STARTED 0x1   /* kwa_task_entry ran for it */
#define KWA_SF_AUTOSTART 0x2 /* registry flag: host starts via kwa_task_entry immediately */
#define KWA_SPAWN_AUTOSTART 0x1 /* wire spawn_flags param: host autostarts this token */

struct kwa_task_slot {
	u32 token;
	struct task_struct *task;
	int (*fn)(void *);
	void *fn_arg;
	u8 flags;
};

struct kwa_task_slot *kwa_task_register(struct task_struct *task,
					int (*fn)(void *), void *fn_arg,
					u8 flags);
struct kwa_task_slot *kwa_task_lookup(u32 token);
struct kwa_task_slot *kwa_task_take(u32 token);
void kwa_task_retire(u32 token);
/* Bridge validation: live, started, non-exiting task; claims running_cpu. */
struct task_struct *kwa_task_validate_running(u32 token, int *cpu_out);

/* Boot continuation support: pristine root stack top captured at _start. */
void kwa_boot_stack_capture(void);
void *kwa_boot_stack_top(void);
/* Registers the boot continuation under the reserved wire token 0 while
 * binding it to the cpu0 idle task, so the idle's opaque self/next token
 * (the init_task pointer) resolves to the same slot — one continuation, one
 * registry identity, no host-side double registration. */
void kwa_boot_register(struct task_struct *idle_task, int (*fn)(void *));

#endif
