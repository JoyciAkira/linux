#include <asm/smp.h>
#include <asm/page.h>
#include <asm/thread_info.h>
#include <asm/globals.h>
#include <asm/process_events.h>
#include <asm/wasm_imports.h>
#include <linux/cache.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/screen_info.h>

unsigned long init_stack[THREAD_SIZE / sizeof(unsigned long)] = { 0 };
unsigned long empty_zero_page[PAGE_SIZE / sizeof(unsigned long)] = { 0 };
struct task_struct *current_tasks[NR_CPUS] = { 0 };

struct screen_info screen_info = {};

__asm__(".globaltype current_cpu, i32\ncurrent_cpu:\n"
	".globaltype current_task, i32\ncurrent_task:\n"
	".globaltype thread_done, i32\nthread_done:\n");

void set_current_cpu(int cpu)
{
	__asm__ volatile("local.get %0\n"
			 "global.set current_cpu" ::"r"(cpu));
}
int get_current_cpu(void)
{
	int cpu;
	__asm__ volatile("global.get current_cpu\n"
			 "local.set %0"
			 : "=r"(cpu));
	return cpu;
}

void set_current_task(struct task_struct *task)
{
	current_tasks[raw_smp_processor_id()] = task;
	__asm__ volatile("local.get %0\n"
			 "global.set current_task" ::"r"(task));
}

void kwa_set_current_task_raw(struct task_struct *task)
{
	__asm__ volatile("local.get %0\n"
			 "global.set current_task" ::"r"(task));
}

struct task_struct *get_current_task(void)
{
	struct task_struct *task;
	__asm__ volatile("global.get current_task\n"
			 "local.set %0"
			 : "=r"(task));
	return task;
}
struct task_struct *get_current_task_on(int cpu)
{
	return current_tasks[cpu];
}

void wasm_set_thread_done(int done)
{
	__asm__ volatile("local.get %0\n"
			 "global.set thread_done" ::"r"(done));
}
int wasm_get_thread_done(void)
{
	int done;
	__asm__ volatile("global.get thread_done\n"
			 "local.set %0"
			 : "=r"(done));
	return done;
}

/* ---- K5 context restore ---------------------------------------------- */

/* Kernel-authored volatile stack cookie: generated on the C stack before the
 * actual suspension, read back from the same volatile after the real resume.
 * Never copied through JS — this is the K5A proof primitive. */
#define KWA_COOKIE_MAGIC 0x4b57410000000000ULL /* "KWA\0..." */
static atomic64_t kwa_cookie_seq = ATOMIC64_INIT(0);

void kwa_ctx_save(struct kwa_exec_ctx *ctx)
{
	ctx->sp = get_stack_pointer();
	ctx->cpu = get_current_cpu();
	ctx->task = get_current_task();
	ctx->thread_done = wasm_get_thread_done();
}

void kwa_ctx_restore_raw(const struct kwa_exec_ctx *ctx)
{
	set_stack_pointer(ctx->sp);
	set_current_cpu(ctx->cpu);
	kwa_set_current_task_raw(ctx->task);
	wasm_set_thread_done(ctx->thread_done);
}

static void kwa_emit_ctx_event(u32 kind, u32 reason, unsigned long sp,
			       u64 cookie)
{
	struct task_struct *t = get_current_task();
	u64 run_id_hi, run_id_lo;

	/* Boot/idle (pid 0) suspensions stay event-silent so the decoder's
	 * strict pid>0 rule holds for every emitted kind, 1-12. */
	if (!t || t->pid <= 0)
		return;

	zn_get_run_id(&run_id_hi, &run_id_lo);
	wasm_kernel_process_event(
		kind, run_id_hi, run_id_lo, zn_get_next_event_seq(), (u32)t->pid,
		(u32)t->tgid,
		t->real_parent ? (u32)t->real_parent->pid : 0,
		reason, /* worker_id carries the yield reason */
		(u64)sp, cookie,
		kind == ZN_EVENT_CTX_SUSPEND ? "<ctx-suspend>" : "<ctx-resume>",
		kind == ZN_EVENT_CTX_SUSPEND ? 13 : 12);
}

u64 kwa_context_suspend(struct kwa_exec_ctx *ctx, u32 reason, u64 deadline_ns,
			u32 next_task)
{
	u64 expected_cookie;
	volatile u64 cookie;

	kwa_ctx_save(ctx);

	/* Owning stacks: every suspension of a stack-adopting task lowers its
	 * park floor, so later syscall continuations start strictly below all
	 * parked frames of the same task (THREAD_SIZE bounds total depth). */
	if (ctx->task) {
		struct thread_info *ti = task_thread_info(ctx->task);
		unsigned long sp = (unsigned long)ctx->sp;

		if (ti->k5_park_floor && sp < ti->k5_park_floor)
			ti->k5_park_floor = sp;
	}

	expected_cookie = KWA_COOKIE_MAGIC |
			  (u64)atomic64_inc_return(&kwa_cookie_seq);
	cookie = expected_cookie;
	kwa_emit_ctx_event(ZN_EVENT_CTX_SUSPEND, reason,
			   (unsigned long)ctx->sp, cookie);

	wasm_kernel_yield(reason, deadline_ns, kwa_task_token(ctx->task),
			  next_task);

	/* --- real resume: rebind globals FIRST, then validate the volatile ---
	 * The cookie mirrors expected_cookie on the C stack; if the JSPI
	 * round-trip did not actually preserve this continuation's stack, the
	 * volatile reads back wrong and we BUG after restoring globals. */
	kwa_ctx_restore_raw(ctx);
	if (cookie != expected_cookie) {
		pr_emerg("K5: stack cookie corrupted across resume (%llx != %llx)\n",
			 (u64)cookie, expected_cookie);
		BUG();
	}
	kwa_emit_ctx_event(ZN_EVENT_CTX_RESUME, reason,
			   (unsigned long)get_stack_pointer(), cookie);
	return cookie;
}

/* ---- K5 kernel task registry ------------------------------------------ */

static struct kwa_task_slot kwa_task_slots[KWA_TASK_SLOTS];

static void *kwa_boot_sp;

struct kwa_task_slot *kwa_task_register(struct task_struct *task,
					int (*fn)(void *), void *fn_arg,
					u8 flags)
{
	struct kwa_task_slot *slot;

	for (slot = kwa_task_slots; slot < &kwa_task_slots[KWA_TASK_SLOTS];
	     slot++) {
		if (slot->token == 0 && slot->fn == NULL) {
			slot->token = kwa_task_token(task);
			slot->task = task;
			slot->fn = fn;
			slot->fn_arg = fn_arg;
			slot->flags = flags;
			return slot;
		}
	}
	pr_emerg("K5: task registry exhausted\n");
	BUG();
	return NULL;
}

struct kwa_task_slot *kwa_task_lookup(u32 token)
{
	struct kwa_task_slot *slot;

	/* token 0 is the boot slot (kwa_task_entry boot path); the brokered
	 * syscall bridge separately refuses it via kwa_task_validate_running.
	 * Alias: a slot also answers for its bound task's opaque pointer, so
	 * the cpu0 idle (boot slot, wire token 0) legitimately resolves when
	 * it announces self/next = &init_task. For every other slot the task
	 * pointer IS the token, so the alias clause is redundant-but-safe. */
	for (slot = kwa_task_slots; slot < &kwa_task_slots[KWA_TASK_SLOTS];
	     slot++) {
		if (!slot->fn)
			continue;
		if (slot->token == token)
			return slot;
		if (slot->task &&
		    (u32)(uintptr_t)slot->task == token)
			return slot;
	}
	return NULL;
}

struct kwa_task_slot *kwa_task_take(u32 token)
{
	struct kwa_task_slot *slot = kwa_task_lookup(token);

	if (slot && !(slot->flags & KWA_SF_STARTED)) {
		slot->flags |= KWA_SF_STARTED;
		return slot;
	}
	return NULL;
}

void kwa_task_retire(u32 token)
{
	struct kwa_task_slot *slot = kwa_task_lookup(token);

	if (slot) {
		memset(slot, 0, sizeof(*slot));
	}
}

/* ---- R11: layout published to the host ----------------------------------
 * The host must never hard-code kernel addresses or struct offsets: a rebuild
 * moves them silently. Everything the host is allowed to read from kernel
 * memory is described here. The host reads the table through the pure-read
 * export kwa_host_layout_ptr() and refuses to start unless magic, version,
 * word count and fingerprint all check out.
 * Wire format: KWA_HOST_LAYOUT_WORDS little-endian u32; the last word is the
 * FNV-1a (32 bit) of the bytes of all preceding words. Append-only: new
 * fields go before the fingerprint and bump KWA_HOST_LAYOUT_VERSION. */
#define KWA_HOST_LAYOUT_MAGIC 0x314c574bu /* bytes "KWL1" */
#define KWA_HOST_LAYOUT_VERSION 1u

struct kwa_host_layout {
	u32 magic;
	u32 version;
	u32 words;
	u32 task_slots_addr;
	u32 task_slot_count;
	u32 task_slot_size;
	u32 slot_off_token;
	u32 slot_off_task;
	u32 slot_off_fn;
	u32 slot_off_fn_arg;
	u32 slot_off_flags;
	u32 slot_flag_started;
	u32 slot_flag_autostart;
	u32 task_off_flags;
	u32 task_off_exit_state;
	u32 task_off_pid;
	u32 task_off_tgid;
	u32 task_pf_exiting;
	u32 fingerprint;
};
#define KWA_HOST_LAYOUT_WORDS (sizeof(struct kwa_host_layout) / sizeof(u32))

static struct kwa_host_layout kwa_host_layout;

/* Pure read after the first call: no locks, no scheduling, no kernel state.
 * Safe before boot() (only link-time constants and offsetof). */
__attribute__((export_name("kwa_host_layout_ptr"))) u32 kwa_host_layout_ptr(void)
{
	struct kwa_host_layout *l = &kwa_host_layout;
	const u8 *p = (const u8 *)l;
	u32 h = 2166136261u;
	size_t i;

	l->magic = KWA_HOST_LAYOUT_MAGIC;
	l->version = KWA_HOST_LAYOUT_VERSION;
	l->words = KWA_HOST_LAYOUT_WORDS;
	l->task_slots_addr = (u32)(uintptr_t)kwa_task_slots;
	l->task_slot_count = KWA_TASK_SLOTS;
	l->task_slot_size = sizeof(struct kwa_task_slot);
	l->slot_off_token = offsetof(struct kwa_task_slot, token);
	l->slot_off_task = offsetof(struct kwa_task_slot, task);
	l->slot_off_fn = offsetof(struct kwa_task_slot, fn);
	l->slot_off_fn_arg = offsetof(struct kwa_task_slot, fn_arg);
	l->slot_off_flags = offsetof(struct kwa_task_slot, flags);
	l->slot_flag_started = KWA_SF_STARTED;
	l->slot_flag_autostart = KWA_SF_AUTOSTART;
	l->task_off_flags = offsetof(struct task_struct, flags);
	l->task_off_exit_state = offsetof(struct task_struct, exit_state);
	l->task_off_pid = offsetof(struct task_struct, pid);
	l->task_off_tgid = offsetof(struct task_struct, tgid);
	l->task_pf_exiting = PF_EXITING;
	for (i = 0; i < sizeof(*l) - sizeof(u32); i++) {
		h ^= p[i];
		h *= 16777619u;
	}
	l->fingerprint = h;
	return (u32)(uintptr_t)l;
}

/* ---- Task state snapshot for the host (diagnostic, pure read) -----------
 * Equivalent of SysRq-T for a host that cannot inject keys: when a guest
 * stalls, the host needs to know which tasks exist and whether each one is
 * runnable or sleeping. The host calls this export from its own event loop,
 * i.e. while no kernel code is on the stack, so the task list is quiescent;
 * no lock is taken and nothing is printed (the console may be the thing that
 * is stuck). Self-describing wire format, little-endian u32 words:
 *   header: magic "KWS1", version, entry_bytes, count, total_tasks
 *   entry : token, pid, tgid, state, exit_state, flags, on_rq, reserved, comm[16]
 * token is the value the host knows the task by (kwa_task_token). */
#define KWA_SNAP_MAGIC 0x3153574bu /* bytes "KWS1" */
#define KWA_SNAP_VERSION 1u
#define KWA_SNAP_MAX 128

struct kwa_task_snap_entry {
	u32 token;
	u32 pid;
	u32 tgid;
	u32 state;
	u32 exit_state;
	u32 flags;
	u32 on_rq;
	u32 reserved;
	char comm[TASK_COMM_LEN];
};

static struct {
	u32 magic;
	u32 version;
	u32 entry_bytes;
	u32 count;
	u32 total;
	struct kwa_task_snap_entry entries[KWA_SNAP_MAX];
} kwa_task_snap;

__attribute__((export_name("kwa_task_snapshot_ptr"))) u32 kwa_task_snapshot_ptr(void)
{
	struct task_struct *g, *t;
	u32 n = 0, total = 0;

	kwa_task_snap.magic = KWA_SNAP_MAGIC;
	kwa_task_snap.version = KWA_SNAP_VERSION;
	kwa_task_snap.entry_bytes = sizeof(struct kwa_task_snap_entry);
	for_each_process_thread(g, t) {
		struct kwa_task_snap_entry *e;

		total++;
		if (n >= KWA_SNAP_MAX)
			continue;
		e = &kwa_task_snap.entries[n++];
		e->token = kwa_task_token(t);
		e->pid = t->pid;
		e->tgid = t->tgid;
		e->state = READ_ONCE(t->__state);
		e->exit_state = READ_ONCE(t->exit_state);
		e->flags = t->flags;
		e->on_rq = t->on_rq;
		e->reserved = 0;
		memcpy(e->comm, t->comm, TASK_COMM_LEN);
	}
	kwa_task_snap.count = n;
	kwa_task_snap.total = total;
	return (u32)(uintptr_t)&kwa_task_snap;
}

struct task_struct *kwa_task_validate_running(u32 token, int *cpu_out)
{
	struct kwa_task_slot *slot;
	struct task_struct *task;
	struct thread_info *ti;
	int cpu;

	if (token == 0) /* boot continuation is never a syscall target */
		return NULL;
	slot = kwa_task_lookup(token);
	if (!slot || !(slot->flags & KWA_SF_STARTED))
		return NULL;
	task = slot->task;
	if (!task || READ_ONCE(task->exit_state) != 0 ||
	    (task->flags & PF_EXITING))
		return NULL;
	/* The boot slot's alias bound to init_task (pid 0) must never become a
	 * syscall target: idle is not a brokered task. */
	if (task->pid == 0)
		return NULL;

	/* CPU ownership is scheduler-owned: running_cpu is assigned by
	 * __switch_to at the handoff. An unscheduled task (< 0) is rejected —
	 * the C layer never manufactures ownership to make a broker request
	 * pass; a real user worker cannot issue a syscall for a task the
	 * scheduler has not given a cpu, so this is fail-closed. */
	ti = task_thread_info(task);
	cpu = atomic_read(&ti->running_cpu);
	if (cpu < 0)
		return NULL;
	if (cpu_out)
		*cpu_out = cpu;
	return task;
}

void kwa_boot_stack_capture(void)
{
	kwa_boot_sp = get_stack_pointer();
}

void *kwa_boot_stack_top(void)
{
	return kwa_boot_sp;
}

void kwa_boot_register(struct task_struct *idle_task, int (*fn)(void *))
{
	struct kwa_task_slot *slot = kwa_task_lookup(0);

	BUG_ON(slot); // boot registered exactly once
	slot = kwa_task_register(idle_task, fn, NULL, KWA_SF_AUTOSTART);
	/* Reserve wire token 0 for the boot slot while binding the cpu0 idle
	 * task: yields/resumes legitimately use the init_task opaque token,
	 * which kwa_task_lookup resolves back to this same slot. */
	slot->token = 0;
}
