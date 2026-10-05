#ifndef _WASM_WASM_IMPORTS_H
#define _WASM_WASM_IMPORTS_H

#include <linux/types.h>

#define wasm_import(ns, name)                                   \
	__attribute__((import_module(#ns), import_name(#name))) \
	wasm_##ns##_##name

void wasm_import(boot, get_devicetree)(char *buf, size_t size);
int wasm_import(boot, get_initramfs)(char *buf, size_t size);

void wasm_import(kernel, breakpoint)(void);
void wasm_import(kernel, halt_worker)(void);

void wasm_import(kernel, boot_console_write)(const char *msg, size_t len);
void wasm_import(kernel, boot_console_close)(void);

void *wasm_import(kernel, return_address)(int level);

unsigned long long wasm_import(kernel, get_now_nsec)(void);

void wasm_import(kernel, get_stacktrace)(char *buf, size_t size);

/** K5: kernel-owned task registry. Host holds opaque tokens only; C validates
 * every token against live kernel task state before acting on it.
 * @share_user_memory: bit0 (0x1) = share user memory (clone-with-fn threads);
 *                     bit1 (0x2) = KWA_SF_AUTOSTART — host starts this token
 *                     via kwa_task_entry immediately (secondary idle). Boot
 *                     (token 0) is separately started when exports.boot
 *                     returns. All other tokens: registration only. */
void wasm_import(kernel, spawn_worker)(int (*fn)(void *), void *arg,
				       char *name, size_t name_len, u32 share_user_memory,
				       u32 task_token, u32 spawn_flags);

void wasm_import(kernel, run_on_main)(void (*fn)(void *), void *arg);

/** K5: cooperative scheduler yield. Suspending (JSPI) — the calling
 * continuation parks here and the host resumes exactly one kernel-named peer.
 * @reason: KWA_YIELD_* code
 * @deadline_ns: ABSOLUTE deadline; 0 = no deadline (resume only when the
 *               kernel-named nextTask chain yields back to selfTask)
 * @self_task: opaque kernel token of the suspending task (0 if none)
 * @next_task: opaque kernel token the host must start/resume (may equal
 *             self_task for bounded self-resume yields; never chosen by host) */
void wasm_import(kernel, yield)(u32 reason, u64 deadline_ns, u32 self_task,
				u32 next_task);

/** K5: terminal handoff. Non-returning: called by __switch_to when the
 * switching-out task has thread_done set. The host cancels the dead task's
 * outstanding claimed broker slots (no invented result), rejects/unwinds only
 * that task's parked guest/root/syscall continuations, retires its user
 * worker, then starts/resumes nextTask. Authority is never self-closed. */
void wasm_import(kernel, finish_task)(u32 self_task, u32 next_task);

/** K5: per-request syscall completion. Synchronous, called inside the
 * kwa_syscall_for_task C frame with C-captured entry identity (immune to
 * cross-task overwrites of the diagnostic kwa_get_last_* globals). The host
 * binds this to the broker slot claimed by @dispatch_id. Exec/exit requests
 * never reach this import: their slots are cancelled by finish_task. */
void wasm_import(kernel, syscall_complete)(u32 task_token, u32 dispatch_id,
					   long result, int pid, int tgid,
					   u32 generation);

/* Yield reasons — stable ABI values consumed by the host scheduler. */
#define KWA_YIELD_SWITCH 1  /* scheduler handoff: next_task is mandatory */
#define KWA_YIELD_IDLE 2    /* idle park: wake on deadline/IRQ */
#define KWA_YIELD_DELAY 3   /* __delay bounded self-resume */
#define KWA_YIELD_FORK_ACK 4
#define KWA_YIELD_RELAX 5   /* cpu_relax bounded self-resume */
void wasm_import(kernel, process_event)(u32 event_kind, u64 run_id_hi, u64 run_id_lo,
					u64 event_seq, u32 pid, u32 tgid, u32 ppid,
					u32 worker_id, u64 data0, u64 data1,
					const char *comm, size_t comm_len);

int wasm_import(user, compile)(u8 *bytes, u32 len);
void wasm_import(user, instantiate)(bool fresh_memory);
int wasm_import(user, call)(void);
#define KWA_USER_CALL_RETURNED 0
#define KWA_USER_CALL_TRAP     1
void wasm_import(user, switch_entry)(u32 fn, u32 arg);
void wasm_import(user, call_signal_handler)(u32 fn, u32 sig);
void wasm_import(user, halt_signal_handler)(void);
void wasm_import(user, fork_user)(u32 pid);

int wasm_import(user, read)(void *to, const void __user *from, unsigned long n);
int wasm_import(user, write)(void __user *to, const void *from, unsigned long n);
int wasm_import(user, write_zeroes)(void __user *to, unsigned long n);

#ifdef CONFIG_VIRTIO_WASM
void wasm_import(virtio, set_features)(u32 id, u64 features);

void wasm_import(virtio, setup)(u32 id, u32 irq, bool *is_config,
				bool *is_vring, u8 *config, u32 config_len);

void wasm_import(virtio, enable_vring)(u32 id, u32 index, u32 size,
				       dma_addr_t desc);
void wasm_import(virtio, disable_vring)(u32 id, u32 index);

void wasm_import(virtio, notify)(u32 id, u32 index);
#endif

#undef wasm_import

#endif
