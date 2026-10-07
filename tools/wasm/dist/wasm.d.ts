export interface Instance extends WebAssembly.Instance {
    exports: {
        __indirect_function_table: WebAssembly.Table;
        boot(): void;
        trigger_irq_for_cpu(cpu: number, irq: number): void;
        syscall(nr: number, arg0: number, arg1: number, arg2: number, arg3: number, arg4: number, arg5: number): number;
        /** K5: per-task syscall bridge — host wraps with WebAssembly.promising.
         * 9th param is a host-generated transport-only dispatch id; C validates
         * the task token and stamps identity inline via kernel.syscall_complete. */
        kwa_syscall_for_task(taskToken: number, nr: number, arg0: number, arg1: number, arg2: number, arg3: number, arg4: number, arg5: number, dispatchId: number): number;
        /** K5: fork-ack wake — child's VAS snapshot is complete; parent resumes. */
        fork_copied(pid: number): void;
        /** K5: kernel-owned task trampoline — start a kernel task continuation
         * by its opaque token; C resolves its own bootstrap args internally. */
        kwa_task_entry(taskToken: number): void;
        get_thread_area(): number;
        get_args_length(): number;
        get_args(buf: number): number;
        arch_wasm_poll(): number;
    };
}
export interface Imports {
    env: {
        memory: WebAssembly.Memory;
    };
    boot: {
        get_devicetree(buf: number, size: number): void;
        get_initramfs(buf: number, size: number): number;
    };
    kernel: {
        breakpoint(): void;
        halt_worker(): void;
        boot_console_write(msg: number, len: number): void;
        boot_console_close(): void;
        return_address(_level: number): number;
        get_now_nsec(): bigint;
        get_stacktrace(buf: number, size: number): void;
        spawn_worker(fn: number, arg: number, comm: number, comm_len: number, share_user_memory: number, taskToken: number, spawn_flags: number): void;
        /** K5A: cooperative yield — 4-arg shared C ABI. selfTask/nextTask are
         * opaque KERNEL-OWNED task addresses (not host PID claims). With authority
         * wiring the import value is a real JSPI `WebAssembly.Suspending`: the
         * wasm stack suspends on the returned promise; JSPI does NOT restore
         * globals — the C kernel re-binds identity/stack on resume. Host may
         * start/resume ONLY the kernel-provided nextTask. */
        yield: WebAssembly.ImportValue;
        /** K5: C terminal handoff — __switch_to saw thread_done. Non-returning:
         * host cancels the dead task's outstanding broker slots (explicit terminal
         * cancellation, never a fake result), rejects its parked continuations,
         * schedules the kernel-named nextTask, then throws to unwind the frame. */
        finish_task(selfTask: number, nextTask: number): void;
        /** K5: per-request completion stamp — called synchronously inside the
         * syscall's C frame with C-LOCAL entry identity/generation (never global
         * getters after await). requestId is the host-generated transport-only
         * dispatch id; host binds it to the pending broker slot. */
        syscall_complete(taskToken: number, requestId: number, result: number, pid: number, tgid: number, generation: number): void;
        run_on_main(fn: number, arg: number): void;
        process_event(event_kind: number, run_id_hi: bigint, run_id_lo: bigint, event_seq: bigint, pid: number, tgid: number, ppid: number, worker_id: number, data0: bigint, data1: bigint, comm: number, comm_len: number): void;
    };
    /** K5: with authority wiring `call` is a JSPI Suspending import (the kernel
     * task parks inside it while the pure user worker runs the guest); the
     * secondary-worker path passes a plain function. */
    user: {
        compile(buf: number, size: number): number;
        instantiate(fresh_memory: number): void;
        call: (() => void) | WebAssembly.ImportValue;
        switch_entry(fn: number, arg: number): void;
        call_signal_handler(fn: number, sig: number): void;
        read(to: number, from: number, n: number): number;
        write(to: number, from: number, n: number): number;
        fork_user(pid: number): void;
        write_zeroes(to: number, n: number): number;
    };
    /** Z1-GABI: guests may import linux.* functions DIRECTLY (busybox declares
     * syscall + get_args_length + get_args + arch_wasm_poll). Kernel-shaped
     * guests (multi-entry linux imports) need this namespace in the full
     * imports object — broker-backed, task-bound. Absent for guests that do
     * not request it. */
    linux?: {
        syscall(nr: number, arg0: number, arg1: number, arg2: number, arg3: number, arg4: number, arg5: number): number;
        get_thread_area(): number;
        get_args_length(): number;
        get_args(buf: number): number;
        arch_wasm_poll(): number;
    };
    /** K5: with authority wiring every virtio import is a JSPI Suspending
     * round-trip to the main process where the devices live; plain function
     * values are the pre-K5 direct-call form. */
    virtio: {
        set_features: ((dev: number, features: bigint) => void) | WebAssembly.ImportValue;
        setup: ((dev: number, irq: number, is_config_addr: number, is_vring_addr: number, config_addr: number, config_len: number) => void) | WebAssembly.ImportValue;
        enable_vring: ((dev: number, vq: number, size: number, desc_addr: number) => void) | WebAssembly.ImportValue;
        disable_vring: ((dev: number, vq: number) => void) | WebAssembly.ImportValue;
        notify: ((dev: number, vq: number) => void) | WebAssembly.ImportValue;
    };
}
/** K5A: Cooperative yield reasons — kernel tells host why it is yielding. */
export declare const YIELD_REASON_SWITCH = 1;
export declare const YIELD_REASON_IDLE = 2;
export declare const YIELD_REASON_DELAY = 3;
export declare const YIELD_REASON_FORK_ACK = 4;
export declare const YIELD_REASON_RELAX = 5;
export declare const HALT_KERNEL: unique symbol;
/** K5: terminal task exit sentinel — finish_task unwinds the dead task's
 * continuation with this rejection; distinct from HALT_KERNEL (halt guard). */
export declare const TERMINAL_TASK_EXIT: unique symbol;
/** K5: exec replacement sentinel — an old image's user.call frame is
 * unwound because the kernel committed a new image for the SAME task. The
 * Linux task did NOT die: registry, attribution and quiesce state stay
 * untouched; the new-image continuation carries the task forward. */
export declare const USER_IMAGE_REPLACED: unique symbol;
export declare function kernel_imports({ is_worker, memory, spawn_worker, boot_console_write, boot_console_close, run_on_main, get_user_module, get_user_memory, process_event_handler, onKernelYield, onFinishTask, onSyscallComplete, onHaltWorker, spawnWorkerRaw, }: {
    is_worker: boolean;
    memory: WebAssembly.Memory;
    /** Adapted spawn callback (name decoded, user module/memory attached).
     * Optional: when `spawnWorkerRaw` is provided the authority fully owns
     * spawn disposition and this is not invoked. */
    spawn_worker?: (fn: number, arg: number, name: string, user_module: WebAssembly.Module | null, user_memory: WebAssembly.Memory | null) => void;
    /** K6R1: raw spawn hook — receives the decoded comm name, share_user_memory
     * (memory topology only), KERNEL-OWNED taskToken, and spawn_flags
     * (scheduling policy only; bit0 0x1 = KWA_SPAWN_AUTOSTART). When provided
     * the authority fully owns spawn disposition and the adapted callback is
     * not invoked. */
    spawnWorkerRaw?: (fn: number, arg: number, name: string, shareUserMemory: number, taskToken: number, spawnFlags: number) => void;
    boot_console_write: (message: ArrayBuffer) => void;
    boot_console_close: () => void;
    run_on_main: (fn: number, arg: number) => void;
    get_user_module: () => WebAssembly.Module | null;
    get_user_memory: () => WebAssembly.Memory | null;
    process_event_handler?: (event_kind: number, run_id_hi: bigint, run_id_lo: bigint, event_seq: bigint, pid: number, tgid: number, ppid: number, worker_id: number, data0: bigint, data1: bigint, comm: string) => void;
    /** K5: authority wiring for the cooperative yield — 4-arg shared C ABI.
     * When provided, the `kernel.yield` import value is a real JSPI
     * `WebAssembly.Suspending`: the wasm stack suspends on the returned
     * promise and resumes when the authority resolves it. selfTask/nextTask
     * are kernel-owned opaque task addresses; the authority starts or resumes
     * ONLY nextTask and parks selfTask until its own deadline/external wake. */
    onKernelYield?: (reason: number, deadlineNs: bigint, selfTask: number, nextTask: number) => Promise<void>;
    /** K5: authority terminal handoff — invoked when C calls
     * kernel.finish_task; MUST throw so the dead task's continuation dies
     * alone while the authority worker and sibling tasks survive. */
    onFinishTask?: (selfTask: number, nextTask: number) => never;
    /** K5: authority per-request completion stamp from C-local identity. */
    onSyscallComplete?: (taskToken: number, requestId: number, result: number, pid: number, tgid: number, generation: number) => void;
    /** K5A: authority halt guard — invoked instead of `self.close()`; MUST
     * throw so a halting continuation dies alone (per-continuation promise
     * rejection) while the worker and its sibling continuations survive. */
    onHaltWorker?: () => never;
}): Imports["kernel"];
