import {
  makeRawProcessEventMessage,
  type RawKernelProcessEvent,
} from "./process-events.ts";

export interface Instance extends WebAssembly.Instance {
  exports: {
    __indirect_function_table: WebAssembly.Table;
    boot(): void;
    trigger_irq_for_cpu(cpu: number, irq: number): void;
    syscall(
      nr: number,
      arg0: number,
      arg1: number,
      arg2: number,
      arg3: number,
      arg4: number,
      arg5: number,
    ): number;
    /** K5: per-task syscall bridge — host wraps with WebAssembly.promising.
     * 9th param is a host-generated transport-only dispatch id; C validates
     * the task token and stamps identity inline via kernel.syscall_complete. */
    kwa_syscall_for_task(
      taskToken: number,
      nr: number,
      arg0: number,
      arg1: number,
      arg2: number,
      arg3: number,
      arg4: number,
      arg5: number,
      dispatchId: number,
    ): number;
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
  env: { memory: WebAssembly.Memory };
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
    spawn_worker(
      fn: number,
      arg: number,
      comm: number,
      comm_len: number,
      share_user_memory: number,
      taskToken: number,
      spawn_flags: number,
    ): void;
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
    syscall_complete(
      taskToken: number,
      requestId: number,
      result: number,
      pid: number,
      tgid: number,
      generation: number,
    ): void;
    run_on_main(fn: number, arg: number): void;
    process_event(
      event_kind: number,
      run_id_hi: bigint,
      run_id_lo: bigint,
      event_seq: bigint,
      pid: number,
      tgid: number,
      ppid: number,
      worker_id: number,
      data0: bigint,
      data1: bigint,
      comm: number,
      comm_len: number,
    ): void;
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
  /** K5: with authority wiring every virtio import is a JSPI Suspending
   * round-trip to the main process where the devices live; plain function
   * values are the pre-K5 direct-call form. */
  virtio: {
    set_features:
      | ((dev: number, features: bigint) => void)
      | WebAssembly.ImportValue;

    setup:
      | ((
        dev: number,
        irq: number,
        is_config_addr: number,
        is_vring_addr: number,
        config_addr: number,
        config_len: number,
      ) => void)
      | WebAssembly.ImportValue;

    enable_vring:
      | ((
        dev: number,
        vq: number,
        size: number,
        desc_addr: number,
      ) => void)
      | WebAssembly.ImportValue;
    disable_vring:
      | ((dev: number, vq: number) => void)
      | WebAssembly.ImportValue;

    notify:
      | ((dev: number, vq: number) => void)
      | WebAssembly.ImportValue;
  };
}

/** K5A: Cooperative yield reasons — kernel tells host why it is yielding. */
export const YIELD_REASON_SWITCH = 1;
export const YIELD_REASON_IDLE = 2;
export const YIELD_REASON_DELAY = 3;
export const YIELD_REASON_FORK_ACK = 4;
export const YIELD_REASON_RELAX = 5;

export const HALT_KERNEL = Symbol("halt kernel");

/** K5: terminal task exit sentinel — finish_task unwinds the dead task's
 * continuation with this rejection; distinct from HALT_KERNEL (halt guard). */
export const TERMINAL_TASK_EXIT = Symbol("terminal task exit");

/** K5: exec replacement sentinel — an old image's user.call frame is
 * unwound because the kernel committed a new image for the SAME task. The
 * Linux task did NOT die: registry, attribution and quiesce state stay
 * untouched; the new-image continuation carries the task forward. */
export const USER_IMAGE_REPLACED = Symbol("user image replaced");

/** JSPI ships natively (Node ≥24, Chromium ≥137) but is absent from current
 * TS lib types — single named cast, runtime-guarded at use sites. `never[]`
 * constraints: strictFunctionTypes contravariance makes `unknown[]` reject
 * concrete callback signatures (never is assignable to every param type, so
 * any concrete F satisfies the constraint without `any`). */
type JspiWebAssembly = typeof WebAssembly & {
  Suspending?: new <F extends (...args: never[]) => unknown>(
    fn: F,
  ) => WebAssembly.ImportValue;
  promising?: <F extends (...args: never[]) => unknown>(
    fn: F,
  ) => (...args: Parameters<F>) => Promise<ReturnType<F>>;
};
const wasmJspi = WebAssembly as JspiWebAssembly;
export function kernel_imports(
  {
    is_worker,
    memory,
    spawn_worker,
    boot_console_write,
    boot_console_close,
    run_on_main,
    get_user_module,
    get_user_memory,
    process_event_handler,
    onKernelYield,
    onFinishTask,
    onSyscallComplete,
    onHaltWorker,
    spawnWorkerRaw,
  }: {
    is_worker: boolean;
    memory: WebAssembly.Memory;
    /** Adapted spawn callback (name decoded, user module/memory attached).
     * Optional: when `spawnWorkerRaw` is provided the authority fully owns
     * spawn disposition and this is not invoked. */
    spawn_worker?: (
      fn: number,
      arg: number,
      name: string,
      user_module: WebAssembly.Module | null,
      user_memory: WebAssembly.Memory | null,
    ) => void;
    /** K6R1: raw spawn hook — receives the decoded comm name, share_user_memory
     * (memory topology only), KERNEL-OWNED taskToken, and spawn_flags
     * (scheduling policy only; bit0 0x1 = KWA_SPAWN_AUTOSTART). When provided
     * the authority fully owns spawn disposition and the adapted callback is
     * not invoked. */
    spawnWorkerRaw?: (
      fn: number,
      arg: number,
      name: string,
      shareUserMemory: number,
      taskToken: number,
      spawnFlags: number,
    ) => void;
    boot_console_write: (message: ArrayBuffer) => void;
    boot_console_close: () => void;
    run_on_main: (fn: number, arg: number) => void;
    get_user_module: () => WebAssembly.Module | null;
    get_user_memory: () => WebAssembly.Memory | null;
    process_event_handler?: (
      event_kind: number,
      run_id_hi: bigint,
      run_id_lo: bigint,
      event_seq: bigint,
      pid: number,
      tgid: number,
      ppid: number,
      worker_id: number,
      data0: bigint,
      data1: bigint,
      comm: string,
    ) => void;
    /** K5: authority wiring for the cooperative yield — 4-arg shared C ABI.
     * When provided, the `kernel.yield` import value is a real JSPI
     * `WebAssembly.Suspending`: the wasm stack suspends on the returned
     * promise and resumes when the authority resolves it. selfTask/nextTask
     * are kernel-owned opaque task addresses; the authority starts or resumes
     * ONLY nextTask and parks selfTask until its own deadline/external wake. */
    onKernelYield?: (
      reason: number,
      deadlineNs: bigint,
      selfTask: number,
      nextTask: number,
    ) => Promise<void>;
    /** K5: authority terminal handoff — invoked when C calls
     * kernel.finish_task; MUST throw so the dead task's continuation dies
     * alone while the authority worker and sibling tasks survive. */
    onFinishTask?: (selfTask: number, nextTask: number) => never;
    /** K5: authority per-request completion stamp from C-local identity. */
    onSyscallComplete?: (
      taskToken: number,
      requestId: number,
      result: number,
      pid: number,
      tgid: number,
      generation: number,
    ) => void;
    /** K5A: authority halt guard — invoked instead of `self.close()`; MUST
     * throw so a halting continuation dies alone (per-continuation promise
     * rejection) while the worker and its sibling continuations survive. */
    onHaltWorker?: () => never;
  },
): Imports["kernel"] {
  const mem = new Uint8Array(memory.buffer);

  const Suspending = wasmJspi.Suspending;
  if (onKernelYield && typeof Suspending !== "function") {
    throw new Error(
      "[K5A] onKernelYield requested but WebAssembly.Suspending unavailable (JSPI required)",
    );
  }
  const yieldImport: WebAssembly.ImportValue = onKernelYield && Suspending
    ? new Suspending(onKernelYield)
    : () => {
      throw new Error(
        "[K5A] kernel.yield called without JSPI authority wiring",
      );
    };

  return {
    breakpoint: () => {
      // deno-lint-ignore no-debugger
      debugger;
    },
    halt_worker: () => {
      if (!is_worker) throw new Error("Halt called in main thread");
      // K5A: authority passes onHaltWorker so a halt never self.close()s the
      // worker (that would kill every parked continuation); the guard throws.
      if (onHaltWorker) onHaltWorker();
      self.close();
      throw HALT_KERNEL;
    },

    boot_console_write: (msg, len) => {
      boot_console_write(mem.slice(msg, msg + len).buffer);
    },
    boot_console_close,

    return_address: (_level) => {
      return 0;
    },

    get_now_nsec: () => {
      /*
        The more straightforward way to do this is
        `BigInt(Math.round(performance.now() * 1_000_000))`.
        Below is semantically identical but has less floating point
        inaccuracy.
        `performance.now()` has 5μs precision in the browser.
        In server runtimes it has full nanosecond precision, but this code
        rounds to the same 5μs precision.
      */
      return BigInt(
        Math.round((performance.now() + performance.timeOrigin) * 200),
      ) * 5000n;
    },

    get_stacktrace: (buf, size) => {
      // 5 lines: strip Error, strip 4 common lines of stack
      const trace = new TextEncoder().encode(
        new Error().stack?.split("\n").slice(5).join("\n"),
      );
      if (trace.byteLength > size) {
        /// 46 = "."
        trace[size - 1] = 46;
        trace[size - 2] = 46;
        trace[size - 3] = 46;
      }
      mem.set(trace.slice(0, size), buf);
    },

    spawn_worker: (fn: number, arg: number, comm: number, comm_len: number, share_user_memory: number, taskToken: number, spawn_flags: number) => {
      const name = new TextDecoder().decode(
        mem.slice(comm, comm + comm_len),
      );
      if (spawnWorkerRaw) {
        // K6R1 ABI v2: share_user_memory and spawn_flags are separate params.
        spawnWorkerRaw(fn, arg, name, share_user_memory | 0, taskToken, spawn_flags ?? 0);
        return;
      }
      if (!spawn_worker) {
        throw new Error(
          "[K5A] kernel.spawn_worker requires spawnWorkerRaw or spawn_worker wiring",
        );
      }
      spawn_worker(
        fn,
        arg,
        name,
        share_user_memory ? get_user_module() : null,
        share_user_memory ? get_user_memory() : null,
      );
    },

    run_on_main,

    // K5: real JSPI suspension when authority-wired; loud stub otherwise.
    yield: yieldImport,

    // K5: C terminal handoff. The wired handler NEVER returns (it schedules
    // nextTask then throws) — so this import is non-returning by contract.
    finish_task: (selfTask, nextTask) => {
      if (onFinishTask) onFinishTask(selfTask, nextTask);
      throw new Error(
        "[K5] kernel.finish_task called without authority wiring",
      );
    },

    // K5: per-request completion stamp with C-local entry identity. The
    // authority writes RESP_ID/RESULT/ERRNO/KERNEL_* into the pending slot
    // synchronously here — no global getters after await.
    syscall_complete: (taskToken, requestId, result, pid, tgid, generation) => {
      if (onSyscallComplete) {
        onSyscallComplete(taskToken, requestId, result, pid, tgid, generation);
        return;
      }
      throw new Error(
        "[K5] kernel.syscall_complete called without authority wiring",
      );
    },

    process_event: (
      event_kind,
      run_id_hi,
      run_id_lo,
      event_seq,
      pid,
      tgid,
      ppid,
      worker_id,
      data0,
      data1,
      comm,
      comm_len,
    ) => {
      const comm_str = new TextDecoder().decode(
        mem.slice(comm, comm + comm_len),
      );
      if (process_event_handler) {
        process_event_handler(
          event_kind,
          run_id_hi,
          run_id_lo,
          event_seq,
          pid,
          tgid,
          ppid,
          worker_id,
          data0,
          data1,
          comm_str,
        );
        // Z1-GABI: fall THROUGH to the forward path below — the handler only
        // observes (imageId binding); main-thread event consumers (witness
        // rawEvents) must keep receiving every event.
      }

      // Kernel process events may originate on any wasm worker. The main
      // Machine owns the authoritative event stream, so worker-side imports
      // must forward the raw event instead of silently dropping it.
      if (is_worker) {
        const raw: RawKernelProcessEvent = {
          event_kind,
          run_id_hi,
          run_id_lo,
          event_seq,
          pid,
          tgid,
          ppid,
          worker_id,
          data0,
          data1,
          comm: comm_str,
        };
        (self as DedicatedWorkerGlobalScope).postMessage(
          makeRawProcessEventMessage(raw),
        );
      }
    },
  };
}
