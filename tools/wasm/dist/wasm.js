import { makeRawProcessEventMessage, } from "./process-events.js";
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
const wasmJspi = WebAssembly;
/** Z1-G6-THREADS: rebindable user-memory binding. When the user image is
 * replaced (exec/fork/switch_thread), the NEW WebAssembly.Memory must be
 * visible to the kernel imports' memory-access handlers. JS function
 * parameters are mutable bindings: reassigning `memory` here is seen by every
 * nested closure. The worker registers this setter and calls it on image
 * replacement; without rebinding, thread children resolve guest pointers
 * against a stale boot-era buffer (RangeError 'Start offset ...'). */
const z1KernelMemorySetters = [];
export function z1RegisterKernelMemorySetter(fn) {
    if (typeof fn === "function")
        z1KernelMemorySetters.push(fn);
}
export function z1RebindKernelMemory(m) {
    for (const fn of z1KernelMemorySetters)
        fn(m);
}
export function kernel_imports({ is_worker, memory, spawn_worker, boot_console_write, boot_console_close, run_on_main, get_user_module, get_user_memory, process_event_handler, onKernelYield, onTimerDeadline, onFinishTask, onSyscallComplete, onHaltWorker, spawnWorkerRaw, }) {
    // Z1-G6-THREADS: register rebindable memory setter so nested closures
    // see updated memory binding on exec/fork/switch_thread image replacement.
    let mem = new Uint8Array(memory.buffer);
    z1RegisterKernelMemorySetter((m) => { if (m) {
        memory = m;
        mem = new Uint8Array(m.buffer);
    } });
    const Suspending = wasmJspi.Suspending;
    if (onKernelYield && typeof Suspending !== "function") {
        throw new Error("[K5A] onKernelYield requested but WebAssembly.Suspending unavailable (JSPI required)");
    }
    const yieldImport = onKernelYield && Suspending
        ? new Suspending(onKernelYield)
        : () => {
            throw new Error("[K5A] kernel.yield called without JSPI authority wiring");
        };
    return {
        breakpoint: () => {
            // deno-lint-ignore no-debugger
            debugger;
        },
        halt_worker: () => {
            if (!is_worker)
                throw new Error("Halt called in main thread");
            // K5A: authority passes onHaltWorker so a halt never self.close()s the
            // worker (that would kill every parked continuation); the guard throws.
            if (onHaltWorker)
                onHaltWorker();
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
            return BigInt(Math.round((performance.now() + performance.timeOrigin) * 200)) * 5000n;
        },
        set_timer_deadline: onTimerDeadline,
        get_stacktrace: (buf, size) => {
            // 5 lines: strip Error, strip 4 common lines of stack
            const trace = new TextEncoder().encode(new Error().stack?.split("\n").slice(5).join("\n"));
            if (trace.byteLength > size) {
                /// 46 = "."
                trace[size - 1] = 46;
                trace[size - 2] = 46;
                trace[size - 3] = 46;
            }
            mem.set(trace.slice(0, size), buf);
        },
        spawn_worker: (fn, arg, comm, comm_len, share_user_memory, taskToken, spawn_flags) => {
            const name = new TextDecoder().decode(mem.slice(comm, comm + comm_len));
            if (spawnWorkerRaw) {
                // K6R1 ABI v2: share_user_memory and spawn_flags are separate params.
                spawnWorkerRaw(fn, arg, name, share_user_memory | 0, taskToken, spawn_flags ?? 0);
                return;
            }
            if (!spawn_worker) {
                throw new Error("[K5A] kernel.spawn_worker requires spawnWorkerRaw or spawn_worker wiring");
            }
            spawn_worker(fn, arg, name, share_user_memory ? get_user_module() : null, share_user_memory ? get_user_memory() : null);
        },
        run_on_main,
        // K5: real JSPI suspension when authority-wired; loud stub otherwise.
        yield: yieldImport,
        // K5: C terminal handoff. The wired handler NEVER returns (it schedules
        // nextTask then throws) — so this import is non-returning by contract.
        finish_task: (selfTask, nextTask) => {
            if (onFinishTask)
                onFinishTask(selfTask, nextTask);
            throw new Error("[K5] kernel.finish_task called without authority wiring");
        },
        // K5: per-request completion stamp with C-local entry identity. The
        // authority writes RESP_ID/RESULT/ERRNO/KERNEL_* into the pending slot
        // synchronously here — no global getters after await.
        syscall_complete: (taskToken, requestId, result, pid, tgid, generation) => {
            if (onSyscallComplete) {
                onSyscallComplete(taskToken, requestId, result, pid, tgid, generation);
                return;
            }
            throw new Error("[K5] kernel.syscall_complete called without authority wiring");
        },
        process_event: (event_kind, run_id_hi, run_id_lo, event_seq, pid, tgid, ppid, worker_id, data0, data1, comm, comm_len) => {
            const comm_str = new TextDecoder().decode(mem.slice(comm, comm + comm_len));
            if (process_event_handler) {
                process_event_handler(event_kind, run_id_hi, run_id_lo, event_seq, pid, tgid, ppid, worker_id, data0, data1, comm_str);
                // Z1-GABI: fall THROUGH to the forward path below — the handler only
                // observes (imageId binding); main-thread event consumers (witness
                // rawEvents) must keep receiving every event.
            }
            // Kernel process events may originate on any wasm worker. The main
            // Machine owns the authoritative event stream, so worker-side imports
            // must forward the raw event instead of silently dropping it.
            if (is_worker) {
                const raw = {
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
                self.postMessage(makeRawProcessEventMessage(raw));
            }
        },
    };
}
//# sourceMappingURL=wasm.js.map