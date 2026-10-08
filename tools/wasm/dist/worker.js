import { assert } from "./util.js";
import { HALT_KERNEL, kernel_imports, TERMINAL_TASK_EXIT, USER_IMAGE_REPLACED, YIELD_REASON_IDLE, } from "./wasm.js";
import { D1RingBuffer } from "./d1-ring-buffer.js";
import { wrapSyscall } from "./d1-syscall-wrapper.js";
import { BrokerClient, idx, N_SLOTS, OFF, S, STATE, } from "./kwa-broker.js";
function postK4Diag(stage, detail) {
    try {
        postMessage({ type: "k4_diag", stage, detail });
    }
    catch { /* best-effort diagnostic */ }
}
function postK5Diag(stage, ok, detail) {
    postMessage({ type: "authority_diag", stage, ok, detail, ts: performance.now() });
}
/** Message handlers the authority block registers once initialized; the
 * onmessage dispatcher routes authority-directed messages to them. */
let authorityHandlers = null;
function isInitMessage(data) {
    return !(typeof data === "object" && data !== null && "type" in data);
}
const unavailable = () => {
    throw new Error("not available on worker thread");
};
const postMessage = self.postMessage;
let workerDoneSent = false;
function signalWorkerDone(reason) {
    if (workerDoneSent)
        return;
    workerDoneSent = true;
    postMessage({ type: "worker_done", reason });
}
const d1TraceBuffer = new D1RingBuffer(4096);
let d1TraceEnabled = false;
let d1RunId = "";
let d1Exported = false;
export function exportD1Trace() {
    if (!d1TraceEnabled || d1Exported)
        return;
    d1Exported = true;
    d1TraceBuffer.recordLifecycle("trace_export_requested", d1RunId);
    if (d1TraceBuffer.getMetadata().wrapped) {
        d1TraceBuffer.recordLifecycle("trace_overwrite_observed", d1RunId);
    }
    d1TraceBuffer.recordLifecycle("trace_export_completed", d1RunId);
    const records = d1TraceBuffer.getRecords();
    const metadata = d1TraceBuffer.getMetadata();
    postMessage({ type: "d1_trace_export", runId: d1RunId, records, metadata });
}
function user_imports({ kernel_memory, get_kernel_instance, parent_user_module: parent_module, parent_user_memory: parent_memory, parent_tls_base, brokerSab, workerId, taskToken, tasksMap, }) {
    const HALT_USER = Symbol("halt user");
    const kernel_memory_buffer = new Uint8Array(kernel_memory.buffer);
    let module = null;
    let parentTlsBase = 0;
    let instance = null;
    let memory = null;
    function call_start() {
        assert(instance);
        const { _start } = instance.exports;
        assert(typeof _start === "function", "_start not found");
        // K5 guests export _start(param i32); extra args are ignored by the JS API
        // for 0-param starts, so 0 satisfies both signatures.
        _start(0);
        throw new Error("_start reached the end without exiting");
    }
    let call_entry = call_start;
    // M115: apply the parent's TLS base to a freshly instantiated clone/thread
    // instance so _Thread_local accesses land on the shared TLS block.
    const applyTlsBase = () => {
        if (!instance || !parent_tls_base)
            return;
        const g = instance.exports.__tls_base;
        if (g && typeof g === "object" && "value" in g)
            g.value = parent_tls_base;
    };
    // shared instantiation body; fall back to the parent's module/memory
    // when this worker has not exec'd its own program (fork child).
    const doInstantiate = () => {
        assert(module);
        if (!memory) {
            const initial = 12288; // 768 MiB
            const maximum = 32768; // 2 GiB tetto
            memory = new WebAssembly.Memory({ initial, maximum, shared: true });
            if (d1TraceEnabled) {
                d1TraceBuffer.recordLifecycle("wasm_memory_constructed", d1RunId, {
                    detail: `initial=${initial} maximum=${maximum}`,
                });
            }
        }
        // K4: Secondary workers MUST NOT access kernel instance directly.
        // All syscalls route through broker SAB; non-syscall imports are stubbed.
        const isBrokerOnly = (() => {
            try {
                get_kernel_instance();
                return false;
            }
            catch {
                return true;
            }
        })();
        if (isBrokerOnly) {
            // Broker-only path: route syscalls through shared SAB to single kernel authority
            // brokerSab and workerId must be available from InitMessage (set in onmessage scope)
            if (typeof brokerSab === "undefined" || typeof workerId === "undefined") {
                throw new Error("[K4] secondary worker missing brokerSab or workerId in InitMessage");
            }
            const brokerClient = new BrokerClient(brokerSab, workerId);
            const originalSyscallHandler = (nr, arg0, arg1, arg2, arg3, arg4, arg5) => {
                return brokerClient.invoke(nr, arg0, arg1, arg2, arg3, arg4, arg5, taskToken ?? 0, 0, () => {
                    postMessage({ type: "broker_kick", workerId });
                }).result;
            };
            const wrappedSyscallHandler = wrapSyscall(originalSyscallHandler, {
                buffer: d1TraceBuffer,
                runId: d1RunId,
                enabled: d1TraceEnabled,
                processId: `worker-${self.name || "unknown"}`,
                getThreadId: () => 0,
            });
            instance = new WebAssembly.Instance(module, {
                env: { memory },
                linux: {
                    syscall: wrappedSyscallHandler,
                    // Z1-GABI NOTE: these three are part of the FROZEN kernel ABI
                    // (bbe4f538 calls them synchronously during guest task setup).
                    // `() => 0` is load-bearing (empty argv / no TLS) until the
                    // kernel-side argv/TLS service lands; making them throw breaks
                    // every guest boot. Real values are a kernel-rebuild step.
                    get_thread_area: () => parent_tls_base ?? 0,
                    get_args_length: () => {
                        const raw = taskToken && tasksMap ? tasksMap.get(taskToken)?.argv : null;
                        let args = ["/bin/sh"];
                        if (raw && raw.byteLength > 0) {
                            const text = new TextDecoder().decode(raw).replace(/\0+$/, "");
                            if (text.length > 0)
                                args = text.split(" ").filter(Boolean);
                        }
                        let strBytes = 0;
                        for (const a of args)
                            strBytes += new TextEncoder().encode(a + "\0").length;
                        return 20 + (args.length + 1) * 4 + 4 + strBytes;
                    },
                    get_args: (buf) => {
                        if (!buf || !memory)
                            return -1;
                        const raw = taskToken && tasksMap ? tasksMap.get(taskToken)?.argv : null;
                        let args = ["/bin/sh"];
                        if (raw && raw.byteLength > 0) {
                            const text = new TextDecoder().decode(raw).replace(/\0+$/, "");
                            if (text.length > 0)
                                args = text.split(" ").filter(Boolean);
                        }
                        const dv = new DataView(memory.buffer, buf);
                        const argc = args.length;
                        const envc = 0;
                        const argvPtr = buf + 20;
                        const envpPtr = argvPtr + (argc + 1) * 4;
                        const strPtr = envpPtr + (envc + 1) * 4;
                        const encoded = [];
                        let totalStrLen = 0;
                        for (const a of args) {
                            const b = new TextEncoder().encode(a + "\0");
                            encoded.push(b);
                            totalStrLen += b.length;
                        }
                        // wasm_process_args header: len, envc, argc, argv_ptr, envp_ptr
                        dv.setInt32(0, totalStrLen, true);
                        dv.setInt32(4, envc, true);
                        dv.setInt32(8, argc, true);
                        dv.setInt32(12, argvPtr, true);
                        dv.setInt32(16, envpPtr, true);
                        // argv pointers table
                        let off = 20;
                        let currStrPtr = strPtr;
                        for (let i = 0; i < argc; i++) {
                            dv.setInt32(off, currStrPtr, true);
                            off += 4;
                            currStrPtr += encoded[i].length;
                        }
                        dv.setInt32(off, 0, true);
                        // envp pointers table (NULL)
                        dv.setInt32(envpPtr - buf, 0, true);
                        // string data
                        const memU8 = new Uint8Array(memory.buffer);
                        let sOff = strPtr;
                        for (const enc of encoded) {
                            memU8.set(enc, sOff);
                            sOff += enc.length;
                        }
                        return 0;
                    },
                    arch_wasm_poll: () => 0,
                },
            });
        }
        else {
            // Boot worker path: direct kernel access (unchanged from pre-K4)
            const kernel_instance = get_kernel_instance();
            const originalSyscallHandler = (nr, arg0, arg1, arg2, arg3, arg4, arg5) => {
                const original_instance = instance;
                let ret;
                try {
                    ret = kernel_instance.exports.syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
                }
                catch (error) {
                    if (error === HALT_KERNEL)
                        throw error;
                    throw error;
                }
                if (instance !== original_instance) {
                    call_entry = call_start;
                    throw HALT_USER;
                }
                return ret;
            };
            const wrappedSyscallHandler = wrapSyscall(originalSyscallHandler, {
                buffer: d1TraceBuffer,
                runId: d1RunId,
                enabled: d1TraceEnabled,
                processId: `worker-${self.name || "unknown"}`,
                getThreadId: () => 0,
            });
            instance = new WebAssembly.Instance(module, {
                env: { memory },
                linux: {
                    syscall: wrappedSyscallHandler,
                    get_thread_area: kernel_instance.exports.get_thread_area,
                    get_args_length: kernel_instance.exports.get_args_length,
                    get_args: kernel_instance.exports.get_args,
                    arch_wasm_poll: kernel_instance.exports.arch_wasm_poll,
                },
            });
        }
        if ("memory" in instance.exports) {
            assert(instance.exports.memory instanceof WebAssembly.Memory);
            memory = instance.exports.memory;
        }
        if (d1TraceEnabled) {
            d1TraceBuffer.recordLifecycle("kernel_module_instantiated", d1RunId);
        }
    };
    return {
        get module() {
            return module;
        },
        set module(m) {
            module = m;
        },
        get memory() {
            return memory;
        },
        set memory(m) {
            memory = m;
        },
        get instance() {
            return instance;
        },
        doInstantiate,
        imports: {
            // program management:
            compile(buf, size) {
                const bytes = new Uint8Array(kernel_memory_buffer.slice(buf, buf + size));
                try {
                    module = new WebAssembly.Module(bytes);
                    return 0;
                }
                catch {
                    return -8; // exec format error
                }
            },
            instantiate(fresh_memory) {
                if (!module && parent_module)
                    module = parent_module;
                // M115 CLONE_VM threads: instantiation rewrites .data defaults over
                // the SHARED live memory, corrupting the parent's runtime globals.
                // Snapshot/restore the .data window around it (blink links ≤2MB).
                const threadShared = !fresh_memory && parent_memory && memory === parent_memory;
                const snap = threadShared && memory ? memory.buffer.slice(0, 2 * 1024 * 1024) : null;
                if (fresh_memory && memory) {
                    // caller explicitly wants a fresh memory: recreate it
                    const initial = 12288; // 768 MiB iniziali
                    const maximum = 32768; // 2 GiB tetto
                    memory = new WebAssembly.Memory({ initial, maximum, shared: true });
                    if (d1TraceEnabled) {
                        d1TraceBuffer.recordLifecycle("wasm_memory_constructed", d1RunId, {
                            detail: `initial=${initial} maximum=${maximum}`,
                        });
                    }
                }
                doInstantiate();
                if (snap && memory) {
                    new Uint8Array(memory.buffer).set(new Uint8Array(snap), 0);
                }
            },
            call() {
                if (d1TraceEnabled) {
                    d1TraceBuffer.recordLifecycle("kernel_start_called", d1RunId);
                }
                for (;;) {
                    try {
                        call_entry();
                    }
                    catch (error) {
                        if (error === HALT_USER) {
                            if (d1TraceEnabled) {
                                d1TraceBuffer.recordLifecycle("halt_user_observed", d1RunId);
                            }
                            continue;
                        }
                        if (error === HALT_KERNEL)
                            throw error;
                        // G12: discriminate kernel do_task_dead (clean thread exit) from real errors.
                        // do_task_dead is the kernel's thread-end sentinel — it uses unreachable intentionally
                        // after sys_exit_group completes. This is NOT an error.
                        if (error instanceof Error &&
                            error.name === "RuntimeError" &&
                            error.message.includes("unreachable")) {
                            const stack = error.stack || "";
                            if (stack.includes("do_task_dead")) {
                                // Clean kernel thread death — treat as HALT_USER, continue event loop
                                console.log("[G12-DIAG] do_task_dead clean exit, continuing event loop");
                                continue;
                            }
                            // G12: Do NOT catch user module exit() traps here.
                            // When a user module (lo-up, blink, etc.) calls exit(), musl wasm32's
                            // exit() is an unreachable stub. This trap MUST propagate to the kernel's
                            // task_entry_inner (process.c:134-149), which handles it by calling
                            // do_exit(SIGSEGV) -> full task cleanup -> do_task_dead().
                            // do_task_dead itself uses unreachable, which we catch above as clean exit.
                            // Catching the trap here (at worker level) corrupts kernel scheduler state
                            // because task_entry_inner never completes its cleanup path.
                            // Non-kernel unreachable — log and fall through to error handler
                            console.log("[G12-DIAG] non-kernel unreachable trap, stack:", stack);
                        }
                        console.log("error running user module:", String(error), (error && error.stack) || "");
                        if (d1TraceEnabled) {
                            d1TraceBuffer.recordRuntimeError(error, d1RunId, {
                                eventType: "runtime_error_caught",
                                activeOperation: "call_entry",
                            });
                            d1TraceBuffer.recordLifecycle("kernel_start_returned", d1RunId, {
                                detail: error?.name ?? "error",
                            });
                            exportD1Trace();
                        }
                        return;
                    }
                }
            },
            switch_entry(fn, arg) {
                // This is called if this thread was created by a clone call,
                // and therefore we our entrypoint is a user-specified function.
                // Our custom variant of the clone syscall spawns a worker that calls
                // switch_entry, then immediately calls instantiate.
                console.log("[CLONE] switch_entry fn=" + fn + " arg=" + arg + " parent_module=" + !!parent_module + " parent_memory=" + !!parent_memory);
                assert(parent_module);
                assert(parent_memory);
                module = parent_module;
                memory = parent_memory;
                call_entry = () => {
                    assert(instance);
                    applyTlsBase();
                    const { __indirect_function_table } = instance.exports;
                    assert(__indirect_function_table instanceof WebAssembly.Table, "Invalid function table");
                    const f = __indirect_function_table.get(fn);
                    console.log("[CLONE] resolved fn=" + fn + " -> " + typeof f + " len=" + (f && f.length));
                    assert(typeof f === "function" && f.length === 1, "Invalid function signature");
                    console.log("[CLONE] calling f(" + arg + ")");
                    f(arg);
                    console.log("[CLONE] f returned");
                    // throw new Error("thread entrypoint reached the end without exiting");
                    console.warn("thread entrypoint reached the end without exiting");
                };
            },
            // G12/M115 fork-mode child: the kernel child task resumes the parent's
            // user state. The guest machine copy happens blink-side (blink's fork
            // path: NewMachine + ax=0 + Blink).
            //
            // M115 memory isolation: plain fork (fn==NULL) spawned this worker with a
            // FRESH WebAssembly.Memory (share_user_memory=false). To give the child a
            // faithful copy of the parent's VAS we must seed the fresh memory from the
            // parent's guest memory BEFORE resuming. The parent's guest memory object is
            // passed as `parent_user_memory`; the fresh child buffer is `memory`.
            // vfork 0x4111 (CLONE_VM) shares the parent memory and does not go through
            // fork_user (it uses switch_entry), so this branch is fork-isolated only.
            fork_user(pid) {
                console.log("[FORK] child pid=" + pid + " resuming guest pm_mod=" + typeof parent_module + ":" + String(parent_module).slice(0, 40) + " pm_mem=" + typeof parent_memory + ":" + String(parent_memory));
                // Fork child worker has not exec'd its own program: bind to the
                // parent's module and instantiate it into a fresh memory, then seed
                // that memory with the parent's VAS before resuming.
                if (!module && parent_module) {
                    module = parent_module;
                    console.log("[FORK] using parent_module");
                }
                if (!memory || memory === parent_memory) {
                    // Match the parent's guest memory size: the copied Machine pointer
                    // and heap live anywhere in the parent's address space.
                    const parentPages = parent_memory
                        ? Math.ceil(parent_memory.buffer.byteLength / 65536)
                        : 12288;
                    const initial = Math.max(parentPages, 12288);
                    const maximum = 32768; // 2 GiB tetto
                    console.log("[FORK] creating fresh child memory pages=" + initial);
                    memory = new WebAssembly.Memory({ initial, maximum, shared: true });
                    if (d1TraceEnabled) {
                        d1TraceBuffer.recordLifecycle("wasm_memory_constructed", d1RunId, {
                            detail: `fork-child initial=${initial} maximum=${maximum}`,
                        });
                    }
                }
                // instantiate the parent's blink module into the fresh child memory
                doInstantiate();
                if (parent_memory && memory && memory !== parent_memory) {
                    const src = new Uint8Array(parent_memory.buffer);
                    const dst = new Uint8Array(memory.buffer);
                    // Copy the parent's full user VAS (limited to child buffer length).
                    dst.set(src.subarray(0, Math.min(src.length, dst.length)));
                }
                else if (!parent_memory && memory) {
                    // No parent guest memory to copy (e.g. boot/idle): keep fresh (zeroed).
                    console.warn("[FORK] no parent guest memory to copy; child starts from zeroed VAS");
                }
                // Release the parked parent: the VAS snapshot is now complete, so the
                // parent may resume from its clone return point. K5: the ack travels
                // fork_copied → main → authority → promising(kernel fork_copied);
                // secondary workers have no kernel instance (K3) and never call it.
                postMessage({ type: "fork_copied", pid, taskToken: 0 });
                // M115 USER_FORK_RESUME: the guest (blink x86 emulator) saved its
                // Machine* + snapshot in its own .data, which is now copied verbatim
                // into this fresh child memory. Jump straight to blink's resume
                // export (reads those globals, rebinds g_machine, restores the x86
                // continuation with ax=0) instead of re-running _start()/main() —
                // the fork child carries no argv, so call_start would fail.
                call_entry = () => {
                    assert(instance);
                    applyTlsBase();
                    const { blink_user_fork_resume } = instance.exports;
                    assert(typeof blink_user_fork_resume === "function", "blink_user_fork_resume not found; not a x86-via-blink guest?");
                    console.log("[FORK] calling blink_user_fork_resume export");
                    try {
                        const rc = blink_user_fork_resume();
                        throw new Error("blink_user_fork_resume returned rc=" + rc);
                    }
                    catch (e) {
                        console.log("[FORK] resume threw: " + String(e?.stack || e));
                        throw e;
                    }
                };
            },
            // signal handling:
            call_signal_handler(fn, sig) {
                assert(instance);
                const { __indirect_function_table } = instance.exports;
                assert(__indirect_function_table instanceof WebAssembly.Table, "Invalid function table");
                const f = __indirect_function_table.get(fn);
                assert(typeof f === "function" && (f.length === 1 || f.length === 3), "Invalid function signature");
                if (f.length === 3)
                    f(sig, 0, 0);
                else
                    f(sig); // SA_SIGINFO: siginfo+ucontext placeholders
            },
            // memory:
            read(to, from, n) {
                assert(memory);
                const slice = new Uint8Array(memory.buffer, from, n);
                kernel_memory_buffer.set(slice, to);
                return n - slice.length;
            },
            write(to, from, n) {
                assert(memory);
                const slice = kernel_memory_buffer.subarray(from, from + n);
                new Uint8Array(memory.buffer, to, n).set(slice);
                return n - slice.length;
            },
            write_zeroes(to, n) {
                assert(memory);
                const slice = new Uint8Array(memory.buffer, to, n);
                slice.fill(0);
                return n - slice.length;
            },
        },
    };
}
self.onmessage = (event) => {
    const data = event.data;
    // Authority service messages (main → authority forwarding).
    if (!isInitMessage(data)) {
        if (data.type === "authority_broker_kick") {
            if (authorityHandlers)
                authorityHandlers.kick();
            else
                postK5Diag("BROKER_DEFERRED_PEER_LIVE", false, { authorityReady: false });
            return;
        }
        if (data.type === "k5a_ping") {
            if (authorityHandlers)
                authorityHandlers.ping();
            else
                postK5Diag("K5A_PONG", true, { authorityReady: false });
            return;
        }
        if (data.type === "authority_fork_copied") {
            if (authorityHandlers)
                authorityHandlers.forkCopied(data.pid);
            else
                postK5Diag("FORK_ACK_FAILED", false, { authorityReady: false, pid: data.pid });
            return;
        }
        if (data.type === "authority_irq") {
            if (authorityHandlers)
                authorityHandlers.irq(data.cpu, data.irq);
            else
                postK5Diag("IRQ_DELIVERY_FAILED", false, { authorityReady: false, cpu: data.cpu, irq: data.irq });
            return;
        }
        if (data.type === "virtio_result") {
            if (authorityHandlers)
                authorityHandlers.virtioResult(data.seq, data.ok, data.value, data.irq);
            else
                postK5Diag("VIRTIO_RESULT_UNATTRIBUTED", false, { seq: data.seq, authorityReady: false });
            return;
        }
        if (data.type === "user_task_error") {
            if (authorityHandlers)
                authorityHandlers.userTaskError(data.taskToken, data.reason, data.faultClass);
            else
                postK5Diag("USER_TASK_ERROR_UNBOUND", false, { taskToken: data.taskToken, reason: data.reason });
            return;
        }
        postK5Diag("FATAL", false, { code: "UNKNOWN_WORKER_MESSAGE", msgType: data.type });
        return;
    }
    const { fn, arg, memory, parent_user_module, parent_user_memory, parent_tls_base, brokerSab, workerId, mode, taskToken, forkPid, argv: spawnedArgv } = data;
    // K4 DIAG: outer synchronous exception boundary
    let currentStage = "INIT_RECEIVED";
    try {
        postK4Diag("INIT_RECEIVED", { fn, arg, workerId, hasBrokerSab: !!brokerSab, hasParentModule: !!parent_user_module, hasParentMemory: !!parent_user_memory });
        if (data.d1TraceEnabled === true) {
            d1TraceEnabled = true;
            d1RunId = data.d1RunId ?? "d1-run";
            d1TraceBuffer.recordLifecycle("trace_initialized", d1RunId);
            d1TraceBuffer.recordLifecycle("worker_start_message_received", d1RunId);
        }
        // K5A DIAGNOSTIC: single-authority kernel worker. Exactly one vmlinux
        // Instance is constructed here (single construction site); boot runs via
        // exports.boot() under real JSPI suspension; kernel task spawns become
        // continuations on this same instance. This is uncommitted diagnostic
        // work pending the principal decision on the untouched-globals scheduler
        // model — not a shipped capability.
        if (data.isKernelAuthority === true) {
            const kernelModule = data.kernelModule;
            if (!kernelModule) {
                throw new Error("[K5A] kernel authority worker missing kernelModule");
            }
            const devicetree = data.devicetree;
            const initramfs = data.initramfs;
            const wasmJspi = WebAssembly;
            if (typeof wasmJspi.Suspending !== "function" ||
                typeof wasmJspi.promising !== "function") {
                postK5Diag("NOT_PROVEN", false, { code: "JSPI_UNAVAILABLE" });
                throw new Error("[K5A] JSPI (WebAssembly.Suspending/promising) unavailable");
            }
            // table.get yields a wasm exported function; JSPI promising needs that
            // runtime kind but TS lib types it loosely — inline named casts used.
            currentStage = "BEFORE_KERNEL_IMPORTS";
            postK4Diag("BEFORE_KERNEL_IMPORTS", { isKernelAuthority: true });
            postK5Diag("AUTHORITY_INIT_RECEIVED", true, {
                hasKernelModule: true,
                hasDevicetree: devicetree instanceof Uint8Array,
                hasInitramfs: initramfs instanceof Uint8Array,
                hasBrokerSab: !!brokerSab,
                workerId: workerId ?? null,
                bootViaExport: true,
            });
            let instance = null;
            let bootReturned = false;
            const tasks = new Map();
            /** taskToken → active yield suspension (kernel parked on this stack). */
            const suspensions = new Map();
            let executingTask = 0;
            /** K5: C may issue a REAL opaque identity for a frame the host
             * registered under a different wire token (boot task starts under wire
             * token 0; C reports its own identity on the first yield). Aliases map
             * issued → canonical so ONE frame never starts twice. */
            const tokenAlias = new Map();
            const canonicalToken = (token) => tokenAlias.get(token) ?? token;
            /** Transport registry: authority-assigned workerId → kernel taskToken.
             * Broker requests are validated against THIS binding; body TASK_ID/TID
             * from callers are non-authoritative and never dispatched. */
            const workerIdToTask = new Map();
            /** Z1-GABI: kernel pid → taskToken, learned from C-stamped completions.
             * Process events carry pids; task records are keyed by tokens. */
            const pidToToken = new Map();
            let nextUserWorkerId = 2; // 1 is the authority worker itself
            let nextDispatchId = 1;
            // ---- broker dispatch state -----------------------------------------
            if (!(brokerSab instanceof SharedArrayBuffer)) {
                throw new Error("[K5] kernel authority worker missing brokerSab");
            }
            const brokerU32 = new Uint32Array(brokerSab);
            const brokerI32 = new Int32Array(brokerSab);
            const pendingDispatch = new Map();
            let pumpRunning = false;
            let pumpQueued = false;
            /** promising()-wrapped kwa_syscall_for_task; assigned at boot tail. */
            let promisingKwaSyscall = null;
            /** authority→main virtio round-trip state. */
            let nextVirtioSeq = 1;
            const virtioPending = new Map();
            /** KernelContext idle-kick contract: the parked idle continuation
             * (YIELD_REASON_IDLE), resolved early when a completion/wake may have
             * made a task runnable — idle re-parks with the same deadline if not. */
            let idleSuspension = null;
            const authorityNowNs = () => BigInt(Math.round((performance.now() + performance.timeOrigin) * 200)) *
                5000n;
            const clearSuspensionTimer = (s) => {
                if (s.timer !== null) {
                    clearTimeout(s.timer);
                    s.timer = null;
                }
            };
            const onHaltWorker = () => {
                // A halt must never self.close() the authority: that would kill every
                // parked continuation. Surface as a continuation-scoped rejection.
                postK5Diag("NOT_PROVEN", false, {
                    code: "AUTHORITY_HALT_BLOCKED",
                    parked: suspensions.size,
                    tasks: tasks.size,
                });
                throw HALT_KERNEL;
            };
            const maybeQuiesce = (origin) => {
                if (!bootReturned || suspensions.size > 0 || tasks.size > 0)
                    return;
                postK5Diag("BOOT_RETURNED", true, { quiesced: true, origin });
                signalWorkerDone("authority_quiesced");
            };
            // ---- K5 scheduler: kernel-owned tokens, kernel-named successors ----
            const startTask = (t) => {
                if (!instance)
                    throw new Error("[K5] task start before kernel instance");
                // Start through the KERNEL-OWNED trampoline export: C resolves its
                // own bootstrap args; the host never authors task entries.
                const entryExport = instance.exports.kwa_task_entry;
                if (typeof entryExport !== "function") {
                    postK5Diag("FATAL", false, {
                        code: "TASK_ENTRY_EXPORT_MISSING",
                        taskToken: t.token,
                    });
                    throw new Error("[K5] vmlinux exports.kwa_task_entry missing");
                }
                t.state = "running";
                executingTask = t.token;
                postK5Diag("TASK_STARTED", true, {
                    taskToken: t.token,
                    name: t.name,
                });
                const promisingEntry = wasmJspi.promising(entryExport);
                const p = promisingEntry(t.token);
                p.then(() => {
                    // task_entry_inner ends in do_exit(0) → finish_task unwinds the
                    // stack; a plain return means the kernel trampoline broke contract.
                    if (tasks.has(t.token)) {
                        postK5Diag("NOT_PROVEN", false, {
                            code: "TASK_RETURNED_WITHOUT_FINISH_TASK",
                            taskToken: t.token,
                            name: t.name,
                        });
                        tasks.delete(t.token);
                    }
                    // Settlement is asynchronous: a kernel-named successor may already
                    // be executing. Clear attribution ONLY when it is still ours.
                    if (executingTask === t.token)
                        executingTask = 0;
                    maybeQuiesce("task_returned");
                }).catch((error) => {
                    if (error === USER_IMAGE_REPLACED) {
                        // Exec: the OLD image's kernel frame unwinds while the SAME task
                        // continues on its new-image continuation (live syscall frame).
                        // The Linux task did NOT die — keep the registry entry, keep
                        // executingTask attribution (old and new frames share the token,
                        // so the guarded clear below would wrongly erase the successor),
                        // and do not count this toward quiescence.
                        postK5Diag("TASK_IMAGE_REPLACED", true, {
                            taskToken: t.token,
                            name: t.name,
                        });
                        return;
                    }
                    const terminal = error === HALT_KERNEL || error === TERMINAL_TASK_EXIT;
                    if (!terminal && tasks.has(t.token)) {
                        postK5Diag("TASK_CONTINUATION_FAILED", false, {
                            taskToken: t.token,
                            name: t.name,
                            errorName: error instanceof Error ? error.name : "unknown",
                            stack: error instanceof Error ? error.stack ?? null : null,
                            message: String(error instanceof Error ? error.message : error).slice(0, 300),
                        });
                    }
                    tasks.delete(t.token);
                    // Settlement is asynchronous: a kernel-named successor may already
                    // be executing. Clear attribution ONLY when it is still ours.
                    if (executingTask === t.token)
                        executingTask = 0;
                    maybeQuiesce(terminal ? "task_terminal" : "task_failed");
                });
            };
            const clearIdleIf = (token) => {
                if (idleSuspension && idleSuspension.token === token) {
                    idleSuspension = null;
                }
            };
            /** Idle-kick rule (KernelContext): after a completion/wake, resolve the
             * parked idle yield early so the scheduler re-evaluates runnability. */
            const kickIdle = (why) => {
                if (!idleSuspension)
                    return;
                const token = idleSuspension.token;
                const s = suspensions.get(token);
                if (!s || s !== idleSuspension.entry) {
                    idleSuspension = null;
                    return;
                }
                clearSuspensionTimer(s);
                suspensions.delete(token);
                clearIdleIf(token);
                const t = tasks.get(token);
                if (t)
                    t.state = "running";
                executingTask = token;
                postK5Diag("IDLE_KICK", true, { taskToken: token, why });
                s.resolve();
            };
            const scheduleTask = (rawToken) => {
                if (rawToken === 0)
                    return; // 0 = kernel named no successor
                // Resolve C-issued identities to the canonical wire token (boot root
                // alias) so a named successor RESUMES the parked frame instead of
                // attempting a second start.
                const token = canonicalToken(rawToken);
                let t = tasks.get(token);
                if (!t) {
                    // KernelContext contract: SWITCH nextTask is always kernel-named.
                    // A token with no host record is started via kwa_task_entry with a
                    // shell record (C owns its bootstrap args).
                    postK5Diag("TASK_SHELL_REGISTERED", true, { taskToken: token });
                    t = {
                        token,
                        name: "kwa-shell",
                        kernelFn: 0,
                        kernelArg: 0,
                        state: "registered",
                        userModule: null,
                        userMemory: null,
                        entryMode: "start",
                        guestFn: 0,
                        guestArg: 0,
                        forkPid: 0,
                        inheritFrom: 0,
                        userWorker: null,
                        userWorkerId: 0,
                        pendingCall: null,
                        imageId: 0n,
                        activeImageId: 0n,
                        argv: null,
                    };
                    tasks.set(token, t);
                }
                if (t.state === "dead")
                    return;
                if (t.state === "parked") {
                    const s = suspensions.get(token);
                    if (!s)
                        return;
                    clearSuspensionTimer(s);
                    suspensions.delete(token);
                    clearIdleIf(token);
                    t.state = "running";
                    executingTask = token;
                    postK5Diag("TASK_RESUMED", true, { taskToken: token, name: t.name });
                    s.resolve();
                    return;
                }
                if (t.state === "registered")
                    startTask(t);
            };
            /** IDLE deadline expiry → real timer interrupt delivery.
             * TIMER_IRQ=2 (arch/wasm/include/asm/irq.h, KernelContext-frozen);
             * raw logical irq value — the export ORs 1<<irq into per-cpu pending.
             * cpu 0: K5 scope is cpus:1, single idle pinned on cpu0. No broadcast;
             * per-cpu idle tokens deferred until cpus>1 is real. */
            const KWA_TIMER_IRQ = 2;
            const triggerTimerIrq = () => {
                if (!instance)
                    return;
                const promisingIrq = wasmJspi.promising(instance.exports.trigger_irq_for_cpu);
                promisingIrq(0, KWA_TIMER_IRQ).catch((error) => {
                    postK5Diag("TIMER_IRQ_FAILED", false, {
                        message: String(error instanceof Error ? error.message : error).slice(0, 200),
                    });
                });
            };
            const onKernelYield = (reason, deadlineNs, selfTaskRaw, nextTaskRaw) => {
                // Resolve through the alias map, and on the FIRST yield from a
                // wire-registered frame whose C-issued selfTask is unknown, bind
                // that identity to the executing task's record (boot root: wire 0 ←
                // C opaque identity). One frame; never a second kwa_task_entry.
                let selfTask = canonicalToken(selfTaskRaw);
                if (!tasks.has(selfTask) && executingTask !== selfTask && tasks.has(executingTask)) {
                    tokenAlias.set(selfTaskRaw, executingTask);
                    postK5Diag("TASK_TOKEN_ALIASED", true, {
                        issuedToken: selfTaskRaw,
                        canonicalToken: executingTask,
                    });
                    selfTask = executingTask;
                }
                const nextTask = canonicalToken(nextTaskRaw);
                return new Promise((resolve, reject) => {
                    const entry = {
                        resolve,
                        reject,
                        timer: null,
                    };
                    suspensions.set(selfTask, entry);
                    const t = tasks.get(selfTask);
                    if (t)
                        t.state = "parked";
                    if (reason === YIELD_REASON_IDLE) {
                        idleSuspension = { token: selfTask, entry };
                    }
                    // C passes ABSOLUTE deadlines (process.c/irq.c/delay.c/fork.c).
                    if (deadlineNs > 0n) {
                        const delayMs = Math.max(0, Number(deadlineNs - authorityNowNs()) / 1_000_000);
                        entry.timer = setTimeout(() => {
                            const cur = suspensions.get(selfTask);
                            if (cur !== entry)
                                return;
                            suspensions.delete(selfTask);
                            clearIdleIf(selfTask);
                            const curTask = tasks.get(selfTask);
                            if (curTask)
                                curTask.state = "running";
                            executingTask = selfTask;
                            // IDLE deadline expiry is a REAL timer interrupt: deliver the
                            // timer IRQ before resolving the park (KernelContext contract).
                            if (reason === YIELD_REASON_IDLE)
                                triggerTimerIrq();
                            postK5Diag("YIELD_RESUME", true, {
                                taskToken: selfTask,
                                reason,
                                via: "deadline",
                                parked: suspensions.size,
                            });
                            resolve();
                        }, delayMs);
                    }
                    postK5Diag("KERNEL_YIELD", true, {
                        taskToken: selfTask,
                        nextTask,
                        reason,
                        deadlineNs: deadlineNs.toString(),
                        parked: suspensions.size,
                    });
                    // Host starts/resumes ONLY the kernel-provided successor.
                    if (nextTaskRaw !== 0 && nextTask !== selfTask)
                        scheduleTask(nextTaskRaw);
                });
            };
            /** IRQ/timer-external wake: resolve parked suspensions. C yield loops
             * re-verify their conditions and re-park — spurious wakes are safe. */
            const wakeAllSuspensions = (via) => {
                for (const [token, s] of [...suspensions]) {
                    if (suspensions.get(token) !== s)
                        continue;
                    clearSuspensionTimer(s);
                    suspensions.delete(token);
                    const t = tasks.get(token);
                    if (t)
                        t.state = "running";
                    executingTask = token;
                    s.resolve();
                }
                if (via)
                    postK5Diag("SUSPENSIONS_WOKE", true, { via });
            };
            // ---- terminal handoff ----------------------------------------------
            const finishTask = (selfTaskRaw, nextTaskRaw) => {
                // Resolve C-issued identities to canonical wire tokens: slot
                // cancellation keys on the canonical token stored in pendingDispatch,
                // and the registry/attribution cleanup must hit the same record the
                // frame was started under (boot root alias included).
                const selfTask = canonicalToken(selfTaskRaw);
                const nextTask = canonicalToken(nextTaskRaw);
                const t = tasks.get(selfTask);
                postK5Diag("TASK_TERMINAL", true, {
                    taskToken: selfTask,
                    rawSelfTask: selfTaskRaw,
                    name: t?.name ?? "unknown",
                    nextTask,
                });
                // 1. Terminal cancellation: free this task's outstanding claimed
                // broker slots WITHOUT inventing a Linux result (exec/exit never
                // return). Observers read TERMINAL_CANCEL_COUNT — never a fake status.
                for (const [dispatchId, pd] of [...pendingDispatch]) {
                    if (pd.taskToken !== selfTask)
                        continue;
                    pendingDispatch.delete(dispatchId);
                    const si = idx(pd.slot, S.STATE);
                    if (Atomics.load(brokerI32, si) === STATE.CLAIMED) {
                        Atomics.add(brokerU32, OFF.TERMINAL_CANCEL_COUNT, 1);
                        Atomics.store(brokerI32, si, STATE.FREE);
                        Atomics.store(brokerU32, idx(pd.slot, S.OWNER), 0);
                        Atomics.notify(brokerI32, si, 1);
                        postK5Diag("BROKER_SLOT_TERMINALLY_CANCELLED", true, {
                            slot: pd.slot,
                            dispatchId,
                            taskToken: selfTask,
                        });
                    }
                    else {
                        Atomics.add(brokerU32, OFF.POST_FREE_DISPATCH_COUNT, 1);
                    }
                }
                if (t) {
                    t.state = "dead";
                    // 2. Retire the pure user worker: its blocked broker wait can never
                    // complete — real retirement after kernel death, not a fake return.
                    if (t.userWorker) {
                        try {
                            t.userWorker.terminate();
                        }
                        catch {
                            /* already gone */
                        }
                        t.userWorker = null;
                    }
                    if (t.userWorkerId !== 0)
                        workerIdToTask.delete(t.userWorkerId);
                    // 3. Unwind this task's parked kernel stack (user.call frame).
                    if (t.pendingCall) {
                        const pc = t.pendingCall;
                        t.pendingCall = null;
                        pc.reject(TERMINAL_TASK_EXIT);
                    }
                    tasks.delete(selfTask);
                }
                const s = suspensions.get(selfTask);
                if (s) {
                    clearSuspensionTimer(s);
                    suspensions.delete(selfTask);
                    s.reject(TERMINAL_TASK_EXIT);
                }
                // 4. The kernel names the successor; start/resume ONLY that target.
                scheduleTask(nextTaskRaw);
                maybeQuiesce("finish_task");
                throw HALT_KERNEL;
            };
            // ---- per-request completion (C-local identity, never getters) ------
            const onSyscallComplete = (taskToken, requestId, result, pid, tgid, generation) => {
                const pd = pendingDispatch.get(requestId);
                if (!pd) {
                    // Completion with no matching pending dispatch: measured and
                    // dropped — never written anywhere, never fabricated.
                    Atomics.add(brokerU32, OFF.UNATTRIBUTED_RESPONSE_COUNT, 1);
                    postK5Diag("UNATTRIBUTED_RESPONSE", false, {
                        requestId,
                        taskToken,
                    });
                    return;
                }
                pendingDispatch.delete(requestId);
                const si = idx(pd.slot, S.STATE);
                if (Atomics.load(brokerI32, si) !== STATE.CLAIMED) {
                    Atomics.add(brokerU32, OFF.POST_FREE_DISPATCH_COUNT, 1);
                    postK5Diag("POST_FREE_DISPATCH", false, {
                        slot: pd.slot,
                        requestId,
                    });
                    return;
                }
                Atomics.store(brokerI32, idx(pd.slot, S.RESULT), result);
                Atomics.store(brokerI32, idx(pd.slot, S.ERRNO), result < 0 ? -result : 0);
                Atomics.store(brokerU32, idx(pd.slot, S.RESP_ID), pd.clientReqId);
                Atomics.store(brokerU32, idx(pd.slot, S.RESP_GENERATION), pd.slotGen);
                Atomics.store(brokerI32, idx(pd.slot, S.KERNEL_PID), pid);
                Atomics.store(brokerI32, idx(pd.slot, S.KERNEL_TGID), tgid);
                Atomics.store(brokerU32, idx(pd.slot, S.KERNEL_GENERATION), generation);
                // Z1-GABI: learn pid→token from C-stamped completion identity.
                if (pid > 0)
                    pidToToken.set(pid, taskToken);
                // Observed evidence: emitted ONLY from the real C completion stamp.
                postK5Diag("BROKER_SERVED", true, {
                    taskToken,
                    workerId: pd.workerId,
                    requestId,
                    nr: pd.nr,
                    result,
                    pid,
                    tgid,
                    generation,
                });
                Atomics.store(brokerI32, si, STATE.COMPLETED);
                Atomics.notify(brokerI32, si, 1);
                // Idle-kick: the completed syscall may have made a task runnable.
                kickIdle("syscall_complete");
            };
            // ---- broker pump: registry-bound dispatch --------------------------
            /** Transport-level rejection for requests with no live registry-bound
             * task: distinct from a fabricated Linux return; the syscall never ran. */
            const rejectStaleRequest = (slot) => {
                Atomics.add(brokerU32, OFF.STALE_TASK_REQUEST_COUNT, 1);
                Atomics.store(brokerI32, idx(slot, S.RESULT), -1);
                Atomics.store(brokerI32, idx(slot, S.ERRNO), 3 /* ESRCH */);
                Atomics.store(brokerU32, idx(slot, S.RESP_ID), Atomics.load(brokerU32, idx(slot, S.REQ_ID)));
                Atomics.store(brokerU32, idx(slot, S.RESP_GENERATION), Atomics.load(brokerU32, idx(slot, S.GENERATION)));
                Atomics.store(brokerI32, idx(slot, S.KERNEL_PID), 0);
                Atomics.store(brokerI32, idx(slot, S.KERNEL_TGID), 0);
                Atomics.store(brokerU32, idx(slot, S.KERNEL_GENERATION), 0);
                Atomics.store(brokerI32, idx(slot, S.STATE), STATE.COMPLETED);
                Atomics.notify(brokerI32, idx(slot, S.STATE), 1);
            };
            const pumpBroker = () => {
                if (!promisingKwaSyscall)
                    return; // boot not finished; no user tasks yet
                if (pumpRunning) {
                    pumpQueued = true;
                    return;
                }
                pumpRunning = true;
                try {
                    for (;;) {
                        let dispatched = false;
                        for (let s = 0; s < N_SLOTS; ++s) {
                            const si = idx(s, S.STATE);
                            if (Atomics.load(brokerI32, si) !== STATE.REQUESTED)
                                continue;
                            const workerId = Atomics.load(brokerU32, idx(s, S.WORKER_ID));
                            // Registry-bound dispatch: the triggering worker's
                            // authority-assigned workerId maps to exactly one kernel task.
                            const boundToken = workerIdToTask.get(workerId);
                            const bodyTaskId = Atomics.load(brokerI32, idx(s, S.TASK_ID));
                            if (boundToken === undefined ||
                                !tasks.has(boundToken) ||
                                (bodyTaskId !== 0 && bodyTaskId !== boundToken)) {
                                if (boundToken !== undefined && bodyTaskId !== 0 && bodyTaskId !== boundToken) {
                                    Atomics.add(brokerU32, OFF.STALE_TASK_REQUEST_COUNT, 1);
                                }
                                rejectStaleRequest(s);
                                continue;
                            }
                            // Z1-GABI NOTE: image-identity and task-boundary enforcement does NOT
                            // live here. executingTask is a transient JSPI-context variable, not
                            // request ownership — K4's proven model is workerIdToTask registry
                            // binding (checked above). Broker SLOTS_OFF was widened (64->80) for
                            // Z1-GABI telemetry counters; enforcement happens at the user-image
                            // layer (user.call entry) where currentTask() is authoritative.
                            if (Atomics.compareExchange(brokerI32, si, STATE.REQUESTED, STATE.CLAIMED) !==
                                STATE.REQUESTED) {
                                continue;
                            }
                            const dispatchId = nextDispatchId++;
                            const nr = Atomics.load(brokerU32, idx(s, S.NR));
                            const a0 = Atomics.load(brokerI32, idx(s, S.A0));
                            const a1 = Atomics.load(brokerI32, idx(s, S.A1));
                            const a2 = Atomics.load(brokerI32, idx(s, S.A2));
                            const a3 = Atomics.load(brokerI32, idx(s, S.A3));
                            const a4 = Atomics.load(brokerI32, idx(s, S.A4));
                            const a5 = Atomics.load(brokerI32, idx(s, S.A5));
                            pendingDispatch.set(dispatchId, {
                                slot: s,
                                taskToken: boundToken,
                                workerId,
                                clientReqId: Atomics.load(brokerU32, idx(s, S.REQ_ID)),
                                slotGen: Atomics.load(brokerU32, idx(s, S.GENERATION)),
                                nr,
                            });
                            dispatched = true;
                            postK5Diag("BROKER_DISPATCH", true, {
                                slot: s,
                                dispatchId,
                                taskToken: boundToken,
                                nr,
                            });
                            // Launched, not awaited: the bridge may park (parent waits while
                            // the child runs) — multiple parked stacks, one executing at a
                            // time, exactly the shared C ABI model. During execution C
                            // re-binds identity; user.* attribution reads executingTask.
                            executingTask = boundToken;
                            const p = promisingKwaSyscall(boundToken, nr, a0, a1, a2, a3, a4, a5, dispatchId);
                            p.then(() => {
                                // KernelContext: the bridge returns -ENOSYS WITHOUT
                                // syscall_complete when token validation fails. A settled
                                // bridge with no completion for this dispatchId = kernel
                                // rejection: cancel the slot loudly, never a fabricated
                                // Linux result.
                                const pd = pendingDispatch.get(dispatchId);
                                if (!pd)
                                    return;
                                pendingDispatch.delete(dispatchId);
                                Atomics.add(brokerU32, OFF.STALE_TASK_REQUEST_COUNT, 1);
                                const psi = idx(pd.slot, S.STATE);
                                if (Atomics.load(brokerI32, psi) === STATE.CLAIMED) {
                                    Atomics.store(brokerI32, psi, STATE.FREE);
                                    Atomics.store(brokerU32, idx(pd.slot, S.OWNER), 0);
                                    Atomics.notify(brokerI32, psi, 1);
                                }
                                postK5Diag("BRIDGE_REJECTED_TASK_TOKEN", false, {
                                    slot: pd.slot,
                                    dispatchId,
                                    taskToken: pd.taskToken,
                                });
                            }).catch((error) => {
                                const pd = pendingDispatch.get(dispatchId);
                                pendingDispatch.delete(dispatchId);
                                if (error === HALT_KERNEL || error === TERMINAL_TASK_EXIT) {
                                    return; // terminal cancellation owned by finishTask
                                }
                                Atomics.add(brokerU32, OFF.BROKER_ERRORS, 1);
                                postK5Diag("BROKER_DISPATCH_FAILED", false, {
                                    slot: pd?.slot ?? s,
                                    dispatchId,
                                    errorName: error instanceof Error ? error.name : "unknown",
                                    message: String(error instanceof Error ? error.message : error).slice(0, 300),
                                });
                                if (pd) {
                                    const psi = idx(pd.slot, S.STATE);
                                    if (Atomics.load(brokerI32, psi) === STATE.CLAIMED) {
                                        Atomics.store(brokerI32, psi, STATE.FREE);
                                        Atomics.store(brokerU32, idx(pd.slot, S.OWNER), 0);
                                        Atomics.notify(brokerI32, psi, 1);
                                    }
                                }
                            });
                        }
                        if (!dispatched)
                            break;
                    }
                }
                finally {
                    pumpRunning = false;
                    if (pumpQueued) {
                        pumpQueued = false;
                        queueMicrotask(pumpBroker);
                    }
                }
            };
            // ---- pure user worker spawn (production path via main) -------------
            const spawnUserWorker = (t) => {
                if (!t.userModule || !t.userMemory) {
                    throw new Error(`[K5] user.call before compile/instantiate for ${t.name}`);
                }
                const workerId = nextUserWorkerId++;
                t.userWorkerId = workerId;
                workerIdToTask.set(workerId, t.token);
                postK5Diag("USER_WORKER_SPAWNED", true, {
                    taskToken: t.token,
                    workerId,
                    name: t.name,
                    mode: t.entryMode,
                    forkPid: t.forkPid !== 0 ? t.forkPid : null,
                    guestFn: t.guestFn,
                    guestArg: t.guestArg,
                    sharedMemory: true,
                    // Shared guest VAS: the generic Node adapter observes real guest
                    // result buffers (magic/pid words) directly through this object.
                    userMemory: t.userMemory,
                });
                postMessage({
                    type: "spawn_worker",
                    fn: t.guestFn,
                    arg: t.guestArg,
                    name: t.name,
                    user_module: t.userModule,
                    user_memory: t.userMemory,
                    taskToken: t.token,
                    workerId,
                    mode: t.entryMode,
                    forkPid: t.forkPid !== 0 ? t.forkPid : undefined,
                    argv: t.argv ?? undefined,
                });
            };
            const handlers = {
                ping() {
                    postK5Diag("K5A_PONG", true, {
                        bootReturned,
                        parked: suspensions.size,
                        tasks: tasks.size,
                    });
                },
                kick() {
                    pumpBroker();
                },
                forkCopied(pid) {
                    if (!instance)
                        return;
                    const promisingForkCopied = wasmJspi.promising(instance.exports.fork_copied);
                    promisingForkCopied(pid)
                        .then(() => {
                        postK5Diag("FORK_ACK_DELIVERED", true, { pid });
                        // Idle-kick: the woken cloner may now be runnable.
                        kickIdle("fork_copied");
                    })
                        .catch((error) => {
                        postK5Diag("FORK_ACK_FAILED", false, {
                            pid,
                            message: String(error instanceof Error ? error.message : error).slice(0, 200),
                        });
                    });
                },
                irq(cpu, irq) {
                    if (!instance)
                        return;
                    const promisingIrq = wasmJspi.promising(instance.exports.trigger_irq_for_cpu);
                    promisingIrq(cpu, irq)
                        .then(() => {
                        // Only idle may be kicked; the kernel assigns CPUs and chooses successors.
                        kickIdle(`irq:${irq}`);
                    })
                        .catch((error) => {
                        postK5Diag("IRQ_DELIVERY_FAILED", false, {
                            cpu,
                            irq,
                            message: String(error instanceof Error ? error.message : error).slice(0, 200),
                        });
                    });
                },
                virtioResult(seq, ok, value, irq) {
                    const pending = virtioPending.get(seq);
                    postK5Diag("Z1VIRTIO_RESULT", ok, { seq, ok, value, irq: irq ?? null });
                    if (pending) {
                        virtioPending.delete(seq);
                        if (ok)
                            pending.resolve(value);
                        else
                            pending.reject(new Error(`virtio op failed (seq=${seq})`));
                    }
                    // Z1-GABI: fire-and-forget virtio imports complete via a DEDICATED
                    // IRQ continuation (promising startTask-like stack — the only
                    // suspend-safe way to re-enter kernel code). Spurious IRQs are
                    // harmless: the driver finds an empty used ring.
                    if (typeof irq === "number" && irq > 0 && instance) {
                        const triggerIrq = wasmJspi.promising(instance.exports.trigger_irq_for_cpu);
                        triggerIrq(0, irq).catch((e) => {
                            postK5Diag("Z1VIRTIO_IRQ_FAILED", false, {
                                irq,
                                error: String(e?.message ?? e).slice(0, 120),
                            });
                        });
                    }
                },
                userTaskError(taskToken, reason, faultClass) {
                    const t = tasks.get(taskToken);
                    if (!t?.pendingCall) {
                        postK5Diag("USER_TASK_ERROR_UNBOUND", false, { taskToken, reason, faultClass });
                        return;
                    }
                    // Z1-GABI §5 (v1.1): STALE IMAGE — a worker spawned under an older
                    // image must never resolve the CURRENT image's pending user.call.
                    // This is exactly the exec window: imageId already rebound, the new
                    // worker not yet spawned (or already running). Drop and count.
                    if (t.activeImageId !== t.imageId) {
                        postK5Diag("Z1_GABI_STALE_IMAGE_REJECT", false, {
                            taskToken,
                            activeImageId: t.activeImageId.toString(16),
                            currentImageId: t.imageId.toString(16),
                            reason: reason.slice(0, 120),
                        });
                        return;
                    }
                    // Z1-GABI §5 (v1.1): POST EXIT — a task that already died cannot
                    // have its (already rejected) pending frame resolved by a worker.
                    if (t.state === "dead") {
                        postK5Diag("Z1_GABI_POST_EXIT_REJECT", false, { taskToken, reason: reason.slice(0, 120) });
                        return;
                    }
                    const pc = t.pendingCall;
                    t.pendingCall = null;
                    // K6R1 typed trap completion: resolve (NEVER reject — that would
                    // destroy the JSPI continuation) so the SAME kernel continuation
                    // resumes in kwa_enter_user_image. wasm_trap → user.call returns
                    // KWA_USER_CALL_TRAP(1) → do_exit(SIGSEGV); returned_without_exit
                    // → 0 → falls through to the do_exit(0) first-lifecycle path.
                    postK5Diag(faultClass === "wasm_trap" ? "CHILD_WASM_TRAP_CAUGHT" : "USER_IMAGE_RETURNED", true, {
                        taskToken,
                        reason: reason.slice(0, 120),
                    });
                    pc.resolve(faultClass === "wasm_trap" ? 1 : 0);
                },
            };
            authorityHandlers = handlers;
            // Kernel linear memory view for user.read/write/write_zeroes.
            const kernelMem = new Uint8Array(memory.buffer);
            const currentTask = () => {
                const t = tasks.get(executingTask);
                if (!t) {
                    throw new Error(`[K5] user.* import outside task context (executingTask=${executingTask})`);
                }
                return t;
            };
            const userCall = () => {
                const t = currentTask();
                // Z1-GABI §5 (v1.1): authoritative user-image entry boundary.
                // currentTask() resolves from executingTask — a live kernel-owned
                // token. Any caller whose identity cannot be proven against the
                // registry is rejected HERE, before the image is entered.
                if (executingTask === 0 || t.token !== executingTask) {
                    postK5Diag("Z1_GABI_WRONG_USER_IMAGE_TASK", false, {
                        taskToken: t.token,
                        executingTask,
                    });
                    throw new Error(`[Z1-GABI] user.call identity mismatch: token ${t.token} != executing ${executingTask}`);
                }
                if (t.state === "dead") {
                    postK5Diag("Z1_GABI_POST_EXIT_REJECT", false, { taskToken: t.token });
                    throw new Error(`[Z1-GABI] user.call after task death: ${t.name}`);
                }
                if (!t.userModule || !t.userMemory) {
                    throw new Error(`[K5] user.call before compile/instantiate for ${t.name}`);
                }
                // Exec re-entry: the C wrapper invokes the newly committed image on
                // this task's exec continuation. A successful exec NEVER returns into
                // the old image — reject its pending frame with the typed sentinel
                // (NOT a resolve: C must never treat the old frame as having
                // returned, and the Linux task does NOT die here) and retire its old
                // worker. finish_task remains the ONLY real-death path.
                if (t.pendingCall) {
                    const prev = t.pendingCall;
                    t.pendingCall = null;
                    prev.reject(USER_IMAGE_REPLACED);
                }
                if (t.userWorker) {
                    try {
                        t.userWorker.terminate();
                    }
                    catch {
                        /* already gone */
                    }
                    t.userWorker = null;
                    if (t.userWorkerId !== 0)
                        workerIdToTask.delete(t.userWorkerId);
                    t.userWorkerId = 0;
                }
                const promise = new Promise((resolve, reject) => {
                    t.pendingCall = { resolve: resolve, reject };
                });
                // Z1-GABI §5: this worker is spawned under the CURRENT image identity.
                // Messages from any older worker (activeImageId != imageId) are stale.
                t.activeImageId = t.imageId;
                spawnUserWorker(t);
                return promise;
            };
            const virtioCall = (dev, op, args, features) => {
                const seq = nextVirtioSeq++;
                // Z1-GABI boundary instrumentation: first missing transition of the
                // block READ path (z1-gabi-virtio-boundary-analysis.json).
                postK5Diag("Z1VIRTIO_CMD_POSTED", true, {
                    seq,
                    dev,
                    op,
                    args: JSON.stringify(args),
                    features: features?.toString(16) ?? null,
                });
                return new Promise((resolve, reject) => {
                    virtioPending.set(seq, { resolve, reject });
                    postMessage({ type: "virtio_cmd", seq, dev, op, args, features });
                });
            };
            const SuspendingCtor = wasmJspi.Suspending;
            const authorityImports = {
                env: { memory },
                boot: {
                    get_devicetree: (buf, size) => {
                        if (!devicetree) {
                            throw new Error("[K5A] kernel requested devicetree but InitMessage.devicetree is missing");
                        }
                        if (size < devicetree.byteLength) {
                            throw new Error(`[K5A] devicetree ${devicetree.byteLength}B exceeds kernel buffer ${size}B (setup.c bound)`);
                        }
                        new Uint8Array(memory.buffer).set(devicetree, buf);
                    },
                    get_initramfs: (buf, size) => {
                        if (!initramfs)
                            return 0;
                        if (size < initramfs.byteLength) {
                            throw new Error(`[K5A] initramfs ${initramfs.byteLength}B exceeds kernel buffer ${size}B (setup.c bound)`);
                        }
                        new Uint8Array(memory.buffer).set(initramfs, buf);
                        return initramfs.byteLength;
                    },
                },
                kernel: kernel_imports({
                    is_worker: true,
                    memory,
                    onKernelYield,
                    onFinishTask: finishTask,
                    onSyscallComplete,
                    onHaltWorker,
                    spawnWorkerRaw(fn, arg, name, shareUserMemory, taskToken, spawnFlags) {
                        // Registration ONLY for normal tasks: continuations start when
                        // the kernel names the token as nextTask — never on spawn.
                        // token==0 is the boot task: registered now, started when
                        // exports.boot returns (shareUserMemory=0 there, never decoded
                        // as autostart). K6R1 ABI v2: spawn_flags is a dedicated param;
                        // bit0 0x1 = KWA_SPAWN_AUTOSTART (fork children, secondary idle).
                        if (tasks.has(taskToken)) {
                            throw new Error(`[K5] duplicate kernel taskToken ${taskToken} for ${name}`);
                        }
                        tasks.set(taskToken, {
                            token: taskToken,
                            name,
                            kernelFn: fn,
                            kernelArg: arg,
                            state: "registered",
                            userModule: null,
                            userMemory: null,
                            entryMode: "start",
                            guestFn: 0,
                            guestArg: 0,
                            forkPid: 0,
                            inheritFrom: executingTask,
                            userWorker: null,
                            userWorkerId: 0,
                            pendingCall: null,
                            // Z1-GABI: clone children share the parent image (CLONE_VM / clone-with-fn
                            // semantics) and never emit their own WASM_EXEC_COMMITTED — inherit the
                            // spawning task's identity. Boot/shell tasks keep 0n until their own exec.
                            imageId: tasks.get(executingTask)?.imageId ?? 0n,
                            activeImageId: tasks.get(executingTask)?.imageId ?? 0n,
                            argv: null,
                        });
                        postK5Diag("TASK_REGISTERED", true, {
                            taskToken,
                            name,
                            fn,
                            arg,
                            inheritFrom: executingTask,
                        });
                        if (taskToken !== 0 && (spawnFlags & 0x1) !== 0) {
                            const idleTask = tasks.get(taskToken);
                            postK5Diag("TASK_AUTOSTART", true, { taskToken, name });
                            const prevExecuting = executingTask;
                            startTask(idleTask);
                            // The spawning continuation keeps attribution; the idle stack
                            // re-binds executingTask when it actually resumes.
                            executingTask = prevExecuting;
                        }
                    },
                    boot_console_write(message) {
                        postMessage({ type: "boot_console_write", message });
                    },
                    boot_console_close() {
                        postMessage({ type: "boot_console_close" });
                    },
                    run_on_main(fn, arg) {
                        if (!instance) {
                            throw new Error("[K5A] run_on_main before kernel instance");
                        }
                        const table = instance.exports.__indirect_function_table;
                        if (!(table instanceof WebAssembly.Table)) {
                            throw new Error("[K5A] run_on_main: kernel function table missing");
                        }
                        const tableEntry = table.get(fn);
                        if (typeof tableEntry !== "function") {
                            throw new Error(`[K5A] run_on_main fn=${fn} not found`);
                        }
                        // Z1-GABI: run the kernel function on a JSPI-CAPABLE stack.
                        // Direct entryFn(arg) runs on THIS handler's plain JS stack, where
                        // any Suspending import the kernel fn calls (virtio.setup/notify
                        // from virtio_wasm_probe -> _setup) throws
                        // SuspendError: trying to suspend JS frames — the probe then fails
                        // silently (driver core logs pr_debug) and root=/dev/vda never
                        // registers. promising() gives the call a suspendable stack; the
                        // returned promise settles when the fn returns (fire-and-forget:
                        // probe completion is the kernel's concern).
                        const promisingEntry = wasmJspi.promising(tableEntry);
                        const p = promisingEntry(arg);
                        p.catch((err) => {
                            postK5Diag("Z1_RUN_ON_MAIN_FAILED", false, {
                                fn,
                                error: String(err?.message ?? err).slice(0, 200),
                            });
                        });
                    },
                    get_user_module: () => currentTask().userModule,
                    get_user_memory: () => currentTask().userMemory,
                    process_event_handler(event_kind, _run_id_hi, _run_id_lo, _event_seq, pid, _tgid, _ppid, _worker_id, data0, _data1, _comm) {
                        // Z1-GABI: derive authoritative image identity from WASM_EXEC_COMMITTED (kind 2).
                        // Events carry kernel pids; task records are keyed by tokens —
                        // resolve through the pidToToken map learned at completions.
                        if (event_kind === 2 /* WASM_EXEC_COMMITTED */) {
                            // Exec/exit syscalls NEVER reach syscall_complete, so
                            // pidToToken has no entry for a freshly exec'd task. The event
                            // is emitted synchronously on the exec bridge continuation —
                            // executingTask IS the exec'd task there.
                            const token = pidToToken.get(pid) ?? executingTask;
                            pidToToken.set(pid, token);
                            const t = tasks.get(token);
                            if (t) {
                                t.imageId = data0;
                                postK5Diag("Z1_GABI_IMAGE_BOUND", true, { taskToken: t.token, pid, imageId: data0.toString(16) });
                            }
                        }
                        // NOTE: NO early return — the bridge falls through to the worker
                        // forward path so main-thread event observers (witness rawEvents,
                        // TASK_DEAD checks, monotonicity) keep receiving every event.
                    },
                }),
                user: {
                    compile(buf, size) {
                        const t = currentTask();
                        const bytes = new Uint8Array(kernelMem.slice(buf, buf + size));
                        try {
                            t.userModule = new WebAssembly.Module(bytes);
                            return 0;
                        }
                        catch {
                            return -8; // exec format error
                        }
                    },
                    instantiate(fresh_memory) {
                        const t = currentTask();
                        if (!t.userModule) {
                            throw new Error("[K5] user.instantiate before user.compile");
                        }
                        if (fresh_memory || !t.userMemory) {
                            // Fresh VAS: exec commits a new image; keep the long-standing
                            // 768MiB floor (blink heap) — guests declaring smaller minimums
                            // accept larger memories up to their 2GiB maximum.
                            t.userMemory = new WebAssembly.Memory({
                                initial: 12288,
                                maximum: 32768,
                                shared: true,
                            });
                            // A REAL exec never returns into the old image's entry context:
                            // reset to the fresh image's own entrypoint (mode start, table
                            // entry 0/_start). Inherited clone context (switch_entry fn,
                            // fork_user pid) applies ONLY to non-fresh clone-path image
                            // binding — fresh=false preserves it untouched. No guest
                            // special-casing, no table-length assumptions.
                            t.entryMode = "start";
                            t.guestFn = 0;
                            t.guestArg = 0;
                            t.forkPid = 0;
                        }
                    },
                    // The kernel parks INSIDE this import while the pure user worker
                    // runs the guest — real suspension via JSPI.
                    call: new SuspendingCtor(userCall),
                    switch_entry(fn, arg) {
                        const t = currentTask();
                        const parent = tasks.get(t.inheritFrom);
                        if (!parent?.userModule || !parent?.userMemory) {
                            throw new Error(`[K5] switch_entry without parent image for ${t.name}`);
                        }
                        // CLONE_VM: the child shares the parent's guest VAS.
                        t.userModule = parent.userModule;
                        t.userMemory = parent.userMemory;
                        t.entryMode = "switch_entry";
                        t.guestFn = fn;
                        t.guestArg = arg;
                        // K4+: Capture argv from guest memory at spawn boundary.
                        // arg is a pointer to a null-terminated command string in the
                        // parent's shared VAS. Read up to 4KB to avoid unbounded copies.
                        if (parent.userMemory && arg > 0) {
                            const mem = new Uint8Array(parent.userMemory.buffer);
                            let end = arg;
                            const maxLen = Math.min(4096, mem.byteLength - arg);
                            while (end < arg + maxLen && mem[end] !== 0)
                                end++;
                            t.argv = mem.slice(arg, end);
                        }
                        else {
                            t.argv = null;
                        }
                    },
                    fork_user(pid) {
                        const t = currentTask();
                        const parent = tasks.get(t.inheritFrom);
                        if (!parent?.userModule || !parent?.userMemory) {
                            throw new Error(`[K5] fork_user without parent image for ${t.name}`);
                        }
                        // Fresh child VAS seeded from the parent at the fork point — the
                        // parent is parked in its bounded fork-ack yield during the copy.
                        const parentPages = Math.ceil(parent.userMemory.buffer.byteLength / 65536);
                        const fresh = new WebAssembly.Memory({
                            initial: Math.max(parentPages, 1),
                            maximum: 32768,
                            shared: true,
                        });
                        new Uint8Array(fresh.buffer).set(new Uint8Array(parent.userMemory.buffer));
                        t.userModule = parent.userModule;
                        t.userMemory = fresh;
                        t.entryMode = "fork_user";
                        t.forkPid = pid;
                        // Guest entry recorded from the clone request that created us.
                    },
                    call_signal_handler(fn, sig) {
                        // Guest signal handlers execute only inside their user worker;
                        // the K5 lifecycle scope has no delivery path — say so loudly.
                        postK5Diag("SIGNAL_HANDLER_DEFERRED", false, {
                            taskToken: currentTask().token,
                            fn,
                            sig,
                        });
                    },
                    read(to, from, n) {
                        const t = currentTask();
                        if (!t.userMemory)
                            throw new Error("[K5] user.read before instantiate");
                        const slice = new Uint8Array(t.userMemory.buffer, from, n);
                        kernelMem.set(slice, to);
                        return n - slice.length;
                    },
                    write(to, from, n) {
                        const t = currentTask();
                        if (!t.userMemory)
                            throw new Error("[K5] user.write before instantiate");
                        const slice = kernelMem.subarray(from, from + n);
                        new Uint8Array(t.userMemory.buffer, to, n).set(slice);
                        return n - slice.length;
                    },
                    write_zeroes(to, n) {
                        const t = currentTask();
                        if (!t.userMemory) {
                            throw new Error("[K5] user.write_zeroes before instantiate");
                        }
                        new Uint8Array(t.userMemory.buffer, to, n).fill(0);
                        return 0;
                    },
                },
                virtio: {
                    // Z1-GABI: FIRE-AND-FORGET imports. Suspending imports called from
                    // arbitrary kernel contexts (virtio probe initcalls, workqueue
                    // items) suspend on stacks that never cooperate with
                    // kwa_context_suspend -> running_cpu bookkeeping corrupts ->
                    // BUG_ON(__switch_to). Fire-and-forget returns immediately; the
                    // device op completes asynchronously on main, and completion is
                    // delivered as a DEDICATED IRQ continuation
                    // (promising(trigger_irq_for_cpu)) — the same proven pattern as
                    // the timer IRQ (startTask-like dedicated stack).
                    set_features: (dev, features) => {
                        void virtioCall(dev, "set_features", [], features);
                    },
                    setup: (dev, irq, is_config_addr, is_vring_addr, config_addr, config_len) => {
                        void virtioCall(dev, "setup", [
                            irq,
                            is_config_addr,
                            is_vring_addr,
                            config_addr,
                            config_len,
                        ]);
                    },
                    enable_vring: (dev, vq, size, desc_addr) => {
                        void virtioCall(dev, "enable_vring", [vq, size, desc_addr]);
                    },
                    disable_vring: (dev, vq) => {
                        void virtioCall(dev, "disable_vring", [vq]);
                    },
                    notify: (dev, vq) => {
                        void virtioCall(dev, "notify", [vq]);
                    },
                },
            };
            currentStage = "AFTER_KERNEL_IMPORTS";
            postK4Diag("AFTER_KERNEL_IMPORTS", { isKernelAuthority: true });
            currentStage = "BEFORE_ENTRYPOINT";
            instance = new WebAssembly.Instance(kernelModule, authorityImports);
            postK5Diag("KERNEL_INSTANTIATED", true, { instanceCount: 1 });
            // K5 per-task syscall bridge — REQUIRED. The naked syscall export stays
            // untouched for standalone K1/K2/K4 witnesses, but the authority never
            // invokes it: every brokered syscall runs under real task binding.
            const bridgeExport = instance.exports.kwa_syscall_for_task;
            if (typeof bridgeExport !== "function") {
                postK5Diag("FATAL", false, { code: "KWA_BRIDGE_EXPORT_MISSING" });
                throw new Error("[K5] vmlinux exports.kwa_syscall_for_task missing");
            }
            promisingKwaSyscall = wasmJspi.promising(bridgeExport);
            const bootExport = instance.exports.boot;
            if (typeof bootExport !== "function") {
                postK5Diag("FATAL", false, { code: "BOOT_EXPORT_MISSING" });
                throw new Error("[K5A] vmlinux exports.boot missing");
            }
            const bootFn = bootExport;
            const promisingBoot = wasmJspi.promising(bootFn);
            postK5Diag("BOOT_STARTED", true, { entry: "exports.boot" });
            const bootPromise = promisingBoot();
            bootPromise
                .then(() => {
                bootReturned = true;
                postK5Diag("BOOT_RETURNED", true, {
                    parked: suspensions.size,
                    tasks: tasks.size,
                });
                // KernelContext: token==0 (boot task) starts when boot returns.
                const bootTask = tasks.get(0);
                if (!bootTask || bootTask.state !== "registered") {
                    throw new Error("[K5] kernel did not register its boot task");
                }
                startTask(bootTask);
                maybeQuiesce("boot_returned");
            })
                .catch((error) => {
                postK5Diag("FATAL", false, {
                    code: "BOOT_REJECTED",
                    errorName: error instanceof Error ? error.name : "unknown",
                    message: String(error instanceof Error ? error.message : error).slice(0, 300),
                });
                signalWorkerDone("authority_boot_rejected");
            });
            return; // authority worker stays alive servicing kicks/irq/virtio/fork
        }
        // K3/K4: Secondary workers MUST NOT instantiate vmlinux.
        // Instantiate ONLY the user module; route all syscalls through broker SAB.
        if (!parent_user_module || !parent_user_memory) {
            throw new Error("[K4] secondary worker missing user module/memory");
        }
        // K4 DIAG: Memory identity verification before user_imports
        currentStage = "MEMORY_IDENTITY";
        postK4Diag("MEMORY_IDENTITY", {
            memory_instanceof: memory instanceof WebAssembly.Memory,
            parent_user_memory_instanceof: parent_user_memory instanceof WebAssembly.Memory,
            memory_identity: memory === parent_user_memory,
            memory_byteLength: memory?.buffer?.byteLength,
            parent_memory_byteLength: parent_user_memory?.buffer?.byteLength,
            brokerSab_instanceof: brokerSab instanceof SharedArrayBuffer,
            brokerSab_byteLength: brokerSab?.byteLength,
            workerId,
        });
        // BrokerClient will be initialized lazily on first syscall via wrappedSyscallHandler.
        // For now we set up the user module imports with broker-routed syscall.
        currentStage = "BEFORE_USER_IMPORTS";
        postK4Diag("BEFORE_USER_IMPORTS");
        const user = user_imports({
            kernel_memory: memory,
            get_kernel_instance: () => {
                throw new Error("[K3] direct kernel instance access forbidden in secondary worker");
            },
            parent_user_module,
            parent_user_memory,
            parent_tls_base: parent_tls_base ?? 0,
            brokerSab,
            workerId,
            taskToken,
            tasksMap: spawnedArgv && taskToken ? new Map([[taskToken, { argv: spawnedArgv }]]) : undefined,
        });
        currentStage = "AFTER_USER_IMPORTS";
        postK4Diag("AFTER_USER_IMPORTS", { hasUserImports: !!user.imports, hasModule: !!user.module, hasMemory: !!user.memory });
        // K4 DIAG: Capture user module import contract
        currentStage = "MODULE_IMPORTS";
        const moduleImports = WebAssembly.Module.imports(parent_user_module);
        postK4Diag("MODULE_IMPORTS", {
            importCount: moduleImports.length,
            imports: moduleImports.map(i => ({ module: i.module, name: i.name, kind: i.kind })),
        });
        // Z1-GABI §4 (v1.1): STRICT IMPORT CONTRACT — INSTANTIATION-TIME FAIL CLOSED.
        // Every (namespace, name) the guest requests must be part of the declared
        // Linux guest ABI the host actually implements. Unknown namespaces or
        // unsupported names reject BEFORE any execution — never degrade to stubs.
        // This is the contract decision; the length-based route below is legacy
        // routing only.
        const Z1_GABI_LINUX_ABI = {
            syscall: true,
            get_thread_area: true,
            get_args_length: true,
            get_args: true,
            arch_wasm_poll: true,
        };
        for (const imp of moduleImports) {
            const ok = (imp.module === "env" && imp.name === "memory") ||
                (imp.module === "linux" && Z1_GABI_LINUX_ABI[imp.name] === true);
            if (!ok) {
                postK4Diag("Z1_GABI_IMPORT_REJECTED", {
                    module: imp.module,
                    name: imp.name,
                });
                throw new Error(`[Z1-GABI] unsupported import ${imp.module}.${imp.name} — instantiation-time fail-closed`);
            }
        }
        currentStage = "BEFORE_KERNEL_IMPORTS";
        postK4Diag("BEFORE_KERNEL_IMPORTS");
        // Z1-GABI: guests may declare MULTIPLE linux.* entries (busybox: syscall +
        // get_args_length + get_args + arch_wasm_poll). The legacy import-count
        // route misclassifies them as kernel-shaped, so the full imports object
        // MUST carry a real `linux` namespace — broker-backed, task-bound via
        // the workerId registry (K4 model). Without it, instantiation throws
        // "Import #0 linux: module is not an object".
        const z1LinuxImports = (() => {
            if (typeof brokerSab === "undefined" || typeof workerId === "undefined") {
                throw new Error("[Z1-GABI] secondary worker missing brokerSab/workerId for linux imports");
            }
            const z1BrokerClient = new BrokerClient(brokerSab, workerId);
            const z1BrokerSyscall = (nr, a0, a1, a2, a3, a4, a5) => z1BrokerClient.invoke(nr, a0, a1, a2, a3, a4, a5, taskToken ?? 0, 0, () => {
                postMessage({ type: "broker_kick", workerId });
            }).result;
            return {
                syscall: z1BrokerSyscall,
                // Z1-GABI NOTE: frozen-kernel ABI placeholders (see user_imports).
                get_thread_area: () => parent_tls_base ?? 0,
                get_args_length: () => {
                    let args = ["/bin/sh"];
                    if (spawnedArgv && spawnedArgv.byteLength > 0) {
                        const text = new TextDecoder().decode(spawnedArgv).replace(/\0+$/, "");
                        if (text.length > 0)
                            args = text.split(" ").filter(Boolean);
                    }
                    let strBytes = 0;
                    for (const a of args)
                        strBytes += new TextEncoder().encode(a + "\0").length;
                    return 20 + (args.length + 1) * 4 + 4 + strBytes;
                },
                get_args: (buf) => {
                    if (!buf || !memory)
                        return -1;
                    let args = ["/bin/sh"];
                    if (spawnedArgv && spawnedArgv.byteLength > 0) {
                        const text = new TextDecoder().decode(spawnedArgv).replace(/\0+$/, "");
                        if (text.length > 0)
                            args = text.split(" ").filter(Boolean);
                    }
                    const dv = new DataView(memory.buffer, buf);
                    const argc = args.length;
                    const envc = 0;
                    const argvPtr = buf + 20;
                    const envpPtr = argvPtr + (argc + 1) * 4;
                    const strPtr = envpPtr + (envc + 1) * 4;
                    const encoded = [];
                    let totalStrLen = 0;
                    for (const a of args) {
                        const b = new TextEncoder().encode(a + "\0");
                        encoded.push(b);
                        totalStrLen += b.length;
                    }
                    // wasm_process_args header: len, envc, argc, argv_ptr, envp_ptr
                    dv.setInt32(0, totalStrLen, true);
                    dv.setInt32(4, envc, true);
                    dv.setInt32(8, argc, true);
                    dv.setInt32(12, argvPtr, true);
                    dv.setInt32(16, envpPtr, true);
                    // argv pointers table
                    let off = 20;
                    let currStrPtr = strPtr;
                    for (let j = 0; j < argc; j++) {
                        dv.setInt32(off, currStrPtr, true);
                        off += 4;
                        currStrPtr += encoded[j].length;
                    }
                    dv.setInt32(off, 0, true);
                    // envp pointers table (NULL)
                    dv.setInt32(envpPtr - buf, 0, true);
                    // string data
                    const memU8 = new Uint8Array(memory.buffer);
                    let sOff = strPtr;
                    for (const enc of encoded) {
                        memU8.set(enc, sOff);
                        sOff += enc.length;
                    }
                    return 0;
                },
                arch_wasm_poll: () => 0,
            };
        })();
        const imports = {
            env: { memory },
            linux: z1LinuxImports,
            boot: {
                get_devicetree: unavailable,
                get_initramfs: unavailable,
            },
            user: user.imports,
            kernel: kernel_imports({
                is_worker: true,
                memory,
                spawn_worker(fn, arg, name, user_module, user_memory) {
                    postMessage({
                        type: "spawn_worker",
                        fn,
                        arg,
                        name,
                        user_module: user_module ?? user.module,
                        user_memory: user_memory ?? user.memory,
                        parent_tls_base: 0, // TLS not available without local kernel instance
                    });
                },
                boot_console_write(message) {
                    postMessage({ type: "boot_console_write", message });
                },
                boot_console_close() {
                    postMessage({ type: "boot_console_close" });
                },
                run_on_main(fn, arg) {
                    postMessage({ type: "run_on_main", fn, arg });
                },
                get_user_module() {
                    return user.module;
                },
                get_user_memory() {
                    return user.memory;
                },
            }),
            virtio: {
                set_features: unavailable,
                setup: unavailable,
                enable_vring: unavailable,
                disable_vring: unavailable,
                notify: unavailable,
            },
        };
        currentStage = "AFTER_KERNEL_IMPORTS";
        postK4Diag("AFTER_KERNEL_IMPORTS");
        // Z1-GABI NOTE: this is a LEGACY ROUTING COMPATIBILITY HEURISTIC for the
        // frozen KWA-v2 substrate. It is NOT a guest classification or authority
        // decision and MUST NOT be used for any Z1-GABI acceptance criterion.
        // KWA-v2.1 successor must replace this with explicit module/import
        // contract validation (instantiation-time fail-closed).
        // K4+: Detect Linux shell / user modules by their actual import signature, not count.
        const hasLinuxNamespace = moduleImports.some(i => i.module === "linux");
        const isLinuxShellModule = hasLinuxNamespace &&
            moduleImports.every(i => i.module === "env" || i.module === "linux");
        let userInstance;
        if (isLinuxShellModule) {
            // Minimal user module path: bind parent module/memory into user_imports closure,
            // then call doInstantiate() which builds broker-only imports correctly.
            user.module = parent_user_module;
            user.memory = parent_user_memory ?? memory;
            user.doInstantiate();
            assert(user.instance, "doInstantiate failed to set instance for minimal user module");
            userInstance = user.instance;
        }
        else {
            // Kernel-shaped module path: use full imports object (existing behavior)
            currentStage = "BEFORE_USER_INSTANTIATE";
            postK4Diag("BEFORE_USER_INSTANTIATE", { importKeys: Object.keys(imports), userImportKeys: Object.keys(imports.user ?? {}) });
            userInstance = new WebAssembly.Instance(parent_user_module, imports);
        }
        currentStage = "AFTER_USER_INSTANTIATE";
        postK4Diag("AFTER_USER_INSTANTIATE", { exportNames: Object.keys(userInstance.exports) });
        try {
            currentStage = "BEFORE_ENTRYPOINT";
            const exportsRec = userInstance.exports;
            const table = exportsRec.__indirect_function_table;
            const resolveTableEntry = () => {
                if (!(table instanceof WebAssembly.Table))
                    return null;
                const entry = table.get(fn);
                return typeof entry === "function" ? entry : null;
            };
            try {
                if (mode === "fork_user") {
                    // K5 fork child: ack the completed VAS snapshot BEFORE resuming, so the
                    // parked parent's bounded fork-ack yield observes it in time.
                    postMessage({ type: "fork_copied", pid: forkPid ?? 0, taskToken: taskToken ?? 0 });
                    currentStage = "BEFORE_ENTRYPOINT_CALL";
                    postK4Diag("BEFORE_ENTRYPOINT_CALL", { fn, arg, mode });
                    const blinkResume = exportsRec.blink_user_fork_resume;
                    if (typeof blinkResume === "function") {
                        blinkResume();
                        throw new Error("blink_user_fork_resume returned; fork child must exit via kernel");
                    }
                    const entry = resolveTableEntry();
                    if (!entry)
                        throw new Error(`[K5] fork_user entry fn=${fn} not found`);
                    entry(arg);
                    console.warn("fork child entrypoint returned without exiting");
                }
                else {
                    const entry = resolveTableEntry();
                    if (entry) {
                        currentStage = "ENTRYPOINT_FOUND";
                        postK4Diag("ENTRYPOINT_FOUND", { fn, entryType: "function" });
                        currentStage = "BEFORE_ENTRYPOINT_CALL";
                        postK4Diag("BEFORE_ENTRYPOINT_CALL", { fn, arg });
                        entry(arg);
                    }
                    else {
                        // K5: minimal WAT guests export _start(param i32); table may be absent.
                        const startExport = exportsRec._start;
                        if (typeof startExport !== "function") {
                            throw new Error(`[K5] no entrypoint: fn=${fn}, no table entry, no _start export`);
                        }
                        currentStage = "BEFORE_ENTRYPOINT_CALL";
                        postK4Diag("BEFORE_ENTRYPOINT_CALL", { fn: "_start", arg, via: "_start_export" });
                        startExport(0);
                    }
                }
            }
            catch (entryError) {
                // K6R1: task-bound user workers report the real failure to the authority;
                // the kernel continuation resolves with it (never a fabricated result).
                // A genuine guest WebAssembly.RuntimeError is a classified wasm_trap:
                // once delivered to the transport, do NOT rethrow — the authority will
                // resume the SAME suspended JSPI kernel continuation via pendingCall.resolve(1).
                // Rethrowing here races the delivery and surfaces as an uncaught worker
                // error that kills the run even though the kernel already owns the death.
                const isGuestTrap = entryError instanceof WebAssembly.RuntimeError;
                let delivered = false;
                if (taskToken) {
                    try {
                        postMessage({
                            type: "user_task_error",
                            taskToken,
                            reason: String(entryError?.message ?? entryError).slice(0, 300),
                            faultClass: isGuestTrap ? "wasm_trap" : "returned_without_exit",
                        });
                        delivered = true;
                    }
                    catch { /* best-effort */ }
                }
                if (isGuestTrap && delivered) {
                    signalWorkerDone("guest_trap_delivered");
                    return;
                }
                throw entryError;
            }
            if (taskToken) {
                // K5: a guest entrypoint that returns normally without exiting the task is
                // an abnormal end for that task's user image.
                try {
                    postMessage({ type: "user_task_error", taskToken, reason: "entrypoint_returned_without_exit", faultClass: "returned_without_exit" });
                }
                catch { /* best-effort */ }
            }
            signalWorkerDone("entrypoint_returned");
        }
        catch (error) {
            if (error === HALT_KERNEL) {
                signalWorkerDone("halt_kernel");
                return;
            }
            signalWorkerDone("uncaught_" + (error?.name ?? "error"));
            throw error;
        }
    }
    catch (fatalError) {
        // K4 DIAG: TOP_LEVEL_FATAL — report before rethrowing
        postK4Diag("TOP_LEVEL_FATAL", {
            stage: currentStage,
            errorName: fatalError?.name,
            errorMessage: String(fatalError?.message ?? fatalError),
            errorStack: fatalError?.stack,
            workerId,
            fn,
        });
        throw fatalError;
    }
};
self.addEventListener("error", (event) => {
    if (d1TraceEnabled) {
        d1TraceBuffer.recordRuntimeError(event.error ?? event.message, d1RunId, {
            eventType: "worker_error_event",
            activeOperation: "self.onerror",
        });
    }
});
self.addEventListener("messageerror", () => {
    if (d1TraceEnabled) {
        d1TraceBuffer.recordLifecycle("worker_messageerror_event", d1RunId);
    }
});
self.addEventListener("unhandledrejection", (event) => {
    if (d1TraceEnabled) {
        d1TraceBuffer.recordRuntimeError(event.reason, d1RunId, {
            eventType: "worker_unhandledrejection",
            activeOperation: "unhandledrejection",
        });
    }
});
