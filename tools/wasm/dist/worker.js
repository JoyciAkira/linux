import { assert, validateEntry } from "./util.js";
import { HALT_KERNEL, kernel_imports, TERMINAL_TASK_EXIT, USER_IMAGE_REPLACED, YIELD_REASON_IDLE, YIELD_REASON_SWITCH, } from "./wasm.js";
import { D1RingBuffer } from "./d1-ring-buffer.js";
import { wrapSyscall } from "./d1-syscall-wrapper.js";
import { BrokerClient, idx, N_SLOTS, OFF, S, STATE, } from "./kwa-broker.js";
function postK4Diag(stage, detail) {
    try {
        postMessage({ type: "k4_diag", stage, detail });
    }
    catch { /* best-effort diagnostic */ }
}
let sampledDiagnosticCount = 0;
function postK5Diag(stage, ok, detail) {
    // Bound hot progress messages; failures and lifecycle evidence are never sampled.
    if (ok && (stage === "KERNEL_YIELD" || stage === "Z1VIRTIO_CMD_POSTED" ||
        stage === "Z1VIRTIO_RESULT" || stage === "TASK_RESUMED" ||
        stage === "TASK_STARTED" || stage === "SUSPENSIONS_WOKE")) {
        if (++sampledDiagnosticCount % 4096 !== 1)
            return;
    }
    postMessage({ type: "authority_diag", stage, ok, detail, ts: performance.now() });
}
/** Message handlers the authority block registers once initialized; the
 * onmessage dispatcher routes authority-directed messages to them. */
let authorityHandlers = null;
function isInitMessage(data) {
    return !(typeof data === "object" && data !== null && "type" in data);
}
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
/** Z1-G6-THREADS: compile a start-stripped variant of the user image for
 * thread children (CLONE_VM). The full module's __wasm_init_memory start
 * section re-applies passive data segments into the SHARED parent VAS at
 * every instantiation, transiently clobbering the parent's live .data while
 * the parent keeps running. For a CLONE_VM child the parent's live image IS
 * the initialized data — nothing may be re-applied. This helper strips the
 * start section from the same bytes so the noinit module is identity-bound
 * to the original (same compilation unit, same type/function indices). */
function compileContinuationImage(bytes) {
    const chunks = [bytes.subarray(0, 8)];
    let pos = 8;
    let length = 8;
    const uleb = () => {
        let value = 0, shift = 0, byte;
        do {
            assert(pos < bytes.length && shift <= 28, "Malformed Wasm section length");
            byte = bytes[pos++];
            value += (byte & 127) * 2 ** shift;
            shift += 7;
        } while (byte & 128);
        return value;
    };
    while (pos < bytes.length) {
        const start = pos;
        const id = bytes[pos++];
        const size = uleb();
        const end = pos + size;
        assert(end <= bytes.length, "Truncated Wasm section");
        if (id === 11) {
            const count = uleb();
            for (let i = 0; i < count; i++) {
                assert(uleb() === 1, "Active data segment cannot share continuation memory");
                const dataSize = uleb();
                pos += dataSize;
                assert(pos <= end, "Truncated passive Wasm data");
            }
        }
        if (id !== 8) {
            chunks.push(bytes.subarray(start, end));
            length += end - start;
        }
        pos = end;
    }
    const output = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
        output.set(chunk, offset);
        offset += chunk.length;
    }
    return new WebAssembly.Module(output);
}
function createGuestImports(data, entry) {
    const memory = data.parent_user_memory;
    assert(memory && data.brokerSab && data.workerId && data.taskToken, "Secondary worker missing task-bound memory or broker");
    assert(Array.isArray(data.args), "Missing kernel argv snapshot");
    const { workerId, taskToken, argsBytes, argsBaseAddr } = data;
    const broker = new BrokerClient(data.brokerSab, workerId);
    const invoke = (nr, a0 = 0, a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0) => broker.invoke(nr, a0, a1, a2, a3, a4, a5, taskToken, 0, () => postMessage({ type: "broker_kick", workerId }));
    let tlsBase = entry.type === "START_PROCESS" ? 0 : data.parent_tls_base;
    const encoder = new TextEncoder();
    const encodedArgs = data.args.map(arg => encoder.encode(arg + "\0"));
    const encodedEnv = [];
    if (argsBytes && argsBaseAddr !== undefined) {
        const raw = new DataView(argsBytes.buffer, argsBytes.byteOffset, argsBytes.byteLength);
        const envc = raw.getInt32(4, true);
        const table = raw.getUint32(16, true) - argsBaseAddr;
        assert(envc >= 0 && table >= 20 && table + (envc + 1) * 4 <= argsBytes.length, "Invalid kernel environment table");
        for (let i = 0; i < envc; i++) {
            const start = raw.getUint32(table + i * 4, true) - argsBaseAddr;
            assert(start >= 20 && start < argsBytes.length, "Invalid kernel environment pointer");
            const end = argsBytes.indexOf(0, start);
            assert(end !== -1, "Unterminated kernel environment");
            encodedEnv.push(argsBytes.slice(start, end + 1));
        }
    }
    const argc = encodedArgs.length;
    const envc = encodedEnv.length;
    const stringBytes = encodedArgs.reduce((size, arg) => size + arg.length, 0) +
        encodedEnv.reduce((size, env) => size + env.length, 0);
    const argvOffset = 20;
    const envpOffset = argvOffset + (argc + 1) * 4;
    const stringsOffset = envpOffset + (envc + 1) * 4 + 16;
    const argsLength = stringsOffset + stringBytes;
    const copyRawArgs = (address, capacity) => {
        const dst = address >>> 0;
        if (!argsBytes || argsBaseAddr === undefined)
            return -22;
        if (!dst || capacity < argsBytes.length ||
            dst > memory.buffer.byteLength - argsBytes.length)
            return -14;
        new Uint8Array(memory.buffer, dst, argsBytes.length).set(argsBytes);
        const view = new DataView(memory.buffer, dst, argsBytes.length);
        const delta = dst - argsBaseAddr;
        const rebase = (field, count) => {
            const oldTable = view.getUint32(field, true);
            const offset = oldTable - argsBaseAddr;
            assert(count >= 0 && offset >= 20 && offset + (count + 1) * 4 <= argsBytes.length, "Invalid kernel argument pointer table");
            view.setUint32(field, oldTable + delta, true);
            for (let i = 0; i < count; i++) {
                const pointer = view.getUint32(offset + i * 4, true);
                view.setUint32(offset + i * 4, pointer ? pointer + delta : 0, true);
            }
        };
        rebase(12, view.getInt32(8, true));
        rebase(16, view.getInt32(4, true));
        return 0;
    };
    const syscall = wrapSyscall((nr, a0, a1, a2, a3, a4, a5) => {
        if (nr === 245)
            return copyRawArgs(a0, a1);
        const result = invoke(nr, a0, a1, a2, a3, a4, a5);
        if (result.errno === 3)
            throw TERMINAL_TASK_EXIT;
        if (nr === 244 && result.result === 0)
            tlsBase = a0 >>> 0;
        if (nr === 93 || nr === 94)
            throw new Error("Linux exit unexpectedly returned without task retirement");
        return result.result;
    }, {
        buffer: d1TraceBuffer, runId: d1RunId, enabled: d1TraceEnabled,
        processId: `worker-${workerId}`, getThreadId: () => 0,
    });
    return {
        env: { memory },
        linux: {
            syscall,
            get_thread_area: () => {
                if (tlsBase === undefined) {
                    const result = invoke(246);
                    assert(result.errno === 0 && result.result !== -1, "Kernel TP unavailable");
                    tlsBase = result.result >>> 0;
                }
                return tlsBase;
            },
            get_args_length: () => argsLength,
            get_args: (address) => {
                const dst = address >>> 0;
                if (!dst || dst > memory.buffer.byteLength - argsLength)
                    return -14;
                const view = new DataView(memory.buffer, dst, argsLength);
                new Uint8Array(memory.buffer, dst, argsLength).fill(0);
                view.setUint32(0, stringBytes, true);
                view.setUint32(4, envc, true);
                view.setUint32(8, argc, true);
                view.setUint32(12, dst + argvOffset, true);
                view.setUint32(16, dst + envpOffset, true);
                let stringOffset = stringsOffset;
                const copyStrings = (strings, tableOffset) => {
                    for (let i = 0; i < strings.length; i++) {
                        const bytes = strings[i];
                        view.setUint32(tableOffset + i * 4, dst + stringOffset, true);
                        new Uint8Array(memory.buffer, dst + stringOffset, bytes.length).set(bytes);
                        stringOffset += bytes.length;
                    }
                };
                copyStrings(encodedArgs, argvOffset);
                copyStrings(encodedEnv, envpOffset);
                return 0;
            },
            arch_wasm_poll: () => 0,
            copy_siginfo: () => 1,
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
                authorityHandlers.virtioResult(data.seq, data.ok, data.value);
            else
                postK5Diag("VIRTIO_RESULT_UNATTRIBUTED", false, { seq: data.seq, authorityReady: false });
            return;
        }
        if (data.type === "user_task_error") {
            if (authorityHandlers)
                authorityHandlers.userTaskError(data.taskToken, data.reason, data.stack ?? "", data.faultClass);
            else
                postK5Diag("USER_TASK_ERROR_UNBOUND", false, { taskToken: data.taskToken, reason: data.reason });
            return;
        }
        postK5Diag("FATAL", false, { code: "UNKNOWN_WORKER_MESSAGE", msgType: data.type });
        return;
    }
    const { fn, arg, memory, parent_user_module, parent_user_memory, brokerSab, workerId, taskToken } = data;
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
            const canonicalToken = (token) => tokenAlias.get(token) ?? Number(token);
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
                        userModuleNoinit: null,
                        guestFn: 0,
                        guestArg: 0,
                        forkPid: 0,
                        inheritFrom: 0,
                        workerId: 0,
                        pendingCall: null,
                        imageId: 0n,
                        activeImageId: 0n,
                        argsBytes: null,
                        argsBaseAddr: 0,
                        args: [],
                        entry: null,
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
            // T3: one real clockevent arm per CPU, independent of task/idle parks.
            // Its IRQ export only sets pending bits; C runs handlers on a safe return.
            const clockevents = new Map();
            const onTimerDeadline = (cpu, deadlineNs) => {
                assert(Number.isInteger(cpu) && cpu >= 0 && deadlineNs >= 0n, "Invalid kernel clockevent arm");
                const previous = clockevents.get(cpu);
                if (previous?.timer !== null && previous?.timer !== undefined) {
                    clearTimeout(previous.timer);
                }
                clockevents.delete(cpu);
                if (deadlineNs === 0n)
                    return;
                const arm = { deadlineNs, timer: null };
                clockevents.set(cpu, arm);
                const expire = () => {
                    if (clockevents.get(cpu) !== arm)
                        return;
                    const remaining = arm.deadlineNs - authorityNowNs();
                    if (remaining > 0n) {
                        arm.timer = setTimeout(expire, Math.min(2_147_483_647, Math.ceil(Number(remaining) / 1_000_000)));
                        return;
                    }
                    clockevents.delete(cpu);
                    try {
                        assert(instance, "Clockevent expired before kernel instantiation");
                        const pendingIrq = instance.exports.trigger_irq_for_cpu;
                        pendingIrq(cpu, 2); // TIMER_IRQ, arch/wasm/include/asm/irq.h
                        postK5Diag("CLOCKEVENT_FIRED", true, {
                            cpu, deadlineNs: arm.deadlineNs.toString(),
                            lateNs: (-remaining).toString(), idleParked: idleSuspension !== null,
                        });
                        kickIdle("clockevent");
                    }
                    catch (error) {
                        postK5Diag("TIMER_IRQ_FAILED", false, {
                            cpu, message: String(error instanceof Error ? error.message : error),
                        });
                    }
                };
                arm.timer = setTimeout(expire, Math.min(2_147_483_647, Math.max(0, Math.ceil(Number(deadlineNs - authorityNowNs()) / 1_000_000))));
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
                        reason,
                    };
                    suspensions.set(selfTask, entry);
                    const t = tasks.get(selfTask);
                    if (t)
                        t.state = "parked";
                    if (reason === YIELD_REASON_IDLE) {
                        idleSuspension = { token: selfTask, entry };
                    }
                    // Idle is woken by a pending IRQ, never by a second clockevent timer.
                    if (deadlineNs > 0n && reason !== YIELD_REASON_IDLE) {
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
                    // A switched-out task resumes only when the kernel names it next.
                    if (s.reason === YIELD_REASON_SWITCH)
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
                    // 2. Retire the pure user worker via main-side registry. The authority
                    // never holds Worker handles; main terminates after validating the
                    // authority-issued workerId + taskToken + imageId match the registry.
                    if (t.workerId !== 0) {
                        postMessage({
                            type: "retire_worker",
                            workerId: t.workerId,
                            taskToken: t.token,
                            imageId: t.activeImageId,
                        });
                        workerIdToTask.delete(t.workerId);
                        t.workerId = 0;
                    }
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
            // Z1-F11-C4-D diag: last syscall numbers per task token (trap context).
            const lastSyscalls = new Map();
            // Guest pointer → C string from a task's linear memory (diag only).
            // Path pointers live in the SYSCALLING task's user memory, which for
            // K5 tasks is a distinct WebAssembly.Memory from the kernel image —
            // fall back to kernel memory only when the task has none.
            const readGuestCString = (mem, addr, max = 96) => {
                try {
                    const view = new Uint8Array((mem ?? memory).buffer);
                    if (!addr || addr >= view.length)
                        return "";
                    let end = addr;
                    while (end < addr + max && end < view.length && view[end] !== 0)
                        end++;
                    return new TextDecoder().decode(view.subarray(addr, end));
                }
                catch {
                    return "";
                }
            };
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
                            // Z1-F11-C4-D diag: per-token syscall ring + openat path capture.
                            {
                                const ring = lastSyscalls.get(boundToken) ?? [];
                                ring.push(nr);
                                if (ring.length > 4)
                                    ring.shift();
                                lastSyscalls.set(boundToken, ring);
                            }
                            postK5Diag("BROKER_DISPATCH", true, {
                                slot: s,
                                dispatchId,
                                taskToken: boundToken,
                                nr,
                            });
                            if (nr === 56 /* openat */ || nr === 221 /* execve */) {
                                const umem = tasks.get(boundToken)?.userMemory ?? null;
                                const hexAt = (mem, addr) => {
                                    try {
                                        if (!mem || !addr)
                                            return "";
                                        const v = new Uint8Array(mem.buffer);
                                        if (addr >= v.length)
                                            return "oob";
                                        return Array.from(v.subarray(addr, Math.min(addr + 16, v.length)))
                                            .map((x) => x.toString(16).padStart(2, "0"))
                                            .join("");
                                    }
                                    catch {
                                        return "err";
                                    }
                                };
                                postK5Diag(nr === 56 ? "Z1_OPENAT_PATH" : "Z1_EXECVE_PATH", true, {
                                    taskToken: boundToken,
                                    dispatchId,
                                    args: `${a0},${a1},${a2}`,
                                    path: readGuestCString(umem, nr === 56 ? a1 : a0),
                                    userHex: hexAt(umem, nr === 56 ? a1 : a0),
                                    kernHex: hexAt(memory, nr === 56 ? a1 : a0),
                                });
                            }
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
                                if (error === HALT_KERNEL || error === TERMINAL_TASK_EXIT ||
                                    error === USER_IMAGE_REPLACED) {
                                    return; // retirement/cancellation belongs to the kernel transition
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
                if (!t.userModule || !t.userMemory || !t.entry) {
                    throw new Error(`[K5] user.call before compile/instantiate/entry for ${t.name}`);
                }
                const workerId = nextUserWorkerId++;
                t.workerId = workerId;
                workerIdToTask.set(workerId, t.token);
                postK5Diag("USER_WORKER_SPAWNED", true, {
                    taskToken: t.token,
                    workerId,
                    name: t.name,
                    entryType: t.entry.type,
                    imageId: t.activeImageId.toString(16),
                    forkPid: t.forkPid !== 0 ? t.forkPid : null,
                    guestFn: t.guestFn,
                    guestArg: t.guestArg,
                    sharedMemory: true,
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
                    entry: t.entry,
                    forkPid: t.forkPid !== 0 ? t.forkPid : undefined,
                    argsBytes: t.argsBytes ?? undefined,
                    argsBaseAddr: t.argsBaseAddr,
                    args: t.args,
                    user_module_noinit: t.userModuleNoinit ?? undefined,
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
                        // Resume parked kernel frames to recheck real IRQ conditions.
                        // The resumed C scheduler still chooses the runnable task.
                        wakeAllSuspensions(`irq:${irq}`);
                    })
                        .catch((error) => {
                        postK5Diag("IRQ_DELIVERY_FAILED", false, {
                            cpu,
                            irq,
                            message: String(error instanceof Error ? error.message : error).slice(0, 200),
                        });
                    });
                },
                virtioResult(seq, ok, value) {
                    const pending = virtioPending.get(seq);
                    if (!pending) {
                        postK5Diag("VIRTIO_RESULT_UNATTRIBUTED", false, { seq });
                        return;
                    }
                    virtioPending.delete(seq);
                    postK5Diag("Z1VIRTIO_RESULT", ok, { seq, ok, value });
                    if (ok)
                        pending.resolve(value);
                    else
                        pending.reject(new Error(`virtio op failed (seq=${seq})`));
                },
                userTaskError(taskToken, reason, stack, faultClass) {
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
                        stack: String(stack ?? "").slice(0, 600),
                        lastSyscalls: (lastSyscalls.get(taskToken) ?? []).join(","),
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
                if (t.workerId !== 0) {
                    postMessage({
                        type: "retire_worker",
                        workerId: t.workerId,
                        taskToken: t.token,
                        imageId: t.activeImageId,
                    });
                    workerIdToTask.delete(t.workerId);
                    t.workerId = 0;
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
                    onTimerDeadline,
                    onFinishTask: finishTask,
                    onSyscallComplete,
                    onHaltWorker,
                    spawnWorkerRaw(fn, arg, name, _shareUserMemory, taskToken, spawnFlags) {
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
                            userModuleNoinit: null,
                            guestFn: 0,
                            guestArg: 0,
                            forkPid: 0,
                            inheritFrom: executingTask,
                            workerId: 0,
                            pendingCall: null,
                            // Z1-GABI: clone children share the parent image (CLONE_VM / clone-with-fn
                            // semantics) and never emit their own WASM_EXEC_COMMITTED — inherit the
                            // spawning task's identity. Boot/shell tasks keep 0n until their own exec.
                            imageId: tasks.get(executingTask)?.imageId ?? 0n,
                            activeImageId: tasks.get(executingTask)?.imageId ?? 0n,
                            argsBytes: tasks.get(executingTask)?.argsBytes ?? null,
                            argsBaseAddr: tasks.get(executingTask)?.argsBaseAddr ?? 0,
                            args: tasks.get(executingTask)?.args ?? [],
                            entry: null,
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
                    process_event_handler(event_kind, _run_id_hi, _run_id_lo, _event_seq, pid, _tgid, _ppid, _worker_id, data0, data1, _comm) {
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
                            assert(t, "Exec committed for an unregistered task");
                            assert(data0 > 0n, "Exec committed without an image identity");
                            // Read the kernel-owned block before user entry, without re-entering C.
                            const argsPtr = Number(data1);
                            assert(Number.isSafeInteger(argsPtr) && argsPtr > 0 &&
                                argsPtr <= memory.buffer.byteLength - 20, "Invalid exec argument pointer");
                            const payloadLen = new DataView(memory.buffer).getInt32(argsPtr, true);
                            assert(payloadLen >= 0 && payloadLen < 262144 &&
                                argsPtr <= memory.buffer.byteLength - 20 - payloadLen, "Invalid exec argument block");
                            const snapshot = new Uint8Array(memory.buffer, argsPtr, 20 + payloadLen).slice();
                            const view = new DataView(snapshot.buffer);
                            const argc = view.getInt32(8, true);
                            const table = view.getUint32(12, true) - argsPtr;
                            assert(argc > 0 && table >= 20 &&
                                table + (argc + 1) * 4 <= snapshot.length, "Invalid exec argument table");
                            const parsed = [];
                            const decoder = new TextDecoder();
                            for (let i = 0; i < argc; i++) {
                                const start = view.getUint32(table + i * 4, true) - argsPtr;
                                assert(start >= 20 && start < snapshot.length, "Invalid exec argument string");
                                const end = snapshot.indexOf(0, start);
                                assert(end !== -1, "Unterminated exec argument string");
                                parsed.push(decoder.decode(snapshot.subarray(start, end)));
                            }
                            t.argsBytes = snapshot;
                            t.argsBaseAddr = argsPtr;
                            t.args = parsed;
                            t.imageId = data0;
                            t.entry = { version: 1, imageId: data0, type: "START_PROCESS" };
                            // activeImageId stays bound to the OLD Worker until userCall retires it.
                            postK5Diag("Z1_GABI_IMAGE_BOUND", true, {
                                taskToken: t.token, pid, imageId: data0.toString(16),
                            });
                            postK5Diag("Z1_F11_ARGV_CAPTURE", true, {
                                taskToken: t.token, pid, argc, bytes: snapshot.length, argv0: parsed[0],
                            });
                        }
                        // Fall through so observers receive every real kernel event.
                        // forward path so main-thread event observers (witness rawEvents,
                        // TASK_DEAD checks, monotonicity) keep receiving every event.
                    },
                }),
                user: {
                    compile(buf, size) {
                        const t = currentTask();
                        const bytes = kernelMem.slice(buf, buf + size);
                        try {
                            const module = new WebAssembly.Module(bytes);
                            const continuation = compileContinuationImage(bytes);
                            t.userModule = module;
                            t.userModuleNoinit = continuation;
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
                            // Z1-F11-C4-D: reduce initial memory for light guests to avoid
                            // renderer OOM at ~30s during multi-process exec chains.
                            // Keep 768MiB floor only for heavy guests (blink/node).
                            let isHeavy = false;
                            if (t.args.length > 0) {
                                const firstArg = t.args[0] ?? "";
                                isHeavy =
                                    firstArg.includes("/bin/blink") ||
                                        firstArg.includes("/bin/node");
                            }
                            const initial = isHeavy ? 12288 : 1024; // 768MiB vs 64MiB
                            const maximum = 65536; // 4 GiB: Blink mappings cross the signed i32 boundary.
                            t.userMemory = new WebAssembly.Memory({
                                initial,
                                maximum,
                                shared: true,
                            });
                            // A REAL exec never returns into the old image's entry context:
                            // reset to the fresh image's own entrypoint (_start). Inherited
                            // clone context (switch_entry fn, fork_user pid) applies ONLY
                            // to non-fresh clone-path image binding — fresh=false preserves
                            // it untouched. No guest special-casing, no table-length assumptions.
                            t.guestFn = 0;
                            t.guestArg = 0;
                            t.forkPid = 0;
                            t.entry = { version: 1, imageId: t.imageId, type: "START_PROCESS" };
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
                        t.userModuleNoinit = parent.userModuleNoinit;
                        t.userMemory = parent.userMemory;
                        t.guestFn = fn;
                        t.guestArg = arg;
                        // Inherit raw args snapshot verbatim — never re-read guest memory.
                        t.argsBytes = parent.argsBytes;
                        t.argsBaseAddr = parent.argsBaseAddr;
                        t.args = parent.args;
                        t.entry = {
                            version: 1,
                            imageId: parent.activeImageId,
                            type: "SWITCH_FUNCTION_TABLE",
                            tableIndex: fn >>> 0,
                            arg: arg | 0,
                        };
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
                            maximum: 65536,
                            shared: true,
                        });
                        new Uint8Array(fresh.buffer).set(new Uint8Array(parent.userMemory.buffer));
                        t.userModule = parent.userModule;
                        t.userModuleNoinit = parent.userModuleNoinit;
                        t.userMemory = fresh;
                        t.forkPid = pid;
                        // Inherit raw args snapshot verbatim — fork children share argv.
                        t.argsBytes = parent.argsBytes;
                        t.argsBaseAddr = parent.argsBaseAddr;
                        t.args = parent.args;
                        t.entry = {
                            version: 1,
                            imageId: parent.activeImageId,
                            type: "RESUME_FORK_IMAGE",
                            forkPid: pid,
                        };
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
                        const source = from >>> 0;
                        const end = source + n;
                        if (end > t.userMemory.buffer.byteLength) {
                            t.userMemory.grow(Math.ceil((end - t.userMemory.buffer.byteLength) / 65536));
                        }
                        const slice = new Uint8Array(t.userMemory.buffer, source, n);
                        kernelMem.set(slice, to >>> 0);
                        return n - slice.length;
                    },
                    write(to, from, n) {
                        const t = currentTask();
                        if (!t.userMemory)
                            throw new Error("[K5] user.write before instantiate");
                        const destination = to >>> 0;
                        const source = from >>> 0;
                        const end = destination + n;
                        if (end > t.userMemory.buffer.byteLength) {
                            t.userMemory.grow(Math.ceil((end - t.userMemory.buffer.byteLength) / 65536));
                        }
                        const slice = kernelMem.subarray(source, source + n);
                        new Uint8Array(t.userMemory.buffer, destination, n).set(slice);
                        return n - slice.length;
                    },
                    write_zeroes(to, n) {
                        const t = currentTask();
                        if (!t.userMemory) {
                            throw new Error("[K5] user.write_zeroes before instantiate");
                        }
                        new Uint8Array(t.userMemory.buffer, to >>> 0, n).fill(0);
                        return 0;
                    },
                },
                virtio: {
                    // Device setup and I/O retain their kernel stack until main completes the operation.
                    set_features: new SuspendingCtor((dev, features) => virtioCall(dev, "set_features", [], features)),
                    setup: new SuspendingCtor((dev, irq, is_config_addr, is_vring_addr, config_addr, config_len) => virtioCall(dev, "setup", [
                        irq, is_config_addr, is_vring_addr, config_addr, config_len,
                    ])),
                    enable_vring: new SuspendingCtor((dev, vq, size, desc_addr, dev_evt_addr) => virtioCall(dev, "enable_vring", [vq, size, desc_addr, dev_evt_addr])),
                    disable_vring: new SuspendingCtor((dev, vq) => virtioCall(dev, "disable_vring", [vq])),
                    notify: new SuspendingCtor((dev, vq) => virtioCall(dev, "notify", [vq])),
                },
            };
            currentStage = "AFTER_KERNEL_IMPORTS";
            postK4Diag("AFTER_KERNEL_IMPORTS", { isKernelAuthority: true });
            currentStage = "BEFORE_ENTRYPOINT";
            instance = new WebAssembly.Instance(kernelModule, authorityImports);
            postK5Diag("KERNEL_INSTANTIATED", true, { instanceCount: 1 });
            // Z1-F11-C3-A: dump the kernel lock-event ring buffer twice post-boot
            // (before the runtime's 60s shell-prompt timeout closes the page).
            // Pure-read exports (kwa_get_last_* precedent) — no kernel re-entry.
            const z1DumpLockDiag = (tag) => {
                try {
                    const kx = instance.exports;
                    if (!kx.z1_ldiag_ptr || !kx.z1_ldiag_count || !kx.z1_ldiag_words) {
                        postK5Diag("Z1_LDIAG_DUMP", false, { tag, reason: "missing exports" });
                        return;
                    }
                    const ptr = kx.z1_ldiag_ptr();
                    const count = kx.z1_ldiag_count();
                    const words = kx.z1_ldiag_words();
                    const dv = new DataView(memory.buffer);
                    const N = 96;
                    const start = 0; /* C3-A rev3: EARLY events (exit/exec) — the tail
                       fills with panic console output after init death. */
                    const end = Math.min(count, start + N);
                    const chunks = [];
                    for (let i = start; i < end; i++) {
                        const slot = i % 256;
                        const base = ptr + slot * words * 4;
                        let hex = "";
                        for (let w = 0; w < words; w++) {
                            const v = dv.getUint32(base + w * 4, true);
                            hex += v.toString(16).padStart(8, "0");
                        }
                        // copy bytes to a plain buffer for the hex encode (SAB-safe path
                        // is unnecessary here — toString on numbers only)
                        chunks.push(hex);
                    }
                    postK5Diag("Z1_LDIAG_DUMP", true, {
                        tag, count, ptr, words, first: start, chunks: chunks.join("."),
                    });
                }
                catch (e) {
                    postK5Diag("Z1_LDIAG_DUMP", false, {
                        tag, error: String(e?.message ?? e).slice(0, 120),
                    });
                }
            };
            setTimeout(() => z1DumpLockDiag("t40"), 40_000);
            setTimeout(() => z1DumpLockDiag("t58"), 58_000);
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
        const userEntry = validateEntry(data.entry);
        const imports = createGuestImports(data, userEntry);
        const selectedModule = userEntry.type === "START_PROCESS"
            ? parent_user_module : data.user_module_noinit;
        assert(selectedModule, "Continuation missing its own no-start module");
        for (const imp of WebAssembly.Module.imports(selectedModule)) {
            const namespace = imports[imp.module];
            const supported = namespace && Object.prototype.hasOwnProperty.call(namespace, imp.name) &&
                ((imp.module === "env" && imp.name === "memory" && imp.kind === "memory") ||
                    (imp.module === "linux" && imp.kind === "function"));
            assert(supported, `Unsupported user import ${imp.module}.${imp.name}`);
        }
        const userInstance = new WebAssembly.Instance(selectedModule, imports);
        currentStage = "AFTER_USER_INSTANTIATE";
        postK4Diag("AFTER_USER_INSTANTIATE", { exportNames: Object.keys(userInstance.exports) });
        try {
            currentStage = "BEFORE_ENTRYPOINT";
            const exportsRec = userInstance.exports;
            try {
                const entryPkt = userEntry;
                if (entryPkt) {
                    switch (entryPkt.type) {
                        case "START_PROCESS": {
                            currentStage = "BEFORE_ENTRYPOINT_CALL";
                            postK4Diag("BEFORE_ENTRYPOINT_CALL", { via: "START_PROCESS" });
                            const startExport = exportsRec._start;
                            if (typeof startExport !== "function") {
                                throw new Error("[ENTRY] START_PROCESS: _start export missing");
                            }
                            startExport(0);
                            break;
                        }
                        case "SWITCH_FUNCTION_TABLE": {
                            const table = exportsRec.__indirect_function_table;
                            if (!(table instanceof WebAssembly.Table)) {
                                throw new Error("[ENTRY] SWITCH_FUNCTION_TABLE: no function table");
                            }
                            if (entryPkt.tableIndex < 0 || entryPkt.tableIndex >= table.length) {
                                throw new Error(`[ENTRY] SWITCH_FUNCTION_TABLE index ${entryPkt.tableIndex} out of bounds (max ${table.length})`);
                            }
                            const f = table.get(entryPkt.tableIndex);
                            if (typeof f !== "function") {
                                throw new Error(`[ENTRY] SWITCH_FUNCTION_TABLE index ${entryPkt.tableIndex} is not a function`);
                            }
                            currentStage = "BEFORE_ENTRYPOINT_CALL";
                            postK4Diag("BEFORE_ENTRYPOINT_CALL", { via: "SWITCH_FUNCTION_TABLE", fn: entryPkt.tableIndex, arg: entryPkt.arg });
                            f(entryPkt.arg);
                            break;
                        }
                        case "RESUME_FORK_IMAGE": {
                            postMessage({ type: "fork_copied", pid: entryPkt.forkPid, taskToken: taskToken ?? 0 });
                            currentStage = "BEFORE_ENTRYPOINT_CALL";
                            postK4Diag("BEFORE_ENTRYPOINT_CALL", { via: "RESUME_FORK_IMAGE", forkPid: entryPkt.forkPid });
                            const blinkResume = exportsRec.blink_user_fork_resume;
                            if (typeof blinkResume === "function") {
                                blinkResume();
                                throw new Error("blink_user_fork_resume returned; fork child must exit via kernel");
                            }
                            throw new Error("Fork image does not export blink_user_fork_resume");
                        }
                    }
                }
                else {
                    throw new Error("[ENTRY] missing entry packet: legacy mode dispatch is no longer supported");
                }
            }
            catch (entryError) {
                if (entryError === TERMINAL_TASK_EXIT) {
                    return;
                }
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
                            // Z1-F11-C3: wasm frames ("wasm-function[N]:0xoff") locate the
                            // exact blink function that trapped — the structural-fix target.
                            stack: String(entryError?.stack ?? "").slice(0, 800),
                            faultClass: isGuestTrap ? "wasm_trap" : "returned_without_exit",
                        });
                        delivered = true;
                    }
                    catch { /* best-effort */ }
                }
                if (isGuestTrap && delivered) {
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
        }
        catch (error) {
            if (error === HALT_KERNEL) {
                return;
            }
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
//# sourceMappingURL=worker.js.map