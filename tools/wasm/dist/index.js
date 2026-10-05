import { generate_devicetree } from "./devicetree.js";
import { assert, EventEmitter, unreachable } from "./util.js";
import { virtio_imports, VirtioDevice } from "./virtio.js";
import { decodeKernelProcessEvent, } from "./process-events.js";
import { createBrokerSab } from "./kwa-broker.js";
export { BlockDevice, ConsoleDevice, EntropyDevice, LoopbackNetworkBridge, NetworkDevice, VsockDevice, } from "./virtio.js";
export { PROCESS_EVENT_KIND, decodeKernelProcessEvent, decodeLinuxWaitStatus, formatRunId, } from "./process-events.js";
const resources = (async () => {
    const vmlinux_response = fetch(new URL("../vmlinux.wasm", import.meta.url));
    let vmlinux;
    if ("compileStreaming" in WebAssembly) {
        vmlinux = await WebAssembly.compileStreaming(vmlinux_response);
    }
    else {
        const buffer = await (await vmlinux_response).arrayBuffer();
        vmlinux = await WebAssembly.compile(buffer);
    }
    const custom_section = (name) => {
        const sections = WebAssembly.Module.customSections(vmlinux, name);
        const section = sections[0];
        assert(section && sections.length === 1, `Missing custom section: ${name}`);
        return section;
    };
    const sections = JSON.parse(new TextDecoder().decode(custom_section(".linux.sections")));
    const initramfs = new Uint8Array(custom_section(".linux.initramfs"));
    return {
        vmlinux,
        sections,
        initramfs,
    };
})();
const INITCPIO_ADDR = 0x200000;
function isD1Record(r) {
    if (typeof r !== "object" || r === null)
        return false;
    const o = r;
    if (typeof o.sequence !== "number")
        return false;
    if (typeof o.eventType !== "string")
        return false;
    if (o.eventType === "syscall_enter") {
        if (typeof o.rawSyscallNumber !== "number")
            return false;
        if (!Array.isArray(o.rawArguments))
            return false;
        if (o.rawArguments.length > 6)
            return false;
        if (o.rawArguments.some((a) => typeof a !== "number"))
            return false;
    }
    if (o.eventType === "syscall_return" && typeof o.rawReturnValue !== "number") {
        return false;
    }
    return true;
}
function isD1Metadata(m) {
    if (typeof m !== "object" || m === null)
        return false;
    const o = m;
    if (typeof o.capacity !== "number" ||
        typeof o.storedRecordCount !== "number" ||
        typeof o.totalRecordCount !== "number" ||
        typeof o.overwriteCount !== "number" ||
        typeof o.wrapped !== "boolean") {
        return false;
    }
    if (o.capacity > 4096)
        return false;
    if (o.storedRecordCount > o.capacity)
        return false;
    if (o.wrapped !== (o.overwriteCount > 0))
        return false;
    return true;
}
export function decodeD1TraceExport(data) {
    if (typeof data.runId !== "string")
        return null;
    if (!Array.isArray(data.records))
        return null;
    if (!isD1Metadata(data.metadata))
        return null;
    if (data.records.length !== data.metadata.storedRecordCount)
        return null;
    if (!data.records.every(isD1Record))
        return null;
    for (let i = 1; i < data.records.length; i++) {
        const prev = data.records[i - 1];
        const cur = data.records[i];
        if (cur.sequence <= prev.sequence)
            return null;
    }
    return {
        runId: data.runId,
        records: data.records,
        metadata: data.metadata,
    };
}
export class Machine extends EventEmitter {
    #boot_console;
    #boot_console_writer;
    #workers = [];
    #memory;
    #devices;
    #initcpio;
    #ncpus;
    #d1_trace_enabled = false;
    #d1_run_id = "d1-run";
    #brokerSab;
    /** Main-assigned transport ids only for legacy secondary spawns; authority
     * ids live in 1..n (authority itself = 1, user workers from 2), so legacy
     * ids start at 1M to keep the spaces disjoint. */
    #nextWorkerId = 1_000_000;
    #process_event_handler;
    memory;
    devicetree;
    get bootConsole() {
        return this.#boot_console.readable;
    }
    #dispatchProcessEvent(raw) {
        const decoded = decodeKernelProcessEvent(raw);
        this.emit("process_event", decoded);
        this.#process_event_handler?.(raw.event_kind, raw.run_id_hi, raw.run_id_lo, raw.event_seq, raw.pid, raw.tgid, raw.ppid, raw.worker_id, raw.data0, raw.data1, raw.comm);
    }
    constructor(options) {
        super();
        this.#boot_console = new TransformStream();
        this.#boot_console_writer = this.#boot_console.writable.getWriter();
        this.#devices = options.devices;
        this.#initcpio = options.initcpio;
        this.#ncpus = options.cpus ?? navigator.hardwareConcurrency;
        this.#process_event_handler = options.processEventHandler;
        this.#d1_trace_enabled = options.d1TraceEnabled === true;
        this.#d1_run_id = options.d1RunId ?? "d1-run";
        // K4R: Use canonical broker SAB layout (7232 bytes) instead of hardcoded 4096
        this.#brokerSab = createBrokerSab();
        const PAGE_SIZE = 0x10000;
        const BYTES_PER_MIB = 0x100000;
        const bytes = (options.memoryMib ?? 128) * BYTES_PER_MIB;
        const pages = bytes / PAGE_SIZE;
        this.#memory = new WebAssembly.Memory({
            initial: pages,
            maximum: pages,
            shared: true,
        });
        assert(this.#memory.buffer.byteLength === bytes);
        this.memory = new Uint8Array(this.#memory.buffer);
        this.devicetree = {
            "#address-cells": 1,
            "#size-cells": 1,
            chosen: {
                "rng-seed": crypto.getRandomValues(new Uint8Array(64)),
                bootargs: `console=hvc0 ${options.cmdline ?? ""}`,
                ncpus: this.#ncpus,
            },
            aliases: {},
            memory: {
                device_type: "memory",
                reg: [0, bytes],
            },
            "reserved-memory": {
                "#address-cells": 1,
                "#size-cells": 1,
                ranges: undefined,
            },
        };
        if (this.#initcpio) {
            const chosen = this.devicetree.chosen;
            chosen["linux,initrd-start"] = INITCPIO_ADDR;
            chosen["linux,initrd-end"] = INITCPIO_ADDR + this.#initcpio.byteLength;
            this.memory.set(new Uint8Array(this.#initcpio.buffer, this.#initcpio.byteOffset, this.#initcpio.byteLength), INITCPIO_ADDR);
        }
        for (const [i, dev] of this.#devices.entries()) {
            this.devicetree[`virtio${i}`] = {
                compatible: `virtio,wasm`,
                "host-id": i,
                "virtio-device-id": dev.ID,
                features: dev.features,
                config: dev.config_bytes,
            };
        }
    }
    async boot() {
        const memory_reservations = [];
        if (this.#initcpio) {
            memory_reservations.push({
                address: INITCPIO_ADDR,
                size: this.#initcpio.byteLength,
            });
        }
        const { sections, vmlinux, initramfs } = await resources;
        this.devicetree.chosen.sections = sections;
        const devicetree = generate_devicetree(this.devicetree, {
            memory_reservations,
        });
        const boot_console_write = (message) => {
            this.#boot_console_writer.write(new Uint8Array(message)).catch(() => {
                // Ignore errors if the console is closed
            });
        };
        const boot_console_close = () => {
            this.#boot_console_writer.close();
        };
        let authorityWorker = null;
        // Main-side device binding: devices live here; the kernel (authority
        // worker) reaches them through virtio_cmd/virtio_result round-trips and
        // receives IRQs back through authority_irq.
        let vimports = null;
        const wireWorker = (worker) => {
            worker.onmessage = (event) => {
                switch (event.data.type) {
                    case "spawn_worker":
                        spawn_worker(event.data.fn, event.data.arg, event.data.name, event.data.user_module, event.data.user_memory, event.data.workerId, event.data.taskToken, event.data.mode, event.data.forkPid);
                        break;
                    case "boot_console_write":
                        boot_console_write(event.data.message);
                        break;
                    case "boot_console_close":
                        boot_console_close();
                        break;
                    case "run_on_main":
                        throw new Error("[K5] run_on_main from a secondary worker is unsupported in the single-authority path");
                    case "process_event": {
                        const raw = event.data;
                        this.#dispatchProcessEvent(raw);
                        break;
                    }
                    case "k4_diag":
                        // K4 diagnostic stage markers are observed data — surface them,
                        // never crash the main thread on them.
                        this.emit("k4_diag", event.data);
                        break;
                    case "authority_diag":
                        this.emit("authority_diag", event.data);
                        break;
                    case "d1_trace_export": {
                        const decoded = decodeD1TraceExport(event.data);
                        if (decoded !== null)
                            this.emit("d1_trace", decoded);
                        break;
                    }
                    case "worker_done": {
                        const idx = this.#workers.indexOf(worker);
                        if (idx !== -1) {
                            this.#workers.splice(idx, 1);
                        }
                        worker.onmessage = null;
                        worker.onerror = null;
                        worker.terminate();
                        break;
                    }
                    case "broker_kick": {
                        // Brokered syscalls are served only by the kernel authority; the
                        // main thread owns no kernel instance and never pumps the SAB.
                        if (!authorityWorker) {
                            throw new Error("[K5] broker_kick before the authority worker exists");
                        }
                        authorityWorker.postMessage({ type: "authority_broker_kick" });
                        break;
                    }
                    case "fork_copied":
                        // Fork child acked its VAS snapshot: wake the parked parent via
                        // the kernel fork_copied export — through the authority only.
                        if (!authorityWorker) {
                            throw new Error("[K5] fork_copied before the authority worker exists");
                        }
                        authorityWorker.postMessage({
                            type: "authority_fork_copied",
                            pid: event.data.pid,
                        });
                        break;
                    case "user_task_error":
                        if (!authorityWorker) {
                            throw new Error("[K5] user_task_error before the authority worker exists");
                        }
                        authorityWorker.postMessage({
                            type: "user_task_error",
                            taskToken: event.data.taskToken,
                            reason: event.data.reason,
                            faultClass: event.data.faultClass,
                        });
                        break;
                    case "virtio_cmd": {
                        // Execute the device op against the real VirtioDevice in main.
                        if (!vimports) {
                            worker.postMessage({
                                type: "virtio_result",
                                seq: event.data.seq,
                                ok: false,
                                value: 0,
                            });
                            console.error("[K5] virtio_cmd before device binding");
                            break;
                        }
                        const { seq, dev, op, args } = event.data;
                        try {
                            // virtio_imports binds plain functions in main; the Suspending
                            // arm only exists on the authority side, so main always holds
                            // the callable arm of the shared Imports union.
                            const callVirtio = vimports;
                            if (op === "set_features") {
                                callVirtio.set_features(dev, event.data.features ?? 0n);
                            }
                            else if (op === "setup") {
                                callVirtio.setup(dev, args[0], args[1], args[2], args[3], args[4]);
                            }
                            else if (op === "enable_vring") {
                                callVirtio.enable_vring(dev, args[0], args[1], args[2]);
                            }
                            else if (op === "disable_vring") {
                                callVirtio.disable_vring(dev, args[0]);
                            }
                            else {
                                callVirtio.notify(dev, args[0]);
                            }
                            worker.postMessage({
                                type: "virtio_result",
                                seq,
                                ok: true,
                                value: 0,
                            });
                        }
                        catch (error) {
                            worker.postMessage({
                                type: "virtio_result",
                                seq,
                                ok: false,
                                value: 0,
                            });
                            console.error(`[K5] virtio ${op} dev=${dev} failed:`, String(error?.message ?? error));
                        }
                        break;
                    }
                    case "authority_broker_kick":
                    case "k5a_ping":
                    case "authority_fork_copied":
                    case "authority_irq":
                    case "virtio_result":
                        // Authority-directed payloads; never valid arriving at main.
                        break;
                    default:
                        unreachable(event.data);
                }
            };
            worker.onerror = (event) => {
                this.emit("error", event);
            };
        };
        const spawn_worker = (fn, arg, name, user_module, user_memory, workerId, taskToken, mode, forkPid) => {
            console.log(`[SPW] fn=${fn} name=${name} umodule=${typeof user_module}:${String(user_module).slice(0, 40)} umem=${typeof user_memory}:${String(user_memory)} taskToken=${taskToken} mode=${mode}`);
            const worker = new Worker(new URL("./worker.js", import.meta.url), {
                type: "module",
                name,
            });
            this.#workers.push(worker);
            wireWorker(worker);
            worker.postMessage({
                fn,
                arg,
                // K3/K5A: secondary workers NEVER receive the kernel module;
                // authority creation is exclusive to the Machine.boot path below.
                memory: this.#memory,
                parent_user_module: user_module,
                parent_user_memory: user_memory,
                // K4/K5: broker SAB + transport worker id for syscall routing.
                // Authority-assigned ids are used verbatim (registry-bound).
                brokerSab: this.#brokerSab,
                workerId: workerId ?? this.#nextWorkerId++,
                taskToken,
                mode,
                forkPid,
                d1TraceEnabled: this.#d1_trace_enabled,
                d1RunId: this.#d1_run_id,
            });
        };
        // K5: single-authority boot. The main thread constructs no kernel
        // instance and never blocks on Atomics.wait; the dedicated authority
        // worker owns the one vmlinux Instance, all kernel task continuations,
        // and every brokered syscall. Devices stay in main: the kernel reaches
        // them through virtio_cmd round-trips; device IRQs return through
        // authority_irq delivery.
        vimports = virtio_imports({
            memory: this.#memory,
            devices: this.#devices,
            ncpus: this.#ncpus,
            trigger_irq_for_cpu: (cpu, irq) => {
                authorityWorker?.postMessage({ type: "authority_irq", cpu, irq });
            },
        });
        const authority = new Worker(new URL("./worker.js", import.meta.url), {
            type: "module",
            name: "kernel-authority",
        });
        this.#workers.push(authority);
        authorityWorker = authority;
        wireWorker(authority);
        authority.postMessage({
            fn: 0,
            arg: 0,
            memory: this.#memory,
            parent_user_module: null,
            parent_user_memory: null,
            isKernelAuthority: true,
            kernelModule: vmlinux,
            bootViaExport: true,
            devicetree,
            initramfs: initramfs.length > 0 ? initramfs : null,
            brokerSab: this.#brokerSab,
            workerId: 1,
            d1TraceEnabled: this.#d1_trace_enabled,
            d1RunId: this.#d1_run_id,
        });
    }
}
