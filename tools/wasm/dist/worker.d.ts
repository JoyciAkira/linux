import { type D1Record, type D1RingMetadata } from "./d1-ring-buffer.ts";
export interface InitMessage {
    fn: number;
    arg: number;
    memory: WebAssembly.Memory;
    parent_user_module: WebAssembly.Module | null;
    parent_user_memory: WebAssembly.Memory | null;
    parent_tls_base?: number;
    brokerSab?: SharedArrayBuffer;
    workerId?: number;
    d1TraceEnabled?: boolean;
    d1RunId?: string;
    /** K5A: true for the dedicated kernel authority worker spawned by setup.c. */
    isKernelAuthority?: boolean;
    /** K5A: vmlinux Module delivered ONLY to kernel authority workers (K3 invariant). */
    kernelModule?: WebAssembly.Module;
    /** K5A diagnostic boot inputs served by the authority's boot imports.
     * devicetree must fit the kernel's static FDT buffer (setup.c bound 2048);
     * initramfs must fit its static initramfs buffer (setup.c bound 512). */
    bootViaExport?: boolean;
    devicetree?: Uint8Array;
    initramfs?: Uint8Array | null;
    /** K5: KERNEL-OWNED task token this user worker executes for. Sent with
     * every broker request as the routing key (kernel truth still stamped C-side). */
    taskToken?: number;
    /** K5: user entry mode — "start": image entrypoint; "switch_entry": CLONE_VM
     * table entry; "fork_user": fresh-memory fork resume with fork-ack. */
    mode?: "start" | "switch_entry" | "fork_user";
    /** K5: real child pid for fork_user fork-ack (kernel fork_copied export). */
    forkPid?: number;
    /** K4+: Captured argv bytes from authority TaskRecord at spawn time. */
    argv?: Uint8Array | null;
}
export type WorkerMessage = {
    type: "spawn_worker";
    fn: number;
    arg: number;
    name: string;
    user_module: WebAssembly.Module | null;
    user_memory: WebAssembly.Memory | null;
    parent_tls_base?: number;
    brokerSab?: SharedArrayBuffer;
    workerId?: number;
    /** K5A: kernel authority workers bypass K4 secondary-worker gate. */
    isKernelAuthority?: boolean;
    /** K5: authority-originated spawn — KERNEL-OWNED task token + entry mode.
     * When workerId is present the authority assigned it (registry-bound);
     * main MUST use it instead of allocating its own. */
    taskToken?: number;
    mode?: "start" | "switch_entry" | "fork_user";
    forkPid?: number;
    argv?: Uint8Array | null;
} | {
    type: "boot_console_write";
    message: ArrayBuffer;
} | {
    type: "boot_console_close";
} | {
    type: "run_on_main";
    fn: number;
    arg: number;
} | {
    type: "broker_kick";
    workerId?: number;
} | {
    type: "worker_done";
    reason: string;
} | {
    type: "d1_trace_export";
    runId: string;
    records: D1Record[];
    metadata: D1RingMetadata;
} | {
    type: "authority_diag";
    stage: string;
    ok: boolean;
    detail: AuthorityDiagMessage["detail"];
    ts: number;
}
/** K4 diagnostic stage markers from secondary workers — surfaced by main,
 * never an unreachable-main error. */
 | {
    type: "k4_diag";
    stage: string;
    detail?: Record<string, unknown>;
}
/** K5: fork child acks its VAS snapshot; authority wakes the parked parent
 * via the kernel fork_copied export. */
 | {
    type: "fork_copied";
    pid: number;
    taskToken: number;
}
/** K5: user worker ended abnormally (image returned without exit / trap);
 * the authority rejects that task's user.call with the real error. */
 | {
    type: "user_task_error";
    taskToken: number;
    reason: string;
    faultClass: "wasm_trap" | "returned_without_exit";
}
/** K5: main → authority: fork ack relay (from a user worker's fork_copied). */
 | {
    type: "authority_fork_copied";
    pid: number;
}
/** K5: main → authority: device IRQ relay — deliver through the kernel. */
 | {
    type: "authority_irq";
    cpu: number;
    irq: number;
}
/** K5: authority → main virtio device round-trip (Suspending import). */
 | {
    type: "virtio_cmd";
    seq: number;
    dev: number;
    op: VirtioOp;
    args: number[];
    features?: bigint;
} | {
    type: "virtio_result";
    seq: number;
    ok: boolean;
    value: number;
    irq?: number;
} | {
    type: "authority_broker_kick";
} | {
    type: "k5a_ping";
};
/** K5: virtio device operations relayed authority→main. */
export type VirtioOp = "set_features" | "setup" | "enable_vring" | "disable_vring" | "notify";
/** K5A diagnostic packet: the only authority evidence channel. `ok:false`
 * marks genuine failure or model-blocked evidence — never a soft warning.
 * detail may carry a shared WebAssembly.Memory so observers (generic Node
 * adapter) can watch real guest result buffers. */
export interface AuthorityDiagMessage {
    type: "authority_diag";
    stage: string;
    ok: boolean;
    detail: Record<string, string | number | boolean | null | WebAssembly.Memory>;
    ts: number;
}
export declare function exportD1Trace(): void;
