import { type DeviceTreeNode } from "./devicetree.ts";
import { EventEmitter } from "./util.ts";
import { VirtioDevice } from "./virtio.ts";
import type { AuthorityDiagMessage } from "./worker.ts";
import { type KernelProcessEvent } from "./process-events.ts";
export { BlockDevice, type BlockDeviceStorage, ConsoleDevice, EntropyDevice, LoopbackNetworkBridge, type NetworkBridge, NetworkDevice, type VsockConnection, VsockDevice, } from "./virtio.ts";
export { PROCESS_EVENT_KIND, decodeKernelProcessEvent, decodeLinuxWaitStatus, formatRunId, } from "./process-events.ts";
export type { AuthorityDiagMessage } from "./worker.ts";
export type { VirtioOp } from "./worker.ts";
/** K4 diagnostic stage markers surfaced from secondary workers — observed
 * data, never an unreachable-main error. */
export interface K4DiagMessage {
    type: "k4_diag";
    stage: string;
    detail?: Record<string, unknown>;
}
export type { KernelProcessEvent, KernelProcessEventKind, KernelProcessEventName, KernelTerminalStatus, RawKernelProcessEvent, RawProcessEventMessage, } from "./process-events.ts";
export interface D1TraceMetadata {
    capacity: number;
    storedRecordCount: number;
    totalRecordCount: number;
    overwriteCount: number;
    firstStoredSequence: number | null;
    lastStoredSequence: number | null;
    wrapped: boolean;
}
export interface D1TraceExport {
    runId: string;
    records: Array<Record<string, unknown>>;
    metadata: D1TraceMetadata;
}
export declare function decodeD1TraceExport(data: {
    runId?: unknown;
    records?: unknown;
    metadata?: unknown;
}): D1TraceExport | null;
export declare class Machine extends EventEmitter<{
    error: ErrorEvent;
    d1_trace: D1TraceExport;
    process_event: KernelProcessEvent;
    authority_diag: AuthorityDiagMessage;
    k4_diag: K4DiagMessage;
}> {
    #private;
    memory: Uint8Array;
    devicetree: DeviceTreeNode;
    get bootConsole(): ReadableStream<Uint8Array<ArrayBufferLike>>;
    constructor(options: {
        cmdline?: string;
        memoryMib?: number;
        cpus?: number;
        devices: VirtioDevice[];
        initcpio?: ArrayBufferView;
        d1TraceEnabled?: boolean;
        d1RunId?: string;
        processEventHandler?: (event_kind: number, run_id_hi: bigint, run_id_lo: bigint, event_seq: bigint, pid: number, tgid: number, ppid: number, worker_id: number, data0: bigint, data1: bigint, comm: string) => void;
    });
    boot(): Promise<void>;
}
