/**
 * KWA Broker — Single Kernel Authority (K1 Six-Arg ABI)
 *
 * Implements the frozen protocol contract v2 (KWA-v2 §2–§3):
 * - SharedArrayBuffer ring with N_SLOTS=64, SLOT_SIZE=96B, SLOTS_OFF=64B.
 * - State machine: FREE (0) -> REQUESTED (1) -> CLAIMED (2) -> COMPLETED (3) -> CONSUMED (4) -> FREE (0).
 * - Owner word reservation (offset 68) before payload store; STATE=REQUESTED published last.
 * - BrokerOpcode namespace distinct from Linux __NR_*; only SYSCALL reads NR slot.
 * - Full six-arg syscall ABI: nr + a0..a5 transported distinctly; result + errno separate.
 * - Authority executes syscall via kernel export, stores RESULT/ERRNO/RESP_ID, then STATE=COMPLETED last.
 * - CPU worker waits with Atomics.wait until COMPLETED && RESP_ID == reqId.
 */
export declare const MAGIC = 1264009475;
/** Broker opcodes — distinct from Linux __NR_* syscall numbers (§2 KWA-v2). */
export declare const BrokerOpcode: {
    readonly SYSCALL: 1;
    readonly TASK_EXIT: 2;
    readonly INTERRUPT: 3;
};
export declare const STATE: {
    readonly FREE: 0;
    readonly REQUESTED: 1;
    readonly CLAIMED: 2;
    readonly COMPLETED: 3;
    readonly CONSUMED: 4;
};
export declare const N_SLOTS = 64;
export declare const SLOT_SIZE = 112;
export declare const SLOTS_OFF = 64;
export declare const OFF: {
    readonly MAGIC: 0;
    /** K5: completion had no matching pending dispatch — result dropped, never faked. */
    readonly UNATTRIBUTED_RESPONSE_COUNT: 1;
    /** K5: finish_task terminal cancellations of outstanding claimed slots. */
    readonly TERMINAL_CANCEL_COUNT: 2;
    readonly BOOT_COUNT: 8;
    readonly SECONDARY_INST_COUNT: 9;
    readonly POST_FREE_DISPATCH_COUNT: 10;
    readonly WRONG_TASK_RESPONSE_COUNT: 11;
    readonly STALE_TASK_REQUEST_COUNT: 12;
    readonly BROKER_ERRORS: 13;
    readonly DOORBELL: 14;
    readonly ABA_REJECT_COUNT: 15;
};
export declare const S: {
    readonly STATE: 0;
    readonly REQ_ID: 4;
    readonly WORKER_ID: 8;
    readonly TASK_ID: 12;
    readonly TID: 16;
    readonly OPCODE: 20;
    readonly A0: 24;
    readonly A1: 28;
    readonly A2: 32;
    readonly A3: 36;
    readonly A4: 40;
    readonly A5: 44;
    readonly NR: 48;
    readonly RESP_ID: 52;
    readonly RESULT: 56;
    readonly ERRNO: 60;
    readonly GENERATION: 64;
    readonly OWNER: 68;
    readonly KERNEL_PID: 72;
    readonly KERNEL_TGID: 76;
    readonly KERNEL_GENERATION: 80;
    /** K5: echo of the client's slot GENERATION snapshot at CLAIM time.
     * Consumer requires RESP_GENERATION === its local reservation generation
     * (ABA/stale-slot guard), alongside KERNEL_GENERATION kernel truth. */
    readonly RESP_GENERATION: 84;
};
export declare const idx: (slot: number, off: number) => number;
export declare function assertBrokerLayout(): void;
export declare function createBrokerSab(): SharedArrayBuffer;
export interface BrokerResponse {
    result: number;
    errno: number;
    kernelPid?: number;
    kernelTgid?: number;
    kernelGeneration?: number;
}
export declare class BrokerClient {
    #private;
    constructor(sab: SharedArrayBuffer, workerId: number);
    syscall(nr: number, a0?: number, a1?: number, a2?: number, a3?: number, a4?: number, a5?: number, taskId?: number, tid?: number): number;
    invoke(nr: number, a0?: number, a1?: number, a2?: number, a3?: number, a4?: number, a5?: number, taskId?: number, tid?: number, notifyAuthority?: () => void): BrokerResponse;
}
export declare function authorityPump(syscallFn: (nr: number, a0: number, a1: number, a2: number, a3: number, a4: number, a5: number) => number, sab: SharedArrayBuffer, kernelIdentity?: {
    getPid: () => number;
    getTgid: () => number;
    getGeneration: () => number;
}): number;
/**
 * K4R2: Production broker_kick servicing function, extracted from Machine.boot()
 * so that both Machine.onmessage and external witnesses (e.g. K4 E2E) invoke the
 * SAME authoritative code path. This is not a simulation or wrapper — it is the
 * production authority pump invocation with real kernel identity.
 *
 * Placed here (not in index.ts) because index.ts has top-level fetch() side effects
 * that prevent Node.js import; kwa-broker.ts is side-effect-free.
 *
 * @param syscallFn - Function to invoke kernel syscall(nr, a0..a5)
 * @param brokerSab - The shared broker SAB for request/response routing
 * @param kernelIdentity - Accessors for real kernel task identity
 */
export declare function serviceBrokerKick(syscallFn: (nr: number, a0: number, a1: number, a2: number, a3: number, a4: number, a5: number) => number, brokerSab: SharedArrayBuffer, kernelIdentity: {
    getPid: () => number;
    getTgid?: () => number;
    getGeneration: () => number;
}): void;
