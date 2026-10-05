export declare const PROCESS_EVENT_KIND: {
    readonly RUN_START: 1;
    readonly WASM_EXEC_COMMITTED: 2;
    readonly CLONE_WORKER_REQUESTED: 3;
    readonly TASK_DEAD: 4;
    readonly USER_SIGNAL_HANDLER_DISPATCH: 5;
    readonly WAIT_REAP_COMMITTED: 6;
    readonly RUN_END: 7;
    /** K5: kernel_clone committed — real child task registered (KernelContext). */
    readonly CLONE_COMMITTED: 8;
    /** K5: released task removed from kernel task table (release_task). */
    readonly TASK_RELEASE_COMMITTED: 9;
    /** K5: parent entered wait4 syscall (post-wait observability). */
    readonly PARENT_POST_WAIT_SYSCALL: 10;
    /** K5: C context suspension proof. data0=stack pointer, data1=cookie. */
    readonly CONTEXT_SUSPEND: 11;
    /** K5: C context resume/rebind proof. data0=stack pointer, data1=cookie. */
    readonly CONTEXT_RESUME: 12;
};
export type KernelProcessEventKind = (typeof PROCESS_EVENT_KIND)[keyof typeof PROCESS_EVENT_KIND];
export type KernelProcessEventName = keyof typeof PROCESS_EVENT_KIND;
export interface RawKernelProcessEvent {
    event_kind: number;
    run_id_hi: bigint;
    run_id_lo: bigint;
    event_seq: bigint;
    pid: number;
    tgid: number;
    ppid: number;
    worker_id: number;
    data0: bigint;
    data1: bigint;
    comm: string;
}
export interface RawProcessEventMessage extends RawKernelProcessEvent {
    type: "process_event";
}
export type KernelTerminalStatus = {
    kind: "exited";
    exitCode: number;
} | {
    kind: "signaled";
    signal: number;
    coreDumped: boolean;
};
export interface KernelProcessEvent extends RawKernelProcessEvent {
    kind: KernelProcessEventKind;
    name: KernelProcessEventName;
    runId: string;
    sequence: bigint;
    terminalStatus?: KernelTerminalStatus;
    /** CONTEXT_SUSPEND/CONTEXT_RESUME only: C stack pointer + cookie proof —
     * real volatile values read from C, never host-derived. */
    contextProof?: {
        sp: bigint;
        cookie: bigint;
    };
}
export declare function formatRunId(hi: bigint, lo: bigint): string;
export declare function decodeLinuxWaitStatus(rawStatus: bigint): KernelTerminalStatus;
export declare function decodeKernelProcessEvent(raw: RawKernelProcessEvent): KernelProcessEvent;
export declare function makeRawProcessEventMessage(raw: RawKernelProcessEvent): RawProcessEventMessage;
