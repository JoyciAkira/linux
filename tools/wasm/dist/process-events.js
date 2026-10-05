export const PROCESS_EVENT_KIND = {
    RUN_START: 1,
    WASM_EXEC_COMMITTED: 2,
    CLONE_WORKER_REQUESTED: 3,
    TASK_DEAD: 4,
    USER_SIGNAL_HANDLER_DISPATCH: 5,
    WAIT_REAP_COMMITTED: 6,
    RUN_END: 7,
    /** K5: kernel_clone committed — real child task registered (KernelContext). */
    CLONE_COMMITTED: 8,
    /** K5: released task removed from kernel task table (release_task). */
    TASK_RELEASE_COMMITTED: 9,
    /** K5: parent entered wait4 syscall (post-wait observability). */
    PARENT_POST_WAIT_SYSCALL: 10,
    /** K5: C context suspension proof. data0=stack pointer, data1=cookie. */
    CONTEXT_SUSPEND: 11,
    /** K5: C context resume/rebind proof. data0=stack pointer, data1=cookie. */
    CONTEXT_RESUME: 12,
    // KernelContext: event 13 (DO_EXIT) intentionally absent — ZN_EVENT_TASK_DEAD
    // (4) already carries exit_code for terminal transitions.
};
const EVENT_NAMES = {
    [PROCESS_EVENT_KIND.RUN_START]: "RUN_START",
    [PROCESS_EVENT_KIND.WASM_EXEC_COMMITTED]: "WASM_EXEC_COMMITTED",
    [PROCESS_EVENT_KIND.CLONE_WORKER_REQUESTED]: "CLONE_WORKER_REQUESTED",
    [PROCESS_EVENT_KIND.TASK_DEAD]: "TASK_DEAD",
    [PROCESS_EVENT_KIND.USER_SIGNAL_HANDLER_DISPATCH]: "USER_SIGNAL_HANDLER_DISPATCH",
    [PROCESS_EVENT_KIND.WAIT_REAP_COMMITTED]: "WAIT_REAP_COMMITTED",
    [PROCESS_EVENT_KIND.RUN_END]: "RUN_END",
    [PROCESS_EVENT_KIND.CLONE_COMMITTED]: "CLONE_COMMITTED",
    [PROCESS_EVENT_KIND.TASK_RELEASE_COMMITTED]: "TASK_RELEASE_COMMITTED",
    [PROCESS_EVENT_KIND.PARENT_POST_WAIT_SYSCALL]: "PARENT_POST_WAIT_SYSCALL",
    [PROCESS_EVENT_KIND.CONTEXT_SUSPEND]: "CONTEXT_SUSPEND",
    [PROCESS_EVENT_KIND.CONTEXT_RESUME]: "CONTEXT_RESUME",
};
function assertUint32(name, value) {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
        throw new Error(`invalid process event ${name}: ${value}`);
    }
}
function assertProcessPid(name, value) {
    assertUint32(name, value);
    if (value === 0) {
        throw new Error(`invalid process event ${name}: zero is not a process pid`);
    }
}
function hex64(value) {
    return BigInt.asUintN(64, value).toString(16).padStart(16, "0");
}
export function formatRunId(hi, lo) {
    return `${hex64(hi)}${hex64(lo)}`;
}
export function decodeLinuxWaitStatus(rawStatus) {
    if (rawStatus < 0n || rawStatus > 0xffffn) {
        throw new Error(`invalid Linux wait status: ${rawStatus}`);
    }
    const status = Number(rawStatus);
    const signal = status & 0x7f;
    if (signal === 0) {
        return { kind: "exited", exitCode: (status >> 8) & 0xff };
    }
    return {
        kind: "signaled",
        signal,
        coreDumped: (status & 0x80) !== 0,
    };
}
export function decodeKernelProcessEvent(raw) {
    const name = EVENT_NAMES[raw.event_kind];
    if (!name) {
        throw new Error(`unknown kernel process event kind: ${raw.event_kind}`);
    }
    if (raw.event_seq <= 0n) {
        throw new Error(`invalid process event sequence: ${raw.event_seq}`);
    }
    assertUint32("pid", raw.pid);
    assertUint32("tgid", raw.tgid);
    assertUint32("ppid", raw.ppid);
    assertUint32("worker_id", raw.worker_id);
    if (raw.event_kind !== PROCESS_EVENT_KIND.RUN_START &&
        raw.event_kind !== PROCESS_EVENT_KIND.RUN_END) {
        assertProcessPid("pid", raw.pid);
    }
    const event = {
        ...raw,
        kind: raw.event_kind,
        name,
        runId: formatRunId(raw.run_id_hi, raw.run_id_lo),
        sequence: raw.event_seq,
    };
    if (raw.event_kind === PROCESS_EVENT_KIND.WAIT_REAP_COMMITTED) {
        event.terminalStatus = decodeLinuxWaitStatus(raw.data0);
    }
    if (raw.event_kind === PROCESS_EVENT_KIND.CONTEXT_SUSPEND ||
        raw.event_kind === PROCESS_EVENT_KIND.CONTEXT_RESUME) {
        event.contextProof = { sp: raw.data0, cookie: raw.data1 };
    }
    return event;
}
export function makeRawProcessEventMessage(raw) {
    return { type: "process_event", ...raw };
}
