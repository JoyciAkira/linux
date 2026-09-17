export const PROCESS_EVENT_KIND = {
  RUN_START: 1,
  WASM_EXEC_COMMITTED: 2,
  CLONE_WORKER_REQUESTED: 3,
  TASK_DEAD: 4,
  USER_SIGNAL_HANDLER_DISPATCH: 5,
  WAIT_REAP_COMMITTED: 6,
  RUN_END: 7,
} as const;

export type KernelProcessEventKind =
  (typeof PROCESS_EVENT_KIND)[keyof typeof PROCESS_EVENT_KIND];

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

export type KernelTerminalStatus =
  | { kind: "exited"; exitCode: number }
  | { kind: "signaled"; signal: number; coreDumped: boolean };

export interface KernelProcessEvent extends RawKernelProcessEvent {
  kind: KernelProcessEventKind;
  name: KernelProcessEventName;
  runId: string;
  sequence: bigint;
  terminalStatus?: KernelTerminalStatus;
}

const EVENT_NAMES: Readonly<Record<number, KernelProcessEventName | undefined>> = {
  [PROCESS_EVENT_KIND.RUN_START]: "RUN_START",
  [PROCESS_EVENT_KIND.WASM_EXEC_COMMITTED]: "WASM_EXEC_COMMITTED",
  [PROCESS_EVENT_KIND.CLONE_WORKER_REQUESTED]: "CLONE_WORKER_REQUESTED",
  [PROCESS_EVENT_KIND.TASK_DEAD]: "TASK_DEAD",
  [PROCESS_EVENT_KIND.USER_SIGNAL_HANDLER_DISPATCH]:
    "USER_SIGNAL_HANDLER_DISPATCH",
  [PROCESS_EVENT_KIND.WAIT_REAP_COMMITTED]: "WAIT_REAP_COMMITTED",
  [PROCESS_EVENT_KIND.RUN_END]: "RUN_END",
};

function assertUint32(name: string, value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error(`invalid process event ${name}: ${value}`);
  }
}

function assertProcessPid(name: string, value: number): void {
  assertUint32(name, value);
  if (value === 0) {
    throw new Error(`invalid process event ${name}: zero is not a process pid`);
  }
}

function hex64(value: bigint): string {
  return BigInt.asUintN(64, value).toString(16).padStart(16, "0");
}

export function formatRunId(hi: bigint, lo: bigint): string {
  return `${hex64(hi)}${hex64(lo)}`;
}

export function decodeLinuxWaitStatus(rawStatus: bigint): KernelTerminalStatus {
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

export function decodeKernelProcessEvent(
  raw: RawKernelProcessEvent,
): KernelProcessEvent {
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

  if (
    raw.event_kind !== PROCESS_EVENT_KIND.RUN_START &&
    raw.event_kind !== PROCESS_EVENT_KIND.RUN_END
  ) {
    assertProcessPid("pid", raw.pid);
  }

  const event: KernelProcessEvent = {
    ...raw,
    kind: raw.event_kind as KernelProcessEventKind,
    name,
    runId: formatRunId(raw.run_id_hi, raw.run_id_lo),
    sequence: raw.event_seq,
  };

  if (raw.event_kind === PROCESS_EVENT_KIND.WAIT_REAP_COMMITTED) {
    event.terminalStatus = decodeLinuxWaitStatus(raw.data0);
  }

  return event;
}

export function makeRawProcessEventMessage(
  raw: RawKernelProcessEvent,
): RawProcessEventMessage {
  return { type: "process_event", ...raw };
}
