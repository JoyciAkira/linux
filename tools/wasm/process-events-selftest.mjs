#!/usr/bin/env node
import assert from "node:assert/strict";
import {
  PROCESS_EVENT_KIND,
  decodeKernelProcessEvent,
  decodeLinuxWaitStatus,
  formatRunId,
} from "./dist/process-events.js";

assert.deepEqual(decodeLinuxWaitStatus(0n), {
  kind: "exited",
  exitCode: 0,
});
assert.deepEqual(decodeLinuxWaitStatus(7n << 8n), {
  kind: "exited",
  exitCode: 7,
});
assert.deepEqual(decodeLinuxWaitStatus(11n), {
  kind: "signaled",
  signal: 11,
  coreDumped: false,
});
assert.deepEqual(decodeLinuxWaitStatus(11n | 0x80n), {
  kind: "signaled",
  signal: 11,
  coreDumped: true,
});

const base = {
  run_id_hi: 1n,
  run_id_lo: 2n,
  event_seq: 3n,
  pid: 42,
  tgid: 42,
  ppid: 1,
  worker_id: 0,
  data0: 0n,
  data1: 0n,
  comm: "probe",
};

const clone = decodeKernelProcessEvent({
  ...base,
  event_kind: PROCESS_EVENT_KIND.CLONE_WORKER_REQUESTED,
  data0: 17n,
});
assert.equal(clone.name, "CLONE_WORKER_REQUESTED");
assert.equal(clone.pid, 42);
assert.equal(clone.runId, formatRunId(1n, 2n));
assert.equal(clone.terminalStatus, undefined);

const reap = decodeKernelProcessEvent({
  ...base,
  event_kind: PROCESS_EVENT_KIND.WAIT_REAP_COMMITTED,
  data0: 9n << 8n,
});
assert.deepEqual(reap.terminalStatus, { kind: "exited", exitCode: 9 });

assert.throws(
  () => decodeKernelProcessEvent({ ...base, event_kind: 999 }),
  /unknown kernel process event kind/,
);
assert.throws(
  () =>
    decodeKernelProcessEvent({
      ...base,
      event_kind: PROCESS_EVENT_KIND.TASK_DEAD,
      pid: 0,
    }),
  /zero is not a process pid/,
);
assert.throws(() => decodeLinuxWaitStatus(0x1_0000n), /invalid Linux wait status/);

console.log(
  JSON.stringify({
    verdict: "PROCESS_EVENT_DECODER_SELFTEST_PASS",
    assertions: 10,
    waitReapEmissionImplemented: false,
  }),
);
