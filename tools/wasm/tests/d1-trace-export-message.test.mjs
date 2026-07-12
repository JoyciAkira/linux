import { test } from "node:test";
import assert from "node:assert/strict";

globalThis.fetch = () => new Promise(() => {});

const { decodeD1TraceExport, Machine } = await import("../dist/index.js");

const validExport = () => ({
  type: "d1_trace_export",
  runId: "run-1",
  records: [
    { sequence: 0, eventType: "trace_initialized", runId: "run-1", monotonic: 1 },
    {
      sequence: 1,
      eventType: "syscall_enter",
      runId: "run-1",
      monotonic: 2,
      rawSyscallNumber: 232,
      decodedSyscallName: "epoll_wait",
      rawArguments: [1, 2, 3, 4, 5, 6],
      argumentCount: 6,
    },
    {
      sequence: 2,
      eventType: "syscall_return",
      runId: "run-1",
      monotonic: 3,
      rawSyscallNumber: 232,
      decodedSyscallName: "epoll_wait",
      rawReturnValue: -22,
      errnoNumber: 22,
      errnoName: "EINVAL",
    },
  ],
  metadata: {
    capacity: 4096,
    storedRecordCount: 3,
    totalRecordCount: 3,
    overwriteCount: 0,
    firstStoredSequence: 0,
    lastStoredSequence: 2,
    wrapped: false,
  },
});

test("valid export is accepted and decoded", () => {
  const d = decodeD1TraceExport(validExport());
  assert.notEqual(d, null);
  assert.equal(d.runId, "run-1");
  assert.equal(d.records.length, 3);
  assert.equal(d.metadata.capacity, 4096);
});

test("reject: missing runId", () => {
  const e = validExport();
  delete e.runId;
  assert.equal(decodeD1TraceExport(e), null);
});

test("reject: records not an array", () => {
  const e = validExport();
  e.records = "nope";
  assert.equal(decodeD1TraceExport(e), null);
});

test("reject: storedRecordCount disagrees with records length", () => {
  const e = validExport();
  e.metadata.storedRecordCount = 99;
  assert.equal(decodeD1TraceExport(e), null);
});

test("reject: non-monotonic sequence", () => {
  const e = validExport();
  e.records[2].sequence = 1;
  assert.equal(decodeD1TraceExport(e), null);
});

test("reject: capacity above 4096", () => {
  const e = validExport();
  e.metadata.capacity = 8192;
  assert.equal(decodeD1TraceExport(e), null);
});

test("reject: storedRecordCount above capacity", () => {
  const e = validExport();
  e.metadata.capacity = 2;
  e.metadata.storedRecordCount = 3;
  assert.equal(decodeD1TraceExport(e), null);
});

test("reject: wrapped flag inconsistent with overwriteCount", () => {
  const e = validExport();
  e.metadata.wrapped = true;
  assert.equal(decodeD1TraceExport(e), null);
});

test("reject: syscall_enter with >6 raw arguments", () => {
  const e = validExport();
  e.records[1].rawArguments = [1, 2, 3, 4, 5, 6, 7];
  assert.equal(decodeD1TraceExport(e), null);
});

test("reject: syscall_enter with non-numeric raw argument", () => {
  const e = validExport();
  e.records[1].rawArguments = [1, 2, "x", 4, 5, 6];
  assert.equal(decodeD1TraceExport(e), null);
});

test("reject: invalid metadata object", () => {
  const e = validExport();
  e.metadata = null;
  assert.equal(decodeD1TraceExport(e), null);
});

test("d1_trace event delivers the decoded trace to subscribers", () => {
  const seen = [];
  const m = new Machine({ devices: [], memoryMib: 1, cpus: 1 });
  m.on("d1_trace", (t) => seen.push(t));
  const decoded = decodeD1TraceExport(validExport());
  Reflect.get(Object.getPrototypeOf(m), "emit").call(m, "d1_trace", decoded);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].records.length, 3);
});
