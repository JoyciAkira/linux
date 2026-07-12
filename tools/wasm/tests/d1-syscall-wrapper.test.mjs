import { test } from "node:test";
import assert from "node:assert/strict";
import { D1RingBuffer } from "../dist/d1-ring-buffer.js";
import { wrapSyscall } from "../dist/d1-syscall-wrapper.js";

function makeKernel() {
  const calls = [];
  const fn = (nr, a0, a1, a2, a3, a4, a5) => {
    calls.push([nr, a0, a1, a2, a3, a4, a5]);
    return nr === 999 ? -22 : 0x1234;
  };
  return { fn, calls };
}

test("disabled: wrapper returns the original function (pure passthrough)", () => {
  const buf = new D1RingBuffer(10);
  const { fn, calls } = makeKernel();
  const wrapped = wrapSyscall(fn, { buffer: buf, runId: "r", enabled: false, processId: "p" });
  assert.equal(wrapped, fn);
  const ret = wrapped(232, 1, 2, 3, 4, 5, 6);
  assert.equal(ret, 0x1234);
  assert.equal(calls.length, 1);
  assert.equal(buf.getMetadata().totalRecordCount, 0);
});

test("enabled: kernel called exactly once with unchanged number and six args", () => {
  const buf = new D1RingBuffer(10);
  const { fn, calls } = makeKernel();
  const wrapped = wrapSyscall(fn, { buffer: buf, runId: "r", enabled: true, processId: "p" });
  const ret = wrapped(232, -1, 0, 4096, 0xdead, 7, 9);
  assert.equal(calls.length, 1, "forward count must be exactly 1");
  assert.deepEqual(calls[0], [232, -1, 0, 4096, 0xdead, 7, 9]);
  assert.equal(ret, 0x1234, "return value must be unchanged");
});

test("enabled: records enter + return, raw values preserved", () => {
  const buf = new D1RingBuffer(10);
  const { fn } = makeKernel();
  const wrapped = wrapSyscall(fn, { buffer: buf, runId: "r", enabled: true, processId: "p" });
  wrapped(999, 1, 2, 3, 4, 5, 6); // returns -22
  const recs = buf.getRecords();
  assert.equal(recs.length, 2);
  assert.equal(recs[0].eventType, "syscall_enter");
  assert.equal(recs[0].rawSyscallNumber, 999);
  assert.deepEqual(recs[0].rawArguments, [1, 2, 3, 4, 5, 6]);
  assert.equal(recs[1].eventType, "syscall_return");
  assert.equal(recs[1].rawReturnValue, -22);
  assert.equal(recs[1].errnoNumber, 22);
});

test("enabled: throw is rethrown unchanged and recorded as syscall_throw", () => {
  const buf = new D1RingBuffer(10);
  const err = new Error("boom");
  err.name = "RuntimeError";
  let callCount = 0;
  const fn = () => { callCount++; throw err; };
  const wrapped = wrapSyscall(fn, { buffer: buf, runId: "r", enabled: true, processId: "p" });
  assert.throws(() => wrapped(232, 0, 0, 0, 0, 0, 0), (e) => e === err);
  assert.equal(callCount, 1, "kernel called exactly once even on throw");
  const recs = buf.getRecords();
  assert.equal(recs[0].eventType, "syscall_enter");
  assert.equal(recs[1].eventType, "syscall_throw");
  assert.equal(recs[1].errorName, "RuntimeError");
  assert.equal(recs[1].errorMessage, "boom");
});

test("enabled: forwarded values are not coerced (negative/large args preserved)", () => {
  const buf = new D1RingBuffer(10);
  const seen = [];
  const fn = (nr, a0) => { seen.push([nr, a0]); return a0; };
  const wrapped = wrapSyscall(fn, { buffer: buf, runId: "r", enabled: true, processId: "p" });
  const ret = wrapped(60, -2147483648, 0, 0, 0, 0, 0);
  assert.deepEqual(seen[0], [60, -2147483648]);
  assert.equal(ret, -2147483648, "no >>>0 / |0 / Number coercion applied");
});
