import { test } from "node:test";
import assert from "node:assert/strict";
import { D1RingBuffer } from "../dist/d1-ring-buffer.js";

test("capacity is enforced and capped at 4096", () => {
  const rb = new D1RingBuffer(10);
  for (let i = 0; i < 25; i++) rb.recordLifecycle("syscall_enter", "r");
  const md = rb.getMetadata();
  assert.equal(md.capacity, 10);
  assert.equal(md.storedRecordCount, 10);
  assert.equal(md.totalRecordCount, 25);
});

test("capacity request above 4096 is clamped to 4096", () => {
  const rb = new D1RingBuffer(99999);
  assert.equal(rb.getMetadata().capacity, 4096);
});

test("chronological order preserved and sequence monotonic across wrap", () => {
  const rb = new D1RingBuffer(4);
  for (let i = 0; i < 10; i++) rb.recordLifecycle("trace_initialized", "r");
  const recs = rb.getRecords();
  for (let i = 1; i < recs.length; i++) {
    assert.ok(recs[i].sequence > recs[i - 1].sequence, "sequence must increase");
  }
  const md = rb.getMetadata();
  assert.equal(md.wrapped, true);
  assert.equal(md.overwriteCount, 6);
  assert.equal(md.storedRecordCount, 4);
  assert.equal(md.totalRecordCount, 10);
});

test("newest records retained on overwrite", () => {
  const rb = new D1RingBuffer(3);
  for (let i = 0; i < 7; i++) rb.recordLifecycle("trace_initialized", "r");
  const recs = rb.getRecords();
  assert.deepEqual(recs.map((r) => r.sequence), [4, 5, 6]);
  const md = rb.getMetadata();
  assert.equal(md.firstStoredSequence, 4);
  assert.equal(md.lastStoredSequence, 6);
});

test("export metadata correct on non-wrapped buffer", () => {
  const rb = new D1RingBuffer(100);
  rb.recordSyscallEnter(232, [1, 2, 3, 4, 5, 6], "r");
  rb.recordSyscallReturn(232, -22, "r");
  const md = rb.getMetadata();
  assert.equal(md.wrapped, false);
  assert.equal(md.overwriteCount, 0);
  assert.equal(md.storedRecordCount, 2);
  assert.equal(md.firstStoredSequence, 0);
  assert.equal(md.lastStoredSequence, 1);
});

test("syscall_enter preserves raw number and args verbatim", () => {
  const rb = new D1RingBuffer(10);
  rb.recordSyscallEnter(232, [0xdead, -1, 0, 4096, 7, 9], "r");
  const rec = rb.getRecords()[0];
  assert.equal(rec.eventType, "syscall_enter");
  assert.equal(rec.rawSyscallNumber, 232);
  assert.equal(rec.decodedSyscallName, "epoll_wait");
  assert.deepEqual(rec.rawArguments, [0xdead, -1, 0, 4096, 7, 9]);
  assert.equal(rec.argumentCount, 6);
});

test("syscall_return classifies errno for negative returns in errno range", () => {
  const rb = new D1RingBuffer(10);
  rb.recordSyscallReturn(232, -22, "r");
  rb.recordSyscallReturn(9, 0x1000, "r");
  const [errRec, okRec] = rb.getRecords();
  assert.equal(errRec.rawReturnValue, -22);
  assert.equal(errRec.errnoNumber, 22);
  assert.equal(errRec.errnoName, "EINVAL");
  assert.equal(okRec.rawReturnValue, 0x1000);
  assert.equal(okRec.errnoNumber, null);
});

test("large negative return outside errno range is not classified as errno", () => {
  const rb = new D1RingBuffer(10);
  rb.recordSyscallReturn(9, -100000, "r");
  const rec = rb.getRecords()[0];
  assert.equal(rec.rawReturnValue, -100000);
  assert.equal(rec.errnoNumber, null);
});

test("syscall_throw record bounds the error message", () => {
  const rb = new D1RingBuffer(10);
  rb.recordSyscallThrow(232, "RuntimeError", "x".repeat(1000), "r");
  const rec = rb.getRecords()[0];
  assert.equal(rec.eventType, "syscall_throw");
  assert.equal(rec.errorName, "RuntimeError");
  assert.ok(rec.errorMessage.length <= 256);
});
