import { test } from "node:test";
import assert from "node:assert/strict";

globalThis.fetch = () => new Promise(() => {});

const { decodeD1TraceExport, Machine } = await import("../dist/index.js");

const validPayload = () => ({
  events: [{ seq: 0, nr: 232, name: "epoll_wait" }],
  stats: { total: 1, captured: 1, dropped: 0 },
});

test("valid d1_trace_export message is accepted and decoded correctly", () => {
  const decoded = decodeD1TraceExport(validPayload());
  assert.notEqual(decoded, null);
  assert.equal(decoded.stats.total, 1);
  assert.equal(decoded.stats.captured, 1);
  assert.equal(decoded.stats.dropped, 0);
  assert.equal(decoded.events.length, 1);
});

test("malformed payload is rejected (fail closed) — bad stats", () => {
  assert.equal(decodeD1TraceExport({ events: [], stats: null }), null);
  assert.equal(decodeD1TraceExport({ events: [], stats: {} }), null);
  assert.equal(
    decodeD1TraceExport({ events: [], stats: { total: 1, captured: 1 } }),
    null,
  );
});

test("malformed payload is rejected (fail closed) — bad events", () => {
  assert.equal(
    decodeD1TraceExport({
      events: "not-array",
      stats: { total: 0, captured: 0, dropped: 0 },
    }),
    null,
  );
});

test("d1_trace event delivers the decoded trace to subscribers", () => {
  const seen = [];
  const m = new Machine({ devices: [], memoryMib: 1, cpus: 1 });
  m.on("d1_trace", (t) => seen.push(t));
  const decoded = decodeD1TraceExport(validPayload());
  Reflect.get(Object.getPrototypeOf(m), "emit").call(m, "d1_trace", decoded);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].stats.captured, 1);
});
