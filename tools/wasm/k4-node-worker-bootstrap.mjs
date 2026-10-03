#!/usr/bin/env node
/**
 * K4 Node Worker Bootstrap
 * Thin adapter: bridges Node.js worker_threads to browser Web Worker semantics
 * so that dist/worker.js (production code) runs unmodified under Node.
 *
 * Provides:
 *   globalThis.self       → worker_threads parentPort bridge
 *   postMessage(msg)      → parentPort.postMessage(msg)
 *   addEventListener()    → parentPort.on("message") / .on("error")
 *   MessageEvent          → { data } wrapper
 *
 * This file is TEST-ONLY infrastructure. It must NOT be imported by production
 * browser code. Production worker.ts uses native Web Worker APIs only.
 */
import { parentPort, workerData } from "node:worker_threads";

if (!parentPort) {
  throw new Error("[K4-BOOTSTRAP] k4-node-worker-bootstrap.mjs must run as a worker_thread, not main thread");
}

// Bridge parentPort to self.postMessage / self.addEventListener
const listeners = new Map();

globalThis.self = {
  name: workerData?.name ?? "k4-secondary",
  postMessage(msg) {
    parentPort.postMessage(msg);
  },
  addEventListener(type, handler) {
    if (type === "message") {
      const wrapped = (data) => handler({ data });
      listeners.set(handler, wrapped);
      parentPort.on("message", wrapped);
    } else if (type === "error") {
      parentPort.on("error", handler);
    } else if (type === "messageerror") {
      // Node doesn't have messageerror; no-op
    } else if (type === "unhandledrejection") {
      process.on("unhandledRejection", handler);
    }
  },
  removeEventListener(type, handler) {
    if (type === "message") {
      const wrapped = listeners.get(handler);
      if (wrapped) {
        parentPort.off("message", wrapped);
        listeners.delete(handler);
      }
    }
  },
};

// K4 TEST MODE: Intercept InitMessage with k4TestMode=true BEFORE production worker.js
// processes it. This allows exercising BrokerClient.invoke() in the real worker thread
// without requiring a WebAssembly.Module (which would trigger the production guard).
// This is TEST-ONLY infrastructure; production browser path always has parent_user_module.
parentPort.on("message", (data) => {
  if (data && data.k4TestMode === true) {
    parentPort.postMessage({ type: "k4_diag", stage: "INIT_RECEIVED", detail: { workerId: data.workerId, k4TestMode: true } });
    // Dynamically import BrokerClient from compiled dist
    import("./dist/kwa-broker.js").then(async ({ BrokerClient }) => {
      const client = new BrokerClient(data.brokerSab, data.workerId);
      const results = [];
      for (let seq = 1; seq <= (data.k4TestSeq || 3); seq++) {
        try {
          const resp = client.invoke(
            data.k4TestNr,
            0, 0, 0, 0, 0,
            data.k4TestA5 | 0,
            0, 0,
            () => { parentPort.postMessage({ type: "broker_kick" }); },
          );
          results.push({
            type: "k4_result",
            seq,
            result: resp.result,
            errno: resp.errno,
            reqId: seq,
            kernelGeneration: resp.kernelGeneration,
            workerId: data.workerId,
          });
          parentPort.postMessage(results[results.length - 1]);
        } catch (err) {
          parentPort.postMessage({
            type: "k4_diag",
            stage: "TOP_LEVEL_FATAL",
            detail: { seq, error: String(err), stack: err?.stack },
          });
          break;
        }
      }
      parentPort.postMessage({ type: "worker_done", reason: "k4_test_complete" });
    }).catch((err) => {
      parentPort.postMessage({
        type: "k4_diag",
        stage: "TOP_LEVEL_FATAL",
        detail: { error: "BrokerClient import failed", message: String(err) },
      });
    });
    // Do NOT forward to production worker.js — test mode handles its own lifecycle
    return;
  }
});

// Import the compiled production worker — this registers self.onmessage etc.
await import("./dist/worker.js");