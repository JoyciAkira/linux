#!/usr/bin/env node
/**
 * K4 Node Worker Bootstrap — Production Path (No Test Bypass)
 *
 * Bridges Node.js worker_threads to browser Web Worker semantics so that
 * dist/worker.js (production code) runs unmodified under Node.
 *
 * Node worker_threads CANNOT transfer WebAssembly.Module or WebAssembly.Memory
 * via postMessage. The witness sends userModuleBytes (Uint8Array) instead;
 * this bootstrap compiles it into a real WebAssembly.Module before forwarding
 * to production worker.ts.
 *
 * CRITICAL: Production worker.ts uses `self.onmessage = handler` (direct
 * assignment), NOT addEventListener. This bootstrap captures that assignment
 * and routes messages through deserialization + forwarding.
 */
import { parentPort, workerData } from "node:worker_threads";

if (!parentPort) {
  throw new Error("[K4-BOOTSTRAP] must run as worker_thread, not main thread");
}

// Storage for the production onmessage handler assigned by dist/worker.js
let productionOnMessage = null;
const addEventListenerListeners = [];

globalThis.self = {
  name: workerData?.name ?? "k4-secondary",
  postMessage(msg) {
    parentPort.postMessage(msg);
  },
  set onmessage(handler) {
    productionOnMessage = handler;
  },
  get onmessage() {
    return productionOnMessage;
  },
  addEventListener(type, handler) {
    if (type === "message") {
      addEventListenerListeners.push(handler);
    } else if (type === "error") {
      parentPort.on("error", handler);
    } else if (type === "unhandledrejection") {
      process.on("unhandledRejection", handler);
    }
  },
};

// Capture uncaught errors for diagnostic forwarding
process.on("uncaughtException", (err) => {
  parentPort.postMessage({
    type: "k4_diag",
    stage: "TOP_LEVEL_FATAL",
    detail: {
      errorName: err?.name,
      errorMessage: String(err?.message ?? err),
      errorStack: err?.stack,
      source: "uncaughtException",
    },
  });
});

// Forward a message event to all registered production handlers
function dispatchToProduction(data) {
  const event = { data };
  if (typeof productionOnMessage === "function") {
    productionOnMessage(event);
  }
  for (const listener of addEventListenerListeners) {
    listener(event);
  }
}

// ONE-SHOT intercept: deserialize first message with userModuleBytes,
// then forward corrected InitMessage to production handlers.
let initHandled = false;
parentPort.on("message", async (rawData) => {
  if (!initHandled && rawData && rawData.userModuleBytes) {
    initHandled = true;
    try {
      const userModule = await WebAssembly.compile(rawData.userModuleBytes);

      // Minimal user modules declare non-shared memory; provide matching memory.
      // Production kernel-shaped modules use shared memory, but our K4 test
      // user module imports plain (memory 1) which is non-shared.
      const userMemory = new WebAssembly.Memory({
        initial: rawData.userMemoryInitial ?? 1,
        maximum: rawData.userMemoryMaximum ?? 256,
      });

      const initMessage = {
        fn: rawData.fn,
        arg: rawData.arg,
        memory: userMemory,
        parent_user_module: userModule,
        parent_user_memory: userMemory,
        parent_tls_base: rawData.parent_tls_base ?? 0,
        brokerSab: rawData.brokerSab,
        workerId: rawData.workerId,
        d1TraceEnabled: rawData.d1TraceEnabled,
        d1RunId: rawData.d1RunId,
      };

      dispatchToProduction(initMessage);

      // K4R3: Read exact syscall return values from user module result_buffer.
      // Layout: [result0:i32, result1:i32, result2:i32, call_count:i32] at offset 0.
      // This proves the user module actually received kernel responses.
      const memView = new DataView(userMemory.buffer);
      const results = [
        memView.getInt32(0, true),
        memView.getInt32(4, true),
        memView.getInt32(8, true),
      ];
      const callCount = memView.getInt32(12, true);
      parentPort.postMessage({
        type: "k4_user_results",
        results,
        callCount,
      });
    } catch (err) {
      parentPort.postMessage({
        type: "k4_diag",
        stage: "TOP_LEVEL_FATAL",
        detail: {
          errorName: err?.name,
          errorMessage: String(err?.message ?? err),
          errorStack: err?.stack,
          source: "module_deserialization",
        },
      });
    }
    return;
  }

  // All subsequent messages: forward directly
  dispatchToProduction(rawData);
});

// Import compiled production worker — assigns self.onmessage etc.
await import("./dist/worker.js");