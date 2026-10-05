#!/usr/bin/env node
/**
 * K2R Real Task Binding Witness Probe
 *
 * Verifies KWA-v2 §4 contracts against rebuilt vmlinux.wasm:
 * 1. REAL_TASK_BINDING: kernel stamps pid/tid/generation at syscall entry
 * 2. CALLER_PID_TID_NON_AUTHORITATIVE: spoofed claims ignored when kernel truth exists
 * 3. REQUEST_RESPONSE_IDENTITY: respId must match reqId (fail-closed in BrokerClient)
 * 4. GENERATION_ABA_PROTECTION: stale generation rejected (fail-closed in BrokerClient)
 * 5. FOREIGN_TASK_REJECTION: cross-task response rejected (fail-closed in BrokerClient)
 * 6. UNATTRIBUTED_RESPONSE = 0
 *
 * LIMITATION: Standalone probe uses init_task fallback (pid=0) because boot()
 * clears current before worker spawn. This proves kernel stamps real task_struct
 * identity, but NOT binding to a specific calling Linux task. Full current-task
 * binding requires integrated runtime with real task scheduling (deferred to K3+).
 *
 * Generates machine-readable K2R receipt from actual run evidence.
 */
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { once } from "node:events";
import { Worker } from "node:worker_threads";
import {
  BrokerClient,
  authorityPump,
  createBrokerSab,
  OFF,
} from "./dist/kwa-broker.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VMLINUX_PATH = process.argv[2] ?? join(__dirname, "vmlinux.wasm");
const receiptPath = process.argv[3] ?? join(__dirname, "k2-receipt.json");
const sourceCommit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: __dirname, encoding: "utf8" }).trim();
const sourceTreeStatusBeforeRun = execFileSync("git", ["status", "--porcelain"], { cwd: __dirname, encoding: "utf8" }).trim() || "clean";
const hashFile = path => createHash("sha256").update(readFileSync(path)).digest("hex");

// Counters for K2R receipt
const COUNTERS = {
  SPOOF_PID_TID_INJECT_COUNT: 0,
  SPOOF_PID_TID_ACCEPT_COUNT: 0,
  WRONG_RESPONSE_ID_INJECT_COUNT: 0,
  WRONG_RESPONSE_ID_ACCEPT_COUNT: 0,
  STALE_GENERATION_INJECT_COUNT: 0,
  STALE_GENERATION_ACCEPT_COUNT: 0,
  FOREIGN_TASK_INJECT_COUNT: 0,
  FOREIGN_TASK_ACCEPT_COUNT: 0,
  ABA_INJECT_COUNT: 0,
  ABA_REJECT_COUNT: 0,
  ABA_ACCEPT_COUNT: 0,
  UNATTRIBUTED_RESPONSE_COUNT: 0,
  POST_FREE_DISPATCH_COUNT: 0,
  BROKER_ERRORS: 0,
};

function makeImports(memory) {
 return {
 env: { memory },
 boot: {
 get_devicetree: () => {},
 get_initramfs: () => 0,
 },
 kernel: {
 breakpoint: () => {},
 halt_worker: () => {},
 boot_console_write: () => {},
 boot_console_close: () => {},
 return_address: () => 0,
 get_now_nsec: () => BigInt(Math.round(performance.now() * 1_000_000)),
 get_stacktrace: () => {},
 spawn_worker: () => {},
 run_on_main: () => {},
 process_event: () => {},
 yield: () => { throw new Error("K2R standalone witness cannot run the scheduler"); },
 finish_task: () => { throw new Error("K2R standalone witness cannot terminate scheduled tasks"); },
 syscall_complete: () => { throw new Error("K2R standalone witness must use the naked syscall entry"); },
 broker_poll: () => {},
 },
 user: {
 compile: () => -1,
 instantiate: () => {},
 call: () => {},
 switch_entry: () => {},
 call_signal_handler: () => {},
 fork_user: () => {},
 read: () => 0,
 write: (to, from, n) => n,
 write_zeroes: (to, n) => n,
 },
 virtio: {
 set_features: () => {},
 setup: () => {},
 enable_vring: () => {},
 disable_vring: () => {},
 notify: () => {},
 },
 };
}

async function main() {
  console.log("[K2R-WITNESS] Loading vmlinux.wasm...");
  const wasmBytes = await readFile(VMLINUX_PATH);
  const wasmSha256 = createHash("sha256").update(wasmBytes).digest("hex");
  const module = await WebAssembly.compile(wasmBytes);

  // Verify K2 exports
  const exportNames = WebAssembly.Module.exports(module).map((e) => e.name);
  const requiredExports = [
    "syscall",
    "kwa_get_last_pid",
    "kwa_get_last_tgid",
    "kwa_get_last_generation",
  ];
  for (const name of requiredExports) {
    if (!exportNames.includes(name)) {
      console.error(`[K2R-WITNESS] FAIL: missing export "${name}"`);
      process.exit(1);
    }
  }
  console.log("[K2R-WITNESS] All K2 witness exports present.");

  const memory = new WebAssembly.Memory({ initial: 256, maximum: 32768, shared: true });
  const imports = makeImports(memory);
  const instance = await WebAssembly.instantiate(module, imports);

  console.log("[K2R-WITNESS] Booting kernel...");
  try {
    instance.exports.boot();
  } catch (e) {
    console.log(`[K2R-WITNESS] Boot note: ${e?.message || e}`);
  }

  const sab = createBrokerSab();
  const workerId = 42;
  const i32 = new Int32Array(sab);

  // Positive Linux binding and negative transport tests use separate SABs.

  const kernelIdentity = {
    getPid: () => instance.exports.kwa_get_last_pid(),
    getTgid: () => instance.exports.kwa_get_last_tgid(),
    getGeneration: () => instance.exports.kwa_get_last_generation(),
  };

  let pass = true;
  let realTaskBindingProven = false;
  let callerNonAuthoritativeProven = false;

  // === TEST 1: Positive — Real kernel task binding round-trip ===
  console.log("\n[K2R-WITNESS] TEST 1: Real kernel task binding...");
  let positiveResponse;
  {
    const SPOOF_PID = 9999;
    const SPOOF_TID = 8888;
    let processed = 0;
    COUNTERS.SPOOF_PID_TID_INJECT_COUNT++;
    const client = new BrokerClient(sab, workerId);
    positiveResponse = client.invoke(172, 0, 0, 0, 0, 0, 0, SPOOF_PID, SPOOF_TID, () => {
      processed = authorityPump(
        (nr, a0, a1, a2, a3, a4, a5) => instance.exports.syscall(nr, a0, a1, a2, a3, a4, a5),
        sab,
        kernelIdentity,
      );
    });
    realTaskBindingProven = processed === 1 &&
      positiveResponse.kernelPid >= 0 && positiveResponse.kernelGeneration > 0 &&
      positiveResponse.kernelPid === kernelIdentity.getPid() &&
      positiveResponse.kernelTgid === kernelIdentity.getTgid() &&
      positiveResponse.kernelGeneration === kernelIdentity.getGeneration() &&
      positiveResponse.result === positiveResponse.kernelPid && positiveResponse.errno === 0;
    callerNonAuthoritativeProven = positiveResponse.kernelPid !== SPOOF_PID &&
      positiveResponse.kernelTgid !== SPOOF_TID;
    if (!callerNonAuthoritativeProven) COUNTERS.SPOOF_PID_TID_ACCEPT_COUNT++;
    pass = realTaskBindingProven && callerNonAuthoritativeProven;
    console.log(`  ${pass ? "PASS" : "FAIL"}: real BrokerClient getpid and kernel-stamped identity`, positiveResponse);
    for (const name of ["UNATTRIBUTED_RESPONSE_COUNT", "POST_FREE_DISPATCH_COUNT", "BROKER_ERRORS"]) {
      COUNTERS[name] = Atomics.load(i32, OFF[name]);
      if (COUNTERS[name] !== 0) pass = false;
    }
  }

  // Negative controls exercise the real consumer, not a copied check.
  // The isolated fault injector fabricates malformed transport replies only;
  // no reply from this section is evidence of a Linux syscall or task.
  const negativeSab = createBrokerSab();
  const negativeWords = new Int32Array(negativeSab);
  const negativeClient = new BrokerClient(negativeSab, workerId);
  const injector = new Worker(new URL("./k2-response-fault-injector.mjs", import.meta.url),
    { workerData: { sab: negativeSab } });
  const negativeResults = [];
  try {
    const [ready] = await once(injector, "message");
    if (ready.ready !== true) throw new Error("Fault injector did not become ready");
    const cases = [
      { name: "valid-baseline", result: 1000 },
      { name: "wrong-response-id", result: 1001, counter: OFF.ABA_REJECT_COUNT },
      { name: "stale-slot-generation", reject: true, counter: OFF.ABA_REJECT_COUNT },
      { name: "foreign-worker", reject: true, counter: OFF.WRONG_TASK_RESPONSE_COUNT },
      { name: "replayed-kernel-generation", reject: true, counter: OFF.STALE_TASK_REQUEST_COUNT },
      { name: "previous-response-id", result: 1005, counter: OFF.ABA_REJECT_COUNT },
    ];
    for (const [index, testCase] of cases.entries()) {
      const before = testCase.counter === undefined ? null : Atomics.load(negativeWords, testCase.counter);
      const injected = once(injector, "message");
      injector.postMessage({ name: testCase.name, index });
      const response = negativeClient.invoke(172, 0, 0, 0, 0, 0, 0);
      const [injection] = await injected;
      const after = testCase.counter === undefined ? null : Atomics.load(negativeWords, testCase.counter);
      const rejected = response.result === -1 && response.errno === 38 &&
        response.kernelPid === 0 && response.kernelTgid === 0 && response.kernelGeneration === 0;
      const responseExact = testCase.reject ? rejected
        : response.result === testCase.result && response.errno === 0 &&
          response.kernelPid === 1 && response.kernelTgid === 1 && response.kernelGeneration === index + 1;
      const counted = testCase.counter === undefined || after > before;
      const passed = responseExact && counted && injection.name === testCase.name &&
        injection.index === index && injection.rejectionObserved !== false;
      negativeResults.push({ name: testCase.name, response, injection, counterBefore: before, counterAfter: after, passed });
      console.log(`  ${passed ? "PASS" : "FAIL"}: real BrokerClient ${testCase.name}`);
      if (!passed) pass = false;
    }
    COUNTERS.WRONG_RESPONSE_ID_INJECT_COUNT = 1;
    COUNTERS.STALE_GENERATION_INJECT_COUNT = 2;
    COUNTERS.FOREIGN_TASK_INJECT_COUNT = 1;
    COUNTERS.ABA_INJECT_COUNT = 1;
    COUNTERS.WRONG_RESPONSE_ID_ACCEPT_COUNT = negativeResults[1].passed ? 0 : 1;
    COUNTERS.STALE_GENERATION_ACCEPT_COUNT =
      (negativeResults[2].passed ? 0 : 1) + (negativeResults[4].passed ? 0 : 1);
    COUNTERS.FOREIGN_TASK_ACCEPT_COUNT = negativeResults[3].passed ? 0 : 1;
    COUNTERS.ABA_ACCEPT_COUNT = negativeResults[5].passed ? 0 : 1;
    COUNTERS.ABA_REJECT_COUNT = Atomics.load(negativeWords, OFF.ABA_REJECT_COUNT);
  } finally {
    await injector.terminate();
  }

  // === Generate K2R Receipt ===
  console.log("\n[K2R-WITNESS] Generating K2R receipt...");

  const receipt = {
    K2R_STATUS: pass ? "PASS" : "FAIL",
    sourceRepository: "JoyciAkira/linux",
    sourceBranch: "fix/kwa-single-authority-v2",
    sourceCommit,
    sourceTreeStatus: sourceTreeStatusBeforeRun,
    sourceTreeStatusBeforeRun,
    timestamp: new Date().toISOString(),
    verdict: pass ? "PASS" : "FAIL",
    kernelBuild: "Frozen K6R1 artifact; not rebuilt by this harness",
    environmentIdentity: `node-${process.version}-${process.platform}-${process.arch}`,
    artifact: {
      path: "tools/wasm/vmlinux.wasm",
      size: wasmBytes.length,
      sha256: wasmSha256,
    },
    harnessArtifacts: Object.fromEntries([
      "src/kwa-broker.ts", "dist/kwa-broker.js",
      "k2-task-binding-witness.mjs", "k2-response-fault-injector.mjs",
    ].map(path => [path, { sha256: hashFile(join(__dirname, path)) }])),
    positiveResponse,
    K1_REGRESSION_STATUS: "PENDING",
    REAL_TASK_BINDING: realTaskBindingProven,
    CALLER_PID_TID_AUTHORITATIVE: !callerNonAuthoritativeProven,
    INIT_TASK_FALLBACK_LIMITATION: true,
    REQUEST_ID_MATCH: COUNTERS.WRONG_RESPONSE_ID_ACCEPT_COUNT === 0,
    GENERATION_BINDING: COUNTERS.STALE_GENERATION_ACCEPT_COUNT === 0,
    ...COUNTERS,
    negativeControls: {
      classification: "ISOLATED_TRANSPORT_FAULT_INJECTION_NOT_LINUX_EVIDENCE",
      results: negativeResults,
      counters: Object.fromEntries(Object.entries(OFF)
        .filter(([name]) => name.endsWith("COUNT") || name === "BROKER_ERRORS")
        .map(([name, index]) => [name, Atomics.load(negativeWords, index)])),
    },
  };

  writeFileSync(receiptPath, JSON.stringify(receipt, null, 2));
  console.log(`[K2R-WITNESS] Receipt written to ${receiptPath}`);

  if (pass) {
    console.log("\n[K2R-WITNESS] ✅ ALL K2R CHECKS PASSED");
  } else {
    console.error("\n[K2R-WITNESS] ❌ SOME K2R CHECKS FAILED");
  }

  process.exit(pass ? 0 : 1);
}

main().catch((err) => {
  console.error("[K2R-WITNESS] FATAL:", err);
  process.exit(2);
});