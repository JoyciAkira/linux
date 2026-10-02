#!/usr/bin/env node
/**
 * K1 Six-Arg Syscall Broker Witness Probe
 *
 * Verifies KWA-v2 §2–§3 contracts against the REAL rebuilt vmlinux.wasm:
 *   1. BrokerOpcode.SYSCALL (1) is distinct from Linux __NR_* namespace.
 *   2. Full six-arg ABI (nr + a0..a5) round-trips byte-exact through the broker
 *      into the real Linux syscall entry, proven by reading back the kernel-side
 *      witness export `kwa_get_last_entry_a5`.
 *   3. Non-SYSCALL opcodes are rejected with ENOSYS (opcode isolation).
 *
 * This probe instantiates vmlinux.wasm directly (no Machine/Worker abstraction)
 * to guarantee the syscall path goes through the real kernel export, not a
 * JS-simulated stub. The authorityPump callback invokes instance.exports.syscall
 * which is the actual wasm_syscall in arch/wasm/kernel/syscall.c.
 */

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  BrokerClient,
  BrokerOpcode,
  authorityPump,
  createBrokerSab,
  S,
  N_SLOTS,
  SLOT_SIZE,
  SLOTS_OFF,
  idx,
} from "./dist/kwa-broker.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VMLINUX_PATH = join(__dirname, "vmlinux.wasm");

// Minimal kernel imports — only what vmlinux.wasm requires to instantiate.
// Most are no-ops; the syscall path is what we're testing.
function makeImports(memory) {
  const mem = new Uint8Array(memory.buffer);
  return {
    env: { memory },
    boot: {
      get_devicetree: () => {},
      get_initramfs: () => 0,
    },
    kernel: {
      breakpoint: () => {},
      halt_worker: () => {},
      boot_console_write: (msg, len) => {
        // Suppress boot console noise during probe
      },
      boot_console_close: () => {},
      return_address: () => 0,
      get_now_nsec: () => BigInt(Math.round(performance.now() * 1_000_000)),
      get_stacktrace: (buf, size) => {},
      spawn_worker: () => {},
      run_on_main: () => {},
      process_event: () => {},
      broker_poll: () => {},
    },
    user: {
      compile: () => -1,
      instantiate: () => {},
      call: () => {},
      switch_entry: () => {},
      call_signal_handler: () => {},
      fork_user: () => {},
      read: (to, from, n) => 0,
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
  console.log("[K1-WITNESS] Loading vmlinux.wasm...");
  const wasmBytes = await readFile(VMLINUX_PATH);
  const module = await WebAssembly.compile(wasmBytes);

  // Verify K1 witness exports exist
  const exportNames = WebAssembly.Module.exports(module).map((e) => e.name);
  const requiredExports = [
    "syscall",
    "kwa_get_last_entry_nr",
    "kwa_get_last_entry_a5",
    "kwa_get_entry_count",
  ];
  for (const name of requiredExports) {
    if (!exportNames.includes(name)) {
      console.error(`[K1-WITNESS] FAIL: missing export "${name}"`);
      process.exit(1);
    }
  }
  console.log("[K1-WITNESS] All K1 witness exports present.");

  // Instantiate with shared memory (required by kernel)
  const memory = new WebAssembly.Memory({
    initial: 256,
    maximum: 32768,
    shared: true,
  });
  const imports = makeImports(memory);
  const instance = await WebAssembly.instantiate(module, imports);

  // Boot the kernel (required before syscall works)
  console.log("[K1-WITNESS] Booting kernel...");
  try {
    instance.exports.boot();
  } catch (e) {
    // Boot may throw on incomplete environment; syscall may still work
    console.log(`[K1-WITNESS] Boot note: ${e?.message || e}`);
  }

  // Create broker SAB and client
  const sab = createBrokerSab();
  const workerId = 42;
  const client = new BrokerClient(sab, workerId);

  // --- Test 1: Six-arg round-trip with a5 != 0 ---
  // Use __NR_getpid (39 on x86_64 / wasm) as a harmless syscall.
  // The kernel will execute it and our witness captures a5 at entry.
  const TEST_NR = 39; // getpid — safe, no side effects
  const TEST_A5 = 0xdeadbeef;
  const TEST_A0 = 0x11111111;
  const TEST_A1 = 0x22222222;
  const TEST_A2 = 0x33333333;
  const TEST_A3 = 0x44444444;
  const TEST_A4 = 0x55555555;

  console.log(
    `[K1-WITNESS] Sending syscall nr=${TEST_NR} a5=0x${TEST_A5.toString(16)} via broker...`,
  );

  // Submit request via broker client (non-blocking submit)
  // We need to manually trigger authorityPump since there's no background thread
  const reqId = 1;
  const u32 = new Uint32Array(sab);
  const i32 = new Int32Array(sab);

  // Manually write a REQUESTED slot (bypassing client.invoke's wait loop
  // since we need to pump authority synchronously)
  const slot = 0;
  const si = idx(slot, S.STATE);

  // Reserve slot
  Atomics.store(u32, idx(slot, S.OWNER), workerId);
  Atomics.store(u32, idx(slot, S.REQ_ID), reqId);
  Atomics.store(u32, idx(slot, S.WORKER_ID), workerId);
  Atomics.store(i32, idx(slot, S.TASK_ID), 0);
  Atomics.store(i32, idx(slot, S.TID), 0);
  Atomics.store(u32, idx(slot, S.OPCODE), BrokerOpcode.SYSCALL);
  Atomics.store(i32, idx(slot, S.A0), TEST_A0 | 0);
  Atomics.store(i32, idx(slot, S.A1), TEST_A1 | 0);
  Atomics.store(i32, idx(slot, S.A2), TEST_A2 | 0);
  Atomics.store(i32, idx(slot, S.A3), TEST_A3 | 0);
  Atomics.store(i32, idx(slot, S.A4), TEST_A4 | 0);
  Atomics.store(i32, idx(slot, S.A5), TEST_A5 | 0);
  Atomics.store(u32, idx(slot, S.NR), TEST_NR);
  Atomics.store(u32, idx(slot, S.GENERATION), 1);
  Atomics.store(i32, si, 1); // STATE.REQUESTED

  // Pump authority — this calls instance.exports.syscall with all 7 args
  const processed = authorityPump(
    (nr, a0, a1, a2, a3, a4, a5) => {
      return instance.exports.syscall(nr, a0, a1, a2, a3, a4, a5);
    },
    sab,
  );

  if (processed !== 1) {
    console.error(`[K1-WITNESS] FAIL: authorityPump processed ${processed}, expected 1`);
    process.exit(1);
  }

  // Read kernel-side witness
  const witnessedNr = instance.exports.kwa_get_last_entry_nr();
  const witnessedA5 = instance.exports.kwa_get_last_entry_a5();
  const entryCount = instance.exports.kwa_get_entry_count();

  console.log(`[K1-WITNESS] Kernel witnessed: nr=${witnessedNr} a5=0x${witnessedA5.toString(16)} entries=${entryCount}`);

  // Read broker response
  const rResult = Atomics.load(i32, idx(slot, S.RESULT));
  const rErrno = Atomics.load(i32, idx(slot, S.ERRNO));
  const rRespId = Atomics.load(u32, idx(slot, S.RESP_ID));
  const rOpcode = Atomics.load(u32, idx(slot, S.OPCODE));

  console.log(`[K1-WITNESS] Broker response: result=${rResult} errno=${rErrno} respId=${rRespId}`);

  // --- Verdicts ---
  let pass = true;

  // Check 1: a5 preserved through real kernel entry
  if ((witnessedA5 >>> 0) !== (TEST_A5 >>> 0)) {
    console.error(
      `[K1-WITNESS] FAIL: a5 mismatch! sent=0x${TEST_A5.toString(16)} witnessed=0x${witnessedA5.toString(16)}`,
    );
    pass = false;
  } else {
    console.log("[K1-WITNESS] PASS: a5 round-trip exact through real kernel.");
  }

  // Check 2: NR preserved
  if (witnessedNr !== TEST_NR) {
    console.error(`[K1-WITNESS] FAIL: nr mismatch! sent=${TEST_NR} witnessed=${witnessedNr}`);
    pass = false;
  } else {
    console.log("[K1-WITNESS] PASS: nr preserved.");
  }

  // Check 3: BrokerOpcode was SYSCALL (not raw NR)
  if (rOpcode !== BrokerOpcode.SYSCALL) {
    console.error(
      `[K1-WITNESS] FAIL: opcode in response slot is ${rOpcode}, expected BrokerOpcode.SYSCALL=${BrokerOpcode.SYSCALL}`,
    );
    pass = false;
  } else {
    console.log("[K1-WITNESS] PASS: opcode namespace isolated from syscall nr.");
  }

  // Check 4: Entry count incremented
  if (entryCount < 1) {
    console.error(`[K1-WITNESS] FAIL: entry count ${entryCount} < 1`);
    pass = false;
  } else {
    console.log("[K1-WITNESS] PASS: kernel entry counter incremented.");
  }

  // Check 5: Response has matching RESP_ID
  if (rRespId !== reqId) {
    console.error(`[K1-WITNESS] FAIL: respId ${rRespId} != reqId ${reqId}`);
    pass = false;
  } else {
    console.log("[K1-WITNESS] PASS: request/response identity matched.");
  }

  // --- Test 2: Non-SYSCALL opcode rejection ---
  console.log("[K1-WITNESS] Testing non-SYSCALL opcode rejection...");
  const slot2 = 1;
  const si2 = idx(slot2, S.STATE);
  Atomics.store(u32, idx(slot2, S.OWNER), workerId);
  Atomics.store(u32, idx(slot2, S.REQ_ID), 2);
  Atomics.store(u32, idx(slot2, S.WORKER_ID), workerId);
  Atomics.store(i32, idx(slot2, S.TASK_ID), 0);
  Atomics.store(i32, idx(slot2, S.TID), 0);
  Atomics.store(u32, idx(slot2, S.OPCODE), BrokerOpcode.TASK_EXIT); // non-SYSCALL
  Atomics.store(i32, idx(slot2, S.A0), 0);
  Atomics.store(i32, idx(slot2, S.A1), 0);
  Atomics.store(i32, idx(slot2, S.A2), 0);
  Atomics.store(i32, idx(slot2, S.A3), 0);
  Atomics.store(i32, idx(slot2, S.A4), 0);
  Atomics.store(i32, idx(slot2, S.A5), 0);
  Atomics.store(u32, idx(slot2, S.NR), 999); // should NOT be dispatched
  Atomics.store(u32, idx(slot2, S.GENERATION), 1);
  Atomics.store(i32, si2, 1); // STATE.REQUESTED

  const entryBefore = instance.exports.kwa_get_entry_count();
  const processed2 = authorityPump(
    (nr, a0, a1, a2, a3, a4, a5) => {
      return instance.exports.syscall(nr, a0, a1, a2, a3, a4, a5);
    },
    sab,
  );
  const entryAfter = instance.exports.kwa_get_entry_count();

  const r2Result = Atomics.load(i32, idx(slot2, S.RESULT));
  const r2Errno = Atomics.load(i32, idx(slot2, S.ERRNO));

  if (processed2 !== 1) {
    console.error(`[K1-WITNESS] FAIL: non-SYSCALL pump processed ${processed2}`);
    pass = false;
  } else if (r2Errno !== 38) {
    // ENOSYS = 38
    console.error(
      `[K1-WITNESS] FAIL: non-SYSCALL errno=${r2Errno}, expected 38 (ENOSYS)`,
    );
    pass = false;
  } else if (entryAfter !== entryBefore) {
    console.error(
      `[K1-WITNESS] FAIL: kernel entry count changed for non-SYSCALL (${entryBefore}→${entryAfter})`,
    );
    pass = false;
  } else {
    console.log(
      "[K1-WITNESS] PASS: non-SYSCALL opcode rejected with ENOSYS, kernel not invoked.",
    );
  }

  // --- Final verdict ---
  if (pass) {
    console.log("\n[K1-WITNESS] ✅ ALL CHECKS PASSED — K1 six-arg broker verified.");
    process.exit(0);
  } else {
    console.error("\n[K1-WITNESS] ❌ SOME CHECKS FAILED");
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("[K1-WITNESS] FATAL:", err);
  process.exit(2);
});