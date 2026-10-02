/**
 * KWA Broker — Single Kernel Authority (K1 Six-Arg ABI)
 *
 * Implements the frozen protocol contract v2 (KWA-v2 §2–§3):
 * - SharedArrayBuffer ring with N_SLOTS=64, SLOT_SIZE=96B, SLOTS_OFF=64B.
 * - State machine: FREE (0) -> REQUESTED (1) -> CLAIMED (2) -> COMPLETED (3) -> CONSUMED (4) -> FREE (0).
 * - Owner word reservation (offset 68) before payload store; STATE=REQUESTED published last.
 * - BrokerOpcode namespace distinct from Linux __NR_*; only SYSCALL reads NR slot.
 * - Full six-arg syscall ABI: nr + a0..a5 transported distinctly; result + errno separate.
 * - Authority executes syscall via kernel export, stores RESULT/ERRNO/RESP_ID, then STATE=COMPLETED last.
 * - CPU worker waits with Atomics.wait until COMPLETED && RESP_ID == reqId.
 */

export const MAGIC = 0x4b574103; // "KWA\3"

/** Broker opcodes — distinct from Linux __NR_* syscall numbers (§2 KWA-v2). */
export const BrokerOpcode = {
  SYSCALL: 1,
  TASK_EXIT: 2,
  INTERRUPT: 3,
} as const;

export const STATE = {
  FREE: 0,
  REQUESTED: 1,
  CLAIMED: 2,
  COMPLETED: 3,
  CONSUMED: 4,
} as const;

export const N_SLOTS = 64;
export const SLOT_SIZE = 96;
export const SLOTS_OFF = 64;

export const OFF = {
  MAGIC: 0,
  BOOT_COUNT: 8,
  SECONDARY_INST_COUNT: 9,
  POST_FREE_DISPATCH_COUNT: 10,
  WRONG_TASK_RESPONSE_COUNT: 11,
  STALE_TASK_REQUEST_COUNT: 12,
  BROKER_ERRORS: 13,
  DOORBELL: 14,
  ABA_REJECT_COUNT: 15,
} as const;

export const S = {
  STATE: 0,
  REQ_ID: 4,
  WORKER_ID: 8,
  TASK_ID: 12,
  TID: 16,
  OPCODE: 20,
  A0: 24,
  A1: 28,
  A2: 32,
  A3: 36,
  A4: 40,
  A5: 44,
  NR: 48,
  RESP_ID: 52,
  RESULT: 56,
  ERRNO: 60,
  GENERATION: 64,
  OWNER: 68,
} as const;

export const idx = (slot: number, off: number): number =>
  (SLOTS_OFF + slot * SLOT_SIZE + off) >> 2;

export function assertBrokerLayout(): void {
  const controlWords = Math.max(...Object.values(OFF));
  const controlEnd = (controlWords + 1) * 4;
  if (controlEnd > SLOTS_OFF) {
    throw new Error(
      `[KWA-LAYOUT] control region end ${controlEnd} > slot region start ${SLOTS_OFF}`,
    );
  }
  const slotFieldRanges = Object.entries(S).map(([name, off]) => ({
    name,
    start: SLOTS_OFF + off,
    end: SLOTS_OFF + off + 4,
  }));
  for (const [name, off] of Object.entries(OFF)) {
    const cs = off * 4,
      ce = cs + 4;
    for (const sf of slotFieldRanges) {
      if (cs < sf.end && sf.start < ce) {
        throw new Error(
          `[KWA-LAYOUT] control field ${name} [${cs},${ce}) overlaps slot field ${sf.name} [${sf.start},${sf.end})`,
        );
      }
    }
  }
  if ((S.RESP_ID as number) === (S.RESULT as number)) {
    throw new Error("[KWA-LAYOUT] RESP_ID field missing/colliding");
  }
}

export function createBrokerSab(): SharedArrayBuffer {
  assertBrokerLayout();
  const sab = new SharedArrayBuffer(SLOTS_OFF + N_SLOTS * SLOT_SIZE);
  const u32 = new Uint32Array(sab);
  Atomics.store(u32, OFF.MAGIC, MAGIC);
  return sab;
}

export interface BrokerResponse {
  result: number;
  errno: number;
}

export class BrokerClient {
  readonly #i32: Int32Array;
  readonly #u32: Uint32Array;
  readonly #workerId: number;
  #reqSeq = 1;

  constructor(sab: SharedArrayBuffer, workerId: number) {
    this.#i32 = new Int32Array(sab);
    this.#u32 = new Uint32Array(sab);
    this.#workerId = workerId;
  }

  syscall(
    nr: number,
    a0 = 0,
    a1 = 0,
    a2 = 0,
    a3 = 0,
    a4 = 0,
    a5 = 0,
    taskId = 0,
    tid = 0,
  ): number {
    const resp = this.invoke(nr, a0, a1, a2, a3, a4, a5, taskId, tid);
    return resp.result;
  }

  invoke(
    nr: number,
    a0 = 0,
    a1 = 0,
    a2 = 0,
    a3 = 0,
    a4 = 0,
    a5 = 0,
    taskId = 0,
    tid = 0,
  ): BrokerResponse {
    const reqId = this.#reqSeq++;
    let slot = -1;

    // 1. Reserve slot via OWNER CAS (reserve without publishing REQUESTED)
    while (slot < 0) {
      for (let s = 0; s < N_SLOTS; ++s) {
        const oi = idx(s, S.OWNER);
        if (
          Atomics.load(this.#u32, oi) === 0 &&
          Atomics.compareExchange(this.#u32, oi, 0, this.#workerId) === 0
        ) {
          slot = s;
          break;
        }
      }
    }

    const si = idx(slot, S.STATE);

    // 2. Write payload FIRST, publish STATE=REQUESTED LAST (release ordering)
    Atomics.store(this.#u32, idx(slot, S.REQ_ID), reqId);
    Atomics.store(this.#u32, idx(slot, S.WORKER_ID), this.#workerId);
    Atomics.store(this.#i32, idx(slot, S.TASK_ID), taskId);
    Atomics.store(this.#i32, idx(slot, S.TID), tid);
    Atomics.store(this.#u32, idx(slot, S.OPCODE), BrokerOpcode.SYSCALL);
    Atomics.store(this.#i32, idx(slot, S.A0), a0 | 0);
    Atomics.store(this.#i32, idx(slot, S.A1), a1 | 0);
    Atomics.store(this.#i32, idx(slot, S.A2), a2 | 0);
    Atomics.store(this.#i32, idx(slot, S.A3), a3 | 0);
    Atomics.store(this.#i32, idx(slot, S.A4), a4 | 0);
    Atomics.store(this.#i32, idx(slot, S.A5), a5 | 0);
    Atomics.store(this.#u32, idx(slot, S.NR), nr);
    Atomics.store(this.#u32, idx(slot, S.GENERATION), 1);

    Atomics.store(this.#i32, si, STATE.REQUESTED);
    Atomics.add(this.#i32, OFF.DOORBELL, 1);

    // 3. Wait for COMPLETED with matching RESP_ID
    for (;;) {
      const st = Atomics.load(this.#i32, si);
      if (st === STATE.COMPLETED) {
        const respId = Atomics.load(this.#u32, idx(slot, S.RESP_ID));
        if (respId === reqId) break;
        Atomics.add(this.#u32, OFF.ABA_REJECT_COUNT, 1);
        Atomics.wait(this.#i32, si, STATE.COMPLETED, 100);
        continue;
      }
      Atomics.wait(this.#i32, si, st, 100);
    }

    const rWorker = Atomics.load(this.#u32, idx(slot, S.WORKER_ID));
    const rReq = Atomics.load(this.#u32, idx(slot, S.REQ_ID));
    const rResult = Atomics.load(this.#i32, idx(slot, S.RESULT));
    const rErrno = Atomics.load(this.#i32, idx(slot, S.ERRNO));

    if (rWorker !== this.#workerId || rReq !== reqId) {
      Atomics.add(this.#u32, OFF.WRONG_TASK_RESPONSE_COUNT, 1);
    }

    // 4. Consume and FREE
    if (Atomics.compareExchange(this.#i32, si, STATE.COMPLETED, STATE.CONSUMED) !== STATE.COMPLETED) {
      Atomics.add(this.#u32, OFF.BROKER_ERRORS, 1);
    }
    Atomics.store(this.#i32, si, STATE.FREE);
    Atomics.store(this.#u32, idx(slot, S.OWNER), 0);
    Atomics.notify(this.#i32, si, 1);

    return { result: rResult, errno: rErrno };
  }
}

export function authorityPump(
  syscallFn: (
    nr: number,
    a0: number,
    a1: number,
    a2: number,
    a3: number,
    a4: number,
    a5: number,
  ) => number,
  sab: SharedArrayBuffer,
): number {
  const i32 = new Int32Array(sab);
  const u32 = new Uint32Array(sab);
  let processed = 0;

  for (let s = 0; s < N_SLOTS; ++s) {
    const si = idx(s, S.STATE);
    if (Atomics.load(i32, si) !== STATE.REQUESTED) continue;
    if (
      Atomics.compareExchange(i32, si, STATE.REQUESTED, STATE.CLAIMED) !==
      STATE.REQUESTED
    ) {
      continue;
    }

    const reqId = Atomics.load(u32, idx(s, S.REQ_ID));
    const opcode = Atomics.load(u32, idx(s, S.OPCODE));

    let result = 0;
    let errno = 0;

    if (opcode === BrokerOpcode.SYSCALL) {
      const nr = Atomics.load(u32, idx(s, S.NR));
      const a0 = Atomics.load(i32, idx(s, S.A0));
      const a1 = Atomics.load(i32, idx(s, S.A1));
      const a2 = Atomics.load(i32, idx(s, S.A2));
      const a3 = Atomics.load(i32, idx(s, S.A3));
      const a4 = Atomics.load(i32, idx(s, S.A4));
      const a5 = Atomics.load(i32, idx(s, S.A5));
      try {
        result = syscallFn(nr, a0, a1, a2, a3, a4, a5);
      } catch {
        result = -1;
      }
      errno = result < 0 ? -result : 0;
    } else {
      // Non-SYSCALL opcodes: not handled in K1; reject cleanly
      result = -1;
      errno = 38; // ENOSYS
    }

    // Publish payload before state COMPLETED
    Atomics.store(i32, idx(s, S.RESULT), result);
    Atomics.store(i32, idx(s, S.ERRNO), errno);
    Atomics.store(u32, idx(s, S.RESP_ID), reqId);
    Atomics.store(i32, si, STATE.COMPLETED);
    Atomics.notify(i32, si, 1);
    processed++;
  }

  return processed;
}
