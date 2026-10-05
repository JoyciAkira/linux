#!/usr/bin/env node
// Isolated malformed transport replies, never Linux syscall/task evidence.
// The witness queues each case before the real, synchronous BrokerClient.invoke.
// This worker runs independently while that client waits on the shared buffer.
import { parentPort, workerData } from 'node:worker_threads';
import { N_SLOTS, OFF, S, STATE, idx } from './dist/kwa-broker.js';

if (!(workerData.sab instanceof SharedArrayBuffer)) throw new Error('Missing broker SAB');
const words = new Int32Array(workerData.sab);
const load = (slot, field) => Atomics.load(words, idx(slot, field));
const store = (slot, field, value) => Atomics.store(words, idx(slot, field), value);

function claimRequest() {
  const deadline = performance.now() + 5000;
  while (performance.now() < deadline) {
    for (let slot = 0; slot < N_SLOTS; slot++) {
      if (Atomics.compareExchange(words, idx(slot, S.STATE), STATE.REQUESTED, STATE.CLAIMED) === STATE.REQUESTED) {
        return slot;
      }
    }
    const doorbell = Atomics.load(words, OFF.DOORBELL);
    Atomics.wait(words, OFF.DOORBELL, doorbell, 10);
  }
  throw new Error('Timed out waiting for a real BrokerClient request');
}

function publish(slot, response) {
  for (const [field, value] of Object.entries(response)) store(slot, S[field], value);
  store(slot, S.STATE, STATE.COMPLETED); // payload first, completion last
  Atomics.notify(words, idx(slot, S.STATE));
}

parentPort.on('message', ({ name, index }) => {
  const slot = claimRequest(); // the client may reuse the same slot each time
  const reqId = load(slot, S.REQ_ID);
  const workerId = load(slot, S.WORKER_ID);
  const generation = load(slot, S.GENERATION);
  const response = {
    RESP_ID: reqId, WORKER_ID: workerId, RESULT: 1000 + index, ERRNO: 0,
    KERNEL_PID: 1, KERNEL_TGID: 1, KERNEL_GENERATION: index + 1,
    RESP_GENERATION: generation,
  };
  const corrupt = { ...response };
  switch (name) {
    case 'valid-baseline': break;
    case 'wrong-response-id': corrupt.RESP_ID = reqId + 100; break;
    case 'previous-response-id': corrupt.RESP_ID = reqId - 1; break;
    case 'stale-slot-generation': corrupt.RESP_GENERATION = generation - 1; break;
    case 'foreign-worker': corrupt.WORKER_ID = workerId + 1; break;
    // Replay the generation accepted by the second (validly completed) request.
    case 'replayed-kernel-generation': corrupt.KERNEL_GENERATION = 2; break;
    default: throw new Error(`Unknown fault case: ${name}`);
  }
  const staleId = corrupt.RESP_ID !== reqId;
  const before = Atomics.load(words, OFF.ABA_REJECT_COUNT);
  if (staleId) corrupt.RESULT = -12345; // accepting stale data cannot look valid
  publish(slot, corrupt);

  let rejectionObserved = null;
  if (staleId) {
    // RESP_ID mismatch means KEEP WAITING, not return ENOSYS. Observe the real
    // guard, then deliver the current response. Never write a client counter.
    const deadline = performance.now() + 2000;
    while (Atomics.load(words, OFF.ABA_REJECT_COUNT) === before &&
           load(slot, S.OWNER) === workerId && performance.now() < deadline) {
      Atomics.wait(words, idx(slot, S.STATE), STATE.COMPLETED, 1);
    }
    rejectionObserved = Atomics.load(words, OFF.ABA_REJECT_COUNT) > before;
    if (load(slot, S.OWNER) === workerId && load(slot, S.REQ_ID) === reqId) {
      publish(slot, response);
    }
  }
  parentPort.postMessage({ name, index, slot, reqId, generation, corrupt, rejectionObserved });
});
parentPort.postMessage({ ready: true });
