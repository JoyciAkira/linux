# ZN-VEP-V1 Process Event Authority — worker forwarding + typed schema

Date: 2026-09-16
Branch: `integration/verifiable-process-authority-v1`
Base: `6af97135c5f81902e020ce63b5cdb9a77bc14ed2`

## Objective

Make the existing arch/wasm process-event seam observable from the host `Machine` regardless of which wasm worker emitted the kernel event, without changing B13 process semantics or claiming a new process-control capability.

## Findings

The kernel already defines process event schema v1:

- `RUN_START = 1`
- `WASM_EXEC_COMMITTED = 2`
- `CLONE_WORKER_REQUESTED = 3`
- `TASK_DEAD = 4`
- `USER_SIGNAL_HANDLER_DISPATCH = 5`
- `WAIT_REAP_COMMITTED = 6` — reserved, not emitted yet
- `RUN_END = 7`

The host `Machine` already accepted a raw `processEventHandler`, but worker-side `kernel_imports()` had no handler, so process events originating inside kernel workers were silently dropped.

## Changes

- Added `tools/wasm/src/process-events.ts` as the typed schema/decoder authority.
- `kernel_imports()` now forwards raw process events from worker contexts through `postMessage` when no local handler exists.
- `Machine` accepts worker-forwarded events, decodes them, and emits a typed `process_event` event.
- The legacy raw `processEventHandler` callback remains supported for compatibility and receives the same event after typed decoding succeeds.
- Linux wait-status decoding is implemented for future `WAIT_REAP_COMMITTED` events and distinguishes normal exit from signal/core termination.
- Unknown event kinds, invalid sequences, invalid process PIDs, and invalid wait statuses fail closed in the typed decoder.
- Added `tools/wasm/process-events-selftest.mjs`; after `make -C tools/wasm`, it validates exit 0, nonzero exit, signaled/core status, clone decoding, future reap decoding, unknown-kind rejection, zero-PID rejection, and wait-status bounds.

## Honest boundary

```text
PROCESS_EVENT_SCHEMA_TYPED = TRUE
WORKER_PROCESS_EVENT_FORWARDING_IMPLEMENTED = TRUE
MACHINE_PROCESS_EVENT_STREAM_IMPLEMENTED = TRUE
WAIT_STATUS_DECODER_IMPLEMENTED = TRUE
WAIT_REAP_COMMITTED_KERNEL_EMISSION = FALSE
HOST_SPAWN_WAIT_SIGNAL_CONTROL = FALSE
REAL_GUEST_PROCESS_AUTHORITY_PROVEN_TO_PRODUCT_LAYER = FALSE
B13_STATUS = FROZEN_PROVEN
KERNEL_PROCESS_SEMANTICS_CHANGED = FALSE
MERGE = NO
```

This commit improves observability only. It does not alter clone/fork/exit/reap semantics and does not claim that the product layer can yet control live guest processes.
