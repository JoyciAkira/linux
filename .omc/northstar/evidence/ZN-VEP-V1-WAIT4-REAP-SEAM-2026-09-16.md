# ZN-VEP-V1 wait4 reap event seam — 2026-09-16

Branch: `integration/verifiable-process-authority-v1`
Parent: `788aa7ccd06e3fda54703b012b0875919111013c`

## Objective

Promote the already-reserved `ZN_EVENT_WAIT_REAP_COMMITTED` event from decoder-only schema to a real arch/wasm kernel emission point without changing generic Linux wait/reap semantics or reopening B13.

## Chosen seam

`arch/wasm/kernel/syscall.c::wasm_syscall()` is the narrow architecture boundary. It sees `wait4` only after the real Linux syscall handler has returned.

For `wait4`:

- `ret > 0` is the PID whose wait condition Linux actually consumed;
- `arg1` is the userspace status pointer;
- after the syscall returns, Linux has already written the raw wait status to that pointer.

The event is therefore emitted only after a committed Linux wait result, not from shell markers, logs, or inferred child state.

## Fail-closed conditions

No `WAIT_REAP_COMMITTED` event is emitted when:

- `ret <= 0` (error or no WNOHANG result),
- the status pointer is null,
- `get_user(status, stat_addr)` fails.

The product layer must continue to treat those cases as lacking authoritative terminal-status evidence.

## Event payload

- `event_kind = ZN_EVENT_WAIT_REAP_COMMITTED`
- `pid = ret` (reaped child PID returned by Linux)
- `tgid = 0` (not reconstructed after reap)
- `ppid = current->pid` (waiting parent)
- `data0 = raw Linux wait status & 0xffff`
- `data1 = 0` reserved
- `comm = <wait4-reap>` to avoid pretending the already-reaped child's comm is still available

`tools/wasm/src/process-events.ts` from parent commit `788aa7cc...` already decodes `data0` into exited vs signaled/core status.

## Scope boundary

```text
WAIT_REAP_COMMITTED_CODE_PATH_IMPLEMENTED = TRUE
WAIT_REAP_COMMITTED_KERNEL_BUILD_VERIFIED = FALSE
WAIT_REAP_COMMITTED_LIVE_EVENT_PROVEN = FALSE
WAITID_REAP_EVENT_IMPLEMENTED = FALSE
HOST_RUNTIME_EVENT_BRIDGE_CODE_IMPLEMENTED = TRUE
HOST_RUNTIME_ARTIFACT_PINNED = FALSE
REAL_GUEST_PROCESS_AUTHORITY_PROVEN_TO_PRODUCT_LAYER = FALSE
B13_STATUS = FROZEN_PROVEN
B13_REOPENED = FALSE
B14_AUTHORIZED_BY_THIS_CHANGE = FALSE
MERGE = NO
```

The next required gate is a clean kernel + `tools/wasm` build from this branch, followed by a live wait4 probe demonstrating one `WAIT_REAP_COMMITTED` event with matching PID and raw status. Only after that evidence may ZeroNode use this event as authoritative wait status.
