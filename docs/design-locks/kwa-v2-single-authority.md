# KWA v2 — Single Kernel Authority Design Freeze

**Status:** FROZEN (K0). No implementation code in this milestone; contracts only.
**Branch:** `fix/kwa-single-authority-v2` forked from `integration/zeronode-kwa-reconciliation-v1` @ `3b8595d13066126446b9ee3d07283c564abbf199`.
**NOT forked from** forensic head `e87af234…` (reference only, see PR #3).
**Date:** 2026-10-02.

This document freezes the architecture that K1–K6 must satisfy. Each contract is a hard gate: a later gate may not pass by reusing simulated semantics from an earlier one. Promotion requires real Linux kernel evidence unless explicitly stated otherwise.

## Forensic reference vs clean baseline

```
FORENSIC (reference only, DO NOT MERGE)
  e87af234dc2b1f335001227274b088984c998a36   recovery/kwa-forensic-20261001
  = RECOVERY-0 captured tree: dcc129af + 9 tracked mods + kwa-broker.ts
  Known-invalid behavior retained intentionally. Not a baseline.

CLEAN BASELINE
  3b8595d13066126446b9ee3d07283c564abbf199   integration/zeronode-kwa-reconciliation-v1
  ↓
  fix/kwa-single-authority-v2   (this work)
```

We introduce changes against the clean baseline so the diff is exactly what KWA v2 adds.

## The four defects being closed

| ID | Defect (observed in forensic tree) | Closed by contract |
|----|------------------------------------|--------------------|
| KWA-V2-A | Broker truncates 6th syscall arg (`a5` hardcoded 0) | §3 |
| KWA-V2-B | Broker opcode conflated with Linux syscall number | §2 |
| KWA-V2-C | No real task binding; synthetic PIDs accepted | §4, §5, §6 |
| KWA-V2-D | Secondary workers instantiate `vmlinux` (`new WebAssembly.Instance`) | §1 |

## Contracts

### 1. SINGLE KERNEL INSTANCE
Exactly one `WebAssembly.Instance` of `vmlinux` exists across the whole runtime. It is owned by the kernel authority worker. CPU/CLONE workers MUST NOT instantiate the kernel module — not even a stub instance whose exports are later replaced. Structural enforcement (module never delivered to secondary workers, or delivery provably absent), not a counter that a test increments.
- Gate K1 verifies: `KERNEL_INSTANCE_COUNT == 1`, `SECONDARY_KERNEL_INSTANCE == 0` measured by construction, not by self-report.

### 2. BROKER OPCODE ≠ LINUX SYSCALL NUMBER
The broker transport carries an explicit `BrokerOpcode` domain distinct from Linux `__NR_*`:
```
BrokerOpcode.SYSCALL      // payload carries a Linux syscall number + args
BrokerOpcode.TASK_EXIT
BrokerOpcode.INTERRUPT
... (extend as needed)
```
Only when `opcode == SYSCALL` is a Linux syscall number read from the slot. The raw Linux NR is never used as a broker dispatch key. This prevents the forensic confusion where export identities and syscall numbers shared a namespace.
- Gate K0/G1 verifies: encoding round-trip; a non-SYSCALL opcode never reaches the kernel syscall table.

### 3. SIX-ARG SYSCALL ABI
The broker transports the full Linux syscall ABI:
```
nr, a0, a1, a2, a3, a4, a5   →   result, errno
```
Seven inputs (nr + six args), two outputs (result + errno) carried distinctly. No argument is hardcoded, dropped, or defaulted to zero on the authority path. `mmap`/`pselect6`/`futex_waitv`-class six-arg syscalls must round-trip all six args byte-exact.
- Gate K1 verifies: a six-arg syscall witness where `a5` is non-zero and observed unchanged at the kernel entry.

### 4. REAL TASK / TID BINDING
Every broker request is bound to a real Linux task identity established by the kernel, not supplied by the caller:
```
runId, generation, workerId, pid, tid, taskIdentity, requestId
```
The authority resolves the calling task from kernel state (`current_pt_regs()` / current task) and stamps the binding. A worker cannot assert an arbitrary pid/tid and have it honored.
- Gate K2 verifies: requests carry kernel-stamped identity; caller-supplied identity fields are ignored or rejected.

### 5. REQUEST ↔ RESPONSE IDENTITY
Each request has a unique `requestId`; the response carries the same `requestId`. A consumer accepts a response only if `STATE == COMPLETED && RESP_ID == reqId`. A completed slot with a foreign `RESP_ID` is a stale-generation artifact (ABA) and MUST be rejected, not consumed.
- Gate K1/K2 verifies: `WRONG_TASK_RESPONSE_COUNT == 0`, `UNATTRIBUTED_RESPONSE == 0` under concurrent contention.

### 6. GENERATION / STALE REQUEST REJECTION
Slots are generational. A response belonging to a prior generation on the same slot is detected via `RESP_ID`/generation mismatch and rejected (`ABA_REJECT_COUNT` increments, consumer keeps waiting for the current generation). A freed slot cannot be dispatched to after free (`POST_FREE_DISPATCH_COUNT == 0`).
- Gate K2/K6 verifies: stale and post-free dispatches are counted and remain zero under stress.

### 7. CHILD LIFECYCLE OWNERSHIP
Child creation, execution, exit and reap are owned by the real Linux process machinery (`kernel_clone` → `do_exit` → `do_task_dead` → `release_task`), observed through kernel process events — not through JS bookkeeping flags like `childExited`. The parent's `wait4` reaps a real `task_struct`.
- Gate K5 (`REAL_CHILD_LIFECYCLE_V1`) verifies the full chain with kernel evidence only.

### 8. EXIT / WAIT4 / REAP AUTHORITY
`exit`, `wait4` and reap authority rest with the kernel. The host/worker layer observes outcomes; it does not synthesize them. A child exit code flows through the real signal/exit path to the reaping parent. No synthetic `childPid`/`childExitCode` variables stand in for kernel state.
- Gate K5 verifies: parent survives child exit, `wait4` returns the real child pid and status, `release_task` observed.

### 9. FAILURE CONTAINMENT
A fault in one worker, one syscall, or one guest module cannot corrupt the kernel authority or other workers. Traps propagate to the kernel task cleanup path (`task_entry_inner` → `do_exit`), not caught at the worker boundary in a way that leaves scheduler state inconsistent. Repeated failures do not leak slots, descriptors, or instances.
- Gate K6 verifies: repeated fault injection leaves counters clean and the authority alive.

### 10. EVIDENCE CONTRACT FOR K1–K6
Every gate K1–K6 emits a machine-readable receipt with the invariant set below. A gate passes only when the receipt is produced by a real run (not a fixture) and every required invariant holds. Simulated semantics in any form invalidate the receipt for that gate.
Required invariants (all must hold where applicable):
```
KERNEL_INSTANCE_COUNT        = 1
SECONDARY_KERNEL_INSTANCE    = 0
WRONG_TASK_RESPONSE_COUNT    = 0
STALE_TASK_REQUEST_COUNT     = 0
POST_FREE_DISPATCH_COUNT     = 0
UNATTRIBUTED_RESPONSE_COUNT  = 0
ABA_REJECT_COUNT             = 0   (or accounted rejections, never silent accepts)
BROKER_ERRORS                = 0
SIX_ARG_ROUNDTRIP_EXACT      = true   (K1+)
REAL_TASK_BINDING            = true   (K2+)
REAL_SYSCALL_WITNESS         = true   (K4+)
REAL_CHILD_LIFECYCLE         = true   (K5+)
REPEATABLE                   = true   (K6)
```
Receipt also records: sourceRepository, sourceCommit, sourceTreeStatus, buildToolchain, buildCommand, environmentIdentity, artifact size + sha256 (see B1).

## Gate ladder (no skipping, no simulated carry-over)

```
K0  DESIGN FREEZE              (this document)            ← here
K1  SIX-ARG SYSCALL BROKER     single instance + 6-arg ABI + opcode separation
K2  REAL TASK BINDING          kernel-stamped identity + request/response + generation
K3  SINGLE KERNEL AUTHORITY    structural proof, secondary instantiation impossible
K4  REAL BROKERED SYSCALL WITNESS  actual Linux syscall path, no simulated getpid/write
K5  REAL CHILD LIFECYCLE       create→exec→exit→wait4→reap, kernel evidence, parent survives
K6  REPEATABILITY + FAILURE CONTAINMENT  stress + fault injection, counters stay clean
B1  REPRODUCIBLE BUILD + PROVENANCE  automatic source/build/artifact record
Z1  ZERONODE INTEGRATION       consumes exact verified artifact via runtime-artifacts.lock.json
P3  PACKAGE CLI LIFECYCLE      on proven substrate; verifies install/spawn/stdio/exit/wait/repeat only
```

A later gate MUST NOT pass using simulated semantics that an earlier gate was supposed to retire. Specifically: K4 retires JS-simulated `getpid`/`write`/`exit`/`wait4`; K5 retires JS `childExited` bookkeeping. If a gate cannot produce real kernel evidence, it fails — it does not fall back to the forensic apparatus.

## What K0 deliberately does NOT do
- Write implementation code.
- Modify the forensic branch or PR #3.
- Touch ZeroNode or Blink.
- Run P3, build the kernel, or execute any guest binary.

K0 output is this frozen contract plus the branch tip. K1 begins implementation against §1–§3 with the K1 gate receipt as the first promotion criterion.