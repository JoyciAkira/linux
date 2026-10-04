# K5A — Cooperative Single-Authority Scheduler Model
**Status:** IN_PROGRESS — principal authorized kernel-owned context restoration; K5A remains NOT_PROVEN
**Date:** 2026-10-04
**Branch:** `fix/kwa-single-authority-v2`
**Depends on:** `kwa-v2-single-authority.md` (K0–K4 CLOSED)

## Problem Statement
The Linux kernel's wasm port uses `__builtin_wasm_memory_atomic_wait32/64` for:
1. **Context switch** (`__switch_to`, process.c:61) — infinite timeout
2. **Idle loop** (`arch_cpu_idle`, irq.c:47) — timer-bounded
3. **CPU relax** (`cpu_relax`, irq.c:64) — 10ms bounded
4. **Delay** (`__delay`, time.c:28) — cycle-bounded
5. **Fork VAS copy ack** (fork.c:75) — 100ms bounded

On the browser main thread, `Atomics.wait` throws `TypeError`. In a dedicated
worker, it blocks the JS event loop indefinitely, preventing the authority from
servicing broker requests, timer ticks, or wakeup events needed to advance Linux.

JSPI (`WebAssembly.Suspending`/`promising`) preserves call stacks across
suspension but does NOT isolate mutable Wasm globals (`current_task`,
`current_cpu`, `thread_done`). Two concurrent suspended tasks on one instance
corrupt each other's `current` pointer. Proven in `local://k5a-jspi-global-context.log`.

## Authorized Revision: Kernel-Owned Context Restoration
The principal selected this revision after the executed single-pending-stack diagnostic proved the peer handoff deadlock.
- Exactly one kernel context executes; multiple Wasm stacks may remain parked.
- Linux selects each next task. C saves/restores the task's stack pointer and execution globals before resumption.
- JS retains opaque continuation handles and delivers wakeups; it does not author PIDs, task state or scheduler decisions.

The revision must preserve these original hard constraints:
- Preserves K0 §1 (single instance, no secondary instantiation)
- Preserves K0 §4 (kernel-stamped task identity, never JS-authored)
- Satisfies the invariant: "kernel says TASK N suspended / kernel scheduler chooses/resumes TASK N"
- Keeps all task state authoritative inside Wasm memory/globals
- Was expected to require one new host import; six blocking sites were found, and peer-resume ownership remains unresolved.

## Architecture

### New Host Import: `wasm_kernel_yield`
```c
// arch/wasm/include/asm/wasm_imports.h
void wasm_import(kernel, yield)(u32 reason, u64 deadline_ns);
```
**Semantics:**
- `reason`: YIELD_REASON_SWITCH | YIELD_REASON_IDLE | YIELD_REASON_DELAY | YIELD_REASON_FORK_ACK | YIELD_REASON_RELAX
- `deadline_ns`: 0 = indefinite (until external wake), >0 = absolute deadline
- Suspends through JSPI and returns control to the host event loop.
- C owns the saved execution globals and restores them at the resume boundary.
- The Wasm call stack remains parked at the call site.
- Resumption continues after the import in the kernel-selected task's original frame.

### Blocking Wait Site Replacements
| File | Line | Old | New |
|------|------|-----|-----|
| process.c | 61 | `atomic_wait32(&from_info->running_cpu, -1, ∞)` | `wasm_kernel_yield(YIELD_SWITCH, 0)` + post-resume atomic read |
| irq.c | 47 | `atomic_wait64(&pending, 0, timeout)` | `wasm_kernel_yield(YIELD_IDLE, deadline)` + post-resume check |
| irq.c | 64 | `atomic_wait64(&pending, 0, 10ms)` | `wasm_kernel_yield(YIELD_RELAX, now+10ms)` |
| time.c | 28 | `atomic_wait32(&zero, 0, cycles)` | `wasm_kernel_yield(YIELD_DELAY, now+cycles)` |
| fork.c | 75 | `atomic_wait32(&g_ufr_copy_pid, 0, 100ms)` | `wasm_kernel_yield(YIELD_FORK_ACK, now+100ms)` |

### Authority Worker Event Loop (Host Side)
```
┌─────────────────────────────────────────────┐
│         AUTHORITY WORKER EVENT LOOP          │
│                                              │
│ 1. Enter Wasm via boot() or resume()         │
│ 2. Kernel executes until wasm_kernel_yield() │
│ 3. Yield returns control to this loop        │
│ 4. Process pending events:                   │
│    - broker SAB requests → inject via IRQ    │
│    - timer deadlines → fire TIMER_IRQ        │
│    - fork ack signals → set g_ufr_copy_pid   │
│    - IPI messages → trigger_irq_for_cpu()    │
│ 5. If wake condition met → resume Wasm       │
│ 6. Else → setTimeout/poll and goto 4         │
└─────────────────────────────────────────────┘
```

### Task Identity Preservation
The critical invariant:
> "kernel says TASK 17 suspended / kernel scheduler chooses/resumes TASK 17"

These are intended properties, not established acceptance evidence:
1. `current_task` Wasm global is set ONLY by kernel code (`set_current_task()`)
2. `__switch_to` sets `from_info->running_cpu = -1` BEFORE yielding
3. On resume, `__switch_to` reads `from_info->running_cpu` (set by waker) and
   restores `current_task` from `get_current_task_on(cpu)` — all kernel-side
4. JS never reads or writes `current_task`; it only delivers external events

## K5A Acceptance Criteria Mapping
| Criterion | How This Design Satisfies It |
|-----------|------------------------------|
| KERNEL_INSTANCE_COUNT=1 | One Instance in authority worker |
| SECONDARY_KERNEL_INSTANCE_COUNT=0 | Secondary workers use broker-only path |
| PARENT_PID > 0 | Must execute a real parent task; `init_task` itself has pid=0 |
| CURRENT_TASK_BINDING_PROVEN | `getpid` syscall returns kernel-stamped `current->pid` |
| TASK_SUSPEND_OBSERVED | `wasm_kernel_yield(YIELD_SWITCH)` emitted from `__switch_to` |
| TASK_RESUME_OBSERVED | Post-yield continuation in same Wasm stack frame |
| RESUMED_PID == PARENT_PID | C restores the kernel-selected task's saved execution context |
| STACK_CONTEXT_PRESERVED | Wasm stack not unwound at yield point |
| AUTHORITY_REMAINS_SERVICEABLE | Event loop processes broker between yields |
| POST_RESUME_BROKERED_SYSCALL | Broker request delivered as IRQ before resume |
| BROKER_ERRORS=0 | Measured broker counter after completed real requests; never inferred from instance count |

## Implementation Order
1. Add `wasm_kernel_yield` import declaration to `wasm_imports.h`
2. Implement host-side yield handler in `wasm.ts` kernel_imports
3. Replace `__switch_to` atomic wait (process.c:61)
4. Replace `arch_cpu_idle` atomic wait (irq.c:47)
5. Replace `cpu_relax` atomic wait (irq.c:64)
6. Replace `__delay` atomic wait (time.c:28)
7. Replace fork VAS copy ack wait (fork.c:75)
8. Add `isKernelAuthority` + `kernelModule` to InitMessage (worker.ts, index.ts)
9. Build vmlinux.wasm and run K5A micro-witness
10. Verify all K5A acceptance criteria
11. Re-run K1–K4 regression suite

## Executed diagnostic findings

- Patched kernel build: LLVM/LLD 19.1.0, artifact `/tmp/kwa-build/tools/wasm/vmlinux.wasm`, SHA256 `671df5d9e7fcdb04ebcc86ee4a0e26fbf87781605024b13e2cca500cf39358b3`; `kernel.yield` import verified.
- Sentinel throwing discarded the Wasm stack; re-entering the export restarted it. A separate native JSPI check preserved an operand-stack cookie across actual Promise suspension. This is mechanics evidence, not real-parent proof.
- The authority boot diagnostic constructed one kernel instance and reached `__switch_to`, then reported `WAKE_TARGET_UNKNOWN`. With one pending continuation, peer entries are refused (`PEER_EXEC_BLOCKED`); Linux cannot hand the CPU back without executing a peer.
- A production secondary broker request timed out after 5000ms. An authority ping returned, but event-loop liveness is not syscall serviceability.
- Receipt: `tools/wasm/k5a-micro-witness-receipt.json`, verdict `NOT_PROVEN`. Parent PID, task binding, kernel stack-preserving resume and post-resume syscall remain unproven; zero broker errors without a completed request is not a pass.
- K1, K2R and K4R4 standalone regressions passed against this artifact. K4R4 still reports `CURRENT_TASK_BINDING_PROVEN=false` with pid=0; these regressions do not close K5A.
- The current host changes are uncommitted diagnostic work, not a shippable cutover: authority broker execution, user-task execution and device support are not implemented. No K5B/K6 execution or promotion is authorized by this diagnostic.

### Decision required

The principal authorized kernel-owned parked JSPI contexts with kernel-side restoration of execution globals and kernel-selected resumption. This revises K5A's untouched-globals premise only. K0–K4 contracts and every K5A acceptance criterion remain unchanged; implementation and fresh proof are still required.
