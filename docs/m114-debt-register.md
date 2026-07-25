# M114 Debt Register

**Maintained:** 2026-07-25
**Purpose:** track technical debts that block `ZERONODE_FULL_NODE_RUNTIME_CERTIFIED` but are out of scope for the current authorized campaigns. Each entry: status, evidence, what's missing, which verdict it blocks.

---

## 1. mremap errno semantics

```
MREMAP_TARGET_WORKLOAD_FIX_VERIFIED
LINUX_MREMAP_ERRNO_SEMANTICS_NOT_RECERTIFIED
```

**Status:** workload-verified (Node boots + core ladder), Linux errno semantics NOT recertified.

**Evidence:**
- Fix commit `20a0b73` (blink): `SysMremap` EINVAL path (workload-verified — Node v20.18.0 runs, NODE_CORE_RUNTIME_LADDER_CERTIFIED 5/5).
- The EINVAL change was validated only against the Node boot workload, NOT against the full Linux `mremap(2)` contract.

**What's missing (future dedicated campaign):** differential test against native Linux for:
- `EINVAL` (invalid args / unaligned / overlap)
- `ENOMEM` (out of memory / growth blocked)
- `EFAULT` (unmapped source range — note: `e7315cf` touched the EFAULT-on-unmapped-source path for musl pthread_getattr_np; needs cross-check)
- `MREMAP_MAYMOVE`
- `MREMAP_FIXED`
- alignment / overlap / zero-size edge cases

**Blocks:** `ZERONODE_FULL_NODE_RUNTIME_CERTIFIED` (final). Does NOT block loopback/process-lifecycle/npm/remote-TCP.

**Authorization:** do NOT modify the workload-verified fix without a dedicated campaign (section 8 directive).

---

## 2. child_process lifecycle (fork)

```
CHILD_PROCESS_FORK_PARENT_PID_ALLOCATION_PROVEN
CHILD_PROCESS_CHILD_CONTINUATION_REFUTED
ARCH_WASM_CLONE_IS_FN_BASED_THREAD_MODEL
ARCH_WASM_FORK_RETURN_BASED_COPY_NOT_IMPLEMENTED
ARCH_WASM_SPAWN_NEW_INSTANCE_FEASIBLE
WAIT4_PARENT_CHILD_RELATIONSHIP_REQUIRES_RUNTIME_VERIFICATION
```

**Status:** boundary localized + feasibility audited; **implementation NOT authorized**.

**Evidence:**
- P0 substrate probe (`fork-p0.c` x86-64 static): `fork()->46` (PID alloc proven), `wait4(46)->ECHILD`, child marker `ZN_CHILD_RETURN_ZERO` never emitted.
- arch/wasm `clone` (`arch/wasm/kernel/fork.c`) is fn-based: child runs `wasm_call_clone_fn` → `wasm_user_switch_entry(fn,arg)` → `wasm_user_instantiate(false)` with **shared** parent memory (`dist/worker.js:45-47`, `share_user_memory=true`).
- `instantiate(true)` (`dist/worker.js:59-77`) allocates **fresh independent** `WebAssembly.Memory` — so clone+execve → independent process is feasible (Option B).

**What's missing:** B3-SPAWN-1 implementation (clone+execve→fresh instance) + process ladder P0-P12 + verify ECHILD/wait relationship.

**Blocks:** `REAL_CHILD_PROCESS_LIFECYCLE_VERIFIED`, `NPM_OFFLINE_RUNTIME_VERIFIED` (npm needs spawn).

**Authorization:** implementation pending owner decision (Option B confirmed feasible; `IMPLEMENTATION_NOT_YET_AUTHORIZED`).

---

## 3. remote TCP (NBR-3)

```
NBR3_ARCH_WASM_INTEGRATION_DESIGN_FROZEN
NODE_REMOTE_TCP_THROUGH_NBR3_VERIFIED  (NOT reached)
```

**Status:** design frozen; **implementation NOT authorized**.

**Evidence/artifacts:**
- Design: [`docs/m114-nbr3-arch-wasm-integration-design.md`](m114-nbr3-arch-wasm-integration-design.md).
- `LoopbackNetworkBridge` = echo-only (`dist/virtio.js:633`); browsers cannot raw TCP → relay required.
- No existing NBR-3 relay implementation (inventory D0: all candidates are simulation/P2P/LKL-specific/contract-only).

**What's missing:** `EthernetRelayBridge` (guest) + `nbr3-relay-server` (host TCP/IP termination + NAT) + `nbr3-fixture`; largest risk = vetted userspace TCP termination for the host relay.

**Blocks:** `NODE_REMOTE_TCP_THROUGH_NBR3_VERIFIED`, N4 TLS, N5 HTTP, DNS (controlled), npm registry.

**Authorization:** implementation pending owner decision.

---

## 4. robustness / soak / fresh-clone

**Status:** not started (terminal-gate items for Full Node).

**What's missing:** crash-after-many-boots, browser/runner restart stability, boot latency, soak, fresh-clone build reproducibility, frozen artifact SHAs, consumer (Zeronode) integration, independent evaluator, negative controls.

**Blocks:** `ZERONODE_FULL_NODE_RUNTIME_CERTIFIED` (final).

---

## Verdict reachability summary

| Verdict | Reachable from current state? | Gate |
|---------|------------------------------|------|
| `NODE_LOOPBACK_TCP_FORENSICALLY_FROZEN` | ✅ DONE | — |
| `REAL_CHILD_PROCESS_LIFECYCLE_VERIFIED` | impl pending | B3-SPAWN-1 auth |
| `NPM_OFFLINE_RUNTIME_VERIFIED` | impl pending | child lifecycle |
| `NBR3_ARCH_WASM_INTEGRATION_DESIGN_FROZEN` | ✅ DONE | — |
| `NODE_REMOTE_TCP_THROUGH_NBR3_VERIFIED` | impl pending | NBR-3 impl auth |
| `ZERONODE_FULL_NODE_RUNTIME_CERTIFIED` | NO | all of above + mremap recert + robustness |
