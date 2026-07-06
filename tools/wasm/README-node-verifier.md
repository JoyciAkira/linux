# M114-NODE-VERIFIER (C1) — real /bin/node under blink, gate-backed

Part of the Zeronode NODE-COMPLETE program (§C1). Turns the M114 "Node EXIT=0"
provenance claim into a **non-falsifiable, independently recomputed** verdict.

## License boundary (important)

This tree (`JoyciAkira/linux`) is a fork of `tombl/linux` → `torvalds/linux`:
**GPL-2.0 WITH Linux-syscall-note**. Everything here (including these C1 files)
is GPL. `blink` is ISC (© Justine Tunney). Neither may be vendored into the
proprietary Zeronode repo — the syscall boundary is the legal boundary.

## Files

| File | Role |
|------|------|
| `node-verifier.html` | Boots the arch/wasm kernel, drives `/bin/node` x86-64 under blink, captures exit via shell `$?` (waitpid) — NOT a wrapper marker |
| `run-node-verifier-v1.mjs` | Producer: headless Chromium, pins artifact SHA256, writes `artifacts/node-run.report.json` + raw log. `producerPass` is NON-authoritative |
| `verify-node-run.mjs` | Independent verifier: recomputes verdict from raw, flags producer/raw disagreement, emits `REAL_NODE_INVOCATION_PROVEN` only when gate-backed |
| `build-node-rootfs.sh` | Reproducible `node-rootfs.ext2` recipe (anchored to the M114 `genext2fs -b 262144` command) |
| `serve-coop.py` | COOP/COEP static server (SharedArrayBuffer isolation) |

## Required inputs (NOT fabricated — must be real, verified artifacts)

1. `vmlinux.wasm` — `make ARCH=wasm LLVM=1 tools/wasm/vmlinux.wasm` in the
   `zeronode-archwasm-build:v1` container (needs the kernel tree + tombl toolchain).
2. `BLINK_WASM` — from `JoyciAkira/blink` `build-wasm.sh` (needs `~/tombl-build`
   musl + compiler-rt).
3. `NODE_X86_64_MUSL` — a real x86-64 **musl-linked** Node 24.x LTS binary.
   Source must be recorded + SHA-verified before trust (the M114 doc does not
   state where the original ~99MB binary came from — this must be pinned).
4. `BUSYBOX_WASM` — wasm32 busybox for `/bin/sh`.

## Run

```bash
NODE_X86_64_MUSL=/path/node BLINK_WASM=/path/blink.wasm BUSYBOX_WASM=/path/busybox.wasm \
  bash build-node-rootfs.sh
# place vmlinux.wasm + node-rootfs.ext2 next to node-verifier.html
node run-node-verifier-v1.mjs      # producer
node verify-node-run.mjs           # independent verdict; exit 0 = REAL_NODE_INVOCATION_PROVEN
```

## Status

Code-complete; **execution-blocked** until the four inputs above exist as
pinned artifacts. The verifier is dry-tested: it PASSES a genuine log and FAILS
(exit 1) when a report claims exit 0 while the raw log shows exit 1.
