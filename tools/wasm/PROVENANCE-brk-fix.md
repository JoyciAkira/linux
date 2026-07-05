# PROVENANCE — arch/wasm brk-ceiling fix (end_brk = -1)

Auditable record binding the fix commit, the tested artifacts, and the
reproducible verdict. Regenerate the verdict with:

    node tools/wasm/run-brk-autotest.mjs

## Commits (local, branch `wasm`, remote NOT pushed)

| Role | SHA | Files |
|------|-----|-------|
| brk fix | `b4a4a31b20f184d41d519132d8090194553639c9` | `arch/wasm/kernel/binfmt_wasm.c` (+4) |
| harness | `ea0eef777ae38c698c80d4d0aeb090e08b4699b8` | `tools/wasm/brk-autotest.html`, `tools/wasm/run-brk-autotest.mjs`, `tools/wasm/.gitignore` |

Note: an earlier harness commit `a737a50e5…` was superseded by an `--amend`
that restored pre-existing `.gitignore` rules; the live SHA is `ea0eef777…`.

## Tested artifacts (SHA256)

| Artifact | SHA256 |
|----------|--------|
| `tools/wasm/vmlinux.wasm` (kernel, with fix) | `15dc11dd7e402d0ee701c801e717621ec544d8d196475242ede0ac153c9b36c7` |
| `tools/wasm/rootfs.ext2` (256MiB ext2) | `1b352b214ae83ddfb59bea65e008eecff7a63fbbd348ca1f587d2cd3bf8d091e` |
| `tools/wasm/dist/index.js` (host runtime) | `51e4190cd41513bf7e56097947a8e94deca890b1b33876ee3621e922255316fb` |
| `tools/wasm/dist/virtio.js` | `d3544cdaf5371ece958022f84d43130b1ba7744c7136ffa72acb6d5fe14d3ba8` |
| `tools/wasm/dist/wasm.js` | `37f10d88f77584a18adc60b79320270071d7981901d52e8765641f055ed9d411` |

Verdict artifacts (regenerated each run, gitignored):
- `artifacts/boot-log.txt` — full kernel console + userspace probe output
- `artifacts/verdict.json` — machine-readable pass/fail

## Verdict (this machine, 2026-07-04)

```
booted        true
rootMounted   true   (VFS: Mounted root (ext2 filesystem) on device 254:0)
shell         true   (BusyBox hush)
bigallocAllOk true   16/64/100/200MB posix_memalign all = 0
maxAllocMb    200    (> old ~47MB ceiling)
memprobeOk    true   wasm memory 768 -> 1024 MB, 512MB malloc OK
blinkmmapOk   true   99MB node binary mmap OK
x86helloOk    true   static x86-64 ELF via blink
x86dynOk      true   dynamic x86-64 ELF via ld-musl
pass          true
```

## Environment

- Kernel source: `tombl/linux` branch `wasm`, HEAD `ea0eef777…`
- Build: `make ARCH=wasm LLVM=1` (LLVM/clang 19.1.7), `vmlinux.wasm` 3,552,151 bytes
- Host runtime: `tools/wasm/dist` (tsc), Node v22.23.1
- Browser: Playwright chromium (headless), COOP/COEP via `serve-coop.py`

## Remote status (honest)

`origin` = `https://github.com/tombl/linux.git` — the PUBLIC UPSTREAM, not our
fork. These commits are LOCAL ONLY. Pushing requires a dedicated fork remote
and explicit approval; it is intentionally NOT done here. Until pushed, this
proof is **locally reproducible** but **not remotely auditable**.

## Known boundary (next milestone: M114-B2)

Real Node under blink fails with ENOMEM inside blink's own memory manager
(`blink/memorymalloc.c` → `AllocateBig` → wasm mmap shim). This is blink guest
arena exhaustion, distinct from kernel/browser memory (which reaches 1024MB).
`blinkmmap` proving the 99MB binary maps successfully narrows the boundary to
post-map process growth. Classification (A configurable ceiling / B eager
commit / C fragmentation / D structural wasm32 / E guest-VA layout conflict)
is deferred to M114-B2.
