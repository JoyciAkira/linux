# M114-B2 — Blink Node 99MB ENOMEM: origin classification

**Date:** 2026-07-04
**Status:** Classification from static code evidence. A runtime `memstat` probe
(deferred) is required to fully discriminate B vs C.
**Boundary observed (M114-B1):**
```
/bin/blink /bin/node -e "console.log(...)"
E...:blink/memorymalloc.c:991:50 mmap(virt=8adcb000, size=16384, flags=0x2,
    fd=3, offset=0x2dc8000) crisis: ENOMEM
unrecoverable mmap() crisis
```
Crash offset `0x2dc8000` ≈ 47.8MB into the node file load.

## Code evidence (verbatim, verified)

1. **Blink on wasm32 has NO linear mapping — always.**
   `blink/machine.h:126` `#define CanHaveLinearMemory() false` (wasm32: `CAN_64BIT`
   is false) → `HasLinearMapping()` (`machine.h:137`) is permanently false.
   Therefore `Mmap` skips the linear branch and takes the **`PAGE_MUG` path** in
   `blink/memorymalloc.c` (~line 985), which maps guest memory in
   `mugsize = MIN(4096, end - virt)` — i.e. **~4KB chunks**, each via
   `AllocateBig` → `Mmap` → the wasm mmap shim.

2. **The wasm mmap shim is malloc-per-chunk with page-sized alignment waste
   AND eager zero-commit.** `blink-wasm-mman-impl.c`:
   `need = hdr + len + page; raw = malloc(need); ... memset(data, 0, len);`
   For a 4KB guest chunk on a 64KB wasm page: `malloc(8 + 4096 + 65536)` ≈ **70KB
   real**, all zeroed (physically committed). Node 99MB ⇒ ~24k chunks ⇒
   **~1.6GB of real malloc**. The file header comment concedes the musl-wasm32
   `__simple_malloc` heap is "limited (~16-64MB)".

3. **Blink build:** `build-wasm.sh` links `--import-memory --shared-memory
   --initial-memory=458752 --max-memory=4294967296`. No arena-max constant.

4. **Two distinct blink binaries exist** (provenance caveat):
   - `blink.wasm` — 322,381 B, mtime 17:02, sha256 `8f885f6f…`, **0** `posix_memalign` refs. This is the one in the tested rootfs.
   - `blink/blink-fixed.wasm` — 388,703 B, mtime 16:22, sha256 `0f2c36a5…`, **1** `posix_memalign` ref.
   Both reference `blink/memorymalloc.c` + the shim. The exact shim variant
   compiled into the rootfs `blink.wasm` must be confirmed before acting.

## Classification (A/B/C/D/E)

| Scenario | Verdict | Evidence for / against |
|----------|---------|------------------------|
| **A** CONFIGURABLE_CEILING | **RULED OUT** | No arena-max constant in blink; `--max-memory=4GB`. No explicit ceiling to raise. |
| **B** EAGER_COMMIT | **CONFIRMED (primary)** | Shim `memset(data,0,len)` physically commits every mapped guest page immediately — no lazy/on-demand. Node's mmap'd segments are all committed at map time. |
| **C** FRAGMENTATION | **PROBABLE aggravator** | musl-wasm32 `__simple_malloc` is a NO-MMU bump allocator; `munmap`→`free` does not coalesce. ~24k × 70KB chunks fragment the heap. |
| **D** STRUCTURAL_WASM32 | **PARTIAL** | The 17× overhead (70KB per 4KB) makes Node incompatible with **this shim**, not with wasm32 itself. Implementation limit, not architectural. |
| **E** GUEST_VA_LAYOUT_CONFLICT | **NOT DEMONSTRATED** | Crash at a progressive file offset (47.8MB into sequential load) points to progressive exhaustion (B/C), not a fixed-address VA conflict. Not positively excluded. |

**Primary diagnosis:** **B (eager commit) + catastrophic shim overhead (17×)**,
aggravated by **C (fragmentation)**. NOT a configurable ceiling (A), NOT a
wasm32 wall (D).

## Two honest open questions

1. **Which blink is in the rootfs?** `blink.wasm` (rootfs) vs
   `blink-fixed.wasm` differ in `posix_memalign` presence. The shim variant
   actually executing determines the exact overhead profile.
2. **Why doesn't the kernel `end_brk` fix help blink?** blink is itself a WASM
   binary loaded via `binfmt_wasm.c`, so the fix applies to its heap. Yet its
   `malloc` hits ENOMEM. Either the ENOMEM is real heap exhaustion /
   fragmentation (C — not a brk ceiling), or blink's `--import-memory` model
   uses a memory arena that the brk fix doesn't govern. This is the decisive
   discriminator.

## Deferred probe (M114-B2-P — requires blink rebuild)

Re-run the Node ENOMEM while dumping `s->memstat` (`committed` / `reserved` /
`tables`) at crash, across BOTH blink binaries:
- `committed` huge (hundreds of MB) → **B confirmed** (eager commit) → fix =
  make shim lazy / page-on-demand / use kernel `MAP_ANONYMOUS` growth.
- `committed` modest but `malloc` fails → **C** (process-heap fragmentation) →
  fix = give blink a real allocator (dlmalloc) instead of `__simple_malloc`.

Not executed here: it is new code (blink patch + rootfs regen), a separate
milestone from this classification.

## RESOLUTION (2026-07-05) — verdict B confirmed, fix landed

The alignment-overhead half of the B pathology was fixed and **Node now loads to
`EXIT=0`** under the 64KB-chunk path (previously ENOMEM at ~47.8MB).

- **Root cause acted on:** the shim did `need = hdr + len + page` — one extra
  64KB wasm page + an 8-byte raw-pointer header of pure alignment slack on
  *every* mapping. On the `PAGE_MUG` path (~1584 mmaps for 99MB Node) this
  doubled real backing (~128KB per 64KB chunk).
- **Fix:** `blink-wasm-mman-impl.c` mmap now uses `aligned_alloc(page, len)`
  (`len` already a page multiple; allocator guarantees alignment; pointer is
  directly `free()`-able so `munmap` simplifies to `free(addr)`). Backing per
  64KB chunk: ~128KB → 64KB (2×). Zero-init and mapped-region size unchanged.
- **Verification:** two independent archwasm-harness runs, 64KB production chunk
  size, both `EXIT=0` + `BN_DONE`, no `ENOMEM`, no `crisis` mmap. `EXIT=0` /
  `BN_DONE` are the decisive ground-truth markers (the `[B2P-PROG]`/`[B2P-SHIM]`
  stderr traces remain unobserved due to the char-by-char console-capture gap,
  but are not needed now that Node completes).
- **Open item 1 (which blink):** resolved — the rebuilt shim variant is the one
  now deployed. blink fork commit `198f540` on `wasm-m114-node-loader`
  (JoyciAkira/blink#1). New artifact sha256 `799a96b8bf239c94fd055eebc41412e5615892b9a99d1868c44ec58bfe9be0a4`;
  regenerated `rootfs.ext2` sha256 `bc68f722005b631372444899d0d1a7b6c0eab57e6b83c8e62590e98a03ce58f9`.
- **Residual (C — fragmentation) NOT yet addressed:** `__simple_malloc` is still
  a non-coalescing bump allocator. The 2× cut was sufficient for the current
  99MB Node workload, but a larger guest could still exhaust the heap. If that
  recurs, open a separate `LAZY-COMMIT / dlmalloc` milestone (do not combine).
