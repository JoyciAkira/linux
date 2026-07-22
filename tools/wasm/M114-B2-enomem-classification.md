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
 - **Verification (2026-07-05):** two archwasm-harness runs reported `EXIT=0` +
   `BN_DONE`. **⚠️ THIS VERIFICATION WAS A FALSE POSITIVE — see RETRACTION below.**
 - **Open item 1 (which blink):** the rebuilt shim variant with `aligned_alloc`
   is deployed. blink fork commit `198f540` on `wasm-m114-node-loader`
   (JoyciAkira/blink#1). Artifact sha256 `799a96b8bf239c94fd055eebc41412e5615892b9a99d1868c44ec58bfe9be0a4`;
   `rootfs.ext2` sha256 `bc68f722005b631372444899d0d1a7b6c0eab57e6b83c8e62590e98a03ce58f9`.

## RETRACTION (2026-07-05, session 3) — B2 is NOT resolved; ENOMEM persists

The "RESOLUTION EXIT=0" above is **withdrawn**. It rested on a measurement bug,
not on Node actually running.

- **The false-positive mechanism:** the probe (`quick-node3.html`) sent
  `/bin/blink -e /bin/node; echo EXIT=$?; echo BN_DONE` and then
  `waitFor("BN_DONE")`. The shell **echoes the typed command** (containing the
  literal `BN_DONE`) to the console *before* executing it, so `waitFor` matched
  the command echo and declared success in seconds — **Node was never awaited**.
  Corroborating: the structured `artifacts-b2p/b2p-verdict.json` from the same
  era reads `"verdict": "B2P_RUNTIME_EVIDENCE_INCONCLUSIVE"`, `"enomemHit": false`
  only because the run never reached Node. Two independent "EXIT=0" runs shared
  the same broken marker.
- **Second bug:** `-e` is a **blink flag** ("also log to stderr"), NOT `node -e`.
  `blink -e /bin/node` launches Node with **no arguments** (REPL on empty stdin →
  immediate clean exit), which never exercises a real workload either.

**Correct re-test (this session):** split-string markers so the command echo
cannot self-match (`echo NV""_DONE`), correct syntax `/bin/blink /bin/node
--version` (args go to the guest). Headless Playwright, real kernel, 768MiB.
**Result: `NV_EXIT=250`, `nodeVersion=null`, hard ENOMEM** — the SAME crash,
same offset as before the "fix":

```
[B2P-PROG] mmaps=11264 mappedGuestMB=204 realBackingMB=270 fails=0
E...:blink/memorymalloc.c:991 mmap(virt=8adcb000, size=16384, flags=0x2,
    fd=3, offset=0x2dc8000) crisis: ENOMEM   (offset = 48.0MB into 99MB node)
```

The `aligned_alloc` change DID cut the *visible* backing overhead to 1.32×, but
it did **not** fix the crash because the real cost is invisible to this metric.

## TRUE ROOT CAUSE (2026-07-05, Oracle-confirmed) — scenario A, refined

Not "eager commit" (B) and not merely fragmentation (C). The dominant cost is
**`aligned_alloc(65536, len)` alignment slack on the non-reclaiming
`__simple_malloc` bump allocator**, invisible to blink's accounting:

- blink's `[B2P-PROG]` `realBackingMB=270` is blink's **sum of requested mapping
  sizes**, NOT the real wasm heap. It cannot see `aligned_alloc`'s over-alloc
  slack nor `__simple_malloc`'s non-coalescing bump.
- Each shim call burns up to a fixed ~64KB slack (`page=65536`) that
  `__simple_malloc` **never reclaims** (its `free` is a no-op; `munmap`=`free`).
  11,264 calls × ~64KB ≈ **~700MB pure slack** on top of ~204MB useful ≈
  **~900MB true footprint** → hits the real `memory.grow` ceiling.
- **wasm has no demand paging / no overcommit**: grown linear memory is 100%
  backed immediately, so alignment slack is 100% real cost. The
  "align-generously" pattern that is cheap on Linux is catastrophic here.
- Consistent with probes: a *single* 512MB alloc and 1024MB grow both succeed
  (low per-call overhead), but *11k small* allocs die at 270MB *accounted*.
- Latent bug: `aligned_alloc` requires `len % align == 0`; `size=16384` is not a
  multiple of 65536 → strictly UB (musl is lenient). Another reason to drop it.

## FIX PLAN (ranked, Oracle-confirmed) — B2 remains OPEN

1. **PRIMARY — shim-owned arena + free-list, 4KB alignment** (not per-call
   `aligned_alloc(64KB)`): one 64KB-aligned slab from `__simple_malloc`, carve
   **4KB-aligned** (guest-page) pieces; `munmap` pushes to a size-classed
   free-list (keyed on 4KB-rounded length) so remaps/relocs REUSE memory. Cuts
   per-alloc slack ~64KB→<4KB (~10-16×) AND kills the no-free leak. Isolated to
   `blink-wasm-mman-impl.c`, ~150-250 LOC, low-med risk.
   - **Zero-on-reuse correctness:** reused anonymous blocks MUST be zeroed;
     file-backed reuses MUST be re-read. (Drop the blanket `memset` for fresh
     slab growth — wasm zero-inits — but zero/re-read reused blocks.)
2. Drop eager `memset` for fresh allocations (perf, do WITH #1's zero-on-reuse).
3. Fallback: replace `__simple_malloc` with dlmalloc (MORECORE/sbrk mode) — wider
   blast radius + `--shared-memory` TLS risk; only if non-shim paths also leak.
4. Last resort: coalesce blink PAGE_MUG 4KB chunks — high risk (breaks per-page
   mprotect/munmap); design-lock required.

**Cheap validation before building #1:** flip shim `page` 65536→4096 and re-run;
expect the crash to move dramatically deeper. Also log
`__builtin_wasm_memory_size(0)*65536` at crash (predict ~900MB-1GB vs 270MB) to
prove the invisible-slack hypothesis.

## CHEAP VALIDATION RESULT (2026-07-06) — slack theory CONFIRMED; FreePage invariant discovered

Run: shim `alloc_gran=4096` (instead of `sysconf(_SC_PAGESIZE)=65536`), rebuilt
blink, injected into rootfs-4k.ext2, headless Playwright 768MiB.

```
[B2P-PROG] mmaps=4096 mappedGuestMB=134 realBackingMB=134 fails=0
Segmentation fault
NV_EXIT=139
```

**Key findings:**

1. **Slack theory CONFIRMED.** `realBackingMB = mappedGuestMB = 134` → overhead
   exactly **1.00×** (zero slack). The ~700MB invisible overhead from
   `aligned_alloc(65536,…)` is gone. ENOMEM disappeared entirely — crash mode
   changed from `mmap crisis` to SIGSEGV. Node loaded ~2.7× further before
   crashing (134MB vs 270MB accounted; 4096 mmaps vs 11264 at crash).

2. **FreePage invariant discovered (blocks naive 4KB fix).** The SIGSEGV comes
   from `blink/memorymalloc.c:649-651` in `FreePage`:
   ```c
   pagesize = FLAG_pagesize;   // = sysconf(_SC_PAGESIZE) = 65536 on arch/wasm
   real = mug = FindHostPage(entry);
   while ((uintptr_t)mug & (pagesize - 1)) mug -= 4096;
   unassert(!Munmap(mug, real - mug + size));
   ```
   When `munmap`-ing a PAGE_MUG chunk, blink rounds the pointer DOWN to the
   nearest 64KB boundary before calling `Munmap`. This is correct when the chunk
   was allocated with 64KB alignment (round-down is a no-op), but with 4KB
   alignment it walks backwards past the real allocation start → `free()` of an
   unowned pointer → UB / SIGSEGV.
   **Conclusion:** every chunk returned by the shim's `mmap` MUST be 64KB-aligned
   at its start. A plain `aligned_alloc(4096,…)` replacement is NOT sufficient.

## REVISED FIX PLAN (post-validation) — arena is mandatory

The fix must satisfy two constraints simultaneously:
- **No per-call 64KB alignment slack** (eliminate the ~700MB invisible overhead).
- **Every returned pointer is 64KB-aligned** (FreePage invariant).

These constraints are reconciled by an **arena allocator inside the shim**:

```
Arena slab layout (one slab = 64KB * PAGES_PER_SLAB):
  [64KB-aligned base]
  ├── slot 0: 64KB  ← mug pointer returned for page 0; 64KB-aligned ✓
  ├── slot 1: 64KB  ← mug pointer for page 1; also 64KB-aligned ✓
  ├── ...
  └── slot N-1: 64KB
```

Each slot is exactly 64KB (one wasm page). On `mmap` for a guest 4KB page, the
shim returns a 64KB slot (64KB-aligned, satisfies FreePage). The waste is now
**64KB per guest 4KB page** in terms of virtual address space, but:
- The slab backing is allocated ONCE upfront (one `aligned_alloc` or `memalign`
  call for `PAGES_PER_SLAB × 64KB`) — total slack = 0 beyond rounded slab size.
- `munmap` pushes the slot onto a free-list; next `mmap` pops it — zero net leak.
- For mappings > 64KB (e.g. a 1MB anonymous region), allocate contiguous slots.

**Implementation notes:**
- Slab size: 256 slots × 64KB = 16MB per slab (grow-on-demand).
- Free-list: singly-linked list embedded in the slot itself (first 8 bytes when
  free; safe because slot is not in use).
- Thread safety: blink with `DISABLE_THREADS` is single-threaded; no lock needed.
- `munmap(addr, len)`: push `len/65536` contiguous slots back (or just push addr
  as a single free slot if len <= 64KB; multi-page frees need contiguous reuse).
- Zero-on-reuse: anonymous reused slots must be zeroed (`memset`); file-backed
  slots must be re-read. Fresh slab growth is already zero (wasm zero-init).
- For the `mugskew` case (file-backed with non-64KB-aligned offset): `mugsize`
  can be up to `4096 + 65535` bytes. One slot (64KB) may not be enough if
  `mugskew > 0`. Use `ceil((mugsize) / 65536)` slots. In practice blink's
  `mugskew = offset - ROUNDDOWN(offset, 65536)` and offset advances by 4096, so
  mugskew cycles through 0,4096,…,61440 → mugsize up to 69632 bytes → 2 slots
  worst case. Free-list entry stores slot count for correct reclaim.

## FINAL RESOLUTION (2026-07-06) — B2 CLOSED, Node v20.18.0 runs

**Status: RESOLVED. All ENOMEM / SAB-ceiling blockers eliminated.**

### What was implemented

**Fix 1 — `blink/map.c`, `GetSystemPageSize()`:**
Added `#elif defined(__wasm32__)` branch returning 4096, identical to the
`__EMSCRIPTEN__` branch that already existed. With `FLAG_pagesize = 4096`,
`FreePage` uses stride=4096 for its round-down loop — so returned pointers must
be 4KB-aligned, not 64KB-aligned. Three lines changed.

**Fix 2 — `blink-wasm-mman-impl.c`, sub-page allocator:**
Replaced the `memory.grow`-per-slot shim with a proper sub-page allocator:
- Each slab = 1 wasm page (64KB, from `memory.grow(1)`, inherently 64KB-aligned).
- 16 slots × 4096 bytes per slab, tracked with `uint16_t used` bitmask.
- `mmap(4096)` → finds lowest free slot via `ctz16`; returns 4KB-aligned pointer.
- `munmap(ptr, 4096)` → clears the slot bit; slab stays live for reuse.
- Requests >64KB → contiguous `memory.grow` + BigFree list.
- Partial-slab free-list via `next_partial` index in `SlabMeta[]`.

The `mugskew` complexity from the REVISED FIX PLAN above is moot: with
`FLAG_pagesize=4096`, `mugskew = offset - ROUNDDOWN(offset, 4096)` and ELF LOAD
segments always have 4096-aligned file offsets, so `mugskew=0` always. Every
`AllocateBig` call from the PAGE_MUG loop receives exactly 4096 bytes.

### Verified metrics (Chrome headless, `run-node-version-subpage.mjs`)

```
[SUBP-PROG] mmaps=18944 mappedGuestMB=168 realSlabMB=168 fails=0
...
v20.18.0
NV_EXIT=0
NV_DONE
```

| Metric | Before (memory.grow per-slot) | After (sub-page allocator) |
|--------|-------------------------------|----------------------------|
| Overhead | 4.58× | **1.00×** |
| Backing at 18944 mmaps | 1278 MB (crash) | 168 MB |
| Exit | 250 (ENOMEM) | **0** |
| Node version | never reached | **v20.18.0** |

### Artifacts

- `blink-fixed.wasm` sha prefix `11274ac1` (fork `JoyciAkira/blink@eff8166`,
  branch `wasm-m114-node-loader`)
- `rootfs-subpage.ext2` — rootfs with sub-page blink
- `artifacts/node-version-subpage-run1.log` — full run log
- `run-node-version-subpage.mjs` + `node-version-subpage-probe.html` — harness
