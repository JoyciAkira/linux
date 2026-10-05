# B1 Provenance Correction

## Historical diagnosis — incorrect

The preserved preliminary `b1-receipt.json` attributed the different rebuild hashes to LLVM 23.1.0 wasm backend non-determinism. That conclusion was not supported by the byte-level evidence and is superseded by the final receipt. The old receipt and every differing artifact remain preserved unchanged.

## Corrected source authority

The K6R1 receipts originally attributed the frozen artifact to `e2301d96c41f050f032efe427c011dd105709f7d` with a clean tree. That commit omitted the seventh `spawn_flags` argument at the boot and secondary-idle call sites. Recovery commit `381e56bb4d9b694e05f456dd90e62af0b2bf6826` restores the exact recovered source ABI; recovered patch SHA256 is `aef0c8936975ef519ec9f408753ba859383ea5d5085e90afb10cd6d62c31d076`.

The machine-readable ABI audit confirms all three `wasm_kernel_spawn_worker` call sites use seven arguments in the declared order. Boot uses `(share_user_memory=false, task_token=0, spawn_flags=0)`. Secondary idle uses `(0, kwa_task_token(idle), KWA_SPAWN_AUTOSTART)`. Normal/fork children use the dedicated task token and `spawn_flags=0`; clone-with-function sets only the memory-sharing argument. No six-argument call site remains. Two comments still describe the former autostart bit in `share_user_memory`; this comment drift is recorded in the audit and does not match the executable call sites.

## Proven first cause

Python parsing of the original wasm files identified `.linux.initramfs` as the sole section that differed between frozen `bbe4f538…`, Build B `91afe986…`, and Build A clean-defconfig `b3bb906f…`. Their newc CPIO mtimes were respectively `1791216968`, `1791230713`, and `1791233423`; Type, Code, Data, and all other sections were byte-identical.

`usr/gen_initramfs.sh` passes a `-t` epoch to `gen_init_cpio` only when `KBUILD_BUILD_TIMESTAMP` is set and `date -d` parses it. On this macOS host, the system date does not provide the GNU `-d` behavior used by the script; failed parsing is suppressed, so the generator receives no `-t`. With no explicit time, `usr/gen_init_cpio.c` uses `time(NULL)`. The wall-clock value is embedded in the CPIO newc mtime fields and then in `.linux.initramfs`.

Pinning `KBUILD_BUILD_TIMESTAMP` globally was not an acceptable fix: it also altered kernel Code/Data build metadata. A global timestamp-controlled diagnostic produced `3687beb6…` with the correct initramfs timestamp but different Code and Data sections. The final build therefore leaves `KBUILD_BUILD_TIMESTAMP` unset for kernel compilation and scopes it only to the standard `cmd_initfs` recipe, with GNU coreutils `date` first in PATH. This retains the original kernel build inputs while fixing the only divergent generated input.

## Reproducibility result

Three independently materialized, clean, serial worktrees at commit `381e56bb4d9b694e05f456dd90e62af0b2bf6826` (tree `59ba33115726e217999c706839bd9c0670eb77ef`) generated the same `.config` SHA256 `d7f4d8a6a6516d4529d5681ec29011f18fbc5d09eaf9fdc5abc2ae2cb90e8a97` and the same 512-byte initramfs SHA256 `372d2dca8eb190958317801b818b4e30f43c4da0c3167c8835997bd4d2ff22b4`.

Build A = Build B = Build C = frozen K6R1 artifact:

`bbe4f538087179597bdfc31dbce672fcc34c16443f629bf222f8c7e616e829c1` (3,718,924 bytes).

All three source trees were clean before and after the build. The parsed section manifest has 16 sections; every section is byte-identical across A/B/C and to the frozen artifact. Run A’s make command succeeded and produced the exact artifact; its first wrapper exited 1 only because an incorrect postcondition expected the tracked wasm output to become modified. The unchanged output correctly left the tree clean. Runs B and C completed with wrapper exit 0. This wrapper issue is disclosed in the machine receipt; no artifact or failure was discarded.

The independent reviewer confirmed the matrix and initially raised a possible `UTS_VERSION` timestamp concern. It is resolved: all three freshly generated `init/utsversion-tmp.h` files have SHA256 `1f3db81e6ac8d6b23672bb7fae4a87a78b269f08efab0bf46bc97b59bc5b9664` and identical content `#define UTS_VERSION "# SMP "`. The wall-clock automatic timestamp is target-specific to `include/generated/utsversion.h` / `version-timestamp.o`, which is not in `init/obj-y`. Reviewer confirmed no remaining B1 blocker. Re-check this if that object becomes linked or global timestamp policy changes.

## Certification impact

No runtime semantics or kernel source was changed during the B1 fix. Because all three clean builds reproduce the exact frozen K6R1 artifact, the existing K1–K6R1 behavioral evidence remains valid and need not be rerun. B1 is PASS; Z1 is READY. Historical receipts and the original failure artifacts remain intact.

## Evidence

The complete machine receipt, first-divergence report, ABI audit, section manifest, build-matrix validation, preserved artifacts, and raw build logs are in `/Volumes/External/DANI/kwa-b1-forensics/20261005T201717Z/`; their content hashes are listed in `b1-receipt-final.json`.
