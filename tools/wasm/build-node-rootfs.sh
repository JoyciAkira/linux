#!/usr/bin/env bash
# build-node-rootfs.sh — reproducible recipe for node-rootfs.ext2 (C1 input).
#
# Closes the "rootfs recipe not in VCS" hole (same class as the missing probe).
# Assembles the ext2 rootfs that node-verifier.html boots: it must contain the
# real x86-64 /bin/node, blink, and the x86 test binaries the existing
# brk-autotest already drives.
#
# This script does NOT fabricate any binary. Inputs that are not buildable from
# this repo (the x86-64 musl Node, blink.wasm) are declared REQUIRED and must be
# provided via env vars pointing at real, verifiable artifacts.
#
# Anchored to the M114 provenance doc's exact command:
#   genext2fs -b 262144 -d rootfs-stage tools/wasm/rootfs.ext2
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGE="$HERE/rootfs-stage"
OUT="${OUT:-$HERE/node-rootfs.ext2}"
BLOCKS="${BLOCKS:-262144}"   # -b 262144 (matches M114 doc)

# ── REQUIRED external inputs (NOT fabricated — must be real artifacts) ────────
: "${NODE_X86_64_MUSL:?set NODE_X86_64_MUSL=/path/to/node (real x86-64 musl-linked Node 24.x LTS binary; e.g. from nodejs unofficial-builds musl, or a self-built musl static node — verify SHA before trusting)}"
: "${BLINK_WASM:?set BLINK_WASM=/path/to/blink.wasm (built via JoyciAkira/blink build-wasm.sh)}"
: "${BUSYBOX_WASM:?set BUSYBOX_WASM=/path/to/busybox.wasm (wasm32 busybox for /bin/sh)}"

need() { command -v "$1" >/dev/null || { echo "FATAL: missing tool: $1" >&2; exit 2; }; }
need genext2fs

echo "=== staging rootfs at $STAGE ==="
rm -rf "$STAGE"
mkdir -p "$STAGE"/{bin,dev,proc,sys,tmp,root}

# /bin/sh (busybox wasm) — the init the verifier boots (init=/bin/sh)
install -m 0755 "$BUSYBOX_WASM" "$STAGE/bin/busybox"
ln -sf busybox "$STAGE/bin/sh"

# blink x86 emulator (wasm) — runs the unmodified x86-64 node
install -m 0755 "$BLINK_WASM" "$STAGE/bin/blink"

# the REAL x86-64 node binary blink executes
install -m 0755 "$NODE_X86_64_MUSL" "$STAGE/bin/node"

# x86 smoke binaries the existing brk-autotest expects (optional; copied if present)
for b in x86hello x86dyn; do
  [ -f "$HERE/testbin/$b" ] && install -m 0755 "$HERE/testbin/$b" "$STAGE/$b" || true
done

echo "=== building ext2 image: genext2fs -b $BLOCKS -d rootfs-stage $OUT ==="
genext2fs -b "$BLOCKS" -d "$STAGE" "$OUT"

echo "=== node-rootfs.ext2 built ==="
ls -la "$OUT"
if command -v sha256sum >/dev/null; then sha256sum "$OUT"; else shasum -a 256 "$OUT"; fi
echo ""
echo "Next: place vmlinux.wasm + $OUT next to node-verifier.html, then:"
echo "  node run-node-verifier-v1.mjs   # producer"
echo "  node verify-node-run.mjs        # independent verdict (REAL_NODE_INVOCATION_PROVEN)"
