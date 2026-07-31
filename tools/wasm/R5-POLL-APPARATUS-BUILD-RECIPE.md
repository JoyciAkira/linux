# R5 V2 Stage 4 Poll Apparatus — Build Recipe

## Compiler
- Path: /opt/homebrew/bin/x86_64-linux-musl-gcc
- Version: x86_64-linux-musl-gcc (GCC) 14.2.0
- Flags: -static -O2

## Build command
```bash
cd /Users/danielecorrao/tombl-build/linux/tools/wasm
x86_64-linux-musl-gcc -static -O2 -o r5-poll-probe r5-poll-probe.c
```

## Input
- r5-poll-probe.c SHA256: 0d65257f2be99a9744b4f24e8ad087933a4334b42c2c291dd6f1e18f456dce86

## Output
- r5-poll-probe SHA256: 01203fe5d2af9e17b22c31e8ef87910dfc8541d2a4a6e550a1664642de35d138
- Format: ELF 64-bit LSB executable, x86-64, statically linked, not stripped

## Derived rootfs
- Source: rootfs-d1f4.ext2 SHA256: 368f144f8fc5f6f7352e80290fe3dbaedb57898181628415dae8ee50f62d1337
- Derived: rootfs-r5-poll-probe.ext2 SHA256: 988ece892aa3068aa52d9c9544fb01c5e47d778475f43c2586f176b35a0de14b
- Injection: debugfs -w -R "write r5-poll-probe /bin/r5-poll-probe" rootfs-r5-poll-probe.ext2
- Guest path: /bin/r5-poll-probe
- Guest mode: 0755, inode 68
- debugfs: /opt/homebrew/Cellar/e2fsprogs/1.47.4/sbin/debugfs

## Execution
```bash
# Guest command (via blink x86-64 emulator):
/bin/blink /bin/r5-poll-probe

# Host runner:
N2_EVIDENCE_DIR=<evidence-dir> node r5-poll-probe-run.mjs <run-number>
```

## Frozen kernel
- vmlinux.wasm SHA256: b76bf2d1e1084e1629f1627ba8b32558c34913a664cdee4f1bc13964eec393a1

## Host runtime
- dist/index.js SHA256: 2f90662af5976605386eb051f7c974dc65d706463245256f7e196e9fb5dee0a7

## Harness repository
- Root: /Users/danielecorrao/tombl-build/linux
- Branch: r5-v2-stage4-poll-apparatus-v1
- Base HEAD: 22fee8995fb3e7af19f71228b401a26b4d14cdf4
