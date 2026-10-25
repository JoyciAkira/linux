#!/bin/bash
set -euo pipefail
run="${1:?Unique build run required}"
exec > >(tee "/evidence/$run.log") 2>&1
trap 'status=$?; printf "{\"exit\":%s,\"finishedAt\":\"%s\"}\n" "$status" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "/evidence/$run-result.json"' EXIT
for tool in clang clang++ llvm-ar llvm-nm llvm-objcopy llvm-objdump llvm-readelf llvm-strip wasm-ld ld.lld; do
  if [[ -x "/usr/bin/${tool}-19" ]]; then
    ln -sf "/usr/bin/${tool}-19" "/usr/local/bin/${tool}"
  fi
  command -v "$tool"
done
clang --version
mkdir -p /src
tar -C /inputs --exclude='.git' --exclude='node_modules' --exclude='*.o' \
  --exclude='*.a' --exclude='*.cmd' --exclude='*.ko' --exclude='*.wasm' \
  --exclude='*.wat' --exclude='./scripts/basic/fixdep' \
  --exclude='./scripts/kconfig/conf' --exclude='./scripts/mod/mk_elfconfig' \
  -cf - . | tar -C /src -xf -
cd /src
printf 'BUILD_SOURCE=%s\n' /src
sha256sum .config arch/wasm/kernel/syscall.c kernel/fork.c kernel/exit.c kernel/sched/core.c
make ARCH=wasm LLVM=1 LLVM_IAS=1 clean
make ARCH=wasm LLVM=1 LLVM_IAS=1 olddefconfig < /dev/null
cp .config "/evidence/$run.config"
sha256sum .config
make ARCH=wasm LLVM=1 LLVM_IAS=1 -j3 tools/wasm/vmlinux.wasm
cp include/generated/autoconf.h "/evidence/$run.autoconf.h"
llvm-readelf --file-header scripts/basic/fixdep
sha256sum tools/wasm/vmlinux.wasm
cp tools/wasm/vmlinux.wasm /evidence/vmlinux.wasm
