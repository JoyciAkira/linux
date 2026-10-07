#define _WASM_UNISTD_H
#ifdef _WASM_UNISTD_H

#define __ARCH_WANT_RENAMEAT
#define __ARCH_WANT_STAT64
#define __ARCH_WANT_SET_GET_RLIMIT
#define __ARCH_WANT_TIME32_SYSCALLS
#define __ARCH_WANT_SYNC_FILE_RANGE2

#include <asm-generic/unistd.h>

#define __NR_set_thread_area (__NR_arch_specific_syscall + 0)
__SYSCALL(__NR_set_thread_area, sys_set_thread_area)

/* Z1-GABI (KWA-v2.1): real Linux guest startup ABI. argv/envp and TLS are
 * kernel-authorized state captured at exec (thread_info->args / tp_value);
 * guests read them through these syscalls via the broker — the host NEVER
 * fabricates the values. */
#define __NR_z1_get_args (__NR_arch_specific_syscall + 1)
__SYSCALL(__NR_z1_get_args, sys_z1_get_args)
#define __NR_z1_get_thread_area (__NR_arch_specific_syscall + 2)
__SYSCALL(__NR_z1_get_thread_area, sys_z1_get_thread_area)

#endif
