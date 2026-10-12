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
#define __NR_z1_snapshot_args (__NR_arch_specific_syscall + 3)
__SYSCALL(__NR_z1_snapshot_args, sys_z1_snapshot_args)

/* Z1-F11-C4-D: wasm kernel has no socket subsystem. The generic table maps
 * 198-210 to sys_ni_syscall → -ENOSYS, which guest libc/blink treat as a
 * fatal "kernel lacks syscalls" condition (musl a_crash → unreachable).
 * Return the semantically correct errors instead: socket creation reports
 * -EAFNOSUPPORT (address family unsupported), everything on an fd reports
 * -ENOTSOCK (fd is not a socket). */
__SYSCALL(__NR_socket, sys_z1_socket_stub)
__SYSCALL(__NR_socketpair, sys_z1_socketpair_stub)
__SYSCALL(__NR_bind, sys_z1_sockfd_stub)
__SYSCALL(__NR_listen, sys_z1_sockfd_stub)
__SYSCALL(__NR_accept, sys_z1_sockfd_stub)
__SYSCALL(__NR_connect, sys_z1_sockfd_stub)
__SYSCALL(__NR_getsockname, sys_z1_sockfd_stub)
__SYSCALL(__NR_getpeername, sys_z1_sockfd_stub)
__SYSCALL(__NR_sendto, sys_z1_sockfd_stub)
__SYSCALL(__NR_recvfrom, sys_z1_sockfd_stub)
__SYSCALL(__NR_setsockopt, sys_z1_sockfd_stub)
__SYSCALL(__NR_getsockopt, sys_z1_sockfd_stub)
__SYSCALL(__NR_shutdown, sys_z1_sockfd_stub)

/* Z1-F11-C5-5: real futex WAIT/WAKE — guest pthread locks park inside the
 * kernel scheduler instead of pure-CAS spinning (which starves sibling
 * guest threads under the one-continuation user worker). */
__SYSCALL(__NR_futex, sys_z1_futex)

#endif
