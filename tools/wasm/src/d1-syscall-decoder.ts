/**
 * D1 Syscall Decoder — syscall number → name mapping
 *
 * For x86-64 syscall numbers used by Node/libuv initialization.
 * Focused on syscalls relevant to uv_loop_init and epoll setup.
 *
 * Authoritative ABI source: this kernel tree's own syscall table,
 *   arch/x86/entry/syscalls/syscall_64.tbl (abi "common").
 * The active runtime is Node v20.18.0 as an x86-64 ELF executed under Blink
 * (x86-64 emulator → wasm32), so x86-64 Linux syscall numbering is authoritative.
 *
 * The table is declared as an array of [number, name] tuples and built into a
 * Map by `buildSyscallMap`, which THROWS on any duplicate numeric key. This
 * makes an accidental duplicate a hard initialization/test failure instead of a
 * silent TypeScript object-literal overwrite.
 */

/**
 * Authoritative x86-64 syscall table entries (decimal numbers shown in hex).
 * Every number verified against arch/x86/entry/syscalls/syscall_64.tbl.
 */
export const SYSCALL_TABLE: ReadonlyArray<readonly [number, string]> = [
  // Process/thread
  [0x00, 'read'],
  [0x01, 'write'],
  [0x02, 'open'],
  [0x03, 'close'],
  [0x09, 'mmap'],
  [0x0a, 'mprotect'],
  [0x0b, 'munmap'],
  [0x0c, 'brk'],

  // Signals
  [0x0d, 'rt_sigaction'],
  [0x0e, 'rt_sigprocmask'],
  [0x0f, 'rt_sigreturn'], // 15

  // Time
  [0xe4, 'clock_gettime'], // 228
  [0xe6, 'clock_nanosleep'], // 230 — corrected: was 0xe8 (collided with epoll_wait)

  // Epoll (CRITICAL for uv_loop_init)
  [0xd5, 'epoll_create'], // 213
  [0x123, 'epoll_create1'], // 291
  [0xe9, 'epoll_ctl'], // 233
  [0xe8, 'epoll_wait'], // 232 — authoritative owner of 0xe8
  [0x119, 'epoll_pwait'], // 281

  // Eventfd/pipe (used by libuv)
  [0x11c, 'eventfd'], // 284 — corrected: was 0x11d (fallocate)
  [0x122, 'eventfd2'], // 290 — corrected: was 0x120 (accept4)
  [0x16, 'pipe'], // 22
  [0x125, 'pipe2'], // 293

  // File control
  [0x48, 'fcntl'], // 72
  [0x10, 'ioctl'], // 16 — corrected: was 0x49 (flock)

  // Random
  [0x13e, 'getrandom'], // 318

  // Misc
  [0x27, 'getpid'], // 39
  [0xba, 'gettid'], // 186
  [0x3c, 'exit'], // 60
  [0xe7, 'exit_group'], // 231
];

/**
 * Build a syscall number → name Map, failing loudly on duplicate numeric keys.
 * @throws Error if any syscall number appears more than once.
 */
export function buildSyscallMap(
  table: ReadonlyArray<readonly [number, string]> = SYSCALL_TABLE,
): Map<number, string> {
  const map = new Map<number, string>();
  for (const [nr, name] of table) {
    const existing = map.get(nr);
    if (existing !== undefined) {
      throw new Error(
        `D1 syscall decoder: duplicate syscall number 0x${nr.toString(16)} ` +
          `(${nr}) assigned to both '${existing}' and '${name}'`,
      );
    }
    map.set(nr, name);
  }
  return map;
}

/** Frozen number → name Map. Construction throws on any duplicate key. */
export const SYSCALL_MAP: ReadonlyMap<number, string> = buildSyscallMap();

/**
 * Decode a syscall number to its name.
 * Unknown numbers return the sentinel `syscall_<nr>` and are treated as unknown
 * by callers (they are never in SYSCALL_MAP).
 */
export function decodeSyscall(nr: number): string {
  return SYSCALL_MAP.get(nr) ?? `syscall_${nr}`;
}

/** True iff the syscall number has an authoritative decoded name. */
export function isKnownSyscall(nr: number): boolean {
  return SYSCALL_MAP.has(nr);
}
