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
export declare const SYSCALL_TABLE: ReadonlyArray<readonly [number, string]>;
/**
 * Build a syscall number → name Map, failing loudly on duplicate numeric keys.
 * @throws Error if any syscall number appears more than once.
 */
export declare function buildSyscallMap(table?: ReadonlyArray<readonly [number, string]>): Map<number, string>;
/** Frozen number → name Map. Construction throws on any duplicate key. */
export declare const SYSCALL_MAP: ReadonlyMap<number, string>;
/**
 * Decode a syscall number to its name.
 * Unknown numbers return the sentinel `syscall_<nr>` and are treated as unknown
 * by callers (they are never in SYSCALL_MAP).
 */
export declare function decodeSyscall(nr: number): string;
/** True iff the syscall number has an authoritative decoded name. */
export declare function isKnownSyscall(nr: number): boolean;
