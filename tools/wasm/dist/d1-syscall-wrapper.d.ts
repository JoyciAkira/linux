/**
 * D1 Syscall Wrapper — passive interception of the linux.syscall import.
 *
 * Records syscall_enter before forwarding, then syscall_return on normal
 * return or syscall_throw on a thrown exception. The kernel syscall export is
 * forwarded EXACTLY ONCE with the raw number and arguments unchanged, and its
 * raw return value is returned unchanged. A thrown exception is rethrown
 * unchanged. Recording is opt-in (enabled=false => pure passthrough).
 */
import { D1RingBuffer } from './d1-ring-buffer.ts';
export type SyscallHostFn = (nr: number, arg0: number, arg1: number, arg2: number, arg3: number, arg4: number, arg5: number) => number;
export interface D1WrapperContext {
    buffer: D1RingBuffer;
    runId: string;
    enabled: boolean;
    processId: string;
    getThreadId?: () => number;
}
export declare function wrapSyscall(originalSyscall: SyscallHostFn, context: D1WrapperContext): SyscallHostFn;
