/**
 * D1 Syscall Wrapper — passive interception of the linux.syscall import.
 *
 * Records syscall_enter before forwarding, then syscall_return on normal
 * return or syscall_throw on a thrown exception. The kernel syscall export is
 * forwarded EXACTLY ONCE with the raw number and arguments unchanged, and its
 * raw return value is returned unchanged. A thrown exception is rethrown
 * unchanged. Recording is opt-in (enabled=false => pure passthrough).
 */
import { D1RingBuffer } from "./d1-ring-buffer.js";
export function wrapSyscall(originalSyscall, context) {
    if (!context.enabled) {
        return originalSyscall;
    }
    return function wrappedSyscall(nr, arg0, arg1, arg2, arg3, arg4, arg5) {
        const recordContext = {
            threadId: context.getThreadId?.(),
            processId: context.processId,
        };
        context.buffer.recordSyscallEnter(nr, [arg0, arg1, arg2, arg3, arg4, arg5], context.runId, recordContext);
        let ret;
        try {
            ret = originalSyscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
        }
        catch (error) {
            context.buffer.recordSyscallThrow(nr, error?.name ?? 'UnknownError', error?.message ?? String(error), context.runId, recordContext);
            throw error;
        }
        context.buffer.recordSyscallReturn(nr, ret, context.runId, recordContext);
        return ret;
    };
}
