/**
 * D1 Ring Buffer — bounded, fixed-capacity trace capture (lifecycle + syscall).
 *
 * Passive tracing: records are appended during execution and serialized after
 * the guest process completes. No console output, no blocking, no async work in
 * the record path. `sequence` is the canonical ordering authority and never
 * resets on wrap; wall-clock time is auxiliary only.
 */
import { decodeSyscall } from "./d1-syscall-decoder.js";
const ERRNO_NAMES = {
    1: 'EPERM', 2: 'ENOENT', 3: 'ESRCH', 4: 'EINTR', 5: 'EIO', 9: 'EBADF',
    11: 'EAGAIN', 12: 'ENOMEM', 13: 'EACCES', 14: 'EFAULT', 16: 'EBUSY',
    22: 'EINVAL', 25: 'ENOTTY', 38: 'ENOSYS',
};
function errnoNameFor(errno) {
    return ERRNO_NAMES[errno] ?? null;
}
export class D1RingBuffer {
    buffer = [];
    maxSize;
    seq = 0;
    overwrites = 0;
    constructor(maxSize = 4096) {
        this.maxSize = Math.min(maxSize, 4096);
    }
    push(record) {
        if (this.buffer.length < this.maxSize) {
            this.buffer.push(record);
        }
        else {
            this.buffer.shift();
            this.buffer.push(record);
            this.overwrites++;
        }
    }
    recordLifecycle(eventType, runId, context) {
        this.push({
            sequence: this.seq++,
            eventType,
            runId,
            monotonic: performance.now(),
            threadId: context?.threadId,
            processId: context?.processId,
            detail: context?.detail,
        });
    }
    recordRuntimeError(error, runId, context) {
        const err = error;
        const stack = err?.stack ?? null;
        const boundedStack = stack ? stack.slice(0, 8192) : null;
        let sourceFile;
        let sourceLine;
        let sourceColumn;
        let sourceFunction;
        if (boundedStack) {
            const locMatch = boundedStack.match(/at (.+?) \((.+?):(\d+):(\d+)\)/);
            if (locMatch) {
                const fn = locMatch[1];
                const file = locMatch[2];
                const line = locMatch[3];
                const col = locMatch[4];
                if (fn && file && line && col) {
                    sourceFunction = fn;
                    sourceFile = file;
                    sourceLine = parseInt(line, 10);
                    sourceColumn = parseInt(col, 10);
                }
            }
        }
        this.push({
            sequence: this.seq++,
            eventType: context?.eventType ?? 'runtime_error_caught',
            runId,
            monotonic: performance.now(),
            threadId: context?.threadId,
            processId: context?.processId,
            errorName: err?.name ?? 'UnknownError',
            errorMessage: (err?.message ?? String(error)).slice(0, 4096),
            boundedStack,
            sourceFile,
            sourceFunction,
            sourceLine,
            sourceColumn,
            activeOperation: context?.activeOperation,
            previousTraceSequence: this.seq > 0 ? this.seq - 1 : undefined,
        });
    }
    recordSyscallEnter(nr, args, runId, context) {
        this.push({
            sequence: this.seq++,
            eventType: 'syscall_enter',
            runId,
            monotonic: performance.now(),
            threadId: context?.threadId,
            processId: context?.processId,
            rawSyscallNumber: nr,
            decodedSyscallName: decodeSyscall(nr),
            rawArguments: args.slice(0, 6),
            argumentCount: args.length,
        });
    }
    recordSyscallReturn(nr, ret, runId, context) {
        const isErrno = ret < 0 && ret >= -4095;
        const errnoNumber = isErrno ? -ret : null;
        this.push({
            sequence: this.seq++,
            eventType: 'syscall_return',
            runId,
            monotonic: performance.now(),
            threadId: context?.threadId,
            processId: context?.processId,
            rawSyscallNumber: nr,
            decodedSyscallName: decodeSyscall(nr),
            rawReturnValue: ret,
            errnoNumber,
            errnoName: errnoNumber !== null ? errnoNameFor(errnoNumber) : null,
        });
    }
    recordSyscallThrow(nr, errorName, errorMessage, runId, context) {
        this.push({
            sequence: this.seq++,
            eventType: 'syscall_throw',
            runId,
            monotonic: performance.now(),
            threadId: context?.threadId,
            processId: context?.processId,
            rawSyscallNumber: nr,
            decodedSyscallName: decodeSyscall(nr),
            errorName,
            errorMessage: errorMessage.slice(0, 256),
        });
    }
    getRecords() {
        return this.buffer.slice();
    }
    getMetadata() {
        const first = this.buffer.length > 0 ? this.buffer[0].sequence : null;
        const last = this.buffer.length > 0 ? this.buffer[this.buffer.length - 1].sequence : null;
        return {
            capacity: this.maxSize,
            storedRecordCount: this.buffer.length,
            totalRecordCount: this.seq,
            overwriteCount: this.overwrites,
            firstStoredSequence: first,
            lastStoredSequence: last,
            wrapped: this.overwrites > 0,
        };
    }
    clear() {
        this.buffer = [];
        this.seq = 0;
        this.overwrites = 0;
    }
}
