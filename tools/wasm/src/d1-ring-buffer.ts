/**
 * D1 Ring Buffer — bounded, fixed-capacity trace capture (lifecycle + syscall).
 *
 * Passive tracing: records are appended during execution and serialized after
 * the guest process completes. No console output, no blocking, no async work in
 * the record path. `sequence` is the canonical ordering authority and never
 * resets on wrap; wall-clock time is auxiliary only.
 */

import { decodeSyscall } from './d1-syscall-decoder.ts';

export type D1EventType =
  | 'trace_initialized'
  | 'worker_module_evaluated'
  | 'worker_start_message_received'
  | 'wasm_memory_constructed'
  | 'kernel_module_instantiated'
  | 'kernel_start_called'
  | 'kernel_start_returned'
  | 'userspace_shell_ready'
  | 'node_version_command_started'
  | 'node_version_command_completed'
  | 'node_eval_command_started'
  | 'node_eval_command_completed'
  | 'halt_user_observed'
  | 'trace_export_requested'
  | 'trace_export_completed'
  | 'trace_overwrite_observed'
  | 'trace_internal_error'
  | 'runtime_error_caught'
  | 'runtime_error_rethrown'
  | 'kernel_start_promise_rejected'
  | 'worker_error_event'
  | 'worker_messageerror_event'
  | 'worker_unhandledrejection'
  | 'syscall_enter'
  | 'syscall_return'
  | 'syscall_throw';

export interface D1CommonFields {
  sequence: number;
  eventType: D1EventType;
  runId: string;
  monotonic: number;
  threadId?: number;
  processId?: string;
}

export interface D1SyscallEnter extends D1CommonFields {
  eventType: 'syscall_enter';
  rawSyscallNumber: number;
  decodedSyscallName: string;
  rawArguments: number[];
  argumentCount: number;
}

export interface D1SyscallReturn extends D1CommonFields {
  eventType: 'syscall_return';
  rawSyscallNumber: number;
  decodedSyscallName: string;
  rawReturnValue: number;
  errnoNumber: number | null;
  errnoName: string | null;
}

export interface D1SyscallThrow extends D1CommonFields {
  eventType: 'syscall_throw';
  rawSyscallNumber: number;
  decodedSyscallName: string;
  errorName: string;
  errorMessage: string;
}

export interface D1LifecycleEvent extends D1CommonFields {
  detail?: string;
}

export interface D1RuntimeErrorEvent extends D1CommonFields {
  eventType: 'runtime_error_caught' | 'runtime_error_rethrown' | 'kernel_start_promise_rejected';
  errorName: string;
  errorMessage: string;
  boundedStack: string | null;
  sourceFile?: string;
  sourceFunction?: string;
  sourceLine?: number;
  sourceColumn?: number;
  activeOperation?: string;
  previousTraceSequence?: number;
}

export type D1Record =
  | D1SyscallEnter
  | D1SyscallReturn
  | D1SyscallThrow
  | D1LifecycleEvent
  | D1RuntimeErrorEvent;

export interface D1RingMetadata {
  capacity: number;
  storedRecordCount: number;
  totalRecordCount: number;
  overwriteCount: number;
  firstStoredSequence: number | null;
  lastStoredSequence: number | null;
  wrapped: boolean;
}

const ERRNO_NAMES: Record<number, string> = {
  1: 'EPERM', 2: 'ENOENT', 3: 'ESRCH', 4: 'EINTR', 5: 'EIO', 9: 'EBADF',
  11: 'EAGAIN', 12: 'ENOMEM', 13: 'EACCES', 14: 'EFAULT', 16: 'EBUSY',
  22: 'EINVAL', 25: 'ENOTTY', 38: 'ENOSYS',
};

function errnoNameFor(errno: number): string | null {
  return ERRNO_NAMES[errno] ?? null;
}

export class D1RingBuffer {
  private buffer: D1Record[] = [];
  private readonly maxSize: number;
  private seq = 0;
  private overwrites = 0;

  constructor(maxSize: number = 4096) {
    this.maxSize = Math.min(maxSize, 4096);
  }

  private push(record: D1Record): void {
    if (this.buffer.length < this.maxSize) {
      this.buffer.push(record);
    } else {
      this.buffer.shift();
      this.buffer.push(record);
      this.overwrites++;
    }
  }

  recordLifecycle(
    eventType: D1EventType,
    runId: string,
    context?: { threadId?: number; processId?: string; detail?: string },
  ): void {
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

  recordRuntimeError(
    error: unknown,
    runId: string,
    context?: {
      eventType?: 'runtime_error_caught' | 'runtime_error_rethrown' | 'kernel_start_promise_rejected' | 'worker_error_event' | 'worker_unhandledrejection';
      activeOperation?: string;
      threadId?: number;
      processId?: string;
    },
  ): void {
    const err = error as Error | undefined;
    const stack = err?.stack ?? null;
    const boundedStack = stack ? stack.slice(0, 8192) : null;
    let sourceFile: string | undefined;
    let sourceLine: number | undefined;
    let sourceColumn: number | undefined;
    let sourceFunction: string | undefined;
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

  recordSyscallEnter(
    nr: number,
    args: readonly number[],
    runId: string,
    context?: { threadId?: number; processId?: string },
  ): void {
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

  recordSyscallReturn(
    nr: number,
    ret: number,
    runId: string,
    context?: { threadId?: number; processId?: string },
  ): void {
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

  recordSyscallThrow(
    nr: number,
    errorName: string,
    errorMessage: string,
    runId: string,
    context?: { threadId?: number; processId?: string },
  ): void {
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

  getRecords(): D1Record[] {
    return this.buffer.slice();
  }

  getMetadata(): D1RingMetadata {
    const first = this.buffer.length > 0 ? this.buffer[0]!.sequence : null;
    const last =
      this.buffer.length > 0 ? this.buffer[this.buffer.length - 1]!.sequence : null;
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

  clear(): void {
    this.buffer = [];
    this.seq = 0;
    this.overwrites = 0;
  }
}
