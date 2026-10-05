/**
 * D1 Ring Buffer — bounded, fixed-capacity trace capture (lifecycle + syscall).
 *
 * Passive tracing: records are appended during execution and serialized after
 * the guest process completes. No console output, no blocking, no async work in
 * the record path. `sequence` is the canonical ordering authority and never
 * resets on wrap; wall-clock time is auxiliary only.
 */
export type D1EventType = 'trace_initialized' | 'worker_module_evaluated' | 'worker_start_message_received' | 'wasm_memory_constructed' | 'kernel_module_instantiated' | 'kernel_start_called' | 'kernel_start_returned' | 'userspace_shell_ready' | 'node_version_command_started' | 'node_version_command_completed' | 'node_eval_command_started' | 'node_eval_command_completed' | 'halt_user_observed' | 'trace_export_requested' | 'trace_export_completed' | 'trace_overwrite_observed' | 'trace_internal_error' | 'runtime_error_caught' | 'runtime_error_rethrown' | 'kernel_start_promise_rejected' | 'worker_error_event' | 'worker_messageerror_event' | 'worker_unhandledrejection' | 'syscall_enter' | 'syscall_return' | 'syscall_throw';
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
export type D1Record = D1SyscallEnter | D1SyscallReturn | D1SyscallThrow | D1LifecycleEvent | D1RuntimeErrorEvent;
export interface D1RingMetadata {
    capacity: number;
    storedRecordCount: number;
    totalRecordCount: number;
    overwriteCount: number;
    firstStoredSequence: number | null;
    lastStoredSequence: number | null;
    wrapped: boolean;
}
export declare class D1RingBuffer {
    private buffer;
    private readonly maxSize;
    private seq;
    private overwrites;
    constructor(maxSize?: number);
    private push;
    recordLifecycle(eventType: D1EventType, runId: string, context?: {
        threadId?: number;
        processId?: string;
        detail?: string;
    }): void;
    recordRuntimeError(error: unknown, runId: string, context?: {
        eventType?: 'runtime_error_caught' | 'runtime_error_rethrown' | 'kernel_start_promise_rejected' | 'worker_error_event' | 'worker_unhandledrejection';
        activeOperation?: string;
        threadId?: number;
        processId?: string;
    }): void;
    recordSyscallEnter(nr: number, args: readonly number[], runId: string, context?: {
        threadId?: number;
        processId?: string;
    }): void;
    recordSyscallReturn(nr: number, ret: number, runId: string, context?: {
        threadId?: number;
        processId?: string;
    }): void;
    recordSyscallThrow(nr: number, errorName: string, errorMessage: string, runId: string, context?: {
        threadId?: number;
        processId?: string;
    }): void;
    getRecords(): D1Record[];
    getMetadata(): D1RingMetadata;
    clear(): void;
}
