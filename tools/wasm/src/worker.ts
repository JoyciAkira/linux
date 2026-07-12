import { assert } from "./util.ts";
import {
  HALT_KERNEL,
  type Imports,
  type Instance,
  kernel_imports,
} from "./wasm.ts";
import { D1RingBuffer, type D1Record, type D1RingMetadata } from "./d1-ring-buffer.ts";
import { wrapSyscall } from "./d1-syscall-wrapper.ts";

export interface InitMessage {
  fn: number;
  arg: number;
  vmlinux: WebAssembly.Module;
  memory: WebAssembly.Memory;
  parent_user_module: WebAssembly.Module | null;
  parent_user_memory: WebAssembly.Memory | null;
  d1TraceEnabled?: boolean;
  d1RunId?: string;
}
export type WorkerMessage =
  | {
    type: "spawn_worker";
    fn: number;
    arg: number;
    name: string;
    user_module: WebAssembly.Module | null;
    user_memory: WebAssembly.Memory | null;
  }
  | { type: "boot_console_write"; message: ArrayBuffer }
  | { type: "boot_console_close" }
  | { type: "run_on_main"; fn: number; arg: number }
  | {
    type: "d1_trace_export";
    runId: string;
    records: D1Record[];
    metadata: D1RingMetadata;
  };

const unavailable = () => {
  throw new Error("not available on worker thread");
};

const postMessage = self.postMessage as (message: WorkerMessage) => void;

const d1TraceBuffer = new D1RingBuffer(4096);
let d1TraceEnabled = false;
let d1RunId = "";
let d1Exported = false;

export function exportD1Trace(): void {
  if (!d1TraceEnabled || d1Exported) return;
  d1Exported = true;
  d1TraceBuffer.recordLifecycle("trace_export_requested", d1RunId);
  if (d1TraceBuffer.getMetadata().wrapped) {
    d1TraceBuffer.recordLifecycle("trace_overwrite_observed", d1RunId);
  }
  d1TraceBuffer.recordLifecycle("trace_export_completed", d1RunId);
  const records = d1TraceBuffer.getRecords();
  const metadata = d1TraceBuffer.getMetadata();
  postMessage({ type: "d1_trace_export", runId: d1RunId, records, metadata });
}

function user_imports({
  kernel_memory,
  get_kernel_instance,
  parent_user_module: parent_module,
  parent_user_memory: parent_memory,
}: {
  kernel_memory: WebAssembly.Memory;
  get_kernel_instance: () => Instance;
  parent_user_module: WebAssembly.Module | null;
  parent_user_memory: WebAssembly.Memory | null;
}): {
  module: WebAssembly.Module | null;
  memory: WebAssembly.Memory | null;
  imports: Imports["user"];
} {
  const HALT_USER = Symbol("halt user");

  const kernel_memory_buffer = new Uint8Array(kernel_memory.buffer);
  let module: WebAssembly.Module | null = null;
  let instance: WebAssembly.Instance | null = null;
  let memory: WebAssembly.Memory | null = null;

  function call_start(): void {
    assert(instance);
    const { _start } = instance.exports;
    assert(typeof _start === "function", "_start not found");
    _start();
    throw new Error("_start reached the end without exiting");
  }
  let call_entry = call_start;

  return {
    get module() {
      return module;
    },
    get memory() {
      return memory;
    },
    imports: {
      // program management:
      compile(buf, size) {
        const bytes = new Uint8Array(
          kernel_memory_buffer.slice(buf, buf + size),
        );
        try {
          module = new WebAssembly.Module(bytes);
          return 0;
        } catch {
          return -8; // exec format error
        }
      },
      instantiate(fresh_memory) {
        assert(module);

        if (fresh_memory || !memory) {
          // memory.grow su shared memory importata fallisce a runtime; quindi la
          // memory deve nascere gia' abbastanza grande per processi come Node/blink
          // (99MB file + heap V8). initial alto, non affidarsi a grow.
          const initial = 12288; // 768 MiB iniziali
          const maximum = 32768; // 2 GiB tetto

          memory = new WebAssembly.Memory({
            initial,
            maximum,
            shared: true,
          });
          if (d1TraceEnabled) {
            d1TraceBuffer.recordLifecycle("wasm_memory_constructed", d1RunId, {
              detail: `initial=${initial} maximum=${maximum}`,
            });
          }
        }

        const kernel_instance = get_kernel_instance();

        // console.log("instantiating with", memory);
        try {
          // D1: Define original syscall handler (before wrapping)
          const originalSyscallHandler = (
            nr: number,
            arg0: number,
            arg1: number,
            arg2: number,
            arg3: number,
            arg4: number,
            arg5: number,
          ): number => {
            const original_instance = instance;
            const ret = kernel_instance.exports.syscall(
              nr,
              arg0,
              arg1,
              arg2,
              arg3,
              arg4,
              arg5,
            );
            if (instance !== original_instance) {
              // if the instance changed, then this was the exec syscall,
              // so call into the new instance:
              call_entry = call_start;

              // and we never want to return to the caller of the syscall, so
              // skip straight to the catch block of the parent's call_entry
              throw HALT_USER;
            }
            return ret;
          };

          const wrappedSyscallHandler = wrapSyscall(originalSyscallHandler, {
            buffer: d1TraceBuffer,
            runId: d1RunId,
            enabled: d1TraceEnabled,
            processId: `worker-${self.name || "unknown"}`,
            getThreadId: () => 0,
          });

          instance = new WebAssembly.Instance(module, {
            env: { memory },
            linux: {
              syscall: wrappedSyscallHandler,
              get_thread_area: kernel_instance.exports.get_thread_area,
              get_args_length: kernel_instance.exports.get_args_length,
              get_args: kernel_instance.exports.get_args,
            },
          });

          if ("memory" in instance.exports) {
            assert(instance.exports.memory instanceof WebAssembly.Memory);
            memory = instance.exports.memory;
          }
          if (d1TraceEnabled) {
            d1TraceBuffer.recordLifecycle("kernel_module_instantiated", d1RunId);
          }
        } catch (error) {
          console.log("error instantiating user module:", String(error));
        }
      },
      call() {
        if (d1TraceEnabled) {
          d1TraceBuffer.recordLifecycle("kernel_start_called", d1RunId);
        }
        for (;;) {
          try {
            call_entry();
          } catch (error) {
            if (error === HALT_USER) {
              if (d1TraceEnabled) {
                d1TraceBuffer.recordLifecycle("halt_user_observed", d1RunId);
              }
              continue;
            }
            if (error === HALT_KERNEL) throw error;
            console.log("error running user module:", String(error), (error && (error as Error).stack) || "");
            if (d1TraceEnabled) {
              d1TraceBuffer.recordRuntimeError(error, d1RunId, {
                eventType: "runtime_error_caught",
                activeOperation: "call_entry",
              });
              d1TraceBuffer.recordLifecycle("kernel_start_returned", d1RunId, {
                detail: (error as Error)?.name ?? "error",
              });
              exportD1Trace();
            }
            return;
          }
        }
      },
      switch_entry(fn, arg) {
        // This is called if this thread was created by a clone call,
        // and therefore we our entrypoint is a user-specified function.
        // Our custom variant of the clone syscall spawns a worker that calls
        // switch_entry, then immediately calls instantiate.
        console.log("[CLONE] switch_entry fn=" + fn + " arg=" + arg + " parent_module=" + !!parent_module + " parent_memory=" + !!parent_memory);

        assert(parent_module);
        assert(parent_memory);

        module = parent_module;
        memory = parent_memory;

        call_entry = () => {
          assert(instance);

          const { __indirect_function_table } = instance.exports;
          assert(
            __indirect_function_table instanceof WebAssembly.Table,
            "Invalid function table",
          );

          const f = __indirect_function_table.get(fn);
          console.log("[CLONE] resolved fn=" + fn + " -> " + typeof f + " len=" + (f && f.length));
          assert(
            typeof f === "function" && f.length === 1,
            "Invalid function signature",
          );

          console.log("[CLONE] calling f(" + arg + ")");
          f(arg);
          console.log("[CLONE] f returned");

          // throw new Error("thread entrypoint reached the end without exiting");
          console.warn("thread entrypoint reached the end without exiting");
        };
      },

      // signal handling:
      call_signal_handler(fn, sig) {
        assert(instance);

        const { __indirect_function_table } = instance.exports;
        assert(
          __indirect_function_table instanceof WebAssembly.Table,
          "Invalid function table",
        );

        const f = __indirect_function_table.get(fn);
        assert(
          typeof f === "function" && f.length === 1,
          "Invalid function signature",
        );

        f(sig); // TODO: the siginfo overload
      },

      // memory:
      read(to, from, n) {
        assert(memory);
        const slice = new Uint8Array(memory.buffer, from, n);
        kernel_memory_buffer.set(slice, to);
        return n - slice.length;
      },
      write(to, from, n) {
        assert(memory);
        const slice = kernel_memory_buffer.subarray(from, from + n);
        new Uint8Array(memory.buffer, to, n).set(slice);
        return n - slice.length;
      },
      write_zeroes(to, n) {
        assert(memory);
        const slice = new Uint8Array(memory.buffer, to, n);
        slice.fill(0);
        return n - slice.length;
      },
    },
  };
}

self.onmessage = (event: MessageEvent<InitMessage>) => {
  const { fn, arg, vmlinux, memory, parent_user_module, parent_user_memory } =
    event.data;

  if (event.data.d1TraceEnabled === true) {
    d1TraceEnabled = true;
    d1RunId = event.data.d1RunId ?? "d1-run";
    d1TraceBuffer.recordLifecycle("trace_initialized", d1RunId);
    d1TraceBuffer.recordLifecycle("worker_start_message_received", d1RunId);
  }

  const user = user_imports({
    kernel_memory: memory,
    get_kernel_instance: () => instance,
    parent_user_module,
    parent_user_memory,
  });

  const imports = {
    env: { memory },
    boot: {
      get_devicetree: unavailable,
      get_initramfs: unavailable,
    },
    user: user.imports,
    kernel: kernel_imports({
      is_worker: true,
      memory,
      spawn_worker(fn, arg, name, user_module, user_memory) {
        postMessage({
          type: "spawn_worker",
          fn,
          arg,
          name,
          user_module,
          user_memory,
        });
      },
      boot_console_write(message) {
        postMessage({ type: "boot_console_write", message });
      },
      boot_console_close() {
        postMessage({ type: "boot_console_close" });
      },
      run_on_main(fn, arg) {
        postMessage({ type: "run_on_main", fn, arg });
      },
      get_user_module() {
        return user.module;
      },
      get_user_memory() {
        return user.memory;
      },
    }),
    virtio: {
      set_features: unavailable,
      setup: unavailable,
      enable_vring: unavailable,
      disable_vring: unavailable,
      notify: unavailable,
    },
  } satisfies Imports;

  const instance = new WebAssembly.Instance(vmlinux, imports) as Instance;
  try {
    instance.exports.__indirect_function_table.get(fn)!(arg);
  } catch (error) {
    if (error === HALT_KERNEL) return;
    throw error;
  }
};

self.addEventListener("error", (event: ErrorEvent) => {
  if (d1TraceEnabled) {
    d1TraceBuffer.recordRuntimeError(event.error ?? event.message, d1RunId, {
      eventType: "worker_error_event",
      activeOperation: "self.onerror",
    });
  }
});
self.addEventListener("messageerror", () => {
  if (d1TraceEnabled) {
    d1TraceBuffer.recordLifecycle("worker_messageerror_event", d1RunId);
  }
});
self.addEventListener("unhandledrejection", (event: PromiseRejectionEvent) => {
  if (d1TraceEnabled) {
    d1TraceBuffer.recordRuntimeError(event.reason, d1RunId, {
      eventType: "worker_unhandledrejection",
      activeOperation: "unhandledrejection",
    });
  }
});
