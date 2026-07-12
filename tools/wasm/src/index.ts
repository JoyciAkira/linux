import { type DeviceTreeNode, generate_devicetree } from "./devicetree.ts";
import { assert, EventEmitter, unreachable } from "./util.ts";
import { virtio_imports, VirtioDevice } from "./virtio.ts";
import { type Imports, type Instance, kernel_imports } from "./wasm.ts";
import type { InitMessage, WorkerMessage } from "./worker.ts";

export {
  BlockDevice,
  type BlockDeviceStorage,
  ConsoleDevice,
  EntropyDevice,
  type VsockConnection,
  VsockDevice,
} from "./virtio.ts";

const resources = (async () => {
  const vmlinux_response = fetch(
    new URL("../vmlinux.wasm", import.meta.url),
  );

  let vmlinux: WebAssembly.Module;
  if ("compileStreaming" in WebAssembly) {
    vmlinux = await WebAssembly.compileStreaming(vmlinux_response);
  } else {
    const buffer = await (await vmlinux_response).arrayBuffer();
    vmlinux = await WebAssembly.compile(buffer);
  }

  const custom_section = (name: string) => {
    const sections = WebAssembly.Module.customSections(vmlinux, name);
    const section = sections[0];
    assert(section && sections.length === 1, `Missing custom section: ${name}`);
    return section;
  };

  const sections = JSON.parse(
    new TextDecoder().decode(custom_section(".linux.sections")),
  );
  const initramfs = new Uint8Array(custom_section(".linux.initramfs"));

  return {
    vmlinux,
    sections,
    initramfs,
  };
})();

const INITCPIO_ADDR = 0x200000;

export interface D1TraceMetadata {
  capacity: number;
  storedRecordCount: number;
  totalRecordCount: number;
  overwriteCount: number;
  firstStoredSequence: number | null;
  lastStoredSequence: number | null;
  wrapped: boolean;
}

export interface D1TraceExport {
  runId: string;
  records: Array<Record<string, unknown>>;
  metadata: D1TraceMetadata;
}

function isD1Record(r: unknown): r is Record<string, unknown> {
  if (typeof r !== "object" || r === null) return false;
  const o = r as Record<string, unknown>;
  if (typeof o.sequence !== "number") return false;
  if (typeof o.eventType !== "string") return false;
  if (o.eventType === "syscall_enter") {
    if (typeof o.rawSyscallNumber !== "number") return false;
    if (!Array.isArray(o.rawArguments)) return false;
    if ((o.rawArguments as unknown[]).length > 6) return false;
    if ((o.rawArguments as unknown[]).some((a) => typeof a !== "number")) return false;
  }
  if (o.eventType === "syscall_return" && typeof o.rawReturnValue !== "number") {
    return false;
  }
  return true;
}

function isD1Metadata(m: unknown): m is D1TraceMetadata {
  if (typeof m !== "object" || m === null) return false;
  const o = m as Record<string, unknown>;
  if (
    typeof o.capacity !== "number" ||
    typeof o.storedRecordCount !== "number" ||
    typeof o.totalRecordCount !== "number" ||
    typeof o.overwriteCount !== "number" ||
    typeof o.wrapped !== "boolean"
  ) {
    return false;
  }
  if (o.capacity > 4096) return false;
  if (o.storedRecordCount > o.capacity) return false;
  if (o.wrapped !== (o.overwriteCount > 0)) return false;
  return true;
}

export function decodeD1TraceExport(
  data: { runId?: unknown; records?: unknown; metadata?: unknown },
): D1TraceExport | null {
  if (typeof data.runId !== "string") return null;
  if (!Array.isArray(data.records)) return null;
  if (!isD1Metadata(data.metadata)) return null;
  if (data.records.length !== data.metadata.storedRecordCount) return null;
  if (!data.records.every(isD1Record)) return null;
  for (let i = 1; i < data.records.length; i++) {
    const prev = data.records[i - 1] as Record<string, unknown>;
    const cur = data.records[i] as Record<string, unknown>;
    if ((cur.sequence as number) <= (prev.sequence as number)) return null;
  }
  return {
    runId: data.runId,
    records: data.records as Array<Record<string, unknown>>,
    metadata: data.metadata,
  };
}

export class Machine extends EventEmitter<{
  error: ErrorEvent;
  d1_trace: D1TraceExport;
}> {
  #boot_console: TransformStream<Uint8Array, Uint8Array>;
  #boot_console_writer: WritableStreamDefaultWriter<Uint8Array>;
  #workers: Worker[] = [];
  #memory: WebAssembly.Memory;
  #devices: VirtioDevice[];
  #initcpio?: ArrayBufferView;
  #ncpus: number;
  #d1_trace_enabled: boolean = false;
  #d1_run_id: string = "d1-run";
  #process_event_handler?: (
    event_kind: number,
    run_id_hi: bigint,
    run_id_lo: bigint,
    event_seq: bigint,
    pid: number,
    tgid: number,
    ppid: number,
    worker_id: number,
    data0: bigint,
    data1: bigint,
    comm: string,
  ) => void;

  memory: Uint8Array;
  devicetree: DeviceTreeNode;

  get bootConsole() {
    return this.#boot_console.readable;
  }

  constructor(options: {
    cmdline?: string;
    memoryMib?: number;
    cpus?: number;
    devices: VirtioDevice[];
    initcpio?: ArrayBufferView;
    d1TraceEnabled?: boolean;
    d1RunId?: string;
    processEventHandler?: (
      event_kind: number,
      run_id_hi: bigint,
      run_id_lo: bigint,
      event_seq: bigint,
      pid: number,
      tgid: number,
      ppid: number,
      worker_id: number,
      data0: bigint,
      data1: bigint,
      comm: string,
    ) => void;
  }) {
    super();
    this.#boot_console = new TransformStream<Uint8Array, Uint8Array>();
    this.#boot_console_writer = this.#boot_console.writable.getWriter();
    this.#devices = options.devices;
    this.#initcpio = options.initcpio;
    this.#ncpus = options.cpus ?? navigator.hardwareConcurrency;
    this.#process_event_handler = options.processEventHandler;
    this.#d1_trace_enabled = options.d1TraceEnabled === true;
    this.#d1_run_id = options.d1RunId ?? "d1-run";

    const PAGE_SIZE = 0x10000;
    const BYTES_PER_MIB = 0x100000;
    const bytes = (options.memoryMib ?? 128) * BYTES_PER_MIB;
    const pages = bytes / PAGE_SIZE;
    this.#memory = new WebAssembly.Memory({
      initial: pages,
      maximum: pages,
      shared: true,
    });
    assert(this.#memory.buffer.byteLength === bytes);
    this.memory = new Uint8Array(this.#memory.buffer);

    this.devicetree = {
      "#address-cells": 1,
      "#size-cells": 1,
      chosen: {
        "rng-seed": crypto.getRandomValues(new Uint8Array(64)),
        bootargs: `console=hvc0 ${options.cmdline ?? ""}`,
        ncpus: this.#ncpus,
      },
      aliases: {},
      memory: {
        device_type: "memory",
        reg: [0, bytes],
      },
      "reserved-memory": {
        "#address-cells": 1,
        "#size-cells": 1,
        ranges: undefined,
      },
    };

    if (this.#initcpio) {
      const chosen = this.devicetree.chosen as DeviceTreeNode;
      chosen["linux,initrd-start"] = INITCPIO_ADDR;
      chosen["linux,initrd-end"] = INITCPIO_ADDR + this.#initcpio.byteLength;

      this.memory.set(
        new Uint8Array(
          this.#initcpio.buffer,
          this.#initcpio.byteOffset,
          this.#initcpio.byteLength,
        ),
        INITCPIO_ADDR,
      );
    }

    for (const [i, dev] of this.#devices.entries()) {
      this.devicetree[`virtio${i}`] = {
        compatible: `virtio,wasm`,
        "host-id": i,
        "virtio-device-id": dev.ID,
        features: dev.features,
        config: dev.config_bytes,
      };
    }
  }

  async boot() {
    const memory_reservations: { address: number; size: number }[] = [];
    if (this.#initcpio) {
      memory_reservations.push({
        address: INITCPIO_ADDR,
        size: this.#initcpio.byteLength,
      });
    }

    const { sections, vmlinux, initramfs } = await resources;
    (this.devicetree.chosen as DeviceTreeNode).sections = sections;

    const devicetree = generate_devicetree(this.devicetree, {
      memory_reservations,
    });

    const boot_console_write = (message: ArrayBuffer) => {
      this.#boot_console_writer.write(new Uint8Array(message)).catch(() => {
        // Ignore errors if the console is closed
      });
    };
    const boot_console_close = () => {
      this.#boot_console_writer.close();
    };

    const spawn_worker = (
      fn: number,
      arg: number,
      name: string,
      user_module: WebAssembly.Module | null,
      user_memory: WebAssembly.Memory | null,
    ) => {
      const worker = new Worker(new URL("./worker.js", import.meta.url), {
        type: "module",
        name,
      });
      this.#workers.push(worker);
      worker.onmessage = (event: MessageEvent<WorkerMessage>) => {
        switch (event.data.type) {
          case "spawn_worker":
            spawn_worker(
              event.data.fn,
              event.data.arg,
              event.data.name,
              event.data.user_module,
              event.data.user_memory,
            );
            break;
          case "boot_console_write":
            boot_console_write(event.data.message);
            break;
          case "boot_console_close":
            boot_console_close();
            break;
          case "run_on_main":
            instance.exports.__indirect_function_table
              .get(event.data.fn)!(event.data.arg);
            break;
          case "d1_trace_export": {
            const decoded = decodeD1TraceExport(event.data);
            if (decoded !== null) this.emit("d1_trace", decoded);
            break;
          }
          default:
            unreachable(event.data);
        }
      };
      worker.onerror = (event) => {
        this.emit("error", event);
      };
      worker.postMessage(
        {
          fn,
          arg,
          vmlinux,
          memory: this.#memory,
          parent_user_module: user_module,
          parent_user_memory: user_memory,
          d1TraceEnabled: this.#d1_trace_enabled,
          d1RunId: this.#d1_run_id,
        } satisfies InitMessage,
      );
    };

    const unavailable = () => {
      throw new Error("not available on main thread");
    };

    const imports = {
      env: { memory: this.#memory },
      boot: {
        get_devicetree: (buf, size) => {
          assert(size >= devicetree.byteLength, "Device tree truncated");
          this.memory.set(devicetree, buf);
        },
        get_initramfs: (buf, size) => {
          assert(size >= initramfs.byteLength, "Initramfs truncated");
          this.memory.set(initramfs, buf);
          return initramfs.byteLength;
        },
      },
      kernel: kernel_imports({
        is_worker: false,
        memory: this.#memory,
        spawn_worker,
        boot_console_write,
        boot_console_close,
        run_on_main: unavailable,
        get_user_module: unavailable,
        get_user_memory: unavailable,
        process_event_handler: this.#process_event_handler,
      }),
      user: {
        compile: unavailable,
        instantiate: unavailable,
        call: unavailable,
        switch_entry: unavailable,
        call_signal_handler: unavailable,
        read: unavailable,
        write: unavailable,
        write_zeroes: unavailable,
      },
      virtio: virtio_imports({
        memory: this.#memory,
        devices: this.#devices,
        ncpus: this.#ncpus,
        trigger_irq_for_cpu(cpu, irq) {
          instance.exports.trigger_irq_for_cpu(cpu, irq);
        },
      }),
    } satisfies Imports;

    const instance =
      (await WebAssembly.instantiate(vmlinux, imports)) as Instance;
    instance.exports.boot();
  }
}
