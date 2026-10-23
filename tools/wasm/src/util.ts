export function assert(
  cond: unknown,
  message = "Assertation failed",
): asserts cond {
  if (!cond) throw new Error(message);
}

export function unreachable(_: never, message = "Unreachable reached"): never {
  throw new Error(message);
}

export type EntryPacket = { version: 1; imageId: bigint } & (
  | { type: "START_PROCESS" }
  | { type: "SWITCH_FUNCTION_TABLE"; tableIndex: number; arg: number }
  | { type: "RESUME_FORK_IMAGE"; forkPid: number }
);

export function validateEntry(value: unknown): EntryPacket {
  assert(typeof value === "object" && value !== null, "Missing user entry");
  const entry = value as Record<string, unknown>;
  assert(entry.version === 1, "Unsupported user entry version");
  assert(typeof entry.imageId === "bigint" && entry.imageId > 0n, "Invalid image identity");
  switch (entry.type) {
    case "START_PROCESS":
      break;
    case "SWITCH_FUNCTION_TABLE":
      assert(typeof entry.tableIndex === "number" &&
        Number.isInteger(entry.tableIndex) && entry.tableIndex >= 0 &&
        entry.tableIndex <= 0xffffffff, "Invalid function table index");
      assert(typeof entry.arg === "number" && Number.isInteger(entry.arg) &&
        entry.arg >= -0x80000000 && entry.arg <= 0xffffffff, "Invalid wasm argument");
      break;
    case "RESUME_FORK_IMAGE":
      assert(typeof entry.forkPid === "number" && Number.isInteger(entry.forkPid) &&
        entry.forkPid > 0 && entry.forkPid <= 0x7fffffff, "Invalid fork PID");
      break;
    default:
      throw new Error("Unknown user entry type");
  }
  return entry as EntryPacket;
}

export class EventEmitter<Events> {
  #subscribers: { [K in keyof Events]?: Set<(data: Events[K]) => void> } = {};
  on<K extends keyof Events>(event: K, handler: (data: Events[K]) => void) {
    (this.#subscribers[event] ??= new Set()).add(handler);
  }
  off<K extends keyof Events>(event: K, handler: (data: Events[K]) => void) {
    this.#subscribers[event]?.delete(handler);
  }
  protected emit<K extends keyof Events>(event: K, data: Events[K]) {
    this.#subscribers[event]?.forEach((handler) => handler(data));
  }
}
