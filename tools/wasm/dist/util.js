export function assert(cond, message = "Assertation failed") {
    if (!cond)
        throw new Error(message);
}
export function unreachable(_, message = "Unreachable reached") {
    throw new Error(message);
}
export function validateEntry(value) {
    assert(typeof value === "object" && value !== null, "Missing user entry");
    const entry = value;
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
    return entry;
}
export class EventEmitter {
    #subscribers = {};
    on(event, handler) {
        (this.#subscribers[event] ??= new Set()).add(handler);
    }
    off(event, handler) {
        this.#subscribers[event]?.delete(handler);
    }
    emit(event, data) {
        this.#subscribers[event]?.forEach((handler) => handler(data));
    }
}
//# sourceMappingURL=util.js.map