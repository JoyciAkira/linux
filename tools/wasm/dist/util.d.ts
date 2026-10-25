export declare function assert(cond: unknown, message?: string): asserts cond;
export declare function unreachable(_: never, message?: string): never;
export type EntryPacket = {
    version: 1;
    imageId: bigint;
} & ({
    type: "START_PROCESS";
} | {
    type: "SWITCH_FUNCTION_TABLE";
    tableIndex: number;
    arg: number;
} | {
    type: "RESUME_FORK_IMAGE";
    forkPid: number;
});
export declare function validateEntry(value: unknown): EntryPacket;
export declare class EventEmitter<Events> {
    #private;
    on<K extends keyof Events>(event: K, handler: (data: Events[K]) => void): void;
    off<K extends keyof Events>(event: K, handler: (data: Events[K]) => void): void;
    protected emit<K extends keyof Events>(event: K, data: Events[K]): void;
}
//# sourceMappingURL=util.d.ts.map