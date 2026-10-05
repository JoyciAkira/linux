import { type Type } from "./bytes.ts";
import type { Imports } from "./wasm.ts";
declare const VirtqDescriptor_base: (new (view: ArrayBufferView) => {
    addr: bigint;
    len: number;
    id: number;
    flags: number;
}) & Type<{
    addr: bigint;
    len: number;
    id: number;
    flags: number;
}>;
declare class VirtqDescriptor extends VirtqDescriptor_base {
}
declare class Chain {
    #private;
    id: number;
    skip: number;
    desc: VirtqDescriptor[];
    constructor(mem: DataView, queue: Virtqueue, id: number, skip: number, desc: VirtqDescriptor[]);
    release(written: number): void;
    [Symbol.iterator](): Generator<{
        array: Uint8Array<ArrayBufferLike>;
        writable: boolean;
    }, void, unknown>;
}
declare class Virtqueue {
    #private;
    size: number;
    desc: VirtqDescriptor[];
    avail_wrap: boolean;
    used_wrap: boolean;
    used_idx: number;
    avail_idx: number;
    constructor(mem: DataView, size: number, desc_addr: number);
    [Symbol.iterator](): Generator<Chain, void, unknown>;
}
export declare abstract class VirtioDevice<Config extends object = object> {
    abstract readonly ID: number;
    abstract config_bytes: Uint8Array;
    abstract config: Config;
    features: bigint;
    trigger_interrupt: (kind: "config" | "vring") => void;
    vqs: Virtqueue[];
    enable(vq: number, queue: Virtqueue): void;
    disable(vq: number): void;
    abstract notify(vq: number): void;
    setup_complete(): void;
}
declare const EmptyStruct_base: (new (view: ArrayBufferView) => object) & Type<object>;
declare class EmptyStruct extends EmptyStruct_base {
}
declare const VsockConfig_base: (new (view: ArrayBufferView) => {
    guest_cid: bigint;
}) & Type<{
    guest_cid: bigint;
}>;
declare class VsockConfig extends VsockConfig_base {
}
export declare class VsockConnection {
    #private;
    local_port: number;
    peer_port: number;
    constructor(device: VsockDevice, local_port: number, peer_port: number);
    get bytes_read(): number;
    update_credit(buf_alloc: number, fwd_cnt: number): void;
    enqueue(data: Uint8Array): void;
    close_from_peer(): void;
    read(): Promise<Uint8Array>;
    readExactly(length: number): Promise<Uint8Array>;
    write(data: Uint8Array): void;
    close(): void;
}
export declare class VsockDevice extends VirtioDevice<VsockConfig> {
    #private;
    ID: number;
    config_bytes: Uint8Array<ArrayBuffer>;
    config: VsockConfig;
    constructor({ guestCid }?: {
        guestCid?: bigint;
    });
    connect(port: number, { timeoutMs }?: {
        timeoutMs?: number | undefined;
    }): Promise<VsockConnection>;
    send_packet(connection: VsockConnection, op: number, flags: number, payload: Uint8Array): void;
    notify(vq: number): void;
}
declare const BlockDeviceConfig_base: (new (view: ArrayBufferView) => {
    capacity: bigint;
}) & Type<{
    capacity: bigint;
}>;
declare class BlockDeviceConfig extends BlockDeviceConfig_base {
}
type MaybePromise<T> = T | Promise<T>;
export interface BlockDeviceStorage {
    read(offset: number, length: number): MaybePromise<Uint8Array>;
    write?(offset: number, data: Uint8Array): MaybePromise<number>;
    flush?(): MaybePromise<void>;
    capacity: number;
}
export declare class BlockDevice extends VirtioDevice<BlockDeviceConfig> {
    #private;
    ID: number;
    config_bytes: Uint8Array<ArrayBuffer>;
    config: BlockDeviceConfig;
    constructor(storage: BlockDeviceStorage);
    notify(vq: number): Promise<void>;
}
export declare class ConsoleDevice extends VirtioDevice<EmptyStruct> {
    #private;
    ID: number;
    config_bytes: Uint8Array<ArrayBuffer>;
    config: EmptyStruct;
    constructor(input: ReadableStream<Uint8Array>, output: WritableStream<Uint8Array>);
    notify(vq: number): Promise<void>;
}
export declare class EntropyDevice extends VirtioDevice<EmptyStruct> {
    ID: number;
    config_bytes: Uint8Array<ArrayBuffer>;
    config: EmptyStruct;
    notify(vq: number): void;
}
declare const NetworkDeviceConfig_base: (new (view: ArrayBufferView) => {
    mac: number[];
    status: number;
    max_virtqueue_pairs: number;
    mtu: number;
}) & Type<{
    mac: number[];
    status: number;
    max_virtqueue_pairs: number;
    mtu: number;
}>;
declare class NetworkDeviceConfig extends NetworkDeviceConfig_base {
}
/**
 * Host-side Ethernet transport for virtio-net.  The bridge deliberately sees
 * complete Ethernet frames, rather than TCP sockets, so guest AF_INET remains
 * owned by the guest kernel.  A production bridge must translate frames into
 * the frozen NBR-3 socket protocol explicitly; it must not substitute fetch
 * or a host Node socket.
 */
export interface NetworkBridge {
    setReceiver(receiver: (frame: Uint8Array) => void): void;
    sendFrame(frame: Uint8Array): void | Promise<void>;
}
/** A deterministic Ethernet loopback bridge for kernel/device bring-up. */
export declare class LoopbackNetworkBridge implements NetworkBridge {
    #private;
    setReceiver(receiver: (frame: Uint8Array) => void): void;
    sendFrame(frame: Uint8Array): void;
}
export declare class NetworkDevice extends VirtioDevice<NetworkDeviceConfig> {
    #private;
    private readonly bridge;
    ID: number;
    config_bytes: Uint8Array<ArrayBuffer>;
    config: NetworkDeviceConfig;
    constructor(bridge: NetworkBridge, { mac, mtu }?: {
        mac?: readonly number[];
        mtu?: number;
    });
    receiveFrame(frame: Uint8Array): void;
    notify(vq: number): Promise<void>;
}
export declare function virtio_imports({ memory, devices, ncpus, trigger_irq_for_cpu, }: {
    memory: WebAssembly.Memory;
    devices: VirtioDevice[];
    ncpus: number;
    trigger_irq_for_cpu: (cpu: number, irq: number) => void;
}): Imports["virtio"];
export {};
