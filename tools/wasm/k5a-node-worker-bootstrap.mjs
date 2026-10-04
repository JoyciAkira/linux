#!/usr/bin/env node
// Test-only browser Worker adapter; production modules remain unmodified.
import { parentPort } from 'node:worker_threads';
if (!parentPort) throw new Error('K5A adapter requires a worker thread');
let handler;
let kernelInstance;
let kernelInstanceCount = 0;
const seen = new WeakSet();
const listeners = new Map();
const record = instance => {
  if (!seen.has(instance)) {
    seen.add(instance);
    kernelInstance = instance;
    parentPort.postMessage({type: 'k5a_instance_observed', count: ++kernelInstanceCount});
  }
  return instance;
};
const NativeInstance = WebAssembly.Instance;
WebAssembly.Instance = new Proxy(NativeInstance, {
  construct(target, args) { return record(Reflect.construct(target, args)); },
});
const nativeInstantiate = WebAssembly.instantiate.bind(WebAssembly);
WebAssembly.instantiate = async (...args) => {
  const result = await nativeInstantiate(...args);
  record(result instanceof NativeInstance ? result : result.instance);
  return result;
};
globalThis.self = {
  name: 'k5a-authority',
  postMessage: message => parentPort.postMessage(message),
  get onmessage() { return handler; },
  set onmessage(value) { handler = value; },
  addEventListener(type, callback) {
    const callbacks = listeners.get(type) ?? [];
    callbacks.push(callback);
    listeners.set(type, callbacks);
  },
  close() { parentPort.close(); },
};
globalThis.postMessage = self.postMessage;
process.on('unhandledRejection', reason => {
  parentPort.postMessage({type:'k5a_adapter_error', error:String(reason?.stack ?? reason)});
});
parentPort.on('message', async data => {
  try {
    await handler?.({data});
    for (const callback of listeners.get('message') ?? []) await callback({data});
  } catch (error) {
    parentPort.postMessage({type:'k5a_adapter_error', error:String(error?.stack ?? error)});
  }
});
await import('./dist/worker.js');
parentPort.postMessage({type:'k5a_adapter_ready'});
