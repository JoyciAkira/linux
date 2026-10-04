import {parentPort, workerData} from 'node:worker_threads';
if (!parentPort || !workerData?.targetUrl) throw new Error('Node worker adapter requires a target URL');

// Browser environment only. The requested production module owns all KWA logic.
const listeners = new Map();
let onmessage;
let kernelModule;
const seenInstances = new WeakSet();
const observation = data => parentPort.postMessage({type:'__node_adapter_observation', ...data});
const NativeInstance = WebAssembly.Instance;
const recordInstance = (module, instance) => {
  if (!seenInstances.has(instance)) {
    seenInstances.add(instance);
    const exports=WebAssembly.Module.exports(module).map(e=>e.name);
    observation({kind:'wasmInstanceCreated',
      kernel:module === kernelModule || (exports.includes('boot') && exports.includes('syscall')), exports});
  }
  return instance;
};
WebAssembly.Instance = new Proxy(NativeInstance, {
  construct(target, args) { return recordInstance(args[0], Reflect.construct(target, args)); },
});
const nativeInstantiate = WebAssembly.instantiate.bind(WebAssembly);
WebAssembly.instantiate = async (module, imports) => {
  const result = await nativeInstantiate(module, imports);
  if (module instanceof WebAssembly.Module) recordInstance(module, result);
  else recordInstance(result.module, result.instance);
  return result;
};

globalThis.self = globalThis;
globalThis.name = workerData.name ?? '';
globalThis.postMessage = (data, transfer = []) => parentPort.postMessage(data, transfer);
globalThis.close = () => parentPort.close();
Object.defineProperty(globalThis, 'onmessage', {configurable:true,
  get:()=>onmessage, set:handler=>{onmessage=handler;}});
globalThis.addEventListener = (type, handler) => {
  const callbacks = listeners.get(type) ?? new Set();
  callbacks.add(handler);
  listeners.set(type, callbacks);
};
globalThis.removeEventListener = (type, handler) => listeners.get(type)?.delete(handler);
process.on('uncaughtExceptionMonitor', error => {
  for (const callback of listeners.get('error') ?? []) callback({error, message:error.message});
});
process.on('unhandledRejection', reason => {
  for (const callback of listeners.get('unhandledrejection') ?? []) callback({reason});
  observation({kind:'unhandledRejection', error:String(reason?.stack ?? reason)});
});
parentPort.on('messageerror', error => {
  for (const callback of listeners.get('messageerror') ?? []) callback({error});
});

await import(workerData.targetUrl);
observation({kind:'targetModuleEvaluated', targetUrl:workerData.targetUrl});
// Register only after the module assigned handlers; native queued messages are retained.
parentPort.on('message', async data => {
  if (data?.kernelModule instanceof WebAssembly.Module) kernelModule = data.kernelModule;
  const event = new MessageEvent('message', {data});
  try {
    await onmessage?.(event);
    for (const callback of listeners.get('message') ?? []) await callback(event);
  } catch (error) {
    observation({kind:'adapterDispatchError', error:String(error?.stack ?? error)});
    queueMicrotask(() => {throw error;});
  }
});
