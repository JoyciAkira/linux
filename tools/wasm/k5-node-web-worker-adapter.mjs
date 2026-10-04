import { Worker as NodeWorker } from 'node:worker_threads';

// Environment adaptation only: no syscall, broker, scheduler or lifecycle logic.
export class NodeWebWorkerAdapter {
  static workers = new Set();
  static observe = () => {};
  #worker;
  #listeners = new Map();
  onmessage = null;
  onerror = null;

  constructor(url, options = {}) {
    const targetUrl = url instanceof URL ? url.href : new URL(String(url), import.meta.url).href;
    this.targetUrl = targetUrl;
    this.name = options.name ?? '';
    this.#worker = new NodeWorker(new URL('./k5-node-worker-bootstrap.mjs', import.meta.url), {
      workerData: {targetUrl, name:this.name},
    });
    NodeWebWorkerAdapter.workers.add(this);
    NodeWebWorkerAdapter.observe({kind:'workerCreated', targetUrl, name:this.name}, this);
    this.#worker.on('message', data => {
      if (data?.type === '__node_adapter_observation') {
        NodeWebWorkerAdapter.observe(data, this);
        return;
      }
      NodeWebWorkerAdapter.observe({kind:'workerMessage', data}, this);
      const event = new MessageEvent('message', {data});
      this.onmessage?.(event);
      for (const listener of this.#listeners.get('message') ?? []) listener(event);
    });
    this.#worker.on('error', error => {
      const event = {type:'error', message:error.message, error};
      NodeWebWorkerAdapter.observe({kind:'workerError', error:String(error.stack ?? error)}, this);
      this.onerror?.(event);
      for (const listener of this.#listeners.get('error') ?? []) listener(event);
    });
    this.#worker.on('exit', code => {
      NodeWebWorkerAdapter.workers.delete(this);
      NodeWebWorkerAdapter.observe({kind:'nodeWorkerExit', code}, this);
    });
  }
  addEventListener(type, listener) {
    const listeners = this.#listeners.get(type) ?? new Set();
    listeners.add(listener);
    this.#listeners.set(type, listeners);
  }
  removeEventListener(type, listener) { this.#listeners.get(type)?.delete(listener); }
  postMessage(data, transfer = []) {
    NodeWebWorkerAdapter.observe({kind:'workerInit', data}, this);
    this.#worker.postMessage(data, transfer);
  }
  terminate() { return this.#worker.terminate(); }
}
