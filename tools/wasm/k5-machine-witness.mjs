import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {dirname, join} from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {NodeWebWorkerAdapter} from './k5-node-web-worker-adapter.mjs';

const dir = dirname(fileURLToPath(import.meta.url));
export const sha256 = path => createHash('sha256').update(readFileSync(path)).digest('hex');
export const json = value => JSON.stringify(value, (_,v)=>typeof v==='bigint'?v.toString():v, 2);

// All runtime semantics stay in the actual Machine, production worker and kernel.
export async function runMachineWitness({kernelPath, archivePath, magic, phaseWord, timeoutMs=30000}) {
  const result = {events:[], rawEvents:[], timeline:[], authority:[], errors:[], adapter:[], guest:null,
    brokerSab:null, machineConstructed:false, machineBootEntered:false, machineBootReturned:false,
    mainKernelInstances:0, kernelInstances:0, secondaryKernelInstances:0,
    secondaryKernelDeliveries:0, targetModulesEvaluated:0, workerCount:0};
  let finish;
  const checkpoint = new Promise(resolve=>{finish=resolve;});
  const userMemories = new Set();
  const natives = {Worker:globalThis.Worker, fetch:globalThis.fetch, Instance:WebAssembly.Instance,
    instantiate:WebAssembly.instantiate};
  let authorityWorker;
  let pingResolve;
  const livePing = new Promise(resolve=>{pingResolve=resolve;});
  let timer;
  try {
    result.sourceCommit = execFileSync('git',['rev-parse','HEAD'],{cwd:dir,encoding:'utf8'}).trim();
    result.sourceTreeStatus = execFileSync('git',['status','--porcelain'],{cwd:dir,encoding:'utf8'});
    result.environmentIdentity = {node:process.version,platform:process.platform,arch:process.arch};
    result.artifacts = Object.fromEntries([kernelPath,archivePath,
      join(dir,'dist/index.js'),join(dir,'dist/worker.js'),join(dir,'dist/wasm.js'),
      join(dir,'dist/kwa-broker.js'),join(dir,'k5-node-web-worker-adapter.mjs'),
      join(dir,'k5-node-worker-bootstrap.mjs'),join(dir,'k5-machine-witness.mjs'),
    ].map(path=>[path,{sha256:sha256(path),bytes:readFileSync(path).byteLength}]));
    const recordMainInstance = (module, instance) => {
      const names = WebAssembly.Module.exports(module).map(e=>e.name);
      if (names.includes('boot') && names.includes('syscall')) result.mainKernelInstances++;
      return instance;
    };
    WebAssembly.Instance = new Proxy(natives.Instance, {
      construct(target,args) {return recordMainInstance(args[0],Reflect.construct(target,args));},
    });
    WebAssembly.instantiate = async (...args)=>{
      const instantiated = await natives.instantiate(...args);
      if(args[0] instanceof WebAssembly.Module) recordMainInstance(args[0],instantiated);
      else recordMainInstance(instantiated.module,instantiated.instance);
      return instantiated;
    };
    const watchGuest = memory => {
      if (!(memory instanceof WebAssembly.Memory) || !(memory.buffer instanceof SharedArrayBuffer) || userMemories.has(memory)) return;
      userMemories.add(memory);
      const words = new Int32Array(memory.buffer);
      const check = () => {
        if (Atomics.load(words,phaseWord) !== 1 || Atomics.load(words,0) !== magic) return;
        result.guest = {words:Array.from(words.subarray(0,8)),bytes:memory.buffer.byteLength};
        finish();
      };
      check();
      const wait = Atomics.waitAsync(words,phaseWord,0,timeoutMs);
      if(wait.async) wait.value.then(check);
      else check();
    };
    NodeWebWorkerAdapter.observe = (observation,worker) => {
      if(observation.kind === 'workerCreated') {
        result.workerCount++;
        result.adapter.push({kind:observation.kind,targetUrl:observation.targetUrl,name:observation.name});
      } else if(observation.kind === 'targetModuleEvaluated') {
        result.targetModulesEvaluated++;
        result.adapter.push(observation);
      } else if(observation.kind === 'wasmInstanceCreated') {
        if(observation.kernel) {
          result.kernelInstances++;
          if(worker !== authorityWorker) result.secondaryKernelInstances++;
        }
        result.adapter.push({kind:observation.kind,kernel:observation.kernel,exports:observation.exports});
      } else if(observation.kind === 'workerInit') {
        const data=observation.data;
        if(data && typeof data==='object') result.adapter.push({kind:'workerInit',name:worker.name,
          keys:Object.keys(data),taskToken:data.taskToken,workerId:data.workerId,
          isKernelAuthority:data.isKernelAuthority===true,hasUserMemory:data.parent_user_memory instanceof WebAssembly.Memory});
        if(data?.isKernelAuthority) authorityWorker=worker;
        if(data?.kernelModule && worker !== authorityWorker) result.secondaryKernelDeliveries++;
        if(data?.brokerSab) result.brokerSab=data.brokerSab;
        if(!data?.isKernelAuthority) watchGuest(data?.parent_user_memory);
      } else if(observation.kind === 'workerMessage') {
        if(['process_event','authority_diag'].includes(observation.data?.type)) {
          result.timeline.push({observationOrder:result.timeline.length+1,message:observation.data});
        }
        if(observation.data?.type==='process_event') result.rawEvents.push(observation.data);
        if(observation.data?.type==='authority_diag' && observation.data.stage==='K5A_PONG') pingResolve(observation.data);
      } else if(['workerError','adapterDispatchError','unhandledRejection'].includes(observation.kind)) {
        result.errors.push(observation.error);
        finish();
      }
    };
    globalThis.Worker = NodeWebWorkerAdapter;
    globalThis.fetch = async (input,options) => {
      const url = input instanceof Request ? new URL(input.url) : new URL(String(input));
      if(url.protocol !== 'file:') return natives.fetch(input,options);
      const requested = fileURLToPath(url);
      const path = requested === join(dir,'vmlinux.wasm') ? kernelPath : requested;
      return new Response(readFileSync(path),{headers:{'Content-Type':path.endsWith('.wasm')?'application/wasm':'application/octet-stream'}});
    };
    const {Machine} = await import('./dist/index.js');
    const machine = new Machine({devices:[],cpus:1,memoryMib:128,initcpio:readFileSync(archivePath)});
    result.machineConstructed = true;
    machine.on('process_event',event=>result.events.push(event));
    machine.on('authority_diag',event=>{
      result.authority.push(event);
      if(event.ok===false) {
        result.errors.push(event.detail?.stack??`${event.stage}: ${json(event.detail)}`);
        finish();
      }
    });
    machine.on('error',event=>{result.errors.push(String(event.error?.stack??event.message??event));finish();});
    const consoleReader = machine.bootConsole.getReader();
    result.console='';
    (async()=>{for(;;){const {done,value}=await consoleReader.read();if(done)break;result.console+=new TextDecoder().decode(value);}})()
      .catch(error=>{result.errors.push(String(error.stack??error));finish();});
    const deadline=new Promise((_,reject)=>{
      timer=setTimeout(()=>reject(new Error(`Machine/guest checkpoint timed out after ${timeoutMs}ms`)),timeoutMs);
    });
    result.machineBootEntered = true;
    await Promise.race([machine.boot(),deadline]);
    result.machineBootReturned = true;
    await Promise.race([checkpoint,deadline]);
    clearTimeout(timer);
    result.userSnapshots=[...userMemories].map(memory=>({
      words:Array.from(new Int32Array(memory.buffer).subarray(0,8)),bytes:memory.buffer.byteLength,
    }));
    if(authorityWorker && result.guest) {
      authorityWorker.postMessage({type:'k5a_ping'});
      result.authorityPing = await Promise.race([livePing,new Promise((_,reject)=>{
        timer=setTimeout(()=>reject(new Error('Authority ping timed out after guest checkpoint')),3000);
      })]);
      clearTimeout(timer);
    }
    if(result.brokerSab) {
      const {OFF}=await import('./dist/kwa-broker.js');
      const view=new Int32Array(result.brokerSab);
      result.brokerCounters=Object.fromEntries(Object.entries(OFF).filter(([name])=>name.endsWith('COUNT')||name==='BROKER_ERRORS')
        .map(([name,index])=>[name,Atomics.load(view,index)]));
    }
  } catch(error) {result.errors.push(String(error.stack??error));}
  finally {
    clearTimeout(timer);
    await Promise.all([...NodeWebWorkerAdapter.workers].map(worker=>worker.terminate()));
    NodeWebWorkerAdapter.observe=()=>{};
    globalThis.Worker=natives.Worker;
    globalThis.fetch=natives.fetch;
    WebAssembly.Instance=natives.Instance;
    WebAssembly.instantiate=natives.instantiate;
  }
  return result;
}
