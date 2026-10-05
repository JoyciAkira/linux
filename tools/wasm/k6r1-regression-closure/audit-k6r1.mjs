import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
const [runtimeDir, out] = process.argv.slice(2);
const { runMachineWitness, json } = await import(pathToFileURL(join(runtimeDir, 'k5-machine-witness.mjs')));
const kernel = join(runtimeDir, 'vmlinux.wasm');
const sha256 = createHash('sha256').update(readFileSync(kernel)).digest('hex');
if (sha256 !== 'bbe4f538087179597bdfc31dbce672fcc34c16443f629bf222f8c7e616e829c1') throw new Error('Frozen kernel mismatch');
const run = await runMachineWitness({kernelPath:kernel,archivePath:join(runtimeDir,'k6-fault-injection.cpio'),magic:0x4b364649,phaseWord:7});
const words=run.guest?.words;
const events=run.rawEvents;
const parent=words?.[4], child=words?.[2];
const event=(kind,pid)=>events.find(e=>e.event_kind===kind&&e.pid===pid);
const chain=[event(8,child),event(4,child),event(9,child),event(6,child)];
const served=run.authority.filter(e=>e.stage==='BROKER_SERVED').map(e=>e.detail);
const trap=run.authority.find(e=>e.stage==='CHILD_WASM_TRAP_CAUGHT');
const storms=events.filter(e=>e.event_kind===8&&e.ppid===parent&&e.pid!==child);
const runIds=new Set(events.map(e=>`${BigInt.asUintN(64,BigInt(e.run_id_hi)).toString(16).padStart(16,'0')}${BigInt.asUintN(64,BigInt(e.run_id_lo)).toString(16).padStart(16,'0')}`));
const checks={
  CLEAN_SOURCE:run.sourceTreeStatus==='',
  PRODUCTION_MACHINE:run.machineConstructed&&run.machineBootEntered&&run.machineBootReturned&&run.targetModulesEvaluated>0,
  INVALID_SYSCALL:words?.[1]===-38,
  REAL_TRAP_OBSERVED:!!trap,
  SIGSEGV_WAIT_STATUS:child>0&&words?.[3]===11,
  TASK_DEAD_FROM_KERNEL:!!chain[1]&&Number(chain[1].data0)===11,
  RELEASE_AND_REAP:chain.every(Boolean)&&Number(chain[3]?.data0)===11&&chain.every((e,i)=>i===0||BigInt(e.event_seq)>BigInt(chain[i-1].event_seq)),
  WAIT4_EXACT_CHILD:served.some(e=>e.nr===260&&e.pid===parent&&e.result===child),
  STORM_TEN_REAL_CHILDREN:words?.[5]===10&&words?.[6]===10&&storms.length===10&&storms.every(({pid})=>{
    const dead=event(4,pid), release=event(9,pid), reap=event(6,pid);
    return dead&&release&&reap&&Number(dead.data0)===1792&&Number(reap.data0)===1792&&
      served.filter(e=>e.nr===172&&e.pid===pid&&e.result===pid).length===3&&
      served.some(e=>e.nr===260&&e.pid===parent&&e.result===pid);
  }),
  AUTHORITY_SURVIVES:parent>0&&!!run.authorityPing,
  SINGLE_AUTHORITY:run.kernelInstances===1&&run.mainKernelInstances===0,
  NO_SECONDARY_KERNEL:run.secondaryKernelInstances===0&&run.secondaryKernelDeliveries===0,
  BROKER_INVARIANTS:['BROKER_ERRORS','WRONG_TASK_RESPONSE_COUNT','STALE_TASK_REQUEST_COUNT','POST_FREE_DISPATCH_COUNT','UNATTRIBUTED_RESPONSE_COUNT'].every(k=>run.brokerCounters?.[k]===0),
  EVENT_ORDER:events.length>0&&events.every((e,i)=>i===0||BigInt(e.event_seq)>BigInt(events[i-1].event_seq)),
  SINGLE_RUN_ID:runIds.size===1&&![...runIds].includes('0'.repeat(32)),
  NO_RUNTIME_ERRORS:run.errors.length===0,
};
const passed=Object.values(checks).every(Boolean);
const receipt={schema:'k6r1-raw-event-audit-v1',verdict:passed?'PASS':'NOT_PROVEN',timestamp:new Date().toISOString(),sourceCommit:run.sourceCommit,sourceTreeStatusBeforeRun:run.sourceTreeStatus===''?'clean':'dirty',kernelSha256:sha256,RUN_ID:runIds.size===1?[...runIds][0]:null,checks,guest:run.guest,brokerCounters:run.brokerCounters,rawEvents:events,served,trap,trapCausalChain:chain,errors:run.errors,artifacts:run.artifacts,limitations:['ABA_REJECT_COUNT is reported, not silently zeroed; this audit does not measure descriptor or worker resource leaks.']};
writeFileSync(out,json(receipt)+'\n');
console.log(json({verdict:receipt.verdict,RUN_ID:receipt.RUN_ID,failed:Object.keys(checks).filter(k=>!checks[k]),brokerCounters:run.brokerCounters,errors:run.errors}));
process.exitCode=passed?0:1;
