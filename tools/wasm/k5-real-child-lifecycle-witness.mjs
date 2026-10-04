#!/usr/bin/env node
import {writeFileSync} from 'node:fs';
import {dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {runMachineWitness,json} from './k5-machine-witness.mjs';
const dir=dirname(fileURLToPath(import.meta.url));
const kernelPath=process.argv[2]??join(dir,'vmlinux.wasm');
const receiptPath=process.argv[3]??join(dir,'k5-real-child-lifecycle-receipt.json');
const run=await runMachineWitness({kernelPath,archivePath:join(dir,'k5-init.cpio'),magic:0x4b355031,phaseWord:7});
const words=run.guest?.words;
const events=run.rawEvents;
const observedClone=events.find(e=>e.event_kind===8&&e.pid>0&&e.ppid>0);
const parent=words?.[1]??observedClone?.ppid??null;
const child=words?.[2]??observedClone?.pid??null;
const belongs=e=>e.pid===child;
const clone=events.find(e=>e.event_kind===8&&belongs(e)&&e.ppid===parent);
const exec=events.find(e=>e.event_kind===2&&belongs(e)&&e.ppid===parent);
const dead=events.find(e=>e.event_kind===4&&belongs(e));
const release=events.find(e=>e.event_kind===9&&belongs(e));
const reap=events.find(e=>e.event_kind===6&&belongs(e)&&e.ppid===parent);
const post=events.find(e=>e.event_kind===10&&e.pid===parent&&Number(e.data0)===parent&&Number(e.data1)===child);
const chain=[clone,exec,dead,release,reap,post];
const complete=chain.every(Boolean);
const seq=e=>BigInt(e.event_seq);
const ordered=complete&&chain.every((e,i)=>i===0||seq(e)>seq(chain[i-1]));
const runId=e=>`${BigInt.asUintN(64,BigInt(e.run_id_hi)).toString(16).padStart(16,'0')}${BigInt.asUintN(64,BigInt(e.run_id_lo)).toString(16).padStart(16,'0')}`;
const ids=new Set(events.map(runId));
const monotonic=events.length>0&&events.every((e,i)=>i===0||seq(e)>seq(events[i-1]));
const counters=['BROKER_ERRORS','WRONG_TASK_RESPONSE_COUNT','STALE_TASK_REQUEST_COUNT',
  'POST_FREE_DISPATCH_COUNT','UNATTRIBUTED_RESPONSE_COUNT','ABA_REJECT_COUNT'];
const served=run.authority.filter(e=>e.stage==='BROKER_SERVED').map(e=>e.detail);
const childCode=run.userSnapshots?.find(s=>s.words[0]===0x4b354331&&s.words[1]===child);
const checks={
  MACHINE_BOOT_PATH_USED:run.machineConstructed&&run.machineBootEntered&&run.machineBootReturned,
  PRODUCTION_MODULE_EVALUATED:run.targetModulesEvaluated>0&&run.adapter.filter(e=>e.kind==='targetModuleEvaluated')
    .every(e=>e.targetUrl===new URL('./dist/worker.js',import.meta.url).href),
  PARENT_CHILD_DISTINCT:Number.isInteger(parent)&&parent>0&&Number.isInteger(child)&&child>0&&parent!==child,
  CURRENT_TASK_BINDING_PROVEN:parent>0&&child>0&&served.some(e=>e.nr===172&&e.pid===parent&&e.result===parent)&&
    served.some(e=>e.nr===172&&e.pid===child&&e.result===child),
  CLONE_COMMITTED:!!clone,
  WASM_EXEC_COMMITTED:!!exec,
  CHILD_GUEST_EXECUTED:!!childCode,
  TASK_DEAD_OBSERVED:!!dead,
  TASK_DEAD_EXIT_STATUS:!!dead&&Number(dead.data0)===9472,
  TASK_RELEASE_COMMITTED:!!release,
  WAIT_REAP_COMMITTED:!!reap,
  WAIT4_EXACT_PID:!!words&&words[3]===child&&child>0,
  WAIT4_RAW_STATUS:!!words&&words[4]===9472&&!!reap&&Number(reap.data0)===9472,
  EXIT_STATUS_FIDELITY:!!words&&(words[4]&127)===0&&((words[4]>>>8)&255)===37,
  SECOND_WAIT4_ECHILD:!!words&&words[5]===-10&&served.some(e=>e.nr===260&&e.pid===parent&&e.result===-10),
  PARENT_SURVIVED_CHILD_EXIT:!!words&&words[6]===parent&&parent>0&&words[7]===1,
  PARENT_POST_WAIT_SYSCALL_OBSERVED:!!post&&served.some(e=>e.nr===172&&e.pid===parent&&e.result===parent),
  PID_CAUSAL_CHAIN_MATCH:complete&&ordered,
  PROCESS_EVENT_SINGLE_RUN_ID:ids.size===1&&![...ids].includes('0'.repeat(32)),
  PROCESS_EVENT_SEQUENCE_MONOTONIC:monotonic,
  KERNEL_AUTHORITY_INSTANCE_COUNT:run.kernelInstances===1&&run.mainKernelInstances===0,
  SECONDARY_VMLINUX_INSTANCE_COUNT:run.secondaryKernelInstances===0&&run.secondaryKernelDeliveries===0,
  BROKER_HEALTH:counters.every(name=>run.brokerCounters?.[name]===0),
  AUTHORITY_ALIVE_AFTER_WAIT:!!run.authorityPing,
  RUNTIME_ERRORS:run.errors.length===0,
};
const behaviorPassed=Object.values(checks).every(Boolean);
const sourceClean=run.sourceTreeStatus?.trim()==='';
const receipt={schema:'k5-real-child-lifecycle-v1',
  K5_STATUS:behaviorPassed&&sourceClean?'PASS':behaviorPassed?'LOCAL_PASS_DIRTY':'NOT_PROVEN',
  sourceRepository:'JoyciAkira/linux',sourceBranch:'fix/kwa-single-authority-v2',
  sourceCommit:run.sourceCommit,sourceTreeStatusBeforeRun:sourceClean?'clean':'dirty',
  timestamp:new Date().toISOString(),MACHINE_BOOT_PATH_USED:checks.MACHINE_BOOT_PATH_USED,
  STANDALONE_KERNEL_HARNESS_USED:run.mainKernelInstances!==0,REAL_CHILD_LIFECYCLE:behaviorPassed,
  PARENT_PID:parent,CHILD_PID:child,CHILD_EXIT_CODE:checks.EXIT_STATUS_FIDELITY?37:null,
  WAIT4_RAW_STATUS:words?.[4]??null,WAIT4_EXIT_STATUS:words?(words[4]>>>8)&255:null,
  WAIT4_SIGNALED:words?(words[4]&127)!==0:null,
  checks,KERNEL_AUTHORITY_INSTANCE_COUNT:run.kernelInstances,SECONDARY_VMLINUX_INSTANCE_COUNT:run.secondaryKernelInstances,
  SECONDARY_VMLINUX_DELIVERY_PATH:run.secondaryKernelDeliveries,
  brokerCounters:run.brokerCounters,RUN_ID:ids.size===1?[...ids][0]:null,
  K5_RUN_COUNT:1,K5_RUN_PASS_COUNT:behaviorPassed?1:0,
  environmentIdentity:run.environmentIdentity,artifacts:run.artifacts,
  events,rawCausalChain:chain,observations:{...run,brokerSab:undefined},
  KWA_CORRECTNESS:'NOT_PROVEN',PRODUCTION_READY:false,
  verdict:behaviorPassed&&sourceClean?'PASS':behaviorPassed?'LOCAL_PASS_DIRTY':'NOT_PROVEN'};
writeFileSync(receiptPath,json(receipt));
console.log(json({verdict:receipt.verdict,PARENT_PID:parent,CHILD_PID:child,checks,errors:run.errors,receiptPath}));
process.exitCode=behaviorPassed?0:1;
