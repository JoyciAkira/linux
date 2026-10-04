#!/usr/bin/env node
import {writeFileSync} from 'node:fs';
import {dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {runMachineWitness,json} from './k5-machine-witness.mjs';
const dir=dirname(fileURLToPath(import.meta.url));
const kernelPath=process.argv[2]??join(dir,'vmlinux.wasm');
const receiptPath=process.argv[3]??join(dir,'k5a-micro-witness-receipt.json');
const run=await runMachineWitness({kernelPath,archivePath:join(dir,'k5a-init.cpio'),magic:0x4b354131,phaseWord:4});
const words=run.guest?.words;
const parentPid=words?.[1]??null;
const resumedPid=words?.[3]??null;
const events=run.rawEvents;
const same=(a,b)=>String(a)===String(b);
const suspend=events.find(e=>e.event_kind===11&&e.pid===parentPid&&parentPid>0);
const resume=suspend&&events.find(e=>e.event_kind===12&&e.pid===parentPid&&
  BigInt(e.event_seq)>BigInt(suspend.event_seq)&&same(e.data0,suspend.data0)&&same(e.data1,suspend.data1));
const resumeOrder=resume&&run.timeline.find(e=>e.message===resume)?.observationOrder;
const served=run.timeline.filter(e=>e.message.type==='authority_diag'&&e.message.stage==='BROKER_SERVED');
const post=served.find(e=>resumeOrder!==undefined&&e.observationOrder>resumeOrder&&
  e.message.detail.nr===172&&e.message.detail.pid===parentPid&&e.message.detail.result===parentPid);
const healthyNames=['BROKER_ERRORS','WRONG_TASK_RESPONSE_COUNT','STALE_TASK_REQUEST_COUNT',
  'POST_FREE_DISPATCH_COUNT','UNATTRIBUTED_RESPONSE_COUNT','ABA_REJECT_COUNT'];
const checks={
  MACHINE_BOOT_PATH_USED:run.machineConstructed&&run.machineBootEntered&&run.machineBootReturned,
  PRODUCTION_WORKER_MODULE_EVALUATED:run.targetModulesEvaluated>0&&run.adapter.filter(e=>e.kind==='targetModuleEvaluated')
    .every(e=>e.targetUrl===new URL('./dist/worker.js',import.meta.url).href),
  KERNEL_INSTANCE_COUNT:run.kernelInstances===1&&run.mainKernelInstances===0,
  SECONDARY_KERNEL_INSTANCE_COUNT:run.secondaryKernelInstances===0&&run.secondaryKernelDeliveries===0,
  PARENT_PID_GT_ZERO:Number.isInteger(parentPid)&&parentPid>0,
  CURRENT_TASK_BINDING_PROVEN:parentPid>0&&served.some(e=>e.message.detail.pid===parentPid&&e.message.detail.nr===172&&e.message.detail.result===parentPid),
  TASK_SUSPEND_OBSERVED:!!suspend,
  TASK_RESUME_OBSERVED:!!resume,
  RESUMED_PID_EQUALS_PARENT:resumedPid===parentPid&&parentPid>0,
  STACK_CONTEXT_PRESERVED:!!resume&&BigInt(resume.data0)>0n&&BigInt(resume.data1)>0n,
  AUTHORITY_REMAINS_SERVICEABLE:!!run.authorityPing&&!!post,
  POST_RESUME_BROKERED_SYSCALL:!!post,
  REAL_NANOSLEEP_COMPLETED:!!words&&words[2]===0&&words[4]===1,
  BROKER_HEALTH:healthyNames.every(name=>run.brokerCounters?.[name]===0),
  RUNTIME_ERRORS:run.errors.length===0,
};
const passed=Object.values(checks).every(Boolean);
const receipt={gate:'K5A_SINGLE_AUTHORITY_SCHEDULER',verdict:passed?'PASS':'NOT_PROVEN',
  timestamp:new Date().toISOString(),PARENT_PID:parentPid,RESUMED_PID:resumedPid,checks,
  sourceRepository:'JoyciAkira/linux',sourceBranch:'fix/kwa-single-authority-v2',
  buildToolchain:'LLVM/LLD19.1.0 aarch64 Debian bookworm',
  buildCommand:'make -C /src O=/build ARCH=wasm LLVM=/llvm/bin/ HOSTCC=gcc -j4; wasm2wat/sections.pl/llvm-objcopy',
  run:{...run,brokerSab:undefined}};
writeFileSync(receiptPath,json(receipt));
console.log(json({verdict:receipt.verdict,PARENT_PID:parentPid,RESUMED_PID:resumedPid,checks,errors:run.errors,receiptPath}));
process.exitCode=passed?0:1;
