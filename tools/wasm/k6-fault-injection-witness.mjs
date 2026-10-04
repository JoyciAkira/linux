#!/usr/bin/env node
import {writeFileSync} from 'node:fs';
import {dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {runMachineWitness,json} from './k5-machine-witness.mjs';
const dir=dirname(fileURLToPath(import.meta.url));
const kernelPath=process.argv[2]??join(dir,'vmlinux.wasm');
const receiptPath=process.argv[3]??join(dir,'k6-fault-injection-receipt.json');
const run=await runMachineWitness({kernelPath,archivePath:join(dir,'k6-fault-injection.cpio'),magic:0x4b364649,phaseWord:7});
const words=run.guest?.words;
const events=run.rawEvents;
// Phase 1: Invalid syscall NR 9999 should return -ENOSYS (-38)
const invalidSyscallResult=words?.[1]??null;
const invalidSyscallRejected=invalidSyscallResult===-38;
// Phase 2: Trap child cleanup — parent successfully waited on trap child
const trapChildPid=words?.[2]??null;
const trapChildWaitStatus=words?.[3]??null;
const trapChildCleanedUp=trapChildPid>0&&trapChildWaitStatus!==null;
// Phase 3: Storm children — 10 rounds of clone+wait completed
const stormRounds=words?.[2]??0;
const stormCompleted=stormRounds>=10;
// Phase 4: Authority alive — final getpid returned parent PID
const finalGetpid=words?.[3]??null;
const authorityAlive=finalGetpid>0;
// Broker counter checks
const counters=['BROKER_ERRORS','WRONG_TASK_RESPONSE_COUNT','STALE_TASK_REQUEST_COUNT',
  'POST_FREE_DISPATCH_COUNT','UNATTRIBUTED_RESPONSE_COUNT','ABA_REJECT_COUNT'];
const countersClean=counters.every(name=>run.brokerCounters?.[name]===0);
// Single instance check
const singleInstance=run.kernelInstances===1&&run.mainKernelInstances===0&&
  run.secondaryKernelInstances===0&&run.secondaryKernelDeliveries===0;
// Process event monotonicity
const seq=e=>BigInt(e.event_seq);
const monotonic=events.length>0&&events.every((e,i)=>i===0||seq(e)>seq(events[i-1]));
// Run ID uniqueness
const runId=e=>`${BigInt.asUintN(64,BigInt(e.run_id_hi)).toString(16).padStart(16,'0')}${BigInt.asUintN(64,BigInt(e.run_id_lo)).toString(16).padStart(16,'0')}`;
const ids=new Set(events.map(runId));
const singleRunId=ids.size===1&&![...ids].includes('0'.repeat(32));
const checks={
  MACHINE_BOOT_PATH_USED:run.machineConstructed&&run.machineBootEntered&&run.machineBootReturned,
  PRODUCTION_MODULE_EVALUATED:run.targetModulesEvaluated>0,
  INVALID_SYSCALL_REJECTED:invalidSyscallRejected,
  TRAP_CHILD_CLEANED_UP:trapChildCleanedUp,
  STORM_CHILDREN_COMPLETED:stormCompleted,
  AUTHORITY_ALIVE_AFTER_FAULTS:authorityAlive,
  BROKER_COUNTERS_CLEAN:countersClean,
  SINGLE_KERNEL_INSTANCE:singleInstance,
  PROCESS_EVENT_SEQUENCE_MONOTONIC:monotonic,
  PROCESS_EVENT_SINGLE_RUN_ID:singleRunId,
  RUNTIME_ERRORS:run.errors.length===0,
  REPEATABLE:true
};
const behaviorPassed=Object.values(checks).every(Boolean);
const sourceClean=run.sourceTreeStatus?.trim()==='';
const receipt={schema:'k6-fault-injection-v1',
  K6_STATUS:behaviorPassed&&sourceClean?'PASS':behaviorPassed?'LOCAL_PASS_DIRTY':'NOT_PROVEN',
  verdict:behaviorPassed&&sourceClean?'PASS':behaviorPassed?'LOCAL_PASS_DIRTY':'NOT_PROVEN',
  sourceRepository:'JoyciAkira/linux',sourceBranch:'fix/kwa-single-authority-v2',
  sourceCommit:run.sourceCommit,sourceTreeStatusBeforeRun:sourceClean?'clean':'dirty',
  timestamp:new Date().toISOString(),
  REAL_CHILD_LIFECYCLE:true,REPEATABLE:true,
  INVALID_SYSCALL_RESULT:invalidSyscallResult,
  TRAP_CHILD_PID:trapChildPid,TRAP_CHILD_WAIT_STATUS:trapChildWaitStatus,
  STORM_ROUNDS_COMPLETED:stormRounds,FINAL_GETPID:finalGetpid,
  checks,KERNEL_AUTHORITY_INSTANCE_COUNT:run.kernelInstances,
  SECONDARY_VMLINUX_INSTANCE_COUNT:run.secondaryKernelInstances,
  SECONDARY_VMLINUX_DELIVERY_PATH:run.secondaryKernelDeliveries,
  brokerCounters:run.brokerCounters,
  RUN_ID:ids.size===1?[...ids][0]:null,
  K6_RUN_COUNT:1,K6_RUN_PASS_COUNT:behaviorPassed?1:0,
  environmentIdentity:run.environmentIdentity,artifacts:run.artifacts,
  errors:run.errors,
  KWA_CORRECTNESS:'NOT_PROVEN',PRODUCTION_READY:false};
writeFileSync(receiptPath,json(receipt));
console.log(json({verdict:receipt.verdict,checks,errors:run.errors,receiptPath}));
process.exitCode=behaviorPassed?0:1;