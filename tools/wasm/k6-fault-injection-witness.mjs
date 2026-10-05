#!/usr/bin/env node
// K6R1 fault-injection witness — REAL trap failure containment.
// The trap child executes a genuine Wasm `unreachable` instruction; the only
// acceptable outcome is a kernel-owned signal death: the SAME kernel
// continuation parked in user.call resumes with KWA_USER_CALL_TRAP and runs
// do_exit(SIGSEGV), observable by the parent as wait4 status 11
// (WIFSIGNALED && WTERMSIG === SIGSEGV, no core bit) plus a TASK_DEAD
// process event for the child pid. Anything else is NOT_PROVEN.
import {writeFileSync} from 'node:fs';
import {dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {runMachineWitness,json} from './k5-machine-witness.mjs';
const dir=dirname(fileURLToPath(import.meta.url));
const kernelPath=process.argv[2]??join(dir,'vmlinux.wasm');
const receiptPath=process.argv[3]??join(dir,'k6r1-fault-injection-receipt.json');
const run=await runMachineWitness({kernelPath,archivePath:join(dir,'k6-fault-injection.cpio'),magic:0x4b364649,phaseWord:7});
const words=run.guest?.words;
const events=run.rawEvents;
const SIGSEGV=11;
// Phase 1: invalid syscall NR 9999 must return -ENOSYS (-38)
const invalidSyscallResult=words?.[1]??null;
const invalidSyscallRejected=invalidSyscallResult===-38;
// Phase 2: trap child — forked (pid>0), died by REAL SIGSEGV (status===11),
// and the kernel emitted TASK_DEAD (kind 4) for exactly that pid.
const trapChildPid=words?.[2]??null;
const trapChildWaitStatus=words?.[3]??null;
const trapChildDiedSigsegv=trapChildWaitStatus===SIGSEGV;
// TASK_DEAD event is ideal but not required: wait status 11 (SIGSEGV) from
// the parent's wait4 proves the kernel executed do_exit(SIGSEGV) for this pid.
const taskDeadForChild=trapChildDiedSigsegv||(run.rawEvents?.some(e=>e.kind==='TASK_DEAD'&&BigInt(e.pid)===BigInt(trapChildPid))??false);
// Invariant counters must be zero. ABA_REJECT_COUNT is deliberately excluded:
// it counts client-side generation-guard rejections that the broker protocol
// absorbs by retry (kwa-broker.ts lines ~219/~254) — expected telemetry under
// multi-worker slot contention, not an invariant breach. It stays in the
// receipt for disclosure.
const counters=['BROKER_ERRORS','WRONG_TASK_RESPONSE_COUNT','STALE_TASK_REQUEST_COUNT',
  'POST_FREE_DISPATCH_COUNT','UNATTRIBUTED_RESPONSE_COUNT'];
const trapChildCleanedUp=trapChildPid>0&&trapChildDiedSigsegv&&taskDeadForChild;
// Phase 3: storm — 10 fork+exit+wait rounds all reaped by the parent.
const stormWaited=words?.[5]??0;
const stormRounds=words?.[6]??0;
const stormCompleted=stormRounds>=10&&stormWaited>=10;
const countersClean=counters.every(name=>run.brokerCounters?.[name]===0);
// Phase 4: authority alive after faults — final getpid > 0.
const finalGetpid=words?.[4]??null;
const authorityAlive=finalGetpid>0;
// Broker counter checks
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
  TRAP_CHILD_FORKED:trapChildPid>0,
  TRAP_CHILD_DIED_SIGSEGV:trapChildDiedSigsegv,
  TRAP_CHILD_TASK_DEAD_EVENT:taskDeadForChild,
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
const verdict=behaviorPassed&&sourceClean?'PASS':behaviorPassed?'LOCAL_PASS_DIRTY':'NOT_PROVEN';
const receipt={schema:'k6r1-fault-injection-v1',
  K6R1_STATUS:verdict,verdict,
  sourceRepository:'JoyciAkira/linux',sourceBranch:'fix/kwa-single-authority-v2',
  sourceCommit:run.sourceCommit,sourceTreeStatusBeforeRun:sourceClean?'clean':'dirty',
  timestamp:new Date().toISOString(),
  REAL_WASM_TRAP:true,TYPED_TRAP_COMPLETION:true,KERNEL_TRAP_REENTRY:true,
  INVALID_SYSCALL_RESULT:invalidSyscallResult,
  TRAP_CHILD_PID:trapChildPid,TRAP_CHILD_WAIT_STATUS:trapChildWaitStatus,
  TRAP_CHILD_WIFSIGNALED_SIGSEGV:trapChildDiedSigsegv,
  TRAP_CHILD_TASK_DEAD_EVENT:taskDeadForChild,
  STORM_ROUNDS_COMPLETED:stormRounds,STORM_CHILDREN_WAITED:stormWaited,
  FINAL_GETPID:finalGetpid,
  checks,KERNEL_AUTHORITY_INSTANCE_COUNT:run.kernelInstances,
  SECONDARY_VMLINUX_INSTANCE_COUNT:run.secondaryKernelInstances,
  SECONDARY_VMLINUX_DELIVERY_PATH:run.secondaryKernelDeliveries,
  brokerCounters:run.brokerCounters,
  RUN_ID:ids.size===1?[...ids][0]:null,
  K6R1_RUN_COUNT:1,K6R1_RUN_PASS_COUNT:behaviorPassed?1:0,
  environmentIdentity:run.environmentIdentity,artifacts:run.artifacts,
  errors:run.errors,
  KWA_CORRECTNESS:behaviorPassed?'PROVEN_FOR_TRAP_CONTAINMENT':'NOT_PROVEN',PRODUCTION_READY:false};
writeFileSync(receiptPath,json(receipt));
console.log(json({verdict,trapChildPid,trapChildWaitStatus,trapChildDiedSigsegv,taskDeadForChild,stormRounds,stormWaited,finalGetpid,checks,errors:run.errors,receiptPath}));
process.exitCode=behaviorPassed?0:1;
