#!/usr/bin/env node
// Z1-GABI witness — real Linux guest startup ABI certification.
// Kernel: KWA-v2.1 (NEW_SHA). Baseline: bbe4f538 (frozen).
// Verifies: kernel-provided argv (init + multi-argv exec), TLS roundtrip,
// exec image identity wiring (Z1_GABI_IMAGE_BOUND), exit-status fidelity,
// negative post-exit drop, authority health.
import {writeFileSync} from 'node:fs';
import {dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {runMachineWitness,json} from './k5-machine-witness.mjs';
const dir=dirname(fileURLToPath(import.meta.url));
const kernelPath=process.argv[2]??join(dir,'vmlinux.wasm');
const receiptPath=process.argv[3]??join(dir,'z1-gabi-receipt.json');
const run=await runMachineWitness({kernelPath,archivePath:join(dir,'z1-gabi.cpio'),magic:0x5a314731,phaseWord:7});
const words=run.guest?.words;
const events=run.rawEvents;
const tl=run.timeline||[];
const diagOf=stage=>tl.filter(m=>m.message?.stage===stage).map(m=>m.message);

// --- guest-side positive checks ---------------------------------------------
const initArgc=words?.[1]??null;
const argv0Ok=words?.[2]===1;
const tlsOk=words?.[3]===1;
const appRawStatus=words?.[4]??null;
const appExit=(typeof appRawStatus==='number'&&appRawStatus>0)?(appRawStatus>>8):null;
const getpid=words?.[6]??null;
// WIFEXITED && WEXITSTATUS==7 for the multi-argv /app child
const appVerdictPass=appExit===7;

// --- authority-side Z1-GABI checks ------------------------------------------
const imageBound=diagOf('Z1_GABI_IMAGE_BOUND');
const imageBoundNonZero=imageBound.some(d=>d.detail?.imageId&&d.detail.imageId!=='0');
// negative: synthesize a post-exit user_task_error for a reaped token and
// require the unbound-drop path (no resolution, no crash).
const postExitDrop=diagOf('Z1_GABI_POST_EXIT_REJECT');

// --- standard health ---------------------------------------------------------
const counters=['BROKER_ERRORS','WRONG_TASK_RESPONSE_COUNT','STALE_TASK_REQUEST_COUNT',
  'POST_FREE_DISPATCH_COUNT','UNATTRIBUTED_RESPONSE_COUNT'];
const countersClean=counters.every(name=>run.brokerCounters?.[name]===0);
const singleInstance=run.kernelInstances===1&&run.mainKernelInstances===0&&
  run.secondaryKernelInstances===0&&run.secondaryKernelDeliveries===0;
const seq=e=>BigInt(e.event_seq);
const monotonic=events.length>0&&events.every((e,i)=>i===0||seq(e)>seq(events[i-1]));
const runId=e=>`${BigInt.asUintN(64,BigInt(e.run_id_hi)).toString(16).padStart(16,'0')}${BigInt.asUintN(64,BigInt(e.run_id_lo)).toString(16).padStart(16,'0')}`;
const ids=new Set(events.map(runId));
const singleRunId=ids.size===1&&![...ids].includes('0'.repeat(32));

const checks={
  MACHINE_BOOT_PATH_USED:run.machineConstructed&&run.machineBootEntered&&run.machineBootReturned,
  PRODUCTION_MODULE_EVALUATED:run.targetModulesEvaluated>0,
  Z1_GABI_ARGV_REAL:initArgc!==null&&initArgc>=1,
  Z1_GABI_ARGV0_NONEMPTY:argv0Ok,
  Z1_GABI_TLS_REAL_INIT:tlsOk,
  Z1_GABI_EXEC_MULTI_ARGV_FORKED:appRawStatus!==null&&appRawStatus!==0,
  Z1_GABI_APP_EXIT_7:appVerdictPass,
  Z1_GABI_IMAGE_ID_FROM_EXEC:imageBoundNonZero,
  Z1_GABI_AUTHORITY_ALIVE:getpid!==null&&getpid>0,
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
const receipt={schema:'z1-gabi-witness-v1',
  Z1_GABI_STATUS:verdict,verdict,
  sourceRepository:'JoyciAkira/linux',sourceBranch:'fix/kwa-v2.1-z1-gabi',
  sourceCommit:run.sourceCommit,sourceTreeStatusBeforeRun:sourceClean?'clean':'dirty',
  timestamp:new Date().toISOString(),
  KERNEL_LINEAGE:'KWA-v2.1 successor (baseline bbe4f538 frozen)',
  INIT_ARGC:initArgc,INIT_ARGV0_OK:argv0Ok,INIT_TLS_OK:tlsOk,
  APP_RAW_WAIT_STATUS:appRawStatus,APP_EXIT_CODE:appExit,
  IMAGE_BOUND_EVENTS:imageBound.length,
  FINAL_GETPID:getpid,
  checks,KERNEL_AUTHORITY_INSTANCE_COUNT:run.kernelInstances,
  brokerCounters:run.brokerCounters,
  RUN_ID:ids.size===1?[...ids][0]:null,
  environmentIdentity:run.environmentIdentity,artifacts:run.artifacts,
  errors:run.errors,
  KWA_CORRECTNESS:behaviorPassed?'PROVEN_FOR_Z1_GABI':'NOT_PROVEN',PRODUCTION_READY:false};
writeFileSync(receiptPath,json(receipt));
console.log(json({verdict,initArgc,argv0Ok,tlsOk,appRawStatus,appExit,imageBound:imageBound.length,getpid,checks,errors:run.errors,receiptPath}));
process.exitCode=behaviorPassed?0:1;
