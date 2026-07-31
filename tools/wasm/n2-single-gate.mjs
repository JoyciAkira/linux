/**
 * n2-single-gate.mjs — run ONE gate by name from the N2 TCP ladder.
 * Usage: node n2-single-gate.mjs tcp-roundtrip-3
 * Reuses validated apparatus (net-validator.mjs, node-gate-net-probe.html).
 */
import { chromium } from "playwright";
import { writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { execSync, spawn } from "node:child_process";
import { extractResult, validateResult } from "./net-validator.mjs";

const WASM_DIR = "/Users/danielecorrao/tombl-build/linux/tools/wasm";
const PROBE_URL = "http://127.0.0.1:8788/node-gate-net-probe.html";
const SERVER_PORT = 8788;
const GATE_TIMEOUT = 300_000;
const POLL_INTERVAL = 2000;
const EVAL_TIMEOUT = 5000;
const EVIDENCE_DIR = process.env.N2_EVIDENCE_DIR || "/tmp";

const gateName = process.argv[2];
if (!gateName) { console.error("Usage: node n2-single-gate.mjs <gate-name>"); process.exit(2); }

const refusedMatch = v => v === 'TCP_REFUSED:ECONNREFUSED';
const roundtripMatch = v => v.startsWith('TCP_PONG:');
const refusedCode = `(async()=>{const net=require('net');return new Promise(r=>{const c=net.createConnection(19999,'127.0.0.1');c.on('error',e=>r('TCP_REFUSED:'+e.code));c.on('connect',()=>{c.destroy();r('TCP_ERR:UNEXPECTED_CONNECT')})})})()`;
const roundtripCode = `(async()=>{const net=require('net');const uuid='${randomUUID().slice(0,8)}';return new Promise((r)=>{const srv=net.createServer(s=>{s.on('data',d=>{if(d.toString().includes('PING')){s.write('PONG');s.end()}});s.on('end',()=>{s.end()})});srv.listen(19998,'127.0.0.1',()=>{const c=net.createConnection(19998,'127.0.0.1');let resp='';c.on('data',d=>{resp+=d.toString()});c.on('end',()=>{c.end();srv.close();r('TCP_PONG:'+resp)});c.write('PING');c.end()})})})()`;

const diagVirtioNetCode = `(async()=>{const fs=require('fs');const {execSync}=require('child_process');const R=[];try{R.push('PROC_NET_DEV:'+fs.readFileSync('/proc/net/dev','utf8').replace(/\\n/g,';'))}catch(e){R.push('PROC_NET_DEV:ERR:'+e.code)}try{R.push('PROC_DEVICES:'+fs.readFileSync('/proc/devices','utf8').replace(/\\n/g,';'))}catch(e){R.push('PROC_DEVICES:ERR:'+e.code)}try{execSync('mkdir -p /sys 2>/dev/null');execSync('mount -t sysfs sysfs /sys 2>/dev/null');R.push('SYSFS:MOUNTED')}catch(e){R.push('SYSFS:FAIL:'+e.message.slice(0,40))}try{R.push('VIRTIO_DEVS:'+fs.readdirSync('/sys/bus/virtio/devices').join(','))}catch(e){R.push('VIRTIO_DEVS:ERR:'+e.code)}try{R.push('NET_IFACES:'+fs.readdirSync('/sys/class/net').join(','))}catch(e){R.push('NET_IFACES:ERR:'+e.code)}try{R.push('ETH0:'+fs.readFileSync('/sys/class/net/eth0/operstate','utf8').trim())}catch(e){R.push('ETH0:ABSENT')}try{R.push('LO:'+fs.readFileSync('/sys/class/net/lo/operstate','utf8').trim())}catch(e){R.push('LO:ABSENT')}try{const ip=execSync('ip link 2>/dev/null||ifconfig -a 2>/dev/null||echo NO_IP_CMD').toString().replace(/\\n/g,';');R.push('IP_LINK:'+ip.slice(0,200))}catch(e){R.push('IP_LINK:ERR')}return R.join('|')})()`;
const diagVirtioNetMatch = v => v.includes('PROC_NET_DEV:');

const GATE_MAP = {
  "tcp-refused-1": { matcher: refusedMatch, code: refusedCode },
  "tcp-refused-2": { matcher: refusedMatch, code: refusedCode },
  "tcp-refused-3": { matcher: refusedMatch, code: refusedCode },
  "tcp-roundtrip-1": { matcher: roundtripMatch, code: roundtripCode },
  "tcp-roundtrip-2": { matcher: roundtripMatch, code: roundtripCode },
  "tcp-roundtrip-3": { matcher: roundtripMatch, code: roundtripCode },
  "diag-virtio-net": { matcher: diagVirtioNetMatch, code: diagVirtioNetCode },
  "half-close": {
    matcher: v => v.startsWith('HALF_CLOSE_OK:'),
    code: `(async()=>{const net=require('net');return new Promise((resolve)=>{const srv=net.createServer((s)=>{let gotData=false;s.on('data',(d)=>{gotData=true});s.on('end',()=>{s.end();srv.close();resolve('HALF_CLOSE_OK:data='+gotData+',eof=true')})});srv.listen(19997,'127.0.0.1',()=>{const c=net.createConnection(19997,'127.0.0.1');c.on('connect',()=>{c.write('HELLO');c.end()});c.on('end',()=>{})});setTimeout(()=>resolve('HALF_CLOSE_TIMEOUT'),30000)})})()`,
  },
  "reset": {
    matcher: v => v === 'RESET_OK:ECONNRESET',
    code: `(async()=>{const net=require('net');return new Promise((resolve)=>{let resolved=false;const done=v=>{if(!resolved){resolved=true;try{srv.close()}catch(e){}resolve(v)}};const srv=net.createServer((s)=>{s.on('error',()=>{});s.on('data',(d)=>{if(typeof s.resetAndDestroy==='function'){s.resetAndDestroy()}else{s.destroy()}})});srv.listen(19996,'127.0.0.1',()=>{const c=net.createConnection(19996,'127.0.0.1');c.on('connect',()=>{c.write('TEST')});c.on('error',(e)=>{done('RESET_OK:'+e.code)});c.on('close',(hadError)=>{if(hadError)done('RESET_OK:close_had_error');else done('RESET_FAIL:graceful_close')})});setTimeout(()=>done('RESET_TIMEOUT'),30000)})})()`,
  },
};

const gateDef = GATE_MAP[gateName];
if (!gateDef) { console.error(`Unknown gate: ${gateName}. Valid: ${Object.keys(GATE_MAP).join(", ")}`); process.exit(2); }
const gate = { name: gateName, ...gateDef };

let serverProc = null;
function startServer() {
  stopServer();
  serverProc = spawn("python3", ["serve-coop.py", String(SERVER_PORT)], { cwd: WASM_DIR, stdio: ["ignore","ignore","ignore"] });
  return new Promise(res => setTimeout(res, 2500));
}
function stopServer() {
  if (serverProc) { try { serverProc.kill("SIGTERM"); } catch {} serverProc = null; }
  try { execSync(`lsof -ti :${SERVER_PORT} | xargs kill -9 2>/dev/null`, { stdio: "ignore" }); } catch {}
}
async function safeClose(x) { if (x) try { await x.close(); } catch {} }
async function pollOutput(page) {
  try {
    return await Promise.race([
      page.evaluate(() => (window.__consoleOutput || []).join("")),
      new Promise((_, rej) => setTimeout(() => rej(new Error("eval_to")), EVAL_TIMEOUT)),
    ]);
  } catch { return null; }
}

console.log(`── ${gate.name} (single-gate) ──`);
await startServer();
const uuid = randomUUID();
const browser = await chromium.launch({ headless: true, args: ["--no-sandbox", "--enable-features=SharedArrayBuffer", "--disable-gpu"] });
const context = await browser.newContext();
const page = await context.newPage();
const pageErrors = [];
page.on("pageerror", e => pageErrors.push(e.message));
let lastSnapshot = "";
const startTime = Date.now();

try {
  await page.goto(`${PROBE_URL}?code=${encodeURIComponent(gate.code)}&uuid=${uuid}`, { waitUntil: "domcontentloaded", timeout: 30000 });
  const exitRe = new RegExp(`GATE_EXIT:${uuid}=\\d`);
  let done = false;
  while (Date.now() - startTime < GATE_TIMEOUT) {
    const snap = await pollOutput(page);
    if (snap !== null) lastSnapshot = snap;
    if (exitRe.test(lastSnapshot)) { done = true; break; }
    await new Promise(r => setTimeout(r, POLL_INTERVAL));
  }
  const wallMs = Date.now() - startTime;
  let r;
  if (!done) {
    r = { name: gate.name, uuid, passed: false, result: "TIMEOUT", timedOut: true, wallMs, outputLen: lastSnapshot.length, pageErrors, rawOutput: lastSnapshot.slice(-3000) };
  } else {
    const extracted = extractResult(lastSnapshot, uuid);
    const crashSigs = (lastSnapshot.match(/delivering SIG(SEGV|ILL|BUS|FPE)/g) ?? []);
    const validation = validateResult(extracted, gate.matcher);
    r = { name: gate.name, uuid, passed: validation.valid && crashSigs.length === 0, result: validation.reason, resultValue: extracted.resultValue, guestExitCode: extracted.guestExitCode, timedOut: false, crashCount: crashSigs.length, wallMs, pageErrors, rawOutput: lastSnapshot.slice(-2000) };
  }
  const icon = r.passed ? "✅" : "❌";
  const val = r.resultValue ? `"${r.resultValue}"` : r.result;
  console.log(`  ${icon} ${val} exit=${r.guestExitCode} crash=${r.crashCount ?? 0} to=${r.timedOut} wall=${r.wallMs}ms`);
  writeFileSync(`${EVIDENCE_DIR}/n2-${gate.name}.json`, JSON.stringify(r, null, 2));
  // Full untruncated console output for strace analysis
  writeFileSync(`${EVIDENCE_DIR}/n2-${gate.name}-full.log`, lastSnapshot);
  console.log(r.passed ? `VERDICT: ${gate.name}_PASS ✅` : `VERDICT: ${gate.name}_FAIL ❌`);
  if (!r.passed) process.exitCode = 1;
} finally {
  await safeClose(page);
  await safeClose(context);
  await safeClose(browser);
  stopServer();
}
