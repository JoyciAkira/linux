/**
 * n2-roundtrip-only.mjs
 * Focused runner for the 3 TCP roundtrip gates only.
 * Reuses the exact same validated apparatus (net-validator.mjs, node-gate-net-probe.html).
 * Created because 6 gates × ~160s ≈ 960s exceeds the 600s single-invocation ceiling.
 * Gate semantics are identical to net-ladder-n2-tcp.mjs — only the gate subset differs.
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

let serverProc = null;
function startServer() {
  stopServer();
  serverProc = spawn("python3", ["serve-coop.py", String(SERVER_PORT)], {
    cwd: WASM_DIR, stdio: ["ignore", "ignore", "ignore"],
  });
  return new Promise(res => setTimeout(res, 2500));
}
function stopServer() {
  if (serverProc) { try { serverProc.kill("SIGTERM"); } catch {} serverProc = null; }
  try { execSync(`lsof -ti :${SERVER_PORT} | xargs kill -9 2>/dev/null`, { stdio: "ignore" }); } catch {}
}

async function safeClose(x) { if (x) try { await x.close(); } catch {} }
async function launchBrowser() {
  return chromium.launch({ headless: true, args: ["--no-sandbox", "--enable-features=SharedArrayBuffer", "--disable-gpu"] });
}

async function pollOutput(page) {
  try {
    return await Promise.race([
      page.evaluate(() => (window.__consoleOutput || []).join("")),
      new Promise((_, rej) => setTimeout(() => rej(new Error("eval_to")), EVAL_TIMEOUT)),
    ]);
  } catch { return null; }
}

async function runGate(gate) {
  const uuid = randomUUID();
  const browser = await launchBrowser();
  const context = await browser.newContext();
  const page = await context.newPage();
  const pageErrors = [];
  const onPageError = e => pageErrors.push(e.message);
  page.on("pageerror", onPageError);
  let lastSnapshot = "";
  const startTime = Date.now();

  try {
    await page.goto(
      `${PROBE_URL}?code=${encodeURIComponent(gate.code)}&uuid=${uuid}`,
      { waitUntil: "domcontentloaded", timeout: 30000 },
    );
    const exitRe = new RegExp(`GATE_EXIT:${uuid}=\\d`);
    let done = false;
    while (Date.now() - startTime < GATE_TIMEOUT) {
      const snap = await pollOutput(page);
      if (snap !== null) lastSnapshot = snap;
      if (exitRe.test(lastSnapshot)) { done = true; break; }
      await new Promise(r => setTimeout(r, POLL_INTERVAL));
    }
    const wallMs = Date.now() - startTime;
    if (!done) {
      const lines = lastSnapshot.split("\n").filter(l => l.trim());
      return { name: gate.name, uuid, passed: false, result: "TIMEOUT", timedOut: true, wallMs, outputLen: lastSnapshot.length, lastLines: lines.slice(-5), pageErrors, rawOutput: lastSnapshot.slice(-3000) };
    }
    const extracted = extractResult(lastSnapshot, uuid);
    const crashSigs = (lastSnapshot.match(/delivering SIG(SEGV|ILL|BUS|FPE)/g) ?? []);
    const validation = validateResult(extracted, gate.matcher);
    return { name: gate.name, uuid, passed: validation.valid && crashSigs.length === 0, result: validation.reason, resultValue: extracted.resultValue, guestExitCode: extracted.guestExitCode, timedOut: false, crashCount: crashSigs.length, wallMs, pageErrors, rawOutput: lastSnapshot.slice(-2000) };
  } finally {
    page.off("pageerror", onPageError);
    await safeClose(page);
    await safeClose(context);
    await safeClose(browser);
  }
}

const roundtripMatch = v => v.startsWith('TCP_PONG:');
const roundtripCode = `(async()=>{const net=require('net');const uuid='${randomUUID().slice(0,8)}';return new Promise((r)=>{const srv=net.createServer(s=>{s.on('data',d=>{if(d.toString().includes('PING')){s.write('PONG');s.end()}});s.on('end',()=>{s.end()})});srv.listen(19998,'127.0.0.1',()=>{const c=net.createConnection(19998,'127.0.0.1');let resp='';c.on('data',d=>{resp+=d.toString()});c.on('end',()=>{c.end();srv.close();r('TCP_PONG:'+resp)});c.write('PING');c.end()})})})()`;

const GATES = [
  { name: "tcp-roundtrip-1", matcher: roundtripMatch, code: roundtripCode },
  { name: "tcp-roundtrip-2", matcher: roundtripMatch, code: roundtripCode },
  { name: "tcp-roundtrip-3", matcher: roundtripMatch, code: roundtripCode },
];

async function main() {
  console.log("═══════════════════════════════════════════════════════════");
  console.log(" N2 TCP ROUNDTRIP ONLY — validated apparatus, fresh browser per gate");
  console.log(` ${new Date().toISOString()}`);
  console.log(` GATES: ${GATES.length}`);
  console.log("═══════════════════════════════════════════════════════════\n");

  const results = [];
  for (const gate of GATES) {
    console.log(`── ${gate.name} ──`);
    await startServer();
    const r = await runGate(gate);
    const icon = r.passed ? "✅" : "❌";
    const val = r.resultValue ? `"${r.resultValue}"` : r.result;
    console.log(`  ${icon} ${val} exit=${r.guestExitCode} crash=${r.crashCount ?? 0} to=${r.timedOut} wall=${r.wallMs}ms`);
    writeFileSync(`${EVIDENCE_DIR}/n2-${gate.name}.json`, JSON.stringify(r, null, 2));
    results.push(r);
    stopServer();
    await new Promise(res => setTimeout(res, 2000));
  }

  const passed = results.filter(r => r.passed).length;
  console.log("\n═══════════════════════════════════════════════════════════");
  console.log(` tcp-roundtrip: ${passed}/${results.length}`);
  console.log("═══════════════════════════════════════════════════════════\n");

  writeFileSync(`${EVIDENCE_DIR}/n2-roundtrip-report.json`, JSON.stringify({
    timestamp: new Date().toISOString(),
    summary: { total: results.length, passed },
    results: results.map(r => ({ gate: r.name, passed: r.passed, result: r.result, resultValue: r.resultValue, guestExitCode: r.guestExitCode, wallMs: r.wallMs })),
  }, null, 2));

  if (passed === results.length) console.log("VERDICT: ROUNDTRIP_3_OF_3_PASS ✅");
  else { console.log("VERDICT: ROUNDTRIP_NOT_VERIFIED ❌"); process.exitCode = 1; }
}

main().catch(e => { console.error(e); process.exit(2); });
