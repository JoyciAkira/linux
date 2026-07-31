/**
 * net-ladder-n2-tcp.mjs
 * N2 TCP loopback ladder: 3× connect-refused + 3× server roundtrip.
 * Uses validated apparatus: line-anchored RESULT extraction, UUID-specific GATE_EXIT wait.
 * Polls window.__consoleOutput — NEVER calls page.evaluate() after timeout.
 */
import { chromium } from "playwright";
import { writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { execSync, spawn } from "node:child_process";
import { extractResult, validateResult } from "./net-validator.mjs";

const WASM_DIR = "/Users/danielecorrao/tombl-build/linux/tools/wasm";
const PROBE_URL = "http://127.0.0.1:8788/node-gate-net-probe.html";
const SERVER_PORT = 8788;
const GATE_TIMEOUT = 300_000; // 5 min — boot may be slow; N1 DNS took 137-153s per gate
const POLL_INTERVAL = 2000;
const EVAL_TIMEOUT = 5000;
const EVIDENCE_DIR = process.env.N2_EVIDENCE_DIR || "/tmp";

// ── server management ──────────────────────────────────────────────────────────
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

// ── poll __consoleOutput safely ────────────────────────────────────────────────
async function pollOutput(page) {
  try {
    return await Promise.race([
      page.evaluate(() => (window.__consoleOutput || []).join("")),
      new Promise((_, rej) => setTimeout(() => rej(new Error("eval_to")), EVAL_TIMEOUT)),
    ]);
  } catch {
    return null;
  }
}

// ── single gate ────────────────────────────────────────────────────────────────
async function runGate(gate) {
  const uuid = randomUUID();
  const browser = await launchBrowser();
  const context = await browser.newContext();
  const page = await context.newPage();

  const pageErrors = [];
  const onPageError = e => pageErrors.push(e.message);
  page.on("pageerror", onPageError);

  let lastSnapshot = ""; // last successful poll — evidence on timeout
  const startTime = Date.now();

  try {
    await page.goto(
      `${PROBE_URL}?code=${encodeURIComponent(gate.code)}&uuid=${uuid}`,
      { waitUntil: "domcontentloaded", timeout: 30000 },
    );

    // Poll until GATE_EXIT:<uuid>=<digit> appears or timeout
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
      // TIMEOUT — save evidence, do NOT call evaluate
      const lines = lastSnapshot.split("\n").filter(l => l.trim());
      return {
        name: gate.name, uuid, passed: false,
        result: "TIMEOUT", timedOut: true,
        wallMs, outputLen: lastSnapshot.length,
        lastLines: lines.slice(-5),
        pageErrors,
        rawOutput: lastSnapshot.slice(-3000),
      };
    }

    // SUCCESS — extract using validated logic
    const extracted = extractResult(lastSnapshot, uuid);
    const crashSigs = (lastSnapshot.match(/delivering SIG(SEGV|ILL|BUS|FPE)/g) ?? []);
    const validation = validateResult(extracted, gate.matcher);

    return {
      name: gate.name, uuid,
      passed: validation.valid && crashSigs.length === 0,
      result: validation.reason,
      resultValue: extracted.resultValue,
      guestExitCode: extracted.guestExitCode,
      timedOut: false,
      crashCount: crashSigs.length,
      wallMs,
      pageErrors,
      rawOutput: lastSnapshot.slice(-2000),
    };
  } finally {
    page.off("pageerror", onPageError);
    await safeClose(page);
    await safeClose(context);
    await safeClose(browser);
  }
}

// ── gate definitions ───────────────────────────────────────────────────────────
const refusedMatch = v => v === 'TCP_REFUSED:ECONNREFUSED';
const roundtripMatch = v => v.startsWith('TCP_PONG:');

// tcp-refused: connect to 127.0.0.1:19999 (closed port), expect ECONNREFUSED
const refusedCode = `(async()=>{const net=require('net');return new Promise(r=>{const c=net.createConnection(19999,'127.0.0.1');c.on('error',e=>r('TCP_REFUSED:'+e.code));c.on('connect',()=>{c.destroy();r('TCP_ERR:UNEXPECTED_CONNECT')})})})()`;

// tcp-roundtrip: create server on 127.0.0.1:19998, connect, send UUID payload, receive PONG, close
const roundtripCode = `(async()=>{const net=require('net');const uuid='${randomUUID().slice(0,8)}';return new Promise((r)=>{const srv=net.createServer(s=>{s.on('data',d=>{if(d.toString().includes('PING')){s.write('PONG');s.end()}});s.on('end',()=>{s.end()})});srv.listen(19998,'127.0.0.1',()=>{const c=net.createConnection(19998,'127.0.0.1');let resp='';c.on('data',d=>{resp+=d.toString()});c.on('end',()=>{c.end();srv.close();r('TCP_PONG:'+resp)});c.write('PING');c.end()})})})()`;

const GATES = [
  {
    name: "tcp-refused-1",
    matcher: refusedMatch,
    code: refusedCode,
  },
  {
    name: "tcp-refused-2",
    matcher: refusedMatch,
    code: refusedCode,
  },
  {
    name: "tcp-refused-3",
    matcher: refusedMatch,
    code: refusedCode,
  },
  {
    name: "tcp-roundtrip-1",
    matcher: roundtripMatch,
    code: roundtripCode,
  },
  {
    name: "tcp-roundtrip-2",
    matcher: roundtripMatch,
    code: roundtripCode,
  },
  {
    name: "tcp-roundtrip-3",
    matcher: roundtripMatch,
    code: roundtripCode,
  },
];

// ── main ───────────────────────────────────────────────────────────────────────
async function main() {
  console.log("═══════════════════════════════════════════════════════════");
  console.log(" N2 TCP LOOPBACK LADDER — validated apparatus, fresh browser per gate");
  console.log(` ${new Date().toISOString()}`);
  console.log(` GATES: ${GATES.length} (3×refused + 3×roundtrip)`);
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
  const refusedPass = results.filter(r => r.name.startsWith("tcp-refused") && r.passed).length;
  const roundtripPass = results.filter(r => r.name.startsWith("tcp-roundtrip") && r.passed).length;

  console.log("\n═══════════════════════════════════════════════════════════");
  console.log(` tcp-refused:   ${refusedPass}/3`);
  console.log(` tcp-roundtrip: ${roundtripPass}/3`);
  console.log(` TOTAL:         ${passed}/${results.length}`);
  console.log("═══════════════════════════════════════════════════════════\n");

  writeFileSync("n2-tcp-loopback-report.json", JSON.stringify({
    timestamp: new Date().toISOString(),
    summary: { total: results.length, passed, refusedPass, roundtripPass },
    results: results.map(r => ({ gate: r.name, passed: r.passed, result: r.result, resultValue: r.resultValue, guestExitCode: r.guestExitCode, wallMs: r.wallMs })),
  }, null, 2));

  if (passed === results.length) {
    console.log("VERDICT: NODE_LOOPBACK_TCP_VERIFIED ✅");
  } else {
    console.log("VERDICT: NODE_LOOPBACK_TCP_NOT_VERIFIED ❌");
    process.exitCode = 1;
  }
}

main().catch(e => { console.error(e); process.exit(2); });