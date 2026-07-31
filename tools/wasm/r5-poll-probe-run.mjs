/**
 * r5-poll-probe-run.mjs — Playwright runner for the guest-native C poll() probe.
 * Usage: node r5-poll-probe-run.mjs <run-number>
 * Executes r5-poll-probe.html in a fresh browser, captures full output.
 */
import { chromium } from "playwright";
import { writeFileSync } from "node:fs";
import { execSync, spawn } from "node:child_process";

const WASM_DIR = "/Users/danielecorrao/tombl-build/linux/tools/wasm";
const PROBE_URL = "http://127.0.0.1:8788/r5-poll-probe.html";
const SERVER_PORT = 8788;
const PROBE_TIMEOUT = 300_000;
const POLL_INTERVAL = 2000;
const EVAL_TIMEOUT = 5000;
const EVIDENCE_DIR = process.env.N2_EVIDENCE_DIR || "/tmp";
const RUN_NUM = process.argv[2] || "1";

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

console.log(`── r5-poll-probe run ${RUN_NUM} ──`);
await startServer();
const browser = await chromium.launch({ headless: true, args: ["--no-sandbox", "--enable-features=SharedArrayBuffer", "--disable-gpu"] });
const context = await browser.newContext();
const page = await context.newPage();
const pageErrors = [];
page.on("pageerror", e => pageErrors.push(e.message));
let lastSnapshot = "";
const startTime = Date.now();

try {
  await page.goto(PROBE_URL, { waitUntil: "domcontentloaded", timeout: 30000 });
  let done = false;
  while (Date.now() - startTime < PROBE_TIMEOUT) {
    const snap = await pollOutput(page);
    if (snap !== null) lastSnapshot = snap;
    if (/R5_POLL_PROBE_END:/.test(lastSnapshot)) { done = true; break; }
    await new Promise(r => setTimeout(r, POLL_INTERVAL));
  }
  const wallMs = Date.now() - startTime;

  // Extract probe output lines
  const lines = lastSnapshot.split("\n");
  const probeLines = lines.filter(l => /^(OK:|FAIL:|R5_POLL_PROBE_)/.test(l.trim()));
  const endMatch = lastSnapshot.match(/R5_POLL_PROBE_END:(\S+)/);
  const exitMatch = lastSnapshot.match(/PROBE_EXIT=(\d+)/);
  const verdict = endMatch ? endMatch[1] : (done ? "UNKNOWN" : "TIMEOUT");
  const exitCode = exitMatch ? parseInt(exitMatch[1], 10) : null;
  const passed = verdict === "PASS" && exitCode === 0;
  const crashSigs = (lastSnapshot.match(/delivering SIG(SEGV|ILL|BUS|FPE|ABRT)/g) ?? []);

  const result = {
    name: `r5-poll-probe-run-${RUN_NUM}`,
    run: RUN_NUM,
    passed: passed && crashSigs.length === 0,
    verdict,
    exitCode,
    timedOut: !done,
    wallMs,
    crashCount: crashSigs.length,
    pageErrors,
    probeLines,
    okCount: probeLines.filter(l => l.trim().startsWith("OK:")).length,
    failCount: probeLines.filter(l => l.trim().startsWith("FAIL:")).length,
  };

  const icon = result.passed ? "✅" : "❌";
  console.log(`  ${icon} verdict=${verdict} exit=${exitCode} ok=${result.okCount} fail=${result.failCount} crash=${crashSigs.length} to=${!done} wall=${wallMs}ms`);
  probeLines.forEach(l => console.log(`    ${l.trim()}`));

  writeFileSync(`${EVIDENCE_DIR}/r5-poll-probe-run-${RUN_NUM}.json`, JSON.stringify(result, null, 2));
  writeFileSync(`${EVIDENCE_DIR}/r5-poll-probe-run-${RUN_NUM}-full.log`, lastSnapshot);
  console.log(result.passed ? `VERDICT: POLL_RUN_${RUN_NUM}_PASS ✅` : `VERDICT: POLL_RUN_${RUN_NUM}_FAIL ❌`);
  if (!result.passed) process.exitCode = 1;
} finally {
  await safeClose(page);
  await safeClose(context);
  await safeClose(browser);
  stopServer();
}
