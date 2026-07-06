#!/usr/bin/env node
// C1 / M114-NODE-VERIFIER — producer driver.
//
// NOTE: this is a NEW verifier probe (v1). The original run-node-diag4.mjs
// referenced by the M114 doc was never committed to VCS; this replaces it with
// an auditable, in-repo probe. Mirrors run-brk-autotest.mjs.
//
// Boots node-rootfs.ext2 in headless Chromium via node-verifier.html, runs the
// REAL /bin/node x86-64 under blink, and writes GATE-BACKED evidence to
// ./artifacts/node-run.report.json + raw boot log. Exit status is captured from
// the guest shell's $? (waitpid), NOT a wrapper string marker.
//
// Requires: dist/ built, node-verifier.html, node-rootfs.ext2 (with /bin/node +
// blink), Playwright chromium. Usage: node run-node-verifier-v1.mjs [port]
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createRequire } from "node:module";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = parseInt(process.argv[2] ?? "8201", 10);
const ARTIFACTS = join(__dirname, "artifacts");
const require = createRequire("/Users/danielecorrao/Zeronode/package.json");

let chromium;
try { ({ chromium } = require("playwright")); }
catch { console.error("FATAL: playwright not resolvable"); process.exit(2); }

const REQUIRED = ["dist/index.js", "node-verifier.html", "node-rootfs.ext2", "serve-coop.py"];
for (const f of REQUIRED) {
  if (!existsSync(join(__dirname, f))) { console.error(`FATAL: missing ${f}`); process.exit(2); }
}
mkdirSync(ARTIFACTS, { recursive: true });

function sha256(path) {
  return existsSync(path) ? createHash("sha256").update(readFileSync(path)).digest("hex") : null;
}
const pinnedInputs = {
  "vmlinux.wasm": sha256(join(__dirname, "vmlinux.wasm")),
  "node-rootfs.ext2": sha256(join(__dirname, "node-rootfs.ext2")),
  "node-verifier.html": sha256(join(__dirname, "node-verifier.html")),
  "probe": sha256(join(__dirname, "run-node-verifier-v1.mjs")),
};

const server = spawn("python3", [join(__dirname, "serve-coop.py"), String(PORT)], {
  cwd: __dirname, stdio: ["ignore", "pipe", "inherit"],
});
const cleanup = () => { try { server.kill(); } catch {} };
process.on("exit", cleanup);
process.on("SIGINT", () => { cleanup(); process.exit(130); });

await new Promise((resolve, reject) => {
  const to = setTimeout(() => reject(new Error("server did not start in 10s")), 10000);
  server.stdout.on("data", (d) => { if (d.toString().includes("serving on")) { clearTimeout(to); resolve(); } });
  server.on("exit", (c) => { clearTimeout(to); reject(new Error("server exited early code=" + c)); });
});
console.log(`[driver] server on ${PORT}`);

const browser = await chromium.launch({ headless: true, args: ["--enable-features=SharedArrayBuffer"] });
let verdict = { pass: false, error: "driver did not complete" };
let bootLog = "";
try {
  const page = await browser.newPage();
  page.on("console", (m) => { const t = m.text(); if (t.includes("[FATAL]") || t.includes("ERROR")) console.log("[page]", t); });
  await page.goto(`http://127.0.0.1:${PORT}/node-verifier.html`);
  await page.waitForFunction(() => window.__done === true, { timeout: 300000 });
  verdict = await page.evaluate(() => window.__result);
  bootLog = await page.evaluate(() => window.__consoleOutput.join(""));
} finally {
  await browser.close();
  cleanup();
}

const report = {
  phase: "C1",
  probe: "run-node-verifier-v1.mjs",
  pinnedInputs,
  execTarget: "/bin/node (x86-64 under blink)",
  exitStatusSource: "shell-waitpid ($?)",
  nodeVersionExit: verdict.nodeVersionExit ?? null,
  nodeEvalExit: verdict.nodeEvalExit ?? null,
  mmapEnomem: verdict.mmapEnomem ?? null,
  mmapCalls: verdict.mmapCalls ?? null,
  bnDoneUsedAsPrimary: false,
  producerPass: verdict.pass === true,
  rawArtifacts: ["artifacts/node-boot-log.txt"],
};
writeFileSync(join(ARTIFACTS, "node-boot-log.txt"), bootLog);
writeFileSync(join(ARTIFACTS, "node-run.report.json"), JSON.stringify(report, null, 2));

console.log("\n===== PRODUCER REPORT =====");
console.log(JSON.stringify(report, null, 2));
console.log(`\nNOTE: producerPass is NOT authoritative. Run verify-node-run.mjs to recompute.`);
process.exit(report.producerPass ? 0 : 1);
