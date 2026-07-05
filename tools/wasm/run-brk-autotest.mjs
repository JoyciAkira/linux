#!/usr/bin/env node
// Reproducible headless driver for the arch/wasm brk-ceiling (end_brk = -1) fix.
//
// Boots vmlinux.wasm in headless Chromium, runs brk-autotest.html which drives
// /bin/sh through the WASM heap/mmap probes + blink x86-64 smoke tests, then
// writes the full boot log + a JSON verdict as artifacts under ./artifacts/.
//
// Exit 0 = PASS (brk fix proven: bigalloc allocates >=200MB, all probes OK).
// Exit 1 = FAIL. Usage: node run-brk-autotest.mjs [port]
//
// Requires: dist/ built, vmlinux.wasm + rootfs.ext2 present, Playwright chromium.
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createRequire } from "node:module";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = parseInt(process.argv[2] ?? "8199", 10);
const ARTIFACTS = join(__dirname, "artifacts");

// Resolve Playwright from the Zeronode repo (the local package.json has none).
const require = createRequire("/Users/danielecorrao/Zeronode/package.json");
let chromium;
try {
  ({ chromium } = require("playwright"));
} catch {
  console.error("FATAL: playwright not resolvable from Zeronode/node_modules");
  process.exit(2);
}

for (const f of ["dist/index.js", "vmlinux.wasm", "rootfs.ext2", "brk-autotest.html"]) {
  if (!existsSync(join(__dirname, f))) {
    console.error(`FATAL: missing required file: ${f}`);
    process.exit(2);
  }
}
mkdirSync(ARTIFACTS, { recursive: true });

// Start the COOP/COEP static server.
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

const browser = await chromium.launch({
  headless: true,
  args: ["--enable-features=SharedArrayBuffer"],
});
let verdict = { pass: false, error: "driver did not complete" };
try {
  const page = await browser.newPage();
  page.on("console", (m) => { const t = m.text(); if (t.includes("[FATAL]") || t.includes("ERROR")) console.log("[page]", t); });
  await page.goto(`http://127.0.0.1:${PORT}/brk-autotest.html`);

  // Autotest drives boot + probes; allow up to 4 minutes total.
  await page.waitForFunction(() => window.__done === true, { timeout: 240000 });

  verdict = await page.evaluate(() => window.__result);
  const bootLog = await page.evaluate(() => window.__consoleOutput.join(""));

  writeFileSync(join(ARTIFACTS, "boot-log.txt"), bootLog);
  writeFileSync(join(ARTIFACTS, "verdict.json"), JSON.stringify(verdict, null, 2));
} finally {
  await browser.close();
  cleanup();
}

console.log("\n===== VERDICT =====");
console.log(JSON.stringify(verdict, null, 2));
console.log(`\nartifacts: ${join(ARTIFACTS, "boot-log.txt")}`);
console.log(`           ${join(ARTIFACTS, "verdict.json")}`);
process.exit(verdict.pass ? 0 : 1);
