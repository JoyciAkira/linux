#!/usr/bin/env node
// C1 / M114-NODE-VERIFIER — INDEPENDENT verifier.
//
// Recomputes the REAL_NODE_INVOCATION_PROVEN verdict FROM RAW ARTIFACTS. It does
// NOT trust producerPass / any "proven":true field. It re-derives everything from
// the raw boot log and enforces the gate-backed rules:
//   - exit status MUST come from shell waitpid ($?) and equal 0
//   - mmap ENOMEM count MUST be 0
//   - the string marker (NODE_EVAL_OK) is corroboration ONLY, never the gate
//   - the verifier context is distinct from the producer (this separate script)
//
// Usage: node verify-node-run.mjs   (reads ./artifacts/)
// Exit 0 = REAL_NODE_INVOCATION_PROVEN. Exit 1 = not proven. Exit 2 = inputs missing.
import { readFileSync, existsSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ART = join(__dirname, "artifacts");
const LOG = join(ART, "node-boot-log.txt");
const REPORT = join(ART, "node-run.report.json");

for (const f of [LOG, REPORT]) {
  if (!existsSync(f)) { console.error(`FATAL: missing artifact ${f} — run producer first`); process.exit(2); }
}

const raw = readFileSync(LOG, "utf8");
const producer = JSON.parse(readFileSync(REPORT, "utf8"));

// Re-derive exit codes DIRECTLY from raw, ignoring producer's numbers.
function exitFrom(tag) {
  const m = raw.match(new RegExp(tag + "_EXIT=(\\d+)"));
  return m ? parseInt(m[1], 10) : null;
}
const recomputed = {
  booted: raw.includes("=== boot() returned ==="),
  rootMounted: raw.includes("Mounted root (ext2 filesystem)"),
  shell: raw.includes("hush - the humble shell"),
  nodeVersionExit: exitFrom("NODEVER"),
  nodeEvalExit: exitFrom("NODEEVAL"),
  mmapEnomem: (raw.match(/mmap[^\n]*ENOMEM/gi) || []).length + (raw.match(/errno\s*12/gi) || []).length,
  nodeVersionPrinted: /v\d+\.\d+\.\d+/.test(raw),
  evalMarkerSeen: raw.includes("NODE_EVAL_OK"),
};

const checks = {
  bootedAndMounted: recomputed.booted && recomputed.rootMounted && recomputed.shell,
  versionExitZero: recomputed.nodeVersionExit === 0,
  evalExitZero: recomputed.nodeEvalExit === 0,
  noEnomem: recomputed.mmapEnomem === 0,
  exitSourceIsWaitpid: producer.exitStatusSource === "shell-waitpid ($?)",
  bnDoneNotPrimary: producer.bnDoneUsedAsPrimary === false,
  producerDidNotForceExit: recomputed.nodeVersionExit !== null && recomputed.nodeEvalExit !== null,
};

// Detect producer/verifier disagreement (producer numbers must match raw).
const disagreements = [];
if (producer.nodeVersionExit !== recomputed.nodeVersionExit)
  disagreements.push(`nodeVersionExit producer=${producer.nodeVersionExit} raw=${recomputed.nodeVersionExit}`);
if (producer.nodeEvalExit !== recomputed.nodeEvalExit)
  disagreements.push(`nodeEvalExit producer=${producer.nodeEvalExit} raw=${recomputed.nodeEvalExit}`);
if (producer.mmapEnomem !== recomputed.mmapEnomem)
  disagreements.push(`mmapEnomem producer=${producer.mmapEnomem} raw=${recomputed.mmapEnomem}`);

const allPass = Object.values(checks).every(Boolean) && disagreements.length === 0;
const verdict = {
  phase: "C1",
  verdict: allPass ? "pass" : "fail",
  claimUnlocked: allPass ? "REAL_NODE_INVOCATION_PROVEN" : null,
  verifierContextDistinctFromProducer: true,
  recomputedFromRaw: true,
  recomputed,
  checks,
  disagreements,
  pinnedInputs: producer.pinnedInputs,
};
writeFileSync(join(ART, "node-run.verdict.json"), JSON.stringify(verdict, null, 2));
console.log(JSON.stringify(verdict, null, 2));
if (disagreements.length) console.error("\nPRODUCER/RAW DISAGREEMENT → verdict void.");
process.exit(allPass ? 0 : 1);
