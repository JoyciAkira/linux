/**
 * net-validator-selftest.mjs
 * Proves the validator logic without a browser.
 * Required verdict: NET_LADDER_APPARATUS_VALIDATED
 */
import { extractResult, validateResult } from "./net-validator.mjs";

const uuid = "abc123def456";
// Matcher: only exact "TCP_REFUSED:ECONNREFUSED" is authorized
const matcher = (v) => v === "TCP_REFUSED:ECONNREFUSED";

let pass = 0, fail = 0;
function check(name, cond, detail = "") {
  const ok = !!cond;
  console.log(`  ${ok ? "✅" : "❌"} ${name}${detail ? " — " + detail : ""}`);
  if (ok) pass++; else fail++;
}

console.log("NET-VALIDATOR SELF-TEST\n");

// T1: Accept correct RESULT
{
  const raw = `\nZN_BEGIN:${uuid}\nZN_RESULT:${uuid}:TCP_REFUSED:ECONNREFUSED\nZN_END:${uuid}\nGATE_EXIT:${uuid}=0\n`;
  const v = validateResult(extractResult(raw, uuid), matcher);
  check("T1 accepts correct RESULT", v.valid, v.reason);
}

// T2: Reject RESULT absent
{
  const raw = `\nZN_BEGIN:${uuid}\nZN_END:${uuid}\nGATE_EXIT:${uuid}=0\n`;
  const v = validateResult(extractResult(raw, uuid), matcher);
  check("T2 rejects RESULT absent", !v.valid && v.reason === "RESULT_ABSENT", v.reason);
}

// T3: Reject wrong UUID
{
  const wrongUuid = "xyz789aaa000";
  const raw = `\nZN_BEGIN:${wrongUuid}\nZN_RESULT:${wrongUuid}:TCP_REFUSED:ECONNREFUSED\nZN_END:${wrongUuid}\nGATE_EXIT:${wrongUuid}=0\n`;
  const v = validateResult(extractResult(raw, uuid), matcher); // searching for OUR uuid
  check("T3 rejects wrong UUID", !v.valid, v.reason);
}

// T4: Reject exit code 1
{
  const raw = `\nZN_BEGIN:${uuid}\nZN_RESULT:${uuid}:TCP_REFUSED:ECONNREFUSED\nZN_END:${uuid}\nGATE_EXIT:${uuid}=1\n`;
  const v = validateResult(extractResult(raw, uuid), matcher);
  check("T4 rejects exit code 1", !v.valid && v.reason === "EXIT_1", v.reason);
}

// T5: Reject token present only in command source (not at line start)
{
  // Shell echo of the command — ZN_RESULT appears inside the -e '...' string, NOT at line start
  const raw = `/bin/blink -e -s /bin/node -e 'console.log("ZN_RESULT:${uuid}:TCP_REFUSED:ECONNREFUSED")' ; echo GATE_EXIT:${uuid}=$?\nZN_BEGIN:${uuid}\nZN_END:${uuid}\nGATE_EXIT:${uuid}=0\n`;
  const v = validateResult(extractResult(raw, uuid), matcher);
  check("T5 rejects token only in command source", !v.valid, v.reason);
}

// T6: Reject TCP_TIMEOUT when expecting TCP_REFUSED:ECONNREFUSED
{
  const raw = `\nZN_BEGIN:${uuid}\nZN_RESULT:${uuid}:TCP_TIMEOUT\nZN_END:${uuid}\nGATE_EXIT:${uuid}=0\n`;
  const v = validateResult(extractResult(raw, uuid), matcher);
  check("T6 rejects wrong value (TIMEOUT vs REFUSED)", !v.valid && v.reason.startsWith("VALUE_MISMATCH"), v.reason);
}

// T7 (bonus): Verify line-anchoring defense — RESULT mid-line in strace must NOT match
{
  // Blink strace writes: I1970... write(1, "ZN_RESULT:uuid:value\n", ...) 
  // The marker is inside a quoted string, NOT at line start
  const raw = `I1970-01-01T00:01:01:blink write(1, "ZN_RESULT:${uuid}:TCP_REFUSED:ECONNREFUSED", 40) -> 40\nZN_BEGIN:${uuid}\nZN_RESULT:${uuid}:TCP_REFUSED:ECONNREFUSED\nZN_END:${uuid}\nGATE_EXIT:${uuid}=0\n`;
  const ext = extractResult(raw, uuid);
  // The line-start RESULT should be the second occurrence (on its own line), not the strace one
  check("T7 line-anchoring: strace noise doesn't hijack RESULT", ext.resultValue === "TCP_REFUSED:ECONNREFUSED", `got: "${ext.resultValue}"`);
}

console.log(`\n${pass}/${pass + fail} PASSED`);
if (fail === 0) {
  console.log("\nVERDICT: NET_LADDER_APPARATUS_VALIDATED ✅");
  process.exit(0);
} else {
  console.log("\nVERDICT: APPARATUS_INVALID ❌");
  process.exit(1);
}
