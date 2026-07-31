/**
 * net-validator.mjs
 * Line-anchored extraction of ZN_RESULT:<uuid>:<value> + exact-match validation.
 * Exported for both self-test and runner.
 */

/**
 * Find a marker that must appear at the START of a line (preceded by \n or at position 0).
 * This prevents matching markers embedded in shell-echoed command source.
 * Returns the character index of the marker itself, or -1.
 */
function indexOfLineStart(text, marker) {
  if (text.startsWith(marker)) return 0;
  const idx = text.indexOf("\n" + marker);
  return idx >= 0 ? idx + 1 : -1; // +1 to skip the \n
}

/**
 * Extract the RESULT value: text after "ZN_RESULT:<uuid>:" up to next \n or \r.
 * Only matches when the marker is at line start (not inside command echo).
 */
function extractResultValue(rawOutput, uuid) {
  const prefix = `ZN_RESULT:${uuid}:`;
  const idx = indexOfLineStart(rawOutput, prefix);
  if (idx < 0) return null;
  const valueStart = idx + prefix.length;
  let end = rawOutput.length;
  const nl = rawOutput.indexOf("\n", valueStart);
  if (nl >= 0) end = Math.min(end, nl);
  const cr = rawOutput.indexOf("\r", valueStart);
  if (cr >= 0) end = Math.min(end, cr);
  return rawOutput.slice(valueStart, end);
}

/**
 * Full extraction: guest exit code, result value, marker positions, order check.
 */
export function extractResult(rawOutput, uuid) {
  const beginIdx = indexOfLineStart(rawOutput, `ZN_BEGIN:${uuid}`);
  const resultIdx = indexOfLineStart(rawOutput, `ZN_RESULT:${uuid}:`);
  const endIdx = indexOfLineStart(rawOutput, `ZN_END:${uuid}`);

  // Exit code: "GATE_EXIT:<uuid>=<digits>" at line start
  const exitPrefix = `GATE_EXIT:${uuid}=`;
  const exitLineIdx = indexOfLineStart(rawOutput, exitPrefix);
  let guestExitCode = null;
  let exitIdx = -1;
  if (exitLineIdx >= 0) {
    const afterEq = exitLineIdx + exitPrefix.length;
    const m = rawOutput.slice(afterEq, afterEq + 5).match(/^(\d+)/);
    if (m) { guestExitCode = parseInt(m[1], 10); exitIdx = exitLineIdx; }
  }

  const resultValue = resultIdx >= 0 ? extractResultValue(rawOutput, uuid) : null;

  // Order: BEGIN < RESULT < END < EXIT (all must be present)
  const orderOk =
    beginIdx >= 0 &&
    resultIdx > beginIdx &&
    endIdx > resultIdx &&
    exitIdx > endIdx;

  return { beginIdx, resultIdx, endIdx, exitIdx, resultValue, guestExitCode, orderOk };
}

/**
 * Validate extracted result against an exact matcher function.
 * Returns { valid, reason }.
 */
export function validateResult(extracted, matcher) {
  if (extracted.resultValue === null)
    return { valid: false, reason: "RESULT_ABSENT" };
  if (!extracted.orderOk)
    return { valid: false, reason: "ORDER_VIOLATION" };
  if (extracted.guestExitCode !== 0)
    return { valid: false, reason: `EXIT_${extracted.guestExitCode}` };
  if (!matcher(extracted.resultValue))
    return { valid: false, reason: `VALUE_MISMATCH:"${extracted.resultValue}"` };
  return { valid: true, reason: "OK" };
}
