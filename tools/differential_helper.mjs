// Node side of tools/differential.py: evaluates a case file through the TypeScript-stack
// CHECKS (imported from cross_check_ts.mjs — the corpus runner there is guarded and does
// not execute on import) and prints [verdict, reason] pairs as JSON on stdout. The
// exception convention mirrors both corpus runners: a throwing check is a malformed input.
import { readFileSync } from "node:fs";
import { CHECKS } from "./cross_check_ts.mjs";

const cases = JSON.parse(readFileSync(process.argv[2], "utf-8"));
const out = cases.map((c) => {
  try {
    const [verdict, reason] = CHECKS[c.kind](c.input);
    return [verdict, reason ?? null];
  } catch {
    return ["malformed", null];
  }
});
process.stdout.write(JSON.stringify(out));
