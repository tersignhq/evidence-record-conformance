// Node side of tools/differential_statement.py: evaluates a case file (a JSON array of chain-statement inputs) through
// the TypeScript engine (tools/cross_check_statement.mjs, whose runner is guarded and does not run on import) and prints
// the [verdict, reason] pairs as JSON on stdout. A check that throws is reported as a crash, never as a verdict.
import { readFileSync } from "node:fs";
import { checkStatement } from "./cross_check_statement.mjs";

const cases = JSON.parse(readFileSync(process.argv[2], "utf-8"));
const out = [];
for (const input of cases) {
  try {
    const [verdict, reason] = await checkStatement(input);
    out.push([verdict, reason ?? null]);
  } catch (e) {
    out.push(["crash", e.constructor.name]);
  }
}
process.stdout.write(JSON.stringify(out));
