#!/usr/bin/env python3
"""Direct engine-parity harness: both implementations, same inputs, byte-compared verdicts.

The corpus cross-check's oracle is MANIFEST.json, so engine agreement there is transitive
through the shared expectations — both engines can hold the same wrong assumption and stay
green, and an input the corpus does not carry is never compared at all. That is how an
explicit-null `record_commits` forked the two engines (Python `is None` vs TS `=== undefined`)
while every run stayed green. Reported as a limit of the corpus cross-check by @Rul1an
(issue #4, second report).

This harness is the non-transitive control: every corpus vector PLUS a deterministic
off-corpus mutation battery at fork-prone keys (explicit nulls, declared/derivable conflicts,
containers of the wrong shape), run through BOTH engines, verdict and reason-code compared
directly. Any divergence exits non-zero and prints the offending input.

Run:  npm i viem  (repo root), then  python3 tools/differential.py
"""

import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from verify import CHECKS, digest_of  # noqa: E402


def py_verdict(kind, inp):
    """Mirror the Python runner's convention: an exception is a malformed input, not a crash."""
    try:
        verdict, reason, _detail = CHECKS[kind](inp)
        return [verdict, reason]
    except Exception:
        return ["malformed", None]


def mutations(kind, inp):
    """Deterministic off-corpus battery. Every case is representable JSON — the absent-key
    case (the only honest 'undefined') is simply a case where the key is not added."""
    out = []

    def with_key(key, value, tag):
        m = json.loads(json.dumps(inp))
        m[key] = value
        out.append((tag, m))

    def without_key(key, tag):
        if key in inp:
            m = json.loads(json.dumps(inp))
            del m[key]
            out.append((tag, m))

    # Fork-prone key 1: record_commits — presence must reject identically whatever it holds.
    with_key("record_commits", ["settlement"], "record_commits=list")
    with_key("record_commits", None, "record_commits=null")
    if kind == "independence_claim":
        with_key("record_commits", "settlement", "record_commits=string")
        with_key("record_commits", [], "record_commits=empty-list")
        # Fork-prone key 2: settlement_result container shape — isinstance(dict) vs
        # typeof 'object' disagree on arrays and null unless both engines exclude them.
        with_key("settlement_result", [], "settlement_result=array")
        with_key("settlement_result", None, "settlement_result=null")
        without_key("settlement_result", "settlement_result-absent")
        # Fork-prone key 3: covers — null-vs-absent and empty-container readings must
        # stay parallel for the same reason record_commits' did not.
        with_key("covers", None, "covers=null")
        with_key("covers", [], "covers=empty-list")
        without_key("covers", "covers-absent")
    if kind == "decision_evidence_binding":
        # Binding-specific fail-closed battery. These cases are intentionally outside the
        # shared manifest oracle so Python/TS shape readings are compared directly.
        without_key("decision_evidence", "decision_evidence=absent")
        with_key("decision_evidence", None, "decision_evidence=null")
        with_key("decision_evidence", [], "decision_evidence=array")
        with_key("decision_evidence", "not-an-object", "decision_evidence=string")
        for tag, record in (
            ("record=absent", None),
            ("record=null", None),
            ("record=array", []),
            ("record=empty-object", {}),
        ):
            m = json.loads(json.dumps(inp))
            if tag == "record=absent":
                m.pop("record", None)
            else:
                m["record"] = record
            out.append((tag, m))
        if isinstance(inp.get("record"), dict):
            for tag, digest in (
                ("commitment=null", None),
                ("commitment=malformed", "0x1234"),
                ("commitment=mismatch", "0x" + "00" * 32),
            ):
                m = json.loads(json.dumps(inp))
                m["record"]["decisionEvidenceDigest"] = digest
                out.append((tag, m))
        if isinstance(inp.get("decision_evidence"), dict):
            m = json.loads(json.dumps(inp))
            m["decision_evidence"].setdefault("policy", {})["version"] = "substituted"
            out.append(("decision_evidence=policy-substitution", m))
    if kind == "offer_binding":
        # Regression for key absence versus an explicit JSON null. Python previously used
        # indexing while JS canonicalization received undefined; a refactor to `.get()` can
        # accidentally turn absence into null and accept a digest of canonical `null`.
        m = json.loads(json.dumps(inp))
        m.pop("offer", None)
        m.setdefault("receipt", {})["offerDigest"] = digest_of(None)
        out.append(("offer=absent-with-null-commitment", m))
    return out


def main():
    vectors_dir = os.path.join(ROOT, "vectors")
    cases = []
    for fname in sorted(os.listdir(vectors_dir)):
        if not fname.endswith(".json"):
            continue
        with open(os.path.join(vectors_dir, fname)) as f:
            vector = json.load(f)
        kind, inp = vector["kind"], vector["input"]
        cases.append({"label": f"{fname}", "kind": kind, "input": inp})
        for tag, mutated in mutations(kind, inp):
            cases.append({"label": f"{fname}::{tag}", "kind": kind, "input": mutated})

    py_results = [py_verdict(c["kind"], c["input"]) for c in cases]

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        json.dump(cases, tf)
        tmp_path = tf.name
    try:
        proc = subprocess.run(
            ["node", os.path.join(ROOT, "tools", "differential_helper.mjs"), tmp_path],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            print("differential: node helper failed:", proc.stderr.strip(), file=sys.stderr)
            return 1
        ts_results = json.loads(proc.stdout)
    finally:
        os.unlink(tmp_path)

    if len(ts_results) != len(cases):
        print(f"differential: case count mismatch ({len(ts_results)} vs {len(cases)})", file=sys.stderr)
        return 1

    diverged = 0
    for case, py_r, ts_r in zip(cases, py_results, ts_results):
        if py_r != ts_r:
            diverged += 1
            print(f"DIVERGE {case['label']}: PY {py_r} vs TS {ts_r}")
            print(f"        input: {json.dumps(case['input'])[:200]}")
    print(
        f"DIFFERENTIAL {'OK' if diverged == 0 else 'FAILED'}: "
        f"{len(cases)} cases ({sum(1 for c in cases if '::' in c['label'])} off-corpus), "
        f"{diverged} divergence(s)"
    )
    return 0 if diverged == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
