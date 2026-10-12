#!/usr/bin/env python3
"""Mutation run for the rules v0.5.9 pins (issue #9), stdlib only.

The boundary_binding rule (`attestedPrefixLength` wherever it is present, coverage, position), and
the chain_set, offer_binding and number-domain clauses #9's ablations found no vector reaching alone.
Each mutant is a one-site change to verify.py or tools/cross_check_ts.mjs, applied in a scratch copy
by tools/mutate_members.py's runner: it is KILLED when the engine's run exits non-zero AND every
vector named for it fails; the unmutated copy must pass first and again at the end.

    python3 tools/mutate_rules.py              # every mutant
    python3 tools/mutate_rules.py NAME ...     # only the named mutants

Exit 0 only if every mutant is killed by its named vectors and both controls pass.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mutate_members import run  # noqa: E402

PY_ATTESTED = ("        if not isinstance(attested, int) or isinstance(attested, bool) or not 0 <= attested <= len(prefix):\n")
PY_PRESENT = "    if \"attestedPrefixLength\" in event:\n"
PY_PREV = "        if r_prev != prev:\n"
PY_OFFER = "    return _check_object_binding(\n        inp.get(\"receipt\"),\n"
PY_BOUND = "        if abs(value) > 2**53 - 1:\n"
PY = {
    # ---- (a) boundary_binding
    "attested-no-upper-bound": (PY_ATTESTED, PY_ATTESTED.replace("not 0 <= attested <= len(prefix)", "not 0 <= attested"),
                                ["n153", "n155", "n159"]),
    "attested-bound-fixed-3": (PY_ATTESTED, PY_ATTESTED.replace("<= len(prefix)", "<= 3"), ["n159"]),
    "attested-bound-plus-one": (PY_ATTESTED, PY_ATTESTED.replace("<= len(prefix)", "<= len(prefix) + 1"), ["n153", "n159"]),
    "attested-bound-exclusive": (PY_ATTESTED, PY_ATTESTED.replace("<= len(prefix)", "< len(prefix)"), ["p18", "p20", "p64"]),
    "attested-no-lower-bound": (PY_ATTESTED, PY_ATTESTED.replace("not 0 <= attested <= len(prefix)", "not attested <= len(prefix)"),
                                ["n154"]),
    "attested-positive-only": (PY_ATTESTED, PY_ATTESTED.replace("not 0 <= attested", "not 1 <= attested"), ["p63"]),
    "attested-bool-as-int": (PY_ATTESTED, PY_ATTESTED.replace(" or isinstance(attested, bool)", ""), ["n157"]),
    "attested-float-as-int": (PY_ATTESTED, PY_ATTESTED.replace("isinstance(attested, int)", "isinstance(attested, (int, float))"),
                              ["n156"]),
    "attested-value-sentinel": (PY_PRESENT, "    if event.get(\"attestedPrefixLength\") is not None:\n", ["n158"]),
    "attested-only-with-coverage": (PY_PRESENT,
                                    "    if \"attestedPrefixLength\" in event and inp.get(\"covered_through\") is not None:\n",
                                    ["n154", "n156", "n157", "n158", "n159"]),
    "coverage-past-attestation-unchecked": ("        if covered > attested:\n", "        if False:\n", ["n166"]),
    "coverage-attested-optional": ("        attested = event.get(\"attestedPrefixLength\")\n",
                                   "        attested = event.get(\"attestedPrefixLength\", len(prefix))\n", ["n167"]),
    "position-presence-only": ("    if position != len(prefix):\n", "    if False:\n", ["n168"]),
    # ---- (b) and (c) chain_set, offer_binding, the number domain
    "head-digest-not-compared": ("    if prev != head_digest:\n", "    if False:\n", ["n160"]),
    "first-prev-unchecked": (PY_PREV, "        if r_prev != prev and r is not records[0]:\n", ["n161"]),
    "prev-checked-only-with-links": (PY_PREV, "        if \"link\" in r and r_prev != prev:\n", ["n162"]),
    "links-required": ("        if \"link\" in r:\n",
                       "        if \"link\" not in r:\n            return \"reject\", \"continuity_reject\", \"no link\"\n"
                       "        if \"link\" in r:\n", ["p65"]),
    "head-digest-read-late": ("    if head_digest is None:\n        return \"reject\", \"completeness_reject\", "
                              "\"head digest is not a parseable 32-byte hex digest\"\n", "", ["n165"]),
    "receipt-without-digest-accepted": (PY_OFFER,
                                        "    if isinstance(inp.get(\"receipt\"), dict) and \"offerDigest\" not in inp[\"receipt\"]:\n"
                                        "        return \"valid\", None, \"no offer digest to compare\"\n" + PY_OFFER, ["n163"]),
    "positive-bound-only": (PY_BOUND, "        if value > 2**53 - 1:\n", ["n164"]),
    "negative-bound-exclusive": (PY_BOUND, "        if value > 2**53 - 1 or value <= -(2**53 - 1):\n", ["p66"]),
}

TS_ATTESTED = "      if (!Number.isInteger(attested) || attested < 0 || attested > prefix.length) return [\"reject\", \"boundary_reject\"];\n"
TS_PRESENT = "    if (\"attestedPrefixLength\" in event) {\n"
TS_PREV = "      if (rPrev !== prev) return [\"reject\", \"continuity_reject\"];\n"
TS_OFFER = "    return checkObjectBinding(inp.receipt, \"offerDigest\", inp.offer);\n"
TS = {
    "ts-attested-no-integer-check": (TS_ATTESTED, TS_ATTESTED.replace("!Number.isInteger(attested) || ", ""),
                                     ["n156", "n157", "n158"]),
    "ts-attested-no-upper-bound": (TS_ATTESTED, TS_ATTESTED.replace(" || attested > prefix.length", ""), ["n153", "n155", "n159"]),
    "ts-attested-value-sentinel": (TS_PRESENT, "    if (event.attestedPrefixLength !== null && event.attestedPrefixLength !== undefined) {\n",
                                   ["n158"]),
    "ts-attested-only-with-coverage": (TS_PRESENT, "    if (\"attestedPrefixLength\" in event && inp.covered_through !== null "
                                                   "&& inp.covered_through !== undefined) {\n",
                                       ["n154", "n156", "n157", "n158", "n159"]),
    "ts-coverage-past-attestation-unchecked": ("      if (covered > attested) return [\"reject\", \"boundary_reject\"];\n", "", ["n166"]),
    "ts-position-presence-only": ("    if (position !== prefix.length) return [\"reject\", \"boundary_reject\"];\n", "", ["n168"]),
    "ts-head-digest-not-compared": ("    return prev === headDigest ? [\"valid\", null] : [\"reject\", \"continuity_reject\"];\n",
                                    "    return [\"valid\", null];\n", ["n160"]),
    "ts-first-prev-unchecked": (TS_PREV, TS_PREV.replace("if (rPrev !== prev)", "if (r !== records[0] && rPrev !== prev)"), ["n161"]),
    "ts-prev-checked-only-with-links": (TS_PREV, TS_PREV.replace("if (rPrev !== prev)", "if (\"link\" in r && rPrev !== prev)"),
                                        ["n162"]),
    "ts-head-digest-read-late": ("    if (headDigest === null) return [\"reject\", \"completeness_reject\"];\n", "", ["n165"]),
    "ts-receipt-without-digest-accepted": (TS_OFFER, "    if (typeof inp.receipt === \"object\" && inp.receipt !== null "
                                                     "&& !(\"offerDigest\" in inp.receipt)) return [\"valid\", null];\n" + TS_OFFER,
                                           ["n163"]),
    "ts-positive-bound-only": ("    if (!Number.isSafeInteger(v)) throw", "    if (v > Number.MAX_SAFE_INTEGER) throw", ["n164"]),
}


if __name__ == "__main__":
    sys.exit(run(PY, TS, sys.argv[1:]))
