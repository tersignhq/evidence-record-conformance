#!/usr/bin/env python3
"""Mutation run for the rules v0.5.9 pins (issue #9), stdlib only.

The boundary_binding rule (`attestedPrefixLength` wherever it is present, coverage, position), and
five of the coverage gaps #9's audit listed (chain_set, offer_binding, the number domain), and the
clauses no vector reached alone before v0.5.9 (an absent attested length, a numeric string,
a null `covered_through`, an unparseable head digest, a non-object attestation beside an outside one).
With composition_independence: one-site mutants of that kind's criterion, each named for the
vectors it must fail. Generation gate (6) in tools/gen_vectors.py checks four engines for each single
feature it lists, in the Python engine only. README.md's composition_independence section lists each
mutant's reading and the vectors it fails, and states what the vectors pin.
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
PY_COMP_JOIN = "    if verdict != \"valid\":\n        return verdict, reason, detail\n    parties = inp.get(\"parties\")\n"
PY_COMP_PARTIES = "        parties = parties + [inp.get(\"counterparty\")]\n"
PY_COMP_ATTESTATIONS = "        \"attestations\": inp.get(\"findings_attestations\"),\n"
PY_COMP_CLAIM_HEAD = ("    verdict, reason, detail = check_independence_claim({\n"
                      "        \"claimed\": inp.get(\"claimed\"),\n        \"parties\": parties,\n")
PY_COMP_AS_WRITTEN_SITE = PY_COMP_PARTIES + PY_COMP_CLAIM_HEAD + PY_COMP_ATTESTATIONS
PY_COMP_CP_FROM = "        parties = parties + [{}]\n"
PY_COMP_JOIN_CALL = "    verdict, reason, detail = _check_object_binding(\n        inp.get(\"decision\"),\n"
PY_FINDINGS = "(inp.get(\"findings_attestations\") if isinstance(inp.get(\"findings_attestations\"), list) else [])"
PY_DECISION = "(inp.get(\"decision_attestations\") if isinstance(inp.get(\"decision_attestations\"), list) else [])"
PY_COMP_BODY = (PY_COMP_JOIN + "    if isinstance(parties, list) and parties:\n" + PY_COMP_PARTIES
                + "    verdict, reason, detail = check_independence_claim({\n"
                + "        \"claimed\": inp.get(\"claimed\"),\n        \"parties\": parties,\n" + PY_COMP_ATTESTATIONS
                + "    })\n    return verdict, reason, f\"findings, the counterparty counted among the parties: {detail}\"\n")
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
    # ---- the clauses no vector reached alone before p67 and n169-n172: an absent attested length, a numeric
    # string, a null `covered_through`, an unparseable head digest, a non-object attestation beside an outside one
    "attested-required": (PY_PRESENT, "    if \"attestedPrefixLength\" not in event:\n"
                                      "        return \"reject\", \"boundary_reject\", \"no attested length\"\n" + PY_PRESENT, ["p67"]),
    "attested-string-coerced": ("        attested = event[\"attestedPrefixLength\"]\n",
                                "        attested = event[\"attestedPrefixLength\"]\n"
                                "        if isinstance(attested, str) and attested.isdigit():\n            attested = int(attested)\n",
                                ["n170"]),
    "coverage-null-as-absent": ("    if \"covered_through\" in inp:\n        covered = inp[\"covered_through\"]\n",
                                "    covered = inp.get(\"covered_through\")\n    if covered is not None:\n", ["n171"]),
    "head-digest-present-only": ("    if head_digest is None:\n        return \"reject\", \"completeness_reject\", "
                                 "\"head digest is not a parseable 32-byte hex digest\"\n",
                                 "    if \"digest\" not in head:\n        return \"reject\", \"completeness_reject\", \"no head digest\"\n",
                                 ["n169"]),
    "attestation-non-object-skipped": ("        if not isinstance(a, dict) or \"by\" not in a:\n",
                                       "        if not isinstance(a, dict):\n            continue\n        if \"by\" not in a:\n", ["n172"]),
    # ---- (d) composition_independence
    "comp-counterparty-not-a-party": (PY_COMP_PARTIES, "        parties = parties\n", ["n173", "n174"]),
    "comp-attestations-pooled": (PY_COMP_ATTESTATIONS,
                                 "        \"attestations\": (inp.get(\"findings_attestations\") or []) "
                                 "+ (inp.get(\"decision_attestations\") or []),\n", ["n174"]),
    "comp-decision-attestations-read": (PY_COMP_ATTESTATIONS, "        \"attestations\": inp.get(\"decision_attestations\"),\n",
                                        ["p68", "n174"]),
    "comp-declared-parties-dropped": (PY_COMP_PARTIES, "        parties = [inp.get(\"counterparty\")]\n", ["n180"]),
    "comp-findings-fallback-to-decision": (PY_COMP_ATTESTATIONS,
                                           "        \"attestations\": inp.get(\"findings_attestations\") "
                                           "or inp.get(\"decision_attestations\"),\n", ["n183"]),
    "comp-decision-attestation-required": (PY_COMP_JOIN, PY_COMP_JOIN.replace(
        "    parties = inp.get(\"parties\")\n",
        "    if not inp.get(\"decision_attestations\"):\n        return \"reject\", \"independence_reject\", \"decision not attested\"\n"
        "    parties = inp.get(\"parties\")\n"), ["p70"]),
    "comp-counterparty-as-written": (PY_COMP_AS_WRITTEN_SITE,
                                     "        parties = parties\n" + PY_COMP_CLAIM_HEAD
                                     + "        \"attestations\": [a for a in (inp.get(\"findings_attestations\") or []) "
                                     "if not (isinstance(a, dict) and a.get(\"by\") == inp.get(\"counterparty\"))],\n", ["n181"]),
    # ---- the counterparty taken from a label or from the decision, each identifier side
    # compared as written, and an attestor that names no 0x-address
    "comp-counterparty-from-role": (PY_COMP_AS_WRITTEN_SITE,
                                    "        parties = parties\n" + PY_COMP_CLAIM_HEAD
                                    + "        \"attestations\": [a for a in (inp.get(\"findings_attestations\") or []) "
                                    "if not (isinstance(a, dict) and \"role\" in a)],\n", ["n185", "p72"]),
    "comp-role-labelled-is-party": (PY_COMP_ATTESTATIONS,
                                    "        \"attestations\": [a for a in (inp.get(\"findings_attestations\") or []) "
                                    "if not (isinstance(a, dict) and \"role\" in a)],\n", ["p72"]),
    "comp-decision-attestors-as-counterparty": (PY_COMP_PARTIES,
                                                "        parties = parties + [a.get(\"by\") for a in "
                                                "(inp.get(\"decision_attestations\") or []) if isinstance(a, dict)]\n",
                                                ["p73"]),
    "comp-decision-attestors-as-parties": (PY_COMP_PARTIES,
                                           "        parties = parties + [inp.get(\"counterparty\")] + [a.get(\"by\") for a in "
                                           "(inp.get(\"decision_attestations\") or []) if isinstance(a, dict)]\n", ["p73"]),
    "comp-counterparty-unnormalized": (PY_COMP_AS_WRITTEN_SITE,
                                       "        parties = parties\n" + PY_COMP_CLAIM_HEAD
                                       + "        \"attestations\": [a for a in (inp.get(\"findings_attestations\") or []) "
                                       "if not (isinstance(a, dict) and _address_key(_norm_addr(a.get(\"by\")) or \"\") "
                                       "== inp.get(\"counterparty\"))],\n", ["n184"]),
    "comp-parties-unnormalized": (PY_COMP_AS_WRITTEN_SITE,
                                  "        parties = [inp.get(\"counterparty\")]\n" + PY_COMP_CLAIM_HEAD
                                  + "        \"attestations\": [a for a in (inp.get(\"findings_attestations\") or []) "
                                  "if not (isinstance(a, dict) and _address_key(_norm_addr(a.get(\"by\")) or \"\") "
                                  "in (inp.get(\"parties\") or []))],\n", ["n186"]),
    "comp-address-identifiers-only": (PY_COMP_JOIN, PY_COMP_JOIN.replace(
        "    parties = inp.get(\"parties\")\n",
        "    if any(isinstance(a, dict) and _norm_addr(a.get(\"by\")) and _address_key(_norm_addr(a.get(\"by\"))) is None "
        "for a in (inp.get(\"findings_attestations\") or [])):\n"
        "        return \"reject\", \"independence_reject\", \"attestor names no address\"\n"
        "    parties = inp.get(\"parties\")\n"), ["p71"]),
    # ---- the counterparty taken from another feature of the attestations (a label on
    # either list, a place in either list, attesting both records, a spelling, a fixed address), a scheme-qualified
    # party refused, a party's attestation compared as written, and the join read off what the decision decides
    "comp-counterparty-first-labelled-findings-attestor": (PY_COMP_PARTIES, PY_COMP_CP_FROM.format(
        "next((a.get(\"by\") for a in (inp.get(\"findings_attestations\") or []) if isinstance(a, dict) and \"role\" in a), None)"),
        ["p74", "p77"]),
    "comp-counterparty-from-decision-label": (PY_COMP_PARTIES, PY_COMP_CP_FROM.format(
        "next((a.get(\"by\") for a in (inp.get(\"decision_attestations\") or []) if isinstance(a, dict) "
        "and a.get(\"role\") == \"counterparty\"), inp.get(\"counterparty\"))"), ["n187", "n190"]),
    "comp-decision-label-is-party": (PY_COMP_PARTIES,
                                     "        parties = parties + [inp.get(\"counterparty\")] + [a.get(\"by\") for a in "
                                     "(inp.get(\"decision_attestations\") or []) if isinstance(a, dict) and a.get(\"role\") == \"counterparty\"]\n",
                                     ["p75"]),
    "comp-counterparty-first-decision-attestor": (PY_COMP_PARTIES, PY_COMP_CP_FROM.format(
        "next((a.get(\"by\") for a in (inp.get(\"decision_attestations\") or []) if isinstance(a, dict)), inp.get(\"counterparty\"))"),
        ["n187", "n190"]),
    "comp-counterparty-only-decision-attestor": (PY_COMP_PARTIES, PY_COMP_CP_FROM.format(
        "inp[\"decision_attestations\"][0].get(\"by\") if isinstance(inp.get(\"decision_attestations\"), list) "
        "and len(inp[\"decision_attestations\"]) == 1 and isinstance(inp[\"decision_attestations\"][0], dict) "
        "else inp.get(\"counterparty\")"), ["n190"]),
    "comp-counterparty-first-findings-attestor": (PY_COMP_PARTIES, PY_COMP_CP_FROM.format(
        "next((a.get(\"by\") for a in (inp.get(\"findings_attestations\") or []) if isinstance(a, dict)), None)"),
        ["p77", "n189"]),
    "comp-first-findings-attestation-is-counterparty": (PY_COMP_AS_WRITTEN_SITE,
                                                        "        parties = parties\n" + PY_COMP_CLAIM_HEAD
                                                        + "        \"attestations\": (inp.get(\"findings_attestations\") or [])[1:],\n",
                                                        ["p77", "n189"]),
    "comp-counterparty-attests-both-records": (PY_COMP_PARTIES, PY_COMP_CP_FROM.format(
        "next((a.get(\"by\") for a in (inp.get(\"findings_attestations\") or []) if isinstance(a, dict) and any("
        "isinstance(d, dict) and d.get(\"by\") == a.get(\"by\") for d in (inp.get(\"decision_attestations\") or []))), "
        "inp.get(\"counterparty\"))"), ["p77"]),
    "comp-counterparty-first-scheme-qualified-attestor": (PY_COMP_PARTIES, PY_COMP_CP_FROM.format(
        "next((a.get(\"by\") for a in (inp.get(\"findings_attestations\") or []) if isinstance(a, dict) "
        "and _norm_addr(a.get(\"by\")) is not None and not ADDR_RE.fullmatch(_norm_addr(a.get(\"by\")))), inp.get(\"counterparty\"))"),
        ["n191"]),
    "comp-counterparty-fixed-address": (PY_COMP_PARTIES, PY_COMP_CP_FROM.format("\"0x2222222222222222222222222222222222222222\""),
                                        ["n192"]),
    "comp-fixed-address-is-party": (PY_COMP_PARTIES, "        parties = parties + [inp.get(\"counterparty\"), "
                                                     "\"0x2222222222222222222222222222222222222222\"]\n", ["p79"]),
    "comp-scheme-qualified-party-refused": (PY_COMP_JOIN, PY_COMP_JOIN.replace(
        "    parties = inp.get(\"parties\")\n",
        "    if inp.get(\"claimed\") == \"independent\" and any(_norm_addr(x) is not None and not ADDR_RE.fullmatch(_norm_addr(x)) "
        "for x in (inp.get(\"parties\") if isinstance(inp.get(\"parties\"), list) else []) + [inp.get(\"counterparty\")]):\n"
        "        return \"reject\", \"independence_reject\", \"scheme-qualified party\"\n"
        "    parties = inp.get(\"parties\")\n"), ["p78"]),
    "comp-party-attestor-as-written": (PY_COMP_AS_WRITTEN_SITE,
                                       "        parties = [inp.get(\"counterparty\")]\n" + PY_COMP_CLAIM_HEAD
                                       + "        \"attestations\": [a for a in (inp.get(\"findings_attestations\") or []) "
                                       "if not (isinstance(a, dict) and a.get(\"by\") in (inp.get(\"parties\") or []))],\n", ["n186", "n191"]),
    "comp-join-requires-accepted-decision": (PY_COMP_JOIN_CALL, PY_COMP_JOIN_CALL.replace(
        "        inp.get(\"decision\"),\n",
        "        (None if isinstance(inp.get(\"decision\"), dict) and inp[\"decision\"].get(\"decision\") != \"accepted\" "
        "else inp.get(\"decision\")),\n"), ["p76"]),
    "comp-join-by-decision-and-result": (PY_COMP_JOIN, "    _d, _f = inp.get(\"decision\"), inp.get(\"findings\")\n"
                                         "    if not (isinstance(_d, dict) and isinstance(_f, dict) and (_d.get(\"decision\") == \"accepted\") "
                                         "== (_f.get(\"result\") == \"meets the stated terms\")):\n"
                                         "        return \"reject\", \"binding_reject\", \"decision and findings disagree\"\n"
                                         "    parties = inp.get(\"parties\")\n", ["p76", "n188"]),
    # ---- the counterparty taken from two features together, an attestor made a party by
    # them or by a findings label, the parties taken from a fixed address, an attestor of the decision alone
    # failing the claim, the join reading what the decision decides, what the findings say or the digest as written,
    # the parties read as their first or last identifier only, or more than one refused, and the join skipped or
    # read after the claim
    "comp-counterparty-labelled-decision-attestor-of-both-records": (PY_COMP_PARTIES, PY_COMP_CP_FROM.format(
        "next((d.get(\"by\") for d in " + PY_DECISION + " if isinstance(d, dict) and d.get(\"role\") == \"counterparty\" "
        "and any(isinstance(a, dict) and a.get(\"by\") == d.get(\"by\") for a in " + PY_FINDINGS + ")), inp.get(\"counterparty\"))"),
        ["p80", "n193"]),
    "comp-counterparty-first-decision-attestor-of-both-records": (PY_COMP_PARTIES, PY_COMP_CP_FROM.format(
        "next((d.get(\"by\") for d in " + PY_DECISION + "[:1] if isinstance(d, dict) "
        "and any(isinstance(a, dict) and a.get(\"by\") == d.get(\"by\") for a in " + PY_FINDINGS + ")), inp.get(\"counterparty\"))"),
        ["p80", "n193"]),
    "comp-counterparty-first-in-both-lists": (PY_COMP_PARTIES, PY_COMP_CP_FROM.format(
        "next((a.get(\"by\") for a in " + PY_FINDINGS + "[:1] if isinstance(a, dict) "
        "and any(isinstance(d, dict) and d.get(\"by\") == a.get(\"by\") for d in " + PY_DECISION + "[:1])), inp.get(\"counterparty\"))"),
        ["p80", "n193"]),
    "comp-first-in-both-lists-is-party": (PY_COMP_PARTIES,
                                          "        parties = parties + [inp.get(\"counterparty\")] + [a.get(\"by\") for a in " + PY_FINDINGS
                                          + "[:1] if isinstance(a, dict) and any(isinstance(d, dict) and d.get(\"by\") == a.get(\"by\") for d in "
                                          + PY_DECISION + "[:1])]\n", ["p80"]),
    "comp-counterparty-labelled-in-both-lists": (PY_COMP_PARTIES, PY_COMP_CP_FROM.format(
        "next((a.get(\"by\") for a in " + PY_FINDINGS + " if isinstance(a, dict) and \"role\" in a "
        "and any(isinstance(d, dict) and \"role\" in d and d.get(\"by\") == a.get(\"by\") for d in " + PY_DECISION + ")), "
        "inp.get(\"counterparty\"))"), ["p80"]),
    "comp-labelled-in-both-lists-is-party": (PY_COMP_PARTIES,
                                             "        parties = parties + [inp.get(\"counterparty\")] + [a.get(\"by\") for a in " + PY_FINDINGS
                                             + " if isinstance(a, dict) and \"role\" in a and any(isinstance(d, dict) and \"role\" in d "
                                             "and d.get(\"by\") == a.get(\"by\") for d in " + PY_DECISION + ")]\n", ["p80"]),
    "comp-findings-label-counterparty-is-party": (PY_COMP_PARTIES,
                                                  "        parties = parties + [inp.get(\"counterparty\")] + [a.get(\"by\") for a in " + PY_FINDINGS
                                                  + " if isinstance(a, dict) and a.get(\"role\") == \"counterparty\"]\n", ["p80"]),
    "comp-counterparty-only-unlabelled-findings-attestor": (PY_COMP_PARTIES, PY_COMP_CP_FROM.format(
        "(lambda f: f[0].get(\"by\") if len(f) == 1 and isinstance(f[0], dict) and \"role\" not in f[0] "
        "else inp.get(\"counterparty\"))(" + PY_FINDINGS + ")"), ["p81"]),
    "comp-counterparty-only-findings-attestor-not-on-decision": (PY_COMP_PARTIES, PY_COMP_CP_FROM.format(
        "(lambda f, d: f[0].get(\"by\") if len(f) == 1 and isinstance(f[0], dict) and not any(isinstance(x, dict) "
        "and x.get(\"by\") == f[0].get(\"by\") for x in d) else inp.get(\"counterparty\"))(" + PY_FINDINGS + ", " + PY_DECISION + ")"),
        ["p81"]),
    "comp-parties-fixed-address": (PY_COMP_PARTIES, "        parties = [\"0x3333333333333333333333333333333333333333\", "
                                                    "inp.get(\"counterparty\")]\n", ["n195"]),
    "comp-parties-first-only": (PY_COMP_PARTIES, "        parties = parties[:1] + [inp.get(\"counterparty\")]\n", ["n196"]),
    "comp-parties-last-only": (PY_COMP_PARTIES, "        parties = parties[-1:] + [inp.get(\"counterparty\")]\n", ["n196"]),
    "comp-parties-multi-rejected": (PY_COMP_PARTIES, "        parties = parties + [inp.get(\"counterparty\")] if len(parties) == 1 else None\n", ["p86"]),
    "comp-decision-only-attestor-fails-closed": (PY_COMP_JOIN, PY_COMP_JOIN.replace(
        "    parties = inp.get(\"parties\")\n",
        "    _id = lambda x: (_address_key(_norm_addr(x)) or _norm_addr(x)) if _norm_addr(x) else None\n"
        "    if any(isinstance(d, dict) and _id(d.get(\"by\")) != _id(inp.get(\"counterparty\")) and not any(isinstance(a, dict) "
        "and _id(a.get(\"by\")) == _id(d.get(\"by\")) for a in " + PY_FINDINGS + ") for d in " + PY_DECISION + "):\n"
        "        return \"reject\", \"independence_reject\", \"an attestor of the decision alone is not the counterparty\"\n"
        "    parties = inp.get(\"parties\")\n"), ["p82"]),
    "comp-join-only-for-accepted-decision": (PY_COMP_JOIN, PY_COMP_JOIN.replace(
        "    if verdict != \"valid\":\n",
        "    if verdict != \"valid\" and not (isinstance(inp.get(\"decision\"), dict) "
        "and inp[\"decision\"].get(\"decision\") != \"accepted\"):\n"), ["n194"]),
    "comp-join-rejects-accepted-unmet-findings": (PY_COMP_JOIN, PY_COMP_JOIN.replace(
        "    parties = inp.get(\"parties\")\n",
        "    if inp[\"decision\"].get(\"decision\") == \"accepted\" and inp[\"findings\"].get(\"result\") != \"meets the stated terms\":\n"
        "        return \"reject\", \"binding_reject\", \"an accepting decision on findings that do not meet the terms\"\n"
        "    parties = inp.get(\"parties\")\n"), ["p83"]),
    "comp-join-reads-findings-result": (PY_COMP_JOIN, PY_COMP_JOIN.replace(
        "    parties = inp.get(\"parties\")\n",
        "    if inp[\"findings\"].get(\"result\") != \"meets the stated terms\":\n"
        "        return \"reject\", \"binding_reject\", \"findings that do not meet the terms\"\n"
        "    parties = inp.get(\"parties\")\n"), ["p83", "p84"]),
    "comp-findings-digest-compared-as-written": (PY_COMP_JOIN_CALL, PY_COMP_JOIN_CALL.replace(
        "        inp.get(\"decision\"),\n",
        "        (lambda d: {**d, \"findings_digest\": None} if isinstance(d, dict) and isinstance(d.get(\"findings_digest\"), str) "
        "and _norm_digest(d[\"findings_digest\"]) != d[\"findings_digest\"] else d)(inp.get(\"decision\")),\n"), ["p85"]),
    "comp-join-skipped": (PY_COMP_JOIN, "    parties = inp.get(\"parties\")\n", ["n175", "n182"]),
    "comp-claim-before-join": (PY_COMP_BODY, PY_COMP_BODY.replace(PY_COMP_JOIN, "    _join = (verdict, reason, detail)\n    parties = inp.get(\"parties\")\n").replace(
        "    return verdict, reason, f\"findings,",
        "    if verdict == \"valid\" and _join[0] != \"valid\":\n        return _join\n    return verdict, reason, f\"findings,"),
        ["n175"]),
}

TS_ATTESTED = "      if (!Number.isInteger(attested) || attested < 0 || attested > prefix.length) return [\"reject\", \"boundary_reject\"];\n"
TS_PRESENT = "    if (\"attestedPrefixLength\" in event) {\n"
TS_PREV = "      if (rPrev !== prev) return [\"reject\", \"continuity_reject\"];\n"
TS_OFFER = "    return checkObjectBinding(inp.receipt, \"offerDigest\", inp.offer);\n"
TS_COMP_JOIN = "    if (joined[0] !== \"valid\") return joined;\n"
TS_COMP_PARTIES = "    if (Array.isArray(parties) && parties.length > 0) parties = [...parties, inp.counterparty];\n"
TS_COMP_ATTESTATIONS = "      attestations: inp.findings_attestations,\n"
TS_COMP_CLAIM_HEAD = "    return CRITERIA.independence_claim({\n      claimed: inp.claimed,\n      parties,\n"
TS_COMP_AS_WRITTEN_SITE = TS_COMP_PARTIES + TS_COMP_CLAIM_HEAD + TS_COMP_ATTESTATIONS
TS_COMP_CP_FROM = "    if (Array.isArray(parties) && parties.length > 0) parties = [...parties, {}];\n"
TS_COMP_JOIN_CALL = "    const joined = checkObjectBinding(inp.decision, \"findings_digest\", inp.findings, { objectRequired: true });\n"
TS_FINDINGS = "(Array.isArray(inp.findings_attestations) ? inp.findings_attestations : [])"
TS_DECISION = "(Array.isArray(inp.decision_attestations) ? inp.decision_attestations : [])"
TS_COMP_BODY = (TS_COMP_JOIN + "    let parties = inp.parties;\n" + TS_COMP_PARTIES
                + "    return CRITERIA.independence_claim({\n      claimed: inp.claimed,\n      parties,\n"
                + TS_COMP_ATTESTATIONS + "    });\n")
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
    # ---- the same clauses (p67, n169-n172)
    "ts-attested-required": (TS_PRESENT, "    if (!(\"attestedPrefixLength\" in event)) return [\"reject\", \"boundary_reject\"];\n" + TS_PRESENT,
                             ["p67"]),
    "ts-attested-string-coerced": (TS_ATTESTED, TS_ATTESTED.replace(
        "if (!Number.isInteger(attested)",
        "if (!Number.isInteger(typeof attested === \"string\" && /^[0-9]+$/.test(attested) ? Number(attested) : attested)"), ["n170"]),
    "ts-coverage-null-as-absent": ("    if (\"covered_through\" in inp) {\n      const covered = inp.covered_through;\n",
                                   "    const covered = inp.covered_through;\n    if (covered !== null && covered !== undefined) {\n", ["n171"]),
    "ts-head-digest-present-only": ("    if (headDigest === null) return [\"reject\", \"completeness_reject\"];\n",
                                    "    if (!(\"digest\" in head)) return [\"reject\", \"completeness_reject\"];\n", ["n169"]),
    "ts-attestation-non-object-skipped": (
        "      if (typeof a !== \"object\" || a === null || Array.isArray(a) || !(\"by\" in a)) return [\"reject\", \"independence_reject\"];\n",
        "      if (typeof a !== \"object\" || a === null || Array.isArray(a)) continue;\n"
        "      if (!(\"by\" in a)) return [\"reject\", \"independence_reject\"];\n", ["n172"]),
    # ---- (d) composition_independence
    "ts-comp-counterparty-not-a-party": (TS_COMP_PARTIES, "", ["n173", "n174"]),
    "ts-comp-attestations-pooled": (TS_COMP_ATTESTATIONS,
                                    "      attestations: [...(inp.findings_attestations ?? []), ...(inp.decision_attestations ?? [])],\n",
                                    ["n174"]),
    "ts-comp-decision-attestations-read": (TS_COMP_ATTESTATIONS, "      attestations: inp.decision_attestations,\n", ["p68", "n174"]),
    "ts-comp-declared-parties-dropped": (TS_COMP_PARTIES, TS_COMP_PARTIES.replace("[...parties, inp.counterparty]", "[inp.counterparty]"),
                                         ["n180"]),
    "ts-comp-findings-fallback-to-decision": (TS_COMP_ATTESTATIONS,
                                              "      attestations: (Array.isArray(inp.findings_attestations) && inp.findings_attestations.length > 0 "
                                              "? inp.findings_attestations : inp.decision_attestations),\n", ["n183"]),
    "ts-comp-decision-attestation-required": (TS_COMP_JOIN, TS_COMP_JOIN
                                              + "    if (!Array.isArray(inp.decision_attestations) || inp.decision_attestations.length === 0) "
                                              "return [\"reject\", \"independence_reject\"];\n", ["p70"]),
    "ts-comp-counterparty-as-written": (TS_COMP_AS_WRITTEN_SITE, TS_COMP_CLAIM_HEAD
                                        + "      attestations: Array.isArray(inp.findings_attestations) ? inp.findings_attestations.filter("
                                        "(a) => !(a && typeof a === \"object\" && a.by === inp.counterparty)) : inp.findings_attestations,\n",
                                        ["n181"]),
    # ---- the same readings: the counterparty taken from a label or from the decision, each identifier side
    # compared as written, and an attestor that names no 0x-address
    "ts-comp-counterparty-from-role": (TS_COMP_AS_WRITTEN_SITE, TS_COMP_CLAIM_HEAD
                                       + "      attestations: Array.isArray(inp.findings_attestations) ? inp.findings_attestations.filter("
                                       "(a) => !(a && typeof a === \"object\" && \"role\" in a)) : inp.findings_attestations,\n",
                                       ["n185", "p72"]),
    "ts-comp-role-labelled-is-party": (TS_COMP_ATTESTATIONS,
                                       "      attestations: Array.isArray(inp.findings_attestations) ? inp.findings_attestations.filter("
                                       "(a) => !(a && typeof a === \"object\" && \"role\" in a)) : inp.findings_attestations,\n",
                                       ["p72"]),
    "ts-comp-decision-attestors-as-counterparty": (TS_COMP_PARTIES, TS_COMP_PARTIES.replace(
        "[...parties, inp.counterparty]",
        "[...parties, ...(Array.isArray(inp.decision_attestations) ? inp.decision_attestations : [])"
        ".filter((a) => a && typeof a === \"object\" && !Array.isArray(a)).map((a) => a.by)]"), ["p73"]),
    "ts-comp-decision-attestors-as-parties": (TS_COMP_PARTIES, TS_COMP_PARTIES.replace(
        "[...parties, inp.counterparty]",
        "[...parties, inp.counterparty, ...(Array.isArray(inp.decision_attestations) ? inp.decision_attestations : [])"
        ".filter((a) => a && typeof a === \"object\" && !Array.isArray(a)).map((a) => a.by)]"), ["p73"]),
    "ts-comp-counterparty-unnormalized": (TS_COMP_AS_WRITTEN_SITE, TS_COMP_CLAIM_HEAD
                                          + "      attestations: Array.isArray(inp.findings_attestations) ? inp.findings_attestations.filter("
                                          "(a) => !(a && typeof a === \"object\" && addressKey(normAddr(a.by) ?? \"\") === inp.counterparty))"
                                          " : inp.findings_attestations,\n", ["n184"]),
    "ts-comp-parties-unnormalized": (TS_COMP_AS_WRITTEN_SITE,
                                     TS_COMP_PARTIES.replace("[...parties, inp.counterparty]", "[inp.counterparty]") + TS_COMP_CLAIM_HEAD
                                     + "      attestations: Array.isArray(inp.findings_attestations) ? inp.findings_attestations.filter("
                                     "(a) => !(a && typeof a === \"object\" && Array.isArray(inp.parties) "
                                     "&& inp.parties.includes(addressKey(normAddr(a.by) ?? \"\")))) : inp.findings_attestations,\n",
                                     ["n186"]),
    "ts-comp-address-identifiers-only": (TS_COMP_JOIN, TS_COMP_JOIN
                                         + "    if ((Array.isArray(inp.findings_attestations) ? inp.findings_attestations : []).some("
                                         "(a) => a && typeof a === \"object\" && normAddr(a.by) !== null && addressKey(normAddr(a.by)) === null)) "
                                         "return [\"reject\", \"independence_reject\"];\n", ["p71"]),
    # ---- the same readings: the counterparty taken from another feature of the attestations, a scheme-qualified
    # party refused, a party's attestation compared as written, and the join read off what the decision decides
    "ts-comp-counterparty-first-labelled-findings-attestor": (TS_COMP_PARTIES, TS_COMP_CP_FROM.format(
        "(" + TS_FINDINGS + ".find((a) => isObject(a) && \"role\" in a) ?? { by: null }).by"), ["p74", "p77"]),
    "ts-comp-counterparty-from-decision-label": (TS_COMP_PARTIES, TS_COMP_CP_FROM.format(
        "(" + TS_DECISION + ".find((a) => isObject(a) && a.role === \"counterparty\") ?? { by: inp.counterparty }).by"),
        ["n187", "n190"]),
    "ts-comp-decision-label-is-party": (TS_COMP_PARTIES, TS_COMP_PARTIES.replace(
        "[...parties, inp.counterparty]",
        "[...parties, inp.counterparty, ..." + TS_DECISION + ".filter((a) => isObject(a) && a.role === \"counterparty\").map((a) => a.by)]"),
        ["p75"]),
    "ts-comp-counterparty-first-decision-attestor": (TS_COMP_PARTIES, TS_COMP_CP_FROM.format(
        "(" + TS_DECISION + ".find((a) => isObject(a)) ?? { by: inp.counterparty }).by"), ["n187", "n190"]),
    "ts-comp-counterparty-only-decision-attestor": (TS_COMP_PARTIES, TS_COMP_CP_FROM.format(
        "(Array.isArray(inp.decision_attestations) && inp.decision_attestations.length === 1 && isObject(inp.decision_attestations[0]) "
        "? inp.decision_attestations[0].by : inp.counterparty)"), ["n190"]),
    "ts-comp-counterparty-first-findings-attestor": (TS_COMP_PARTIES, TS_COMP_CP_FROM.format(
        "(" + TS_FINDINGS + ".find((a) => isObject(a)) ?? { by: null }).by"), ["p77", "n189"]),
    "ts-comp-first-findings-attestation-is-counterparty": (TS_COMP_AS_WRITTEN_SITE, TS_COMP_CLAIM_HEAD
                                                           + "      attestations: " + TS_FINDINGS + ".slice(1),\n", ["p77", "n189"]),
    "ts-comp-counterparty-attests-both-records": (TS_COMP_PARTIES, TS_COMP_CP_FROM.format(
        "(" + TS_FINDINGS + ".find((a) => isObject(a) && " + TS_DECISION + ".some((d) => isObject(d) && d.by === a.by)) "
        "?? { by: inp.counterparty }).by"), ["p77"]),
    "ts-comp-counterparty-first-scheme-qualified-attestor": (TS_COMP_PARTIES, TS_COMP_CP_FROM.format(
        "(" + TS_FINDINGS + ".find((a) => isObject(a) && normAddr(a.by) !== null && !ADDR_RE.test(normAddr(a.by))) "
        "?? { by: inp.counterparty }).by"), ["n191"]),
    "ts-comp-counterparty-fixed-address": (TS_COMP_PARTIES, TS_COMP_CP_FROM.format("\"0x2222222222222222222222222222222222222222\""),
                                           ["n192"]),
    "ts-comp-fixed-address-is-party": (TS_COMP_PARTIES, TS_COMP_PARTIES.replace(
        "[...parties, inp.counterparty]", "[...parties, inp.counterparty, \"0x2222222222222222222222222222222222222222\"]"), ["p79"]),
    "ts-comp-scheme-qualified-party-refused": (TS_COMP_JOIN, TS_COMP_JOIN
                                               + "    if (inp.claimed === \"independent\" && [...(Array.isArray(inp.parties) ? inp.parties : []), "
                                               "inp.counterparty].some((x) => normAddr(x) !== null && !ADDR_RE.test(normAddr(x)))) "
                                               "return [\"reject\", \"independence_reject\"];\n", ["p78"]),
    "ts-comp-party-attestor-as-written": (TS_COMP_AS_WRITTEN_SITE,
                                          TS_COMP_PARTIES.replace("[...parties, inp.counterparty]", "[inp.counterparty]") + TS_COMP_CLAIM_HEAD
                                          + "      attestations: Array.isArray(inp.findings_attestations) ? inp.findings_attestations.filter("
                                          "(a) => !(a && typeof a === \"object\" && Array.isArray(inp.parties) && inp.parties.includes(a.by))) "
                                          ": inp.findings_attestations,\n", ["n186", "n191"]),
    "ts-comp-join-requires-accepted-decision": (TS_COMP_JOIN_CALL, TS_COMP_JOIN_CALL.replace(
        "checkObjectBinding(inp.decision,",
        "checkObjectBinding(isObject(inp.decision) && inp.decision.decision !== \"accepted\" ? null : inp.decision,"), ["p76"]),
    "ts-comp-join-by-decision-and-result": (TS_COMP_JOIN_CALL,
                                            "    const joined = isObject(inp.decision) && isObject(inp.findings) && (inp.decision.decision === \"accepted\") "
                                            "=== (inp.findings.result === \"meets the stated terms\") ? [\"valid\", null] : [\"reject\", \"binding_reject\"];\n",
                                            ["p76", "n188"]),
    # ---- the same readings: the counterparty taken from two features together, an attestor made a party by
    # them or by a findings label, the parties taken from a fixed address, an attestor of the decision alone
    # failing the claim, the join reading what the decision decides, what the findings say or the digest as written,
    # the parties read as their first or last identifier only, or more than one refused, and the join skipped or
    # read after the claim
    "ts-comp-counterparty-labelled-decision-attestor-of-both-records": (TS_COMP_PARTIES, TS_COMP_CP_FROM.format(
        "(" + TS_DECISION + ".find((d) => isObject(d) && d.role === \"counterparty\" && " + TS_FINDINGS
        + ".some((a) => isObject(a) && a.by === d.by)) ?? { by: inp.counterparty }).by"), ["p80", "n193"]),
    "ts-comp-counterparty-first-decision-attestor-of-both-records": (TS_COMP_PARTIES, TS_COMP_CP_FROM.format(
        "(" + TS_DECISION + ".slice(0, 1).find((d) => isObject(d) && " + TS_FINDINGS
        + ".some((a) => isObject(a) && a.by === d.by)) ?? { by: inp.counterparty }).by"), ["p80", "n193"]),
    "ts-comp-counterparty-first-in-both-lists": (TS_COMP_PARTIES, TS_COMP_CP_FROM.format(
        "(" + TS_FINDINGS + ".slice(0, 1).find((a) => isObject(a) && " + TS_DECISION
        + ".slice(0, 1).some((d) => isObject(d) && d.by === a.by)) ?? { by: inp.counterparty }).by"), ["p80", "n193"]),
    "ts-comp-first-in-both-lists-is-party": (TS_COMP_PARTIES, TS_COMP_PARTIES.replace(
        "[...parties, inp.counterparty]",
        "[...parties, inp.counterparty, ..." + TS_FINDINGS + ".slice(0, 1).filter((a) => isObject(a) && " + TS_DECISION
        + ".slice(0, 1).some((d) => isObject(d) && d.by === a.by)).map((a) => a.by)]"), ["p80"]),
    "ts-comp-counterparty-labelled-in-both-lists": (TS_COMP_PARTIES, TS_COMP_CP_FROM.format(
        "(" + TS_FINDINGS + ".find((a) => isObject(a) && \"role\" in a && " + TS_DECISION
        + ".some((d) => isObject(d) && \"role\" in d && d.by === a.by)) ?? { by: inp.counterparty }).by"), ["p80"]),
    "ts-comp-labelled-in-both-lists-is-party": (TS_COMP_PARTIES, TS_COMP_PARTIES.replace(
        "[...parties, inp.counterparty]",
        "[...parties, inp.counterparty, ..." + TS_FINDINGS + ".filter((a) => isObject(a) && \"role\" in a && " + TS_DECISION
        + ".some((d) => isObject(d) && \"role\" in d && d.by === a.by)).map((a) => a.by)]"), ["p80"]),
    "ts-comp-findings-label-counterparty-is-party": (TS_COMP_PARTIES, TS_COMP_PARTIES.replace(
        "[...parties, inp.counterparty]",
        "[...parties, inp.counterparty, ..." + TS_FINDINGS + ".filter((a) => isObject(a) && a.role === \"counterparty\").map((a) => a.by)]"),
        ["p80"]),
    "ts-comp-counterparty-only-unlabelled-findings-attestor": (TS_COMP_PARTIES, TS_COMP_CP_FROM.format(
        "((f) => (f.length === 1 && isObject(f[0]) && !(\"role\" in f[0]) ? f[0].by : inp.counterparty))(" + TS_FINDINGS + ")"),
        ["p81"]),
    "ts-comp-counterparty-only-findings-attestor-not-on-decision": (TS_COMP_PARTIES, TS_COMP_CP_FROM.format(
        "((f, d) => (f.length === 1 && isObject(f[0]) && !d.some((x) => isObject(x) && x.by === f[0].by) ? f[0].by : inp.counterparty))("
        + TS_FINDINGS + ", " + TS_DECISION + ")"), ["p81"]),
    "ts-comp-parties-fixed-address": (TS_COMP_PARTIES, TS_COMP_PARTIES.replace(
        "[...parties, inp.counterparty]", "[\"0x3333333333333333333333333333333333333333\", inp.counterparty]"), ["n195"]),
    "ts-comp-parties-first-only": (TS_COMP_PARTIES, TS_COMP_PARTIES.replace(
        "[...parties, inp.counterparty]", "[parties[0], inp.counterparty]"), ["n196"]),
    "ts-comp-parties-last-only": (TS_COMP_PARTIES, TS_COMP_PARTIES.replace(
        "[...parties, inp.counterparty]", "[parties[parties.length - 1], inp.counterparty]"), ["n196"]),
    "ts-comp-parties-multi-rejected": (TS_COMP_PARTIES, TS_COMP_PARTIES.replace(
        "[...parties, inp.counterparty]", "(parties.length === 1 ? [...parties, inp.counterparty] : null)"), ["p86"]),
    "ts-comp-decision-only-attestor-fails-closed": (TS_COMP_JOIN, TS_COMP_JOIN
                                                    + "    const idOf = (x) => (normAddr(x) === null ? null : (addressKey(normAddr(x)) ?? normAddr(x)));\n"
                                                    "    if (" + TS_DECISION + ".some((d) => isObject(d) && idOf(d.by) !== idOf(inp.counterparty) && !"
                                                    + TS_FINDINGS + ".some((a) => isObject(a) && idOf(a.by) === idOf(d.by)))) "
                                                    "return [\"reject\", \"independence_reject\"];\n", ["p82"]),
    "ts-comp-join-only-for-accepted-decision": (TS_COMP_JOIN, "    if (joined[0] !== \"valid\" && !(isObject(inp.decision) "
                                                              "&& inp.decision.decision !== \"accepted\")) return joined;\n", ["n194"]),
    "ts-comp-join-rejects-accepted-unmet-findings": (TS_COMP_JOIN, TS_COMP_JOIN
                                                     + "    if (inp.decision.decision === \"accepted\" && inp.findings.result !== \"meets the stated terms\") "
                                                     "return [\"reject\", \"binding_reject\"];\n", ["p83"]),
    "ts-comp-join-reads-findings-result": (TS_COMP_JOIN, TS_COMP_JOIN
                                           + "    if (inp.findings.result !== \"meets the stated terms\") return [\"reject\", \"binding_reject\"];\n",
                                           ["p83", "p84"]),
    "ts-comp-findings-digest-compared-as-written": (TS_COMP_JOIN_CALL, TS_COMP_JOIN_CALL.replace(
        "checkObjectBinding(inp.decision,",
        "checkObjectBinding(isObject(inp.decision) && typeof inp.decision.findings_digest === \"string\" "
        "&& normDigest(inp.decision.findings_digest) !== inp.decision.findings_digest ? { ...inp.decision, findings_digest: null } "
        ": inp.decision,"), ["p85"]),
    "ts-comp-join-skipped": (TS_COMP_JOIN, "", ["n175", "n182"]),
    "ts-comp-claim-before-join": (TS_COMP_BODY, TS_COMP_BODY.replace(TS_COMP_JOIN, "").replace(
        "    return CRITERIA.independence_claim({", "    const r = CRITERIA.independence_claim({").replace(
        "    });\n", "    });\n    return r[0] === \"valid\" && joined[0] !== \"valid\" ? joined : r;\n"), ["n175"]),
}


if __name__ == "__main__":
    sys.exit(run(PY, TS, sys.argv[1:]))
