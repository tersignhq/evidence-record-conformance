#!/usr/bin/env python3
"""Mutation run for the chain-statement profile's two engines, stdlib only.

Each mutant is one change to statement/verify_statement.py or tools/cross_check_statement.mjs, applied in a scratch
copy of the repository with tools/mutate_members.py's copy. Most edit one site. A change of order moves one check past
another: it swaps two adjacent blocks in one edit, deletes the check at one site and inserts it at another, or (the
envelope-signer and every-series-shape moves) inserts a copy of the check ahead of the other; and the two "anchor
before range.to read like one at it" mutants edit two lines, the seq rule and the at-range.to branch. A mutant is KILLED when the engine's run over statement/MANIFEST.json exits non-zero AND every vector named for
it fails; the unmutated copy must pass first and again at the end. Each engine also runs one comment-only IDENTITY
mutant, which must survive: a run in which it is killed measures something other than the change. The TypeScript
mutants need `node` and `viem` (`npm i viem` in the repository root, as CI does). These complement
`statement/verify_statement.py --mutants`, whose mutants are switched inside the Python engine.

    python3 tools/mutate_statement.py              # every mutant
    python3 tools/mutate_statement.py NAME ...     # only the named mutants

Exit 0 only if every mutant is killed by its named vectors, both identity mutants survive, and both controls pass.
"""
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mutate_members import scratch, _vid  # noqa: E402

PY_FILE, TS_FILE = "statement/verify_statement.py", "tools/cross_check_statement.mjs"

# ---- Python engine sites
PY_SCOPE = ('    scope = st["scope"]\n    if mut == "scope_case_folded" and isinstance(scope, str):\n'
            '        scope = scope.lower()\n    if not (isinstance(scope, str) and scope in SCOPES) and mut != "scope_unchecked":\n'
            '        return "scope"\n\n')
PY_RANGE = '    rng = st["range"]\n'
PY_SELLER = '    if not isinstance(chain["sellerId"], str) or chain["sellerId"] == "":\n        return "shape"\n'
PY_BEFORE = '    before, through = st["before"], st["through"]\n'
PY_ANCHOR_MEMBERS = '    if not _exactly(a, ANCHOR_MEMBERS, mut if mut == "extra_members_ignored" else None):\n'
PY_DUP_LOOP = '        for d in s["duplicates"]:\n'
PY_STATEMENT = '    st = body["statement"]\n    why = statement_refusal(st, mut)\n'
PY_ENVELOPE_SIGNER = ('    signer = body["signer"]\n'
                      '    if mut == "envelope_signer_case_folded" and isinstance(signer, str) and signer.lower() == st["ledger"].lower():\n'
                      '        signer = st["ledger"]\n'
                      '    if signer != st["ledger"] and mut != "envelope_signer_unchecked":\n'
                      '        return "reject", "shape"\n')
PY_DIGEST = ('    digest = "0x" + keccak256(canonical(st).encode("utf-8")).hex()\n'
             '    presented = body["statementDigest"]\n'
             '    if mut == "digest_case_folded" and isinstance(presented, str):\n'
             '        presented = presented.lower()\n')
PY_DIGEST_CMP = '    if presented != digest and mut != "digest_unchecked":\n        return "reject", "digest"\n'
PY_SIGNATURE = ('    who = recover_signer(body["statementDigest"] if mut == "digest_unchecked" else digest, body["signature"], mut)\n'
                '    if who is None or who != st["ledger"].lower():\n        return "reject", "signature"\n')
PY_EXPECTED = ('    if "expected_signer" in inp and mut != "expected_signer_ignored":\n'
               '        expected = inp["expected_signer"]\n'
               '        if mut != "expected_signer_case_sensitive":\n'
               '            expected = expected.lower()\n'
               '            if expected != st["ledger"].lower():\n'
               '                return "reject", "signer"\n'
               '        elif expected != st["ledger"]:\n'
               '            return "reject", "signer"\n')
PY_VALID = '    return "valid", None\n'
PY_MEMBERS = '    if not _exactly(st, MEMBERS, mut if mut == "extra_members_ignored" else None):\n'
PY_TEXT_TYPE = '    if not isinstance(text, str):\n        raise Reject("parse")\n'
PY_SERIES_COUNT = '    if len(series) > iq["boundRecords"]:\n        return "consistency"\n'
PY_ANCHOR_START = '    a, bridge = st["anchor"], st["bridge"]\n'
PY_GROUPED = '    grouped = set()   # every ledger seq a duplicate names, across all series\n'
PY_MISSING_SET = '        missing = set(s["missing"])\n'


def superset(site):
    """_exactly(o, members) read as `members are present`, extra members ignored, at one site."""
    return [(site, site.replace("))", "), \"extra_members_ignored\")", 1))]


PY = {
    # ---- rule parts no vector reached before
    "py-seq0-head-one-direction": ([('    if (before["seq"] == 0) != (before["head"] is None):\n',
                                     '    if before["seq"] != 0 and before["head"] is None:\n')], ["sn131"]),
    "py-anchor-at-to-head-only": ([('    if a["seq"] == to and (a["acc"] != through["acc"] or a["head"] != through["head"]):\n',
                                    '    if a["seq"] == to and a["head"] != through["head"]:\n')], ["sn132"]),
    "py-bridge-link-count-dropped": ([('    if len(links) != a["seq"] - to or not all(_hex32(x) for x in links):\n',
                                       '    if not all(_hex32(x) for x in links):\n')], ["sn133"]),
    "py-missing-max-exclusive": ([('m > s["max"]', 'm >= s["max"]')], ["sp35"]),
    "py-missing-min-exclusive": ([('m < s["min"]', 'm <= s["min"]')], ["sp35"]),
    # ---- correctionSeq, undefined and absent members, the bridge, anchor.seq and the integer bound
    "py-correction-seq-null-only": ([('(d["correctionSeq"] is None or (_int(d["correctionSeq"]) and d["correctionSeq"] >= 0))',
                                      'd["correctionSeq"] is None')], ["sp35"]),
    "py-correction-seq-positive-only": ([('d["correctionSeq"] >= 0', 'd["correctionSeq"] > 0')], ["sp35"]),
    "py-before-extra-members-ignored": (superset('_exactly(before, ("seq", "head", "acc"))'), ["sn137"]),
    "py-through-extra-members-ignored": (superset('_exactly(through, ("seq", "head", "acc"))'), ["sn138"]),
    "py-issuer-seq-extra-members-ignored": (superset('_exactly(iq, ISSUER_COUNTS + ("series", "truncated"))'), ["sn139"]),
    "py-duplicate-extra-members-ignored": (superset('_exactly(d, ("seq", "correctionSeq", "ledgerSeqs"))'), ["sn140"]),
    "py-bridge-extra-members-ignored": (superset('_exactly(bridge, ("from", "to", "links"))'), ["sn141"]),
    "py-range-extra-members-ignored": (superset('_exactly(rng, ("from", "to"))'), ["sn42"]),
    "py-series-extra-members-ignored": (superset('_exactly(s, ("series", "min", "max", "missing", "duplicates"))'),
                                        ["sn80"]),
    "py-before-head-absent-as-null": ([(PY_BEFORE, PY_BEFORE + '    if isinstance(before, dict) and "head" not in before:\n'
                                                              '        before = dict(before, head=None)\n')], ["sn142"]),
    "py-batch-root-absent-as-null": ([(PY_ANCHOR_MEMBERS, '    if isinstance(a, dict) and "batchRoot" not in a:\n'
                                                          '        a = dict(a, batchRoot=None)\n' + PY_ANCHOR_MEMBERS)],
                                     ["sn143"]),
    "py-height-absent-as-null": ([(PY_ANCHOR_MEMBERS, '    if isinstance(a, dict) and "bitcoinBlockHeight" not in a:\n'
                                                      '        a = dict(a, bitcoinBlockHeight=None)\n' + PY_ANCHOR_MEMBERS)],
                                 ["sn144"]),
    "py-correction-seq-absent-as-null": ([(PY_DUP_LOOP, PY_DUP_LOOP + '            if isinstance(d, dict) and "correctionSeq" not in d:\n'
                                                                      '                d = dict(d, correctionSeq=None)\n')],
                                         ["sn145"]),
    "py-bridge-from-unchecked": ([(' and bridge["from"] == to + 1', '')], ["sn134"]),
    "py-bridge-to-unchecked": ([(' and bridge["to"] == a["seq"]', '')], ["sn135"]),
    "py-anchor-before-to-read-as-at-to": ([('    if not _int(a["seq"]) or a["seq"] < to:\n', '    if not _int(a["seq"]):\n'),
                                           ('    if a["seq"] == to:\n        if mut ==', '    if a["seq"] <= to:\n        if mut ==')],
                                          ["sn136"]),
    "py-height-positive-only": ([('a["bitcoinBlockHeight"] >= 0', 'a["bitcoinBlockHeight"] > 0')], ["sp36"]),
    "py-anchor-seq-type-unchecked": ([('    if not _int(a["seq"]) or a["seq"] < to:\n', '    if a["seq"] < to:\n')], ["sn175"]),
    "py-integer-bound-exclusive": ([('return type(v) is int and -SAFE <= v <= SAFE', 'return type(v) is int and -SAFE < v < SAFE')],
                                   ["sp37"]),
    # ---- the served text
    "py-surrogate-halves-joined": ([('            v.encode("utf-8")\n',
                                     '            v.encode("utf-16-be", "surrogatepass").decode("utf-16-be").encode("utf-8")\n')],
                                   ["sn146", "sn147"]),
    "py-depth-bound-63": ([('    if _depth(text) > MAX_DEPTH:\n', '    if _depth(text) >= MAX_DEPTH:\n')], ["sn148"]),
    # ---- check order: one check moved past the next
    "py-scope-after-chain": ([(PY_SCOPE, ''),
                              (PY_RANGE, '    if not (isinstance(st["scope"], str) and st["scope"] in SCOPES):\n'
                                         '        return "scope"\n' + PY_RANGE)], ["sn152"]),
    "py-chain-key-before-seller-id": ([(PY_SELLER, ''), (PY_RANGE, PY_SELLER + PY_RANGE)], ["sn153"]),
    "py-envelope-signer-before-statement-rules": ([(PY_STATEMENT, '    st = body["statement"]\n'
                                                                  '    if isinstance(st, dict) and body["signer"] != st.get("ledger"):\n'
                                                                  '        return "reject", "shape"\n'
                                                                  '    why = statement_refusal(st, mut)\n')], ["sn170"]),
    "py-envelope-signer-after-digest": ([(PY_ENVELOPE_SIGNER + PY_DIGEST + PY_DIGEST_CMP,
                                          PY_DIGEST + PY_DIGEST_CMP + PY_ENVELOPE_SIGNER)], ["sn171"]),
    "py-digest-after-signature": ([(PY_DIGEST_CMP + PY_SIGNATURE, PY_SIGNATURE + PY_DIGEST_CMP)], ["sn172"]),
    "py-expected-signer-before-signature": ([(PY_SIGNATURE + PY_EXPECTED, PY_EXPECTED + PY_SIGNATURE)], ["sn173"]),
    "py-records-before-expected-signer": ([(PY_EXPECTED, ""), (PY_VALID, PY_EXPECTED + PY_VALID)], ["sn174"]),
    # ---- clauses no vector isolated before
    "py-issuer-counts-negative-allowed": ([("_int(iq[k]) and iq[k] >= 0", "_int(iq[k])")], ["sn176"]),
    "py-series-min-negative-allowed": ([(' or s["min"] < 0', "")], ["sn177"]),
    "py-series-min-positive-only": ([('s["min"] < 0', 's["min"] <= 0')], ["sp40"]),
    "py-missing-below-min-allowed": ([('m < s["min"] or ', "")], ["sn178"]),
    "py-ledger-seqs-from-0": ([("1 <= q <= hi", "q <= hi")], ["sn179"]),
    "py-ledger-seqs-distinct-only": ([("q > ls[i - 1]", "q != ls[i - 1]")], ["sn180"]),
    "py-ledger-seqs-non-strict": ([("q > ls[i - 1]", "q >= ls[i - 1]")], ["sn181"]),
    "py-series-id-form-unchecked": ([(' and _hex32(s["series"])', "")], ["sn182"]),
    "py-series-ids-distinct-only": ([('s["series"] <= last_series', 's["series"] == last_series')], ["sn183"]),
    "py-missing-distinct-only": ([("m <= prev", "m == prev")], ["sn184"]),
    "py-anchor-absent-as-null": ([(PY_MEMBERS, '    if isinstance(st, dict) and "anchor" not in st:\n'
                                               '        st = dict(st, anchor=None)\n' + PY_MEMBERS)], ["sn185"]),
    "py-bridge-absent-as-null": ([(PY_MEMBERS, '    if isinstance(st, dict) and "bridge" not in st:\n'
                                               '        st = dict(st, bridge=None)\n' + PY_MEMBERS)], ["sn186"]),
    "py-parse-lower-bound-exclusive": ([("not -SAFE <= v <= SAFE", "not -SAFE < v <= SAFE")], ["sn187"]),
    "py-parse-no-lower-bound": ([("not -SAFE <= v <= SAFE", "not v <= SAFE")], ["sn188"]),
    "py-parse-requires-object": ([("    return body\n", '    if not isinstance(body, dict):\n        raise Reject("parse")\n'
                                                       "    return body\n")], ["sn189"]),
    "py-every-series-shape-first": ([('    last_series = ""\n',
                                      '    for s in series:\n'
                                      '        if not (_exactly(s, ("series", "min", "max", "missing", "duplicates")) '
                                      'and _hex32(s["series"])\n'
                                      '                and _int(s["min"]) and _int(s["max"]) and isinstance(s["missing"], list)\n'
                                      '                and isinstance(s["duplicates"], list)):\n'
                                      '            return "shape"\n'
                                      '    last_series = ""\n')], ["sn190"]),
    "py-raw-astral-refused": ([(PY_TEXT_TYPE, PY_TEXT_TYPE + '    if any(ord(ch) > 0xFFFF for ch in text):\n'
                                                             '        raise Reject("parse")\n')], ["sp39"]),
    # ---- the report's definition (rules.issuer_report)
    "py-series-count-unchecked": ([(PY_SERIES_COUNT, "")], ["sn229", "sn230"]),
    "py-series-count-inclusive": ([('len(series) > iq["boundRecords"]', 'len(series) >= iq["boundRecords"]')], ["sp42"]),
    "py-series-count-after-series": ([(PY_SERIES_COUNT, ""), (PY_ANCHOR_START, PY_SERIES_COUNT + PY_ANCHOR_START)],
                                     ["sn230"]),
    "py-duplicate-above-max-allowed": ([(' or d["seq"] > s["max"]', "")], ["sn224"]),
    "py-duplicate-below-min-allowed": ([('d["seq"] < s["min"] or ', "")], ["sn225"]),
    "py-duplicate-max-exclusive": ([('d["seq"] > s["max"]', 'd["seq"] >= s["max"]')], ["sp35"]),
    "py-duplicate-min-exclusive": ([('d["seq"] < s["min"]', 'd["seq"] <= s["min"]')], ["sp35"]),
    "py-original-of-missing-allowed": ([('            if d["correctionSeq"] is None and d["seq"] in missing:\n'
                                         '                return "consistency"\n', "")], ["sn226"]),
    "py-correction-of-missing-refused": ([('d["correctionSeq"] is None and d["seq"] in missing', 'd["seq"] in missing')],
                                         ["sp35"]),
    "py-ledger-seqs-grouped-per-series": ([(PY_GROUPED, ""), (PY_MISSING_SET, PY_MISSING_SET + "        grouped = set()\n")],
                                          ["sn228"]),
    "py-ledger-seqs-grouped-unchecked": ([('            if any(q in grouped for q in ls):\n'
                                           '                return "consistency"\n', "")], ["sn227", "sn228"]),
}

TS_SCAN = '    if (scanText(text) || illFormed(body)) return ["reject", "parse"];\n'
TS_SERIES_COUNT = '  if (iq.series.length > iq.boundRecords) return "consistency";\n'
TS_ANCHOR_START = '  const a = st.anchor;\n'
TS_GROUPED = '  const grouped = new Set(); // every ledger seq a duplicate names, across all series\n'
TS_MISSING_SET = '    const missing = new Set(s.missing);\n'
TS_ENVELOPE = '  if (!exactly(body, ENVELOPE)) return ["reject", "shape"];\n'
TS_SCOPE = '  if (typeof st.scope !== "string" || !SCOPES.includes(st.scope)) return "scope";\n'
TS_SELLER = '  if (typeof chain.sellerId !== "string" || chain.sellerId === "") return "shape";\n'
TS_KEY = '  if (own(chain, "key") && (!isHex32(chain.key) || chain.key === ZERO32)) return "chain_key";\n'
TS_RANGE_SHAPE = '  if (!exactly(st.range, ["from", "to"])) return "shape";\n'
TS_RANGE = '  if (!isInt(from) || !isInt(to) || from < 1 || from > to) return "range";\n'
TS_ATT_VERSION = '  if (!isInt(att.version) || att.version !== ATTACHMENTS_VERSION) return "attachments_version";\n'
TS_ENTRIES_ARRAY = '  if (!Array.isArray(att.entries)) return "attachment_entry";\n'
TS_BEFORE_SHAPE = '  if (!exactly(before, ["seq", "head", "acc"])'
TS_THROUGH_SEQ = '  if (through.seq !== to) return "consistency";\n'
TS_LV_SHAPE = '  if (!exactly(lv, ["v1", "v2"]) || !isInt(lv.v1) || !isInt(lv.v2) || lv.v1 < 0 || lv.v2 < 0) return "shape";\n'
TS_LV_COUNT = '  if (lv.v1 + lv.v2 !== count) return "consistency";\n'
TS_SEALED = ('  if (lv.v1 > 0 && att.entries.some((e) => e.binding === "sealed" && e.position < firstV2)) '
             'return "attachment_entry";\n')
TS_IQ_SHAPE = '  if (!exactly(iq, [...ISSUER_COUNTS, "series", "truncated"])'
TS_LIST_CAP = '  if (iq.listCap !== LIST_CAP) return "consistency";\n'
TS_STATEMENT = '  const why = statementRefusal(st);\n'
TS_ENVELOPE_SIGNER = '  if (body.signer !== st.ledger) return ["reject", "shape"];\n'
TS_DIGEST = '  const digest = digestOf(st);\n'
TS_DIGEST_CMP = '  if (body.statementDigest !== digest) return ["reject", "digest"];\n'
TS_SIGNATURE = ('  const who = await recoverSigner(digest, body.signature);\n'
                '  if (who === null || who !== st.ledger.toLowerCase()) return ["reject", "signature"];\n')
TS_EXPECTED = ('  if (own(input, "expected_signer") && input.expected_signer.toLowerCase() !== st.ledger.toLowerCase()) '
               'return ["reject", "signer"];\n')
TS_RECORDS_END = '    if (acc !== st.through.acc || prev !== st.through.head) return ["reject", "records"];\n  }\n'
TS_BEFORE_DECL = '  const { before, through } = st;\n'
TS_ANCHOR_DECL = '  const a = st.anchor;\n'
TS_DUP_LOOP = '    for (const d of s.duplicates) {\n'
TS_MEMBERS = '  if (!exactly(st, MEMBERS)) return "shape";\n'


def ts_superset(site, members):
    """exactly(o, [...]) read as `members are present`, extra members ignored, at one site."""
    obj = site[len("exactly("):site.index(",")]
    return [(site, "(isObj(%s) && %s.every((m) => own(%s, m)))" % (obj, members, obj))]


TS = {
    # ---- rule parts no vector reached before
    "ts-seq0-head-one-direction": ([('  if ((before.seq === 0) !== (before.head === null)) return "consistency";\n',
                                     '  if (before.seq !== 0 && before.head === null) return "consistency";\n')], ["sn131"]),
    "ts-anchor-at-to-head-only": ([('  if (a.seq === to && (a.acc !== through.acc || a.head !== through.head)) return "anchor";\n',
                                    '  if (a.seq === to && a.head !== through.head) return "anchor";\n')], ["sn132"]),
    "ts-bridge-link-count-dropped": ([('  if (bridge.links.length !== a.seq - to || !bridge.links.every(isHex32)) return "anchor";\n',
                                       '  if (!bridge.links.every(isHex32)) return "anchor";\n')], ["sn133"]),
    "ts-missing-max-exclusive": ([("m > s.max", "m >= s.max")], ["sp35"]),
    "ts-missing-min-exclusive": ([("m < s.min", "m <= s.min")], ["sp35"]),
    # ---- correctionSeq, undefined and absent members, the bridge, anchor.seq and the integer bound
    "ts-correction-seq-null-only": ([("!(d.correctionSeq === null || (isInt(d.correctionSeq) && d.correctionSeq >= 0))",
                                      "!(d.correctionSeq === null)")], ["sp35"]),
    "ts-correction-seq-positive-only": ([("d.correctionSeq >= 0", "d.correctionSeq > 0")], ["sp35"]),
    "ts-before-extra-members-ignored": (ts_superset('exactly(before, ["seq", "head", "acc"])', '["seq", "head", "acc"]'),
                                        ["sn137"]),
    "ts-through-extra-members-ignored": (ts_superset('exactly(through, ["seq", "head", "acc"])', '["seq", "head", "acc"]'),
                                         ["sn138"]),
    "ts-issuer-seq-extra-members-ignored": (ts_superset('exactly(iq, [...ISSUER_COUNTS, "series", "truncated"])',
                                                        '[...ISSUER_COUNTS, "series", "truncated"]'), ["sn139"]),
    "ts-duplicate-extra-members-ignored": (ts_superset('exactly(d, ["seq", "correctionSeq", "ledgerSeqs"])',
                                                       '["seq", "correctionSeq", "ledgerSeqs"]'), ["sn140"]),
    "ts-bridge-extra-members-ignored": (ts_superset('exactly(bridge, ["from", "to", "links"])', '["from", "to", "links"]'),
                                        ["sn141"]),
    "ts-before-head-absent-as-null": ([(TS_BEFORE_DECL, '  const { through } = st;\n  const before = isObj(st.before) && '
                                                        '!own(st.before, "head") ? { ...st.before, head: null } : st.before;\n')],
                                      ["sn142"]),
    "ts-batch-root-absent-as-null": ([(TS_ANCHOR_DECL, '  const a = isObj(st.anchor) && !own(st.anchor, "batchRoot") ? '
                                                       '{ ...st.anchor, batchRoot: null } : st.anchor;\n')], ["sn143"]),
    "ts-height-absent-as-null": ([(TS_ANCHOR_DECL, '  const a = isObj(st.anchor) && !own(st.anchor, "bitcoinBlockHeight") ? '
                                                   '{ ...st.anchor, bitcoinBlockHeight: null } : st.anchor;\n')], ["sn144"]),
    "ts-correction-seq-absent-as-null": ([(TS_DUP_LOOP, '    for (const d0 of s.duplicates) {\n      const d = isObj(d0) && '
                                                        '!own(d0, "correctionSeq") ? { ...d0, correctionSeq: null } : d0;\n')],
                                         ["sn145"]),
    "ts-bridge-from-unchecked": ([(" || bridge.from !== to + 1", "")], ["sn134"]),
    "ts-bridge-to-unchecked": ([(" || bridge.to !== a.seq", "")], ["sn135"]),
    "ts-anchor-before-to-read-as-at-to": ([('  if (!isInt(a.seq) || a.seq < to) return "anchor";\n', '  if (!isInt(a.seq)) return "anchor";\n'),
                                           ("  if (a.seq === to || a.seq - to > BRIDGE_CAP)", "  if (a.seq <= to || a.seq - to > BRIDGE_CAP)")],
                                          ["sn136"]),
    "ts-height-positive-only": ([("a.bitcoinBlockHeight >= 0", "a.bitcoinBlockHeight > 0")], ["sp36"]),
    "ts-integer-bound-exclusive": ([("const isInt = (v) => typeof v === \"number\" && Number.isSafeInteger(v);",
                                     "const isInt = (v) => typeof v === \"number\" && Number.isSafeInteger(v) && "
                                     "Math.abs(v) < Number.MAX_SAFE_INTEGER;")], ["sp37"]),
    # ---- the served text
    "ts-raw-surrogate-unchecked": ([('    if (LONE_SURROGATE.test(text)) return ["reject", "parse"];\n', "")],
                                   ["sn146", "sn147"]),
    "ts-depth-unbounded": ([("      if (stack.length > MAX_DEPTH) return true;\n", "")], ["sn149"]),
    "ts-depth-bound-63": ([("stack.length > MAX_DEPTH", "stack.length >= MAX_DEPTH")], ["sn148"]),
    # ---- check order: one check moved past the next
    "ts-envelope-before-text-rules": ([(TS_SCAN, TS_ENVELOPE + TS_SCAN), ("  }\n" + TS_ENVELOPE, "  }\n")], ["sn150"]),
    "ts-scope-after-chain": ([(TS_SCOPE, ""), (TS_KEY, TS_KEY + TS_SCOPE)], ["sn152"]),
    "ts-chain-key-before-seller-id": ([(TS_SELLER + TS_KEY, TS_KEY + TS_SELLER)], ["sn153"]),
    "ts-range-before-range-shape": ([(TS_RANGE_SHAPE + "  const { from, to } = st.range;\n" + TS_RANGE,
                                      "  const { from, to } = st.range ?? {};\n" + TS_RANGE + TS_RANGE_SHAPE)], ["sn155"]),
    "ts-entries-before-attachments-version": ([(TS_ATT_VERSION + TS_ENTRIES_ARRAY, TS_ENTRIES_ARRAY + TS_ATT_VERSION)],
                                              ["sn157"]),
    "ts-through-seq-before-shape": ([(TS_THROUGH_SEQ, ""), (TS_BEFORE_SHAPE, "  if (isObj(through) && through.seq !== to) "
                                                                             "return \"consistency\";\n" + TS_BEFORE_SHAPE)],
                                    ["sn159"]),
    "ts-link-versions-count-before-shape": ([(TS_LV_SHAPE + TS_LV_COUNT, TS_LV_COUNT + TS_LV_SHAPE)], ["sn161"]),
    "ts-sealed-before-link-versions-count": ([(TS_LV_COUNT, ""), (TS_SEALED, TS_SEALED + TS_LV_COUNT)], ["sn162"]),
    "ts-list-cap-before-issuer-seq-shape": ([(TS_LIST_CAP, ""), (TS_IQ_SHAPE, "  if (isObj(iq) && iq.listCap !== LIST_CAP) "
                                                                             "return \"consistency\";\n" + TS_IQ_SHAPE)],
                                            ["sn164"]),
    "ts-envelope-signer-before-statement-rules": ([(TS_STATEMENT, "  if (isObj(st) && body.signer !== st.ledger) "
                                                                  "return [\"reject\", \"shape\"];\n" + TS_STATEMENT)], ["sn170"]),
    "ts-envelope-signer-after-digest": ([(TS_ENVELOPE_SIGNER + TS_DIGEST + TS_DIGEST_CMP,
                                          TS_DIGEST + TS_DIGEST_CMP + TS_ENVELOPE_SIGNER)], ["sn171"]),
    "ts-digest-after-signature": ([(TS_DIGEST_CMP + TS_SIGNATURE, TS_SIGNATURE + TS_DIGEST_CMP)], ["sn172"]),
    "ts-expected-signer-before-signature": ([(TS_SIGNATURE + TS_EXPECTED, TS_EXPECTED + TS_SIGNATURE)], ["sn173"]),
    "ts-records-before-expected-signer": ([(TS_EXPECTED, ""), (TS_RECORDS_END, TS_RECORDS_END + TS_EXPECTED)], ["sn174"]),
    # ---- clauses no vector isolated before
    "ts-issuer-counts-negative-allowed": ([("isInt(iq[k]) && iq[k] >= 0", "isInt(iq[k])")], ["sn176"]),
    "ts-series-min-negative-allowed": ([(" || s.min < 0", "")], ["sn177"]),
    "ts-series-min-positive-only": ([("s.min < 0", "s.min <= 0")], ["sp40"]),
    "ts-missing-below-min-allowed": ([("m < s.min || ", "")], ["sn178"]),
    "ts-ledger-seqs-from-0": ([("q >= 1 && ", "")], ["sn179"]),
    "ts-ledger-seqs-distinct-only": ([("q > ls[k - 1]", "q !== ls[k - 1]")], ["sn180"]),
    "ts-ledger-seqs-non-strict": ([("q > ls[k - 1]", "q >= ls[k - 1]")], ["sn181"]),
    "ts-series-id-form-unchecked": ([(" || !isHex32(s.series)", "")], ["sn182"]),
    "ts-series-ids-distinct-only": ([("s.series <= lastSeries", "s.series === lastSeries")], ["sn183"]),
    "ts-missing-distinct-only": ([("m <= prev", "m === prev")], ["sn184"]),
    "ts-anchor-absent-as-null": ([(TS_MEMBERS, '  if (isObj(st) && !own(st, "anchor")) st = { ...st, anchor: null };\n'
                                               + TS_MEMBERS)], ["sn185"]),
    "ts-bridge-absent-as-null": ([(TS_MEMBERS, '  if (isObj(st) && !own(st, "bridge")) st = { ...st, bridge: null };\n'
                                               + TS_MEMBERS)], ["sn186"]),
    "ts-parse-lower-bound-exclusive": ([("if (v > SAFE || v < -SAFE) return true;", "if (v > SAFE || v <= -SAFE) return true;")],
                                       ["sn187"]),
    "ts-parse-no-lower-bound": ([("if (v > SAFE || v < -SAFE) return true;", "if (v > SAFE) return true;")], ["sn188"]),
    "ts-parse-requires-object": ([("    body = JSON.parse(text);\n",
                                   '    body = JSON.parse(text);\n    if (!isObj(body)) return ["reject", "parse"];\n')], ["sn189"]),
    "ts-every-series-shape-first": ([('  let lastSeries = "";\n',
                                      '  for (const s of iq.series) {\n'
                                      '    if (!exactly(s, ["series", "min", "max", "missing", "duplicates"]) || !isHex32(s.series) || '
                                      '!isInt(s.min) || !isInt(s.max) ||\n'
                                      '      !Array.isArray(s.missing) || !Array.isArray(s.duplicates)) return "shape";\n'
                                      '  }\n'
                                      '  let lastSeries = "";\n')], ["sn190"]),
    "ts-raw-astral-refused": ([('    if (LONE_SURROGATE.test(text)) return ["reject", "parse"];\n',
                                '    if (/[\\uD800-\\uDFFF]/.test(text)) return ["reject", "parse"];\n')], ["sp39"]),
    # ---- the report's definition (rules.issuer_report)
    "ts-series-count-unchecked": ([(TS_SERIES_COUNT, "")], ["sn229", "sn230"]),
    "ts-series-count-inclusive": ([("iq.series.length > iq.boundRecords", "iq.series.length >= iq.boundRecords")], ["sp42"]),
    "ts-series-count-after-series": ([(TS_SERIES_COUNT, ""), (TS_ANCHOR_START, TS_SERIES_COUNT + TS_ANCHOR_START)],
                                     ["sn230"]),
    "ts-duplicate-above-max-allowed": ([(" || d.seq > s.max", "")], ["sn224"]),
    "ts-duplicate-below-min-allowed": ([("d.seq < s.min || ", "")], ["sn225"]),
    "ts-duplicate-max-exclusive": ([("d.seq > s.max", "d.seq >= s.max")], ["sp35"]),
    "ts-duplicate-min-exclusive": ([("d.seq < s.min", "d.seq <= s.min")], ["sp35"]),
    "ts-original-of-missing-allowed": ([('      if (d.correctionSeq === null && missing.has(d.seq)) return "consistency";\n', "")],
                                       ["sn226"]),
    "ts-correction-of-missing-refused": ([("d.correctionSeq === null && missing.has(d.seq)", "missing.has(d.seq)")],
                                         ["sp35"]),
    "ts-ledger-seqs-grouped-per-series": ([(TS_GROUPED, ""), (TS_MISSING_SET, TS_MISSING_SET + "    const grouped = new Set();\n")],
                                          ["sn228"]),
    "ts-ledger-seqs-grouped-unchecked": ([('      if (ls.some((q) => grouped.has(q))) return "consistency";\n', "")],
                                         ["sn227", "sn228"]),
}

IDENTITY = {   # comment-only edits: each must SURVIVE (no vector may fail)
    "py-identity-comment": (PY_FILE, [(PY_RANGE, "    # identity mutant: a comment only\n" + PY_RANGE)]),
    "ts-identity-comment": (TS_FILE, [(TS_RANGE_SHAPE, "  // identity mutant: a comment only\n" + TS_RANGE_SHAPE)]),
}


def run_py(root):
    p = subprocess.run([sys.executable, "-B", PY_FILE], cwd=root, capture_output=True, text=True, timeout=600)
    fails = {_vid(line.split()[1]) for line in p.stdout.splitlines() if line.startswith("FAIL ")}
    return p.returncode, fails


def run_ts(root):
    p = subprocess.run(["node", TS_FILE], cwd=root, capture_output=True, text=True, timeout=600)
    fails = {_vid(line.split()[1]) for line in p.stdout.splitlines()
             if line.startswith("DIVERGE ") and line.split()[1].endswith(".json")}
    return p.returncode, fails


def apply(root, fname, edits):
    """Write the edited file; None when a site does not occur exactly once (the mutant is NOT APPLIED)."""
    path = os.path.join(root, fname)
    with open(path, encoding="utf-8") as f:
        orig = f.read()
    src = orig
    for old, new in edits:
        if src.count(old) != 1:
            return orig, "its site occurs %d times: %r" % (src.count(old), old[:60])
        src = src.replace(old, new)
    with open(path, "w", encoding="utf-8") as f:
        f.write(src)
    with open(path, encoding="utf-8") as f:
        if f.read() != src or src == orig:
            return orig, "the edit did not take"
    return orig, None


def main(only=()):
    d, root = scratch()
    try:
        controls = [("py", run_py(root)), ("ts", run_ts(root))]
        for name, (rc, fails) in controls:
            print("control %s: rc=%d failing=%s" % (name, rc, sorted(fails)))
        if any(rc or fails for _, (rc, fails) in controls):
            return 1
        total = killed = 0
        for table, fname, runner in ((PY, PY_FILE, run_py), (TS, TS_FILE, run_ts)):
            for name, (edits, killers) in table.items():
                if only and name not in only:
                    continue
                total += 1
                orig, problem = apply(root, fname, edits)
                if problem:
                    with open(os.path.join(root, fname), "w", encoding="utf-8") as f:
                        f.write(orig)
                    print("NOT APPLIED %s: %s" % (name, problem))
                    continue
                try:
                    rc, fails = runner(root)
                finally:
                    with open(os.path.join(root, fname), "w", encoding="utf-8") as f:
                        f.write(orig)
                missed = [k for k in killers if k not in fails]
                ok = rc != 0 and bool(killers) and not missed
                killed += ok
                print("%-8s %-44s rc=%d named=%s%s" % ("KILLED" if ok else "SURVIVED", name, rc, ",".join(killers),
                                                        " missed=" + ",".join(missed) if missed else ""))
        identity_ok = True
        for name, (fname, edits) in IDENTITY.items():
            if only and name not in only:
                continue
            orig, problem = apply(root, fname, edits)
            if problem:
                with open(os.path.join(root, fname), "w", encoding="utf-8") as f:
                    f.write(orig)
                print("NOT APPLIED %s: %s" % (name, problem))
                identity_ok = False
                continue
            try:
                rc, fails = (run_py if fname == PY_FILE else run_ts)(root)
            finally:
                with open(os.path.join(root, fname), "w", encoding="utf-8") as f:
                    f.write(orig)
            survived = rc == 0 and not fails
            identity_ok = identity_ok and survived
            print("%-8s %-44s rc=%d failing=%s (an identity mutant must survive)" % (
                "survived" if survived else "KILLED", name, rc, sorted(fails)))
        after = [("py", run_py(root)), ("ts", run_ts(root))]
        for name, (rc, fails) in after:
            print("restored %s: rc=%d failing=%s" % (name, rc, sorted(fails)))
        print("%d/%d mutants killed by their named vectors; identity mutants %s" % (
            killed, total, "survived" if identity_ok else "FAILED"))
        return 0 if total and killed == total and identity_ok and not any(rc or fails for _, (rc, fails) in after) else 1
    finally:
        shutil.rmtree(d)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
