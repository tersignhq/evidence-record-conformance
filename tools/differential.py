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
containers of the wrong shape; since v0.5.0 also the chain kinds — dropped, renumbered,
swapped, truncated and (v0.5.2) duplicated records, an off-by-one head, and every plausible
wrong accumulator fold at `head.acc`; since v0.5.4 the `payload_text` raw-text pathway —
duplicate names, non-JSON constants, unparseable and non-string text, and shape-vs-number
precedence — a fixed list of alias forms for each class of the identifier rule (whitespace,
case, trailing punctuation, percent-encoding, dot-segments, query and fragment components,
cross-namespace address forms) on a party and an attestor, and the whitespace characters the
two host languages' strip functions disagree on, at identifiers, digests and settlement
fields; since v0.5.5 the chain_link sequence domain at and past both bounds, the phase rule's
clauses at the shapes the two languages read differently, and a fixed string-domain battery:
non-ASCII values under the encodings _encodings names (not n98's HTML escapes or n102's
escaped DEL), and unpaired surrogates in values, names, arrays and nested objects, through
digest_recompute, payload_text and the objects the binding and boundary criteria digest, and
duplicate names that differ only in how a surrogate pair is written, one half raw and the other
escaped; since v0.5.8 defined members on every input — an undefined member at the top level
under each value class, the names every JavaScript object inherits, letter-case, fullwidth and
trailing-space variants of each name, and, one level down, an undefined member and a variant of
the first name in each object, and an undefined member and `constructor` in the first object of
each array, closed, not read or open), run
through BOTH engines,
verdict and reason-code compared directly. A form not on the list is not compared.
Any divergence exits non-zero and prints the offending input.

Run:  npm i viem  (repo root), then  python3 tools/differential.py
"""

import json
import os
import subprocess
import sys
import tempfile
import unicodedata

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from verify import CHECKS, canonical, digest_of, chain_link_digest, chain_acc_step, ACC_GENESIS  # noqa: E402
from keccak import keccak256  # noqa: E402

BACKSLASH = chr(92)


def py_verdict(kind, inp):
    """Mirror the Python runner's convention: an exception is a malformed input, not a crash."""
    try:
        verdict, reason, _detail = CHECKS[kind](inp)
        return [verdict, reason]
    except Exception:
        return ["malformed", None]


def _chain_rows(inp):
    """The chain rows of a chain_set / chain_commitment input in seq order, or None when the
    input is not shaped for a fold (the fold-variant mutations need parseable digests and
    integer seqs; a shape-broken input is already covered by the shape mutations)."""
    records = inp.get("records")
    if not isinstance(records, list) or not records:
        return None
    rows = []
    for r in records:
        if not isinstance(r, dict) or not isinstance(r.get("seq"), int) or isinstance(r.get("seq"), bool):
            return None
        if not 1 <= r["seq"] < 2**64:
            return None
        a = r.get("artifact_digest")
        if not isinstance(a, str) or len(a) != 66 or not a.startswith("0x"):
            return None
        try:
            bytes.fromhex(a[2:])
        except ValueError:
            return None
        rows.append((r["seq"], a.lower()))
    return sorted(rows)


def _fold(rows, seed, step):
    """Fold `step(acc, link_or_artifact)` over the presented rows with prev = previous artifact."""
    acc, prev = seed, None
    for seq, artifact in rows:
        acc = step(acc, chain_link_digest(artifact, prev, seq), artifact)
        prev = artifact
    return acc


def mutations(kind, inp):
    """Deterministic off-corpus battery. Every case is representable JSON — the absent-key
    case (the only honest 'undefined') is simply a case where the key is not added.
    Yields (tag, kind, input): a mutation may re-target the input at a sibling kind (the
    chain_set → chain_commitment promotions) so the two predicates are compared over the
    same bytes."""
    out = []

    def with_key(key, value, tag):
        m = json.loads(json.dumps(inp))
        m[key] = value
        out.append((tag, kind, m))

    def without_key(key, tag):
        if key in inp:
            m = json.loads(json.dumps(inp))
            del m[key]
            out.append((tag, kind, m))

    if kind in ("chain_set", "chain_commitment"):
        # First off-corpus coverage for the chain kinds (v0.5.0). The structural shape
        # mutations run under BOTH kinds — chain_commitment propagates chain_set's verdict
        # unchanged, so any fork there shows up twice — and the accumulator variants pin
        # every plausible wrong fold at the one key the accumulator lives on. For chain_set
        # inputs the accumulator cases are promoted to chain_commitment, so the same bytes
        # are compared under both predicates.
        acc_kind = "chain_commitment"

        def with_head(key, value, tag, target=kind):
            m = json.loads(json.dumps(inp))
            if isinstance(m.get("head"), dict):
                m["head"][key] = value
                out.append((tag, target, m))

        def with_records(fn, tag):
            m = json.loads(json.dumps(inp))
            if isinstance(m.get("records"), list) and all(isinstance(r, dict) for r in m["records"]):
                fn(m["records"])
                out.append((tag, kind, m))

        def _drop_middle(records):
            if len(records) >= 2:
                del records[len(records) // 2]

        def _renumber_last(records):
            if records and isinstance(records[-1].get("seq"), int):
                records[-1]["seq"] += 1

        def _swap_2_3(records):
            if len(records) >= 3:
                records[1], records[2] = records[2], records[1]
                records[1]["seq"], records[2]["seq"] = records[2]["seq"], records[1]["seq"]

        def _truncate(records):
            if records:
                del records[-1]

        def _float_seq_first(records):
            if records and isinstance(records[0].get("seq"), int):
                records[0]["seq"] = float(records[0]["seq"])  # wire token `1.0` (v0.5.1, B25)

        def _duplicate_middle(records):
            # v0.5.2: a second, different record at an occupied seq, inserted beside the
            # original. Both engines must return the same verdict and reason whatever order
            # their sort leaves the two in.
            if records:
                dup = dict(records[len(records) // 2])
                dup["artifact_digest"] = "0x" + "ee" * 32
                records.insert(len(records) // 2 + 1, dup)

        with_records(_float_seq_first, "records[0].seq=float-token")
        with_records(_duplicate_middle, "records=duplicated-middle")
        if isinstance(inp.get("head"), dict) and isinstance(inp["head"].get("seq"), int):
            with_head("seq", float(inp["head"]["seq"]), "head.seq=float-token")
            with_head("seq", float(inp["head"]["seq"]), "head.seq=float-token@commitment", acc_kind)
        with_records(_drop_middle, "records=dropped-middle")
        with_records(_renumber_last, "records=renumbered-last")
        with_records(_swap_2_3, "records=swapped-2-3")
        with_records(_truncate, "records=truncated-under-full-head")
        if isinstance(inp.get("head"), dict) and isinstance(inp["head"].get("seq"), int):
            with_head("seq", inp["head"]["seq"] + 1, "head.seq=off-by-one")
        with_head("acc", None, "head.acc=null", acc_kind)
        with_head("acc", "0x1234", "head.acc=malformed", acc_kind)
        m = json.loads(json.dumps(inp))
        if isinstance(m.get("head"), dict):
            m["head"].pop("acc", None)
            out.append(("head.acc-absent", acc_kind, m))
        rows = _chain_rows(inp)
        if rows is not None:
            true_acc = _fold(rows, ACC_GENESIS, lambda acc, link, _a: chain_acc_step(acc, link))
            with_head("acc", true_acc, "head.acc=true-fold", acc_kind)
            with_head("acc", "0x" + true_acc[2:].upper(), "head.acc=true-fold-uppercase", acc_kind)
            with_head("acc", "  " + true_acc + "  ", "head.acc=true-fold-padded", acc_kind)
            with_head("acc", _fold(rows, "0x" + "00" * 32, lambda acc, link, _a: chain_acc_step(acc, link)),
                      "head.acc=zero-seed-fold", acc_kind)
            with_head("acc", _fold(rows, ACC_GENESIS, lambda acc, link, _a: chain_acc_step(link, acc)),
                      "head.acc=link-then-acc-fold", acc_kind)
            with_head("acc", _fold(rows, ACC_GENESIS, lambda acc, _l, artifact: chain_acc_step(acc, artifact)),
                      "head.acc=artifact-fold", acc_kind)
            with_head("acc", chain_acc_step(ACC_GENESIS, chain_link_digest(rows[-1][1], rows[-2][1] if len(rows) > 1 else None, rows[-1][0])),
                      "head.acc=last-link-only", acc_kind)
            with_head("acc", "0x" + keccak256(b"tersign-chain-commitment-v1").hex(), "head.acc=seed-only", acc_kind)
            # The true fold over a truncated presentation under the full head: completeness must
            # win before the accumulator is even consulted, in both engines.
            m = json.loads(json.dumps(inp))
            if isinstance(m.get("head"), dict) and len(m.get("records") or []) > 1:
                del m["records"][-1]
                m["head"]["acc"] = _fold(rows[:-1], ACC_GENESIS, lambda acc, link, _a: chain_acc_step(acc, link))
                out.append(("records=truncated+head.acc=fold-of-truncation", acc_kind, m))

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
        # Fork-prone key 4: the delivery pair — key PRESENCE decides evaluability, the
        # recompute decides commitment. null-vs-absent, container shape, digest case, and a
        # non-ASCII suffix (utf8 in Python `.encode` vs viem `stringToHex`) must read
        # identically in both engines.
        with_key("deliverable_bytes", None, "deliverable_bytes=null")
        with_key("deliverable_bytes", [], "deliverable_bytes=array")
        with_key("deliverable_bytes", {"v": 1}, "deliverable_bytes=object")
        without_key("deliverable_bytes", "deliverable_bytes-absent")
        with_key("deliverable_digest", None, "deliverable_digest=null")
        with_key("deliverable_digest", "0x1234", "deliverable_digest=malformed")
        with_key("deliverable_digest", "0x" + "00" * 32, "deliverable_digest=mismatch")
        without_key("deliverable_digest", "deliverable_digest-absent")
        if isinstance(inp.get("deliverable_digest"), str):
            with_key("deliverable_digest", "0x" + inp["deliverable_digest"][2:].upper(), "deliverable_digest=uppercase")
            with_key("deliverable_digest", "  " + inp["deliverable_digest"] + "  ", "deliverable_digest=padded")
        if isinstance(inp.get("deliverable_bytes"), str):
            with_key("deliverable_bytes", inp["deliverable_bytes"] + " ", "deliverable_bytes=trailing-space")
            with_key("deliverable_bytes", inp["deliverable_bytes"] + "\u00e9", "deliverable_bytes=non-ascii-suffix")
            with_key("deliverable_bytes", inp["deliverable_bytes"] + "\U0001F600", "deliverable_bytes=astral-suffix")
            # Valid JSON, no UTF-8 form: the one string both engines must refuse to hash.
            with_key("deliverable_bytes", inp["deliverable_bytes"] + "\ud800", "deliverable_bytes=lone-surrogate")
        if "deliverable_bytes" not in inp:
            # A settlement-shaped record that grows a digest-only delivery key: both engines
            # must read it as presented-and-empty, never as unevaluable.
            with_key("deliverable_digest", "0x" + "00" * 32, "deliverable_digest-only")
        # Both commitment sources at once: composition order must not leak into the verdict.
        m = json.loads(json.dumps(inp))
        m.setdefault("settlement_result", {"success": True, "transaction": "0xab", "network": "eip155:8453"})
        m["covers"] = ["settlement", "delivery"]
        out.append(("covers=settlement+delivery", kind, m))
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
            out.append((tag, kind, m))
        if isinstance(inp.get("record"), dict):
            for tag, digest in (
                ("commitment=null", None),
                ("commitment=malformed", "0x1234"),
                ("commitment=mismatch", "0x" + "00" * 32),
            ):
                m = json.loads(json.dumps(inp))
                m["record"]["decisionEvidenceDigest"] = digest
                out.append((tag, kind, m))
        if isinstance(inp.get("decision_evidence"), dict):
            m = json.loads(json.dumps(inp))
            m["decision_evidence"].setdefault("policy", {})["version"] = "substituted"
            out.append(("decision_evidence=policy-substitution", kind, m))
    if kind == "canonical_bytes":
        # v0.5.4 (issue #10): the raw-text pathway. Each text is paired with the canonical
        # form a last-wins parser would produce, so an engine that fails open reads `valid`.
        # Precedence cases (a duplicate beside a >4300-digit integer, both orders; a float
        # token beside a duplicate) pin that text shape is decided before number tokens.
        huge = "9" * 5000
        texts = [
            '{"a":1,"a":2}', '{"a":1,"' + BACKSLASH + 'u0061":2}', '{"a":{"b":1,"b":2}}',
            '[{"a":1,"a":1}]', '{"a":"}","a":1}', '{"a' + BACKSLASH + '"":1,"a' + BACKSLASH + '"":2}',
            '{"a":{"a":1},"b":[{"a":2},{"a":3}]}', '{"a":NaN}', '{"a":Infinity}', '{"a":-Infinity}',
            '{"a":1', chr(0xFEFF) + '{"a":1}', '{"a":1} ', '{"a":' + huge + ',"a":1}',
            '{"a":1,"a":' + huge + '}', '{"a":' + huge + '}', '{"a":2.0,"a":1}', '{"a":1,"a":2.0}',
            '{"a":[1,2],"a":3}', '{"k":"v","v":1}', '{"a":[{"a":1}],"a":2}', '{"a":["b","c"],"b":1}',
            '{"a":{"b":[1,{"c":2}],"c":3},"a":4}', '[{"a":[{"b":1,"b":2}]}]',
        ]
        if isinstance(inp.get("payload_text"), str):
            t = inp["payload_text"]
            texts += [t[:-1], chr(0xFEFF) + t, t + " ", t.replace("{", '{"dup":0,"dup":0,', 1)]
        for n, text in enumerate(texts):
            try:
                claimed = canonical(json.loads(text))
            except Exception:
                claimed = inp.get("claimed_canonical")
            out.append((f"payload_text=battery-{n}", kind, {"payload_text": text, "claimed_canonical": claimed}))
        for tag, value in (("number", 2), ("null", None), ("array", ["{}"]), ("object", {}), ("true", True)):
            out.append((f"payload_text={tag}", kind, {"payload_text": value, "claimed_canonical": json.dumps(value)}))
    if kind == "independence_claim":
        # v0.5.4 (issue #8): a fixed list of alias forms per class of the identifier rule, on the
        # first party and on the first attestor, and the whitespace characters the two hosts'
        # strip functions disagree on (U+001C-U+001F and U+0085 are Python-only, U+FEFF
        # JavaScript-only).
        def id_variants(ident):
            vs = [(f"ws-{c:04x}-{side}", (chr(c) + ident) if side == "pre" else (ident + chr(c)))
                  for c in (0x0B, 0x1C, 0x1F, 0x85, 0xA0, 0x2028, 0x3000, 0xFEFF) for side in ("pre", "post")]
            vs.append(("upper", ident.upper()))
            if ident.lower().startswith("0x"):
                vs += [("caip10", "eip155:8453:" + ident), ("did-pkh", "did:pkh:eip155:1:" + ident),
                       ("caip10-upper", "EIP155:1:" + ident.upper()[:2].lower() + ident.upper()[2:]),
                       ("caip10-trail", "eip155:1:" + ident + "/"), ("caip10-longer", "eip155:1:" + ident + "0"),
                       ("did-ethr", "did:ethr:" + ident), ("ethereum", "ethereum:" + ident),
                       ("did-ethr-network", "did:ethr:0x1:" + ident), ("acct", "acct:" + ident),
                       ("org", "org:" + ident)]
            if ":" in ident and not ident.lower().startswith("0x"):
                scheme, path = ident.split(":", 1)
                vs += [("trail-dot", ident + "."), ("trail-hash", ident + "#"), ("trail-slash", ident + "/"),
                       ("trail-mixed", ident + "/.#"), ("enc-dot", ident + "%2E"), ("enc-dot-lc", ident + "%2e"),
                       ("enc-slash", ident + "%2F"), ("enc-space", ident + "%20"), ("enc-pct", ident + "%25"),
                       ("enc-bad", ident + "%zz"), ("enc-short", ident + "%2"),
                       ("enc-first", f"{scheme}:%{ord(path[0]):02X}{path[1:]}"),
                       ("enc-first-lc", f"{scheme}:%{ord(path[0]):02x}{path[1:]}"),
                       ("scheme-upper", scheme.upper() + ":" + path), ("empty-path", scheme + ":/"),
                       ("empty-path-hash", scheme + ":#."),
                       ("enc-tilde", ident + "%7E"), ("enc-underscore", ident + "%5f"),
                       ("enc-digit", ident + "%30"), ("enc-letter", ident + "%41"),
                       ("enc-pct-then-hex", ident + "%2541"), ("enc-assembled", ident + "%%34%31"),
                       ("dot-seg-trail", ident + "/."), ("dotdot-seg-trail", ident + "/x/.."),
                       ("dot-seg-lead", f"{scheme}:./{path}"), ("dotdot-seg-lead", f"{scheme}:../{path}"),
                       ("dot-seg-mid", f"{scheme}:{path}/./x"),
                       ("enc-dotdot-seg", ident + "/x/%2E%2E"), ("dots-not-seg", ident + "/..x/.y/..."),
                       ("query-empty", ident + "?"), ("query", ident + "?a=b"),
                       ("fragment", ident + "#x"), ("fragment-then-trail", ident + "#x/."),
                       ("caip10-of-urn", "eip155:1:" + path)]
                if "-" in path:
                    vs += [("enc-hyphen", ident.replace("-", "%2D", 1)), ("double-enc", ident.replace("-", "%252D", 1))]
            return vs

        if isinstance(inp.get("attestations"), list) and inp["attestations"] \
                and isinstance(inp["attestations"][0], dict) and isinstance(inp["attestations"][0].get("by"), str):
            for tag, by in id_variants(inp["attestations"][0]["by"]):
                m = json.loads(json.dumps(inp))
                m["attestations"][0]["by"] = by
                out.append((f"attestor=alias-{tag}", kind, m))
        if isinstance(inp.get("parties"), list) and inp["parties"] and isinstance(inp["parties"][0], str):
            for tag, party in id_variants(inp["parties"][0]):
                m = json.loads(json.dumps(inp))
                m["parties"][0] = party
                out.append((f"party=alias-{tag}", kind, m))
        if isinstance(inp.get("settlement_result"), dict):
            for c in (0x1C, 0x85, 0xFEFF, 0xA0):
                for key in ("transaction", "network"):
                    m = json.loads(json.dumps(inp))
                    m["settlement_result"][key] = chr(c)
                    out.append((f"settlement_result.{key}=ws-only-{c:04x}", kind, m))
    # v0.5.4: digests strip the same closed whitespace set in both engines.
    for key in ("expected_digest", "artifact_digest", "expected_link", "subject_digest", "anchored_digest"):
        if isinstance(inp.get(key), str):
            for c in (0x1C, 0x85, 0xFEFF):
                with_key(key, chr(c) + inp[key], f"{key}=ws-pad-{c:04x}")
    if kind == "chain_link" and isinstance(inp.get("artifact_digest"), str):
        # v0.5.5: the sequence domain [1, 2^53-1]. An integer seq carries the link recomputed
        # for that seq (where 8 bytes hold it), so only the domain can reject. 2^53+1 is the
        # token a double-based parser reads as 2^53 (it forked the engines until v0.5.5), 1.0
        # the integer-valued float token, and the rest are not numbers at all.
        art = _norm_hex(inp["artifact_digest"], 32)
        prev_raw = inp.get("prev_digest")
        prev = None if prev_raw is None else _norm_hex(prev_raw, 32)
        for seq in (0, -1, 1, 2, SEQ_MAX - 1, SEQ_MAX, SEQ_MAX + 1, SEQ_MAX + 2, 2**63, 2**64 - 1, 2**64,
                    1.0, float(SEQ_MAX), "1", True, False, None, [1]):
            m = json.loads(json.dumps(inp))
            m["seq"] = seq
            if art is not None and (prev_raw is None or prev is not None) \
                    and isinstance(seq, int) and not isinstance(seq, bool) and 0 <= seq < 2**64:
                m["expected_link"] = chain_link_digest(art, prev, seq)
            out.append((f"seq={seq!r}", kind, m))
        without_key("seq", "seq-absent")
    if kind == "phase_claim":
        # v0.5.5: every clause of the phase rule, at the shapes the two languages read
        # differently (null against absent, arrays, non-string phases, letter case).
        for tag, record in (("null", None), ("array", []), ("string", "delivery"), ("empty-object", {}),
                            ("phase-null", {"economic_phase": None}),
                            ("phase-array", {"economic_phase": ["delivery"]}),
                            ("phase-upper", {"economic_phase": "Delivery"}),
                            ("phase-number", {"economic_phase": 1})):
            with_key("record", record, f"record={tag}")
        without_key("record", "record-absent")
        for tag, presented in (("null", None), ("upper", "Delivery"), ("array", ["delivery"]),
                               ("unrecognized", "shipped")):
            with_key("presented_as", presented, f"presented_as={tag}")
        without_key("presented_as", "presented_as-absent")
        if isinstance(inp.get("record"), dict) and "economic_phase" in inp["record"]:
            m = json.loads(json.dumps(inp))
            m["presented_as"] = m["record"]["economic_phase"]
            out.append(("presented_as=the-record-phase", kind, m))
            m = json.loads(json.dumps(inp))
            m["record"]["economic_phase"] = m["presented_as"] = "shipped"
            out.append(("phase=presented=unrecognized", kind, m))
    if kind == "offer_binding":
        # Regression for key absence versus an explicit JSON null. Python previously used
        # indexing while JS canonicalization received undefined; a refactor to `.get()` can
        # accidentally turn absence into null and accept a digest of canonical `null`.
        m = json.loads(json.dumps(inp))
        m.pop("offer", None)
        m.setdefault("receipt", {})["offerDigest"] = digest_of(None)
        out.append(("offer=absent-with-null-commitment", kind, m))
    out += _member_mutations(kind, inp)
    return out


def _fullwidth(name):
    """Each printable ASCII character as its fullwidth form (U+FF01-U+FF5E), which NFKC folds back."""
    return "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in name)


def _member_mutations(kind, inp):
    """v0.5.8 (issue #17): defined members. On every input: an undefined member at the top level
    under each value class (a number, null, the empty string, object and array, false, zero);
    the names every JavaScript object inherits, `__proto__` included; a letter-case, a fullwidth
    and a trailing-space variant of each name the input carries, with the same value; and, one
    level down, an undefined member and a variant of the first name in each object the input
    carries, and an undefined member and `constructor` in the first object of each array,
    whether that object is closed, permitted and not read, or open."""
    out = []
    if not isinstance(inp, dict):
        return out

    def copy_with(fn, tag):
        m = json.loads(json.dumps(inp))
        fn(m)
        out.append((tag, kind, m))

    for tag, value in (("1", 1), ("null", None), ("empty-string", ""), ("empty-object", {}),
                       ("empty-array", []), ("false", False), ("zero", 0)):
        copy_with(lambda m, v=value: m.__setitem__("x_undefined", v), f"member=undefined-{tag}")
    for name in ("constructor", "__proto__", "toString", "hasOwnProperty", "valueOf", "isPrototypeOf"):
        copy_with(lambda m, n=name: m.__setitem__(n, 1), f"member={name}")
    for name in list(inp):
        for tag, variant in (("upper", name.upper()), ("capitalized", name[:1].upper() + name[1:]),
                             ("fullwidth", _fullwidth(name)), ("trailing-space", name + " ")):
            if variant != name and variant not in inp:
                copy_with(lambda m, n=name, v=variant: m.__setitem__(v, m[n]), f"member={name}-{tag}")
    for key, value in inp.items():
        if isinstance(value, dict):
            copy_with(lambda m, k=key: m[k].__setitem__("x_undefined", 1), f"{key}.member=undefined")
            for name in list(value)[:1]:
                variant = name.upper() if name.upper() != name else name + " "
                copy_with(lambda m, k=key, n=name, v=variant: m[k].__setitem__(v, m[k][n]), f"{key}.member={name}-variant")
        elif isinstance(value, list):
            for i, entry in enumerate(value):
                if isinstance(entry, dict):
                    copy_with(lambda m, k=key, j=i: m[k][j].__setitem__("x_undefined", 1), f"{key}[{i}].member=undefined")
                    copy_with(lambda m, k=key, j=i: m[k][j].__setitem__("constructor", 1), f"{key}[{i}].member=constructor")
                    break
    return out


SEQ_MAX = 2**53 - 1


def _norm_hex(x, n):
    """A 0x-prefixed digest of n bytes, lowercased, or None; builds links in the battery only."""
    if not isinstance(x, str) or len(x) != 2 + 2 * n or not x.startswith("0x"):
        return None
    try:
        bytes.fromhex(x[2:])
    except ValueError:
        return None
    return x.lower()


def _units(text):
    """UTF-16 code units of a string, an unpaired surrogate included."""
    u = text.encode("utf-16-be", "surrogatepass")
    return [int.from_bytes(u[i:i + 2], "big") for i in range(0, len(u), 2)]


def _esc(unit):
    """A lowercase backslash-u escape of one UTF-16 code unit."""
    return BACKSLASH + "u%04x" % unit


def _k(b):
    return "0x" + keccak256(b).hex()


def _js_text(v):
    """The text a canonicalizer built on JSON.stringify emits when it does not check for
    unpaired surrogates: canonical() as written, except that an unpaired surrogate is written
    as a lowercase backslash-u escape (ES2019 JSON.stringify) instead of failing. Integer
    numbers only, as in the corpus."""
    if isinstance(v, str):
        units, out, i = _units(v), [], 0
        while i < len(units):
            u = units[i]
            if 0xD800 <= u <= 0xDBFF and i + 1 < len(units) and 0xDC00 <= units[i + 1] <= 0xDFFF:
                out.append(chr(0x10000 + ((u - 0xD800) << 10) + (units[i + 1] - 0xDC00)))
                i += 2
                continue
            out.append(_esc(u) if 0xD800 <= u <= 0xDFFF else json.dumps(chr(u), ensure_ascii=False)[1:-1])
            i += 1
        return '"' + "".join(out) + '"'
    if isinstance(v, bool) or v is None:
        return json.dumps(v)
    if isinstance(v, int):
        return str(v)
    if isinstance(v, list):
        return "[" + ",".join(_js_text(x) for x in v) + "]"
    keys = sorted(v, key=lambda k: k.encode("utf-16-be", "surrogatepass"))
    return "{" + ",".join(_js_text(k) + ":" + _js_text(v[k]) for k in keys) + "}"


def _as_is(v):
    """canonical() as written with an unpaired surrogate left as is, the text
    json.dumps(..., ensure_ascii=False) emits when nothing checks."""
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, bool) or v is None:
        return json.dumps(v)
    if isinstance(v, int):
        return str(v)
    if isinstance(v, list):
        return "[" + ",".join(_as_is(x) for x in v) + "]"
    keys = sorted(v, key=lambda k: k.encode("utf-16-be", "surrogatepass"))
    return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _as_is(v[k]) for k in keys) + "}"


def _encodings(text):
    """Digests of one canonical text under UTF-8 (where the text has one), every non-ASCII code
    unit escaped (DEL stays raw), Latin-1 truncation, CESU-8, NFC and NFD, and the bytes a UTF-8
    encoder with no surrogate check emits: the encodings n71-n74, n85 and n86 name. Not the
    encodings n98 and n102 name: nothing here escapes "<", ">", "&" or DEL."""
    units = _units(text)
    out = {
        "surrogatepass": _k(text.encode("utf-8", "surrogatepass")),
        "latin1": _k(bytes(u & 0xFF for u in units)),
        "cesu8": _k("".join(chr(u) for u in units).encode("utf-8", "surrogatepass")),
        "escaped": _k("".join(chr(u) if u < 0x80 else _esc(u) for u in units).encode("ascii")),
    }
    try:
        out["utf8"] = _k(text.encode("utf-8"))
        out["nfc"] = _k(unicodedata.normalize("NFC", text).encode("utf-8"))
        out["nfd"] = _k(unicodedata.normalize("NFD", text).encode("utf-8"))
    except UnicodeEncodeError:
        pass
    return out


def fixed_battery():
    """v0.5.5: string-domain cases, independent of any vector. Non-ASCII values (Latin-1, BMP,
    astral, decomposed, line and paragraph separators, C1 controls, a BOM, noncharacters,
    controls), each with its digest under every encoding _encodings names; unpaired surrogates
    in values, names, arrays and nested objects (high, low, reversed), each with the escaped
    digest a JSON.stringify-based canonicalizer computes and the as-is bytes; the same objects
    through payload_text with both claimed forms; and the same objects inside what the binding
    and boundary criteria digest, committed to by the JSON.stringify-based digest; and an
    unpaired surrogate beside a number token or another shape fault, in both orders."""
    c = chr
    clean = [
        {"a": c(0xE9)}, {"a": "e" + c(0x301)}, {"a": c(0x4E2D) + c(0x6587)}, {"a": c(0x20BB7)},
        {"a": c(0x1F600)}, {c(0x20BB7): "x", c(0xFF61): "y"}, {"a": c(0x2028) + c(0x2029)},
        {"a": c(0x7F) + c(0x80) + c(0x9F)}, {"a": c(0xFEFF)}, {"a": c(0xFFFF)}, {"a": c(0xFDD0)},
        {"a": c(0x1FFFF)}, {"a": c(0) + c(0x1F) + c(8)},
        {"a": c(0xE9), "b": [c(0x20BB7), {"c": "e" + c(0x301)}]},
        {"e" + c(0x301): 1, c(0xE9): 2},
    ]
    lone = [
        {"a": c(0xD800)}, {"a": c(0xDC00)}, {"a": c(0xDC00) + c(0xD800)}, {"a": "x" + c(0xD83D) + "y"},
        {c(0xD800): 1}, {c(0xDFB7): c(0x20BB7)}, {"a": ["x", c(0xDFFF)]}, {"a": {"b": c(0xD83D)}},
        {c(0x20BB7): c(0xD842)},
    ]
    out = []
    for n, payload in enumerate(clean + lone):
        text = _js_text(payload)
        digests = _encodings(text)
        digests["as-is"] = _k(_as_is(payload).encode("utf-8", "surrogatepass"))
        digests["zero"] = "0x" + "00" * 32
        for enc, dg in sorted(digests.items()):
            out.append((f"fixed::digest-{n}-{enc}", "digest_recompute", {"payload": payload, "expected_digest": dg}))
        # The object as raw JSON text with every non-ASCII code unit escaped, so a pair arrives
        # as an escaped pair and an unpaired half as a lone escape, in both engines.
        ptext = "".join(c(u) if u < 0x80 else _esc(u) for u in _units(json.dumps(payload, ensure_ascii=False)))
        for form, claimed in (("escaped-claim", text), ("as-is-claim", _as_is(payload))):
            out.append((f"fixed::payload_text-{n}-{form}", "canonical_bytes",
                        {"payload_text": ptext, "claimed_canonical": claimed}))
        offer = {"resourceUrl": "https://api.example/x", **payload}
        out.append((f"fixed::offer-{n}", "offer_binding",
                    {"offer": offer, "receipt": {"offerDigest": _k(_js_text(offer).encode("utf-8"))}}))
        out.append((f"fixed::decision-{n}", "decision_evidence_binding",
                    {"decision_evidence": payload, "record": {"decisionEvidenceDigest": _k(text.encode("utf-8"))}}))
        out.append((f"fixed::boundary-{n}", "boundary_binding",
                    {"prefix": [payload],
                     "boundary_event": {"prefixDigest": _k(_js_text([payload]).encode("utf-8")), "position": 1}}))
    # Precedence: in payload_text an unpaired surrogate is part of the text's shape and is
    # decided before any number token, in both engines; in a loaded payload both engines meet
    # names first, then values in canonical order, so the first fault in that order names the
    # reason. Each case is a fault pair, in both orders.
    lone_esc = _esc(0xD800)
    huge = "9" * 5000
    for n, text in enumerate([
        '{"a":"' + lone_esc + '","b":2.0}', '{"a":2.0,"b":"' + lone_esc + '"}',
        '{"' + lone_esc + '":1,"b":2.0}', '{"b":2.0,"' + lone_esc + '":1}',
        '{"a":"' + lone_esc + '","b":' + huge + '}', '{"a":' + huge + ',"b":"' + lone_esc + '"}',
        '{"a":"' + lone_esc + '","a":1}', '{"a":1,"a":"' + lone_esc + '"}',
        '{"a":"' + lone_esc + '","b":NaN}', '[2.0,"' + lone_esc + '"]', '["' + lone_esc + '",2.0]',
        '{"a":"' + lone_esc + '"', '{"a":[{"b":"' + lone_esc + '"}],"c":1e2}',
    ]):
        out.append((f"fixed::precedence-text-{n}", "canonical_bytes", {"payload_text": text, "claimed_canonical": "{}"}))
    # Duplicate names that differ only in how a surrogate pair is written (n93): one half raw and
    # the other escaped, beside the pair as two escapes, as one raw astral code point, and as two
    # raw halves; in one object they are one name, in two objects they are not.
    pair_esc = _esc(0xD842) + _esc(0xDFB7)
    forms = {"raw-high": c(0xD842) + _esc(0xDFB7), "raw-low": _esc(0xD842) + c(0xDFB7),
             "raw-halves": c(0xD842) + c(0xDFB7), "astral": c(0x20BB7), "escaped": pair_esc}
    names = sorted(forms)
    astral = c(0x20BB7)
    for i, a in enumerate(names):
        for b in names[i:]:
            for shape, text in (
                ("same-object", '{"' + forms[a] + '":1,"' + forms[b] + '":2}'),
                ("nested", '{"x":{"' + forms[a] + '":1,"' + forms[b] + '":2}}'),
                ("two-objects", '[{"' + forms[a] + '":1},{"' + forms[b] + '":2}]'),
            ):
                for form, claimed in (
                    ("dup-claim", '{"' + astral + '":1,"' + astral + '":2}'),
                    ("last-claim", '{"' + astral + '":2}'),
                    ("arrays-claim", '[{"' + astral + '":1},{"' + astral + '":2}]'),
                ):
                    out.append((f"fixed::split-pair-{a}-{b}-{shape}-{form}", "canonical_bytes",
                                {"payload_text": text, "claimed_canonical": claimed}))
    for n, payload in enumerate([
        {"a": c(0xD800), "b": 2.0}, {"a": 2.0, "b": c(0xD800)}, {c(0xD800): 2.0}, {"b": 2.0, c(0xDC00): 1},
        [2.0, c(0xD800)], [c(0xD800), 2.0], {"a": c(0xD800), "b": 2**53}, {"a": 2**53, "b": c(0xD800)},
    ]):
        out.append((f"fixed::precedence-digest-{n}", "digest_recompute", {"payload": payload, "expected_digest": "0x" + "00" * 32}))
        out.append((f"fixed::precedence-bytes-{n}", "canonical_bytes", {"payload": payload, "claimed_canonical": "{}"}))
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
        for tag, target_kind, mutated in mutations(kind, inp):
            label = f"{fname}::{tag}" if target_kind == kind else f"{fname}::{tag}@{target_kind}"
            cases.append({"label": label, "kind": target_kind, "input": mutated})
    for label, kind, inp in fixed_battery():
        cases.append({"label": label, "kind": kind, "input": inp})

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
