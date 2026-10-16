#!/usr/bin/env python3
"""Generates every chain-statement vector (statement/vectors/) and statement/MANIFEST.json, byte for byte. Stdlib only.
    python3 statement/gen_statement_vectors.py      (CI regenerates and requires byte-identical output)

Material: three synthetic chains whose record digests are keccak256 of fixed labels, statements built from them member by
member in the order a ledger serves them, and signatures by two published test keys with a nonce derived per signature,
all in this file. No vector carries a record, a key or an anchor of any live ledger, so no vector says anything about a
live ledger's key: a valid verdict here establishes only that the published test key signed the bytes.

Every rejecting vector is built from an accepting vector of this set, its twin, by the change its description names:
one value, or one logical change that moves values bound to each other, or, for the order vectors, two faults. Where the
change is to the statement, the twin's key signs the changed statement again, so the digest and signature checks cannot
be what rejects it (the digest, signature and signer vectors exist to test those). The vectors that change the served
text instead keep the twin's digest and signature; the rule that rejects each is decided before the digest is checked.

Every accepting vector that carries a v2 link has its issuer-numbering report computed by issuer_report() from one link
binding per ledger seq, the way the format defines the report, so each is a report a ledger could sign; the others
carry the report of an all-v1 range (every record unbound, no series). A rejecting vector changes one."""
import copy
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "crypto"))
from keccak import keccak256  # noqa: E402
from verify import canonical, chain_link_digest, chain_acc_step, ACC_GENESIS  # noqa: E402
import secp256k1_recover as S  # noqa: E402
import verify_statement as V  # noqa: E402
from gen_crypto_vectors import PRIV as KEY1, TEST_KEY_DERIVATION as KEY1_DERIVATION  # noqa: E402

KEY2_DERIVATION = 'keccak256("evidence-record-conformance statement-profile second test key v1") mod n'
KEY2 = int.from_bytes(keccak256(b"evidence-record-conformance statement-profile second test key v1"), "big") % S.N
NONCE_DERIVATION = "keccak256(the private key as 32 big-endian bytes || the 32-byte message hash) mod n, per signature"
BASE = "https://ledger.example"
HEIGHT = 900000
AUTHOR = "Tersign (@wowlegend)"
VERSION = "0.6.0"   # the suite release this set belongs to, as MANIFEST.json "version"


def address(priv):
    """The key's address in the mixed case a ledger serves it (each letter upper-case where the keccak256 of the
    lower-case hex has a nibble of 8 or more at that position)."""
    low = S.address(S._mul(priv, S.G))[2:]
    h = keccak256(low.encode("ascii")).hex()
    return "0x" + "".join(c.upper() if c.isalpha() and int(h[i], 16) >= 8 else c for i, c in enumerate(low))


LEDGER = address(KEY1)
OTHER = address(KEY2)


def js_string(s):
    """A JSON string literal as a JavaScript JSON.stringify writes it: the core's form, except that a surrogate that is
    not half of a pair is written as a lower-case \\u escape instead of failing."""
    out = []
    for c in s:
        if 0xD800 <= ord(c) <= 0xDFFF:
            out.append("\\u%04x" % ord(c))
        else:
            out.append(json.dumps(c, ensure_ascii=False)[1:-1])
    return '"' + "".join(out) + '"'


def js_canonical(v):
    """canonical(v), extended to the lone-surrogate strings the parse vectors carry, as a JavaScript signer computes it."""
    if isinstance(v, str):
        return js_string(v)
    if isinstance(v, list):
        return "[" + ",".join(js_canonical(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(js_string(k) + ":" + js_canonical(v[k]) for k in keys) + "}"
    return canonical(v)


def js_text(v):
    """The served text: members in insertion order, no whitespace (JSON.stringify's form)."""
    if isinstance(v, str):
        return js_string(v)
    if isinstance(v, list):
        return "[" + ",".join(js_text(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(js_string(k) + ":" + js_text(x) for k, x in v.items()) + "}"
    return canonical(v)


def digest_of(st):
    text = js_canonical(st)
    try:
        assert text == canonical(st)
    except ValueError:
        pass                                    # a lone surrogate: no core canonical form; the JavaScript form is signed
    return "0x" + keccak256(text.encode("utf-8", "surrogatepass")).hex()


def sign(msg_hash, priv):
    k = int.from_bytes(keccak256(priv.to_bytes(32, "big") + msg_hash), "big") % S.N
    r, s, rec = S.sign(msg_hash, priv, k)
    return "0x" + r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + bytes([27 + rec]).hex()


def envelope(st, priv=KEY1, **over):
    d = digest_of(st)
    body = {"statement": st, "statementDigest": d, "signature": sign(V.signature_message_hash(d), priv),
            "signer": st["ledger"]}
    body.update(over)
    return js_text(body)


class Chain:
    def __init__(self, label, n):
        self.digests = [None] + ["0x" + keccak256(("statement-profile %s record %d" % (label, k)).encode()).hex()
                                 for k in range(1, n + 1)]
        self.links, self.accs = [None], [ACC_GENESIS]
        for k in range(1, n + 1):
            self.links.append(chain_link_digest(self.digests[k], self.digests[k - 1], k))
            self.accs.append(chain_acc_step(self.accs[-1], self.links[-1]))


def anchor_at(seq, head, acc, status="confirmed", height=HEIGHT, batch=None, schema=V.COMMITMENT_SCHEMA):
    subject = "0x" + keccak256(canonical({"acc": acc, "head": head, "schema": schema, "seq": seq}).encode()).hex()
    aid = "seller:" + subject
    return {"id": aid, "subjectSchema": schema, "seq": seq, "head": head, "acc": acc, "subjectDigest": subject,
            "anchoredDigest": "0x" + hashlib.sha256(bytes.fromhex(subject[2:])).hexdigest(), "batchRoot": batch,
            "status": status, "bitcoinBlockHeight": height, "proofUrl": "%s/v1/anchors/%s/proof.ots" % (BASE, aid)}


def build(chain, chain_id, frm, to, anchor_seq=None):
    n = to - frm + 1
    anchor = bridge = None
    if anchor_seq is not None:
        anchor = anchor_at(anchor_seq, chain.digests[anchor_seq], chain.accs[anchor_seq])
        if to < anchor_seq <= to + V.BRIDGE_CAP:
            bridge = {"from": to + 1, "to": anchor_seq, "links": chain.links[to + 1:anchor_seq + 1]}
    return {
        "schema": V.SCHEMA, "ledger": LEDGER, "chain": {"sellerId": chain_id}, "range": {"from": frm, "to": to},
        "scope": "range", "attachments": {"version": V.ATTACHMENTS_VERSION, "entries": []},
        "commitmentSchema": V.COMMITMENT_SCHEMA,
        "before": {"seq": frm - 1, "head": chain.digests[frm - 1], "acc": chain.accs[frm - 1]},
        "through": {"seq": to, "head": chain.digests[to], "acc": chain.accs[to]},
        "linkVersions": {"v1": n, "v2": 0},
        "issuerSeq": {"boundRecords": 0, "unboundRecords": n, "absentRecords": 0, "series": [], "listCap": V.LIST_CAP,
                      "truncated": False},
        "anchor": anchor, "bridge": bridge, "limits": V.LIMITS,
    }


def upper(h):
    u = "0x" + h[2:].upper()
    assert u != h, h
    return u


def hex32(i):
    return "0x" + format(i, "064x")


SER1, SER2 = "0x" + "0a" * 32, "0x" + "0b" * 32
E1 = {"position": 1, "type": "example-type", "binding": "declared"}
E2 = {"position": 4, "type": "example-other", "binding": "declared"}

ABSENT = "a v2 link that binds no issuer number"


def issuer_report(bindings, frm, to):
    """(linkVersions, issuerSeq) for the range frm..to, from one link binding per ledger seq 1..to: None for a v1 link
    (it binds no issuer numbering), ABSENT for a v2 link that binds no number, or (series, seq, correctionSeq). As the
    format defines the report: the counts, and each series' min and max, are over the range; a series is reported when
    a record in the range binds it; a number between min and max is missing when no original (correctionSeq null)
    binding at or before `to` names it; a duplicate is a (seq, correctionSeq) named by two or more bindings at or before
    `to`, one of them in the range, ordered by seq, then correctionSeq with null first; each list stops at the cap, and
    then `truncated` is true."""
    assert sorted(bindings) == list(range(1, to + 1)), "one binding per ledger seq 1..to"
    in_range = range(frm, to + 1)
    v1 = sum(1 for q in in_range if bindings[q] is None)
    absent = sum(1 for q in in_range if bindings[q] is ABSENT)
    bound = [(q, b) for q, b in sorted(bindings.items()) if b is not None and b is not ABSENT]
    series, truncated = [], False
    for sid in sorted({b[0] for q, b in bound if q >= frm}):
        if len(series) >= V.LIST_CAP:
            truncated = True
            break
        mine = [(q, b) for q, b in bound if b[0] == sid]
        nums = [b[1] for q, b in mine if q >= frm]
        originals = {b[1] for q, b in mine if b[2] is None}
        missing = []
        for n in range(min(nums), max(nums) + 1):
            if n in originals:
                continue
            if len(missing) >= V.LIST_CAP:
                truncated = True
                break
            missing.append(n)
        groups = {}
        for q, b in mine:
            groups.setdefault((b[1], b[2]), []).append(q)
        dups = sorted(({"seq": k[0], "correctionSeq": k[1], "ledgerSeqs": sorted(qs)} for k, qs in groups.items()
                       if len(qs) >= 2 and max(qs) >= frm),
                      key=lambda d: (d["seq"], -1 if d["correctionSeq"] is None else d["correctionSeq"]))
        truncated = truncated or len(dups) > V.LIST_CAP
        series.append({"series": sid, "min": min(nums), "max": max(nums), "missing": missing,
                       "duplicates": dups[:V.LIST_CAP]})
    return ({"v1": v1, "v2": len(in_range) - v1},
            {"boundRecords": len(in_range) - v1 - absent, "unboundRecords": v1, "absentRecords": absent,
             "series": series, "listCap": V.LIST_CAP, "truncated": truncated})


# Link bindings for the accepting issuer-numbering vectors: {ledger seq: binding}, every seq from 1 to range.to.
REPORT = {1: (SER1, 1, None), 2: (SER1, 1, None), 3: (SER1, 3, None), 4: (SER2, 7, None), 5: ABSENT}
REPORT_CORRECTIONS = {1: (SER1, 1, None), 2: (SER1, 2, 0), 3: (SER1, 2, 0), 4: (SER1, 3, 1), 5: (SER1, 3, 1)}
REPORT_MISSING_AT_CAP = dict(REPORT)
REPORT_MISSING_AT_CAP[3] = (SER1, 258, None)
REPORT_SERIES_AT_CAP = {q: (None if q == 1 else ("0x" + format(q - 1, "064x"), 1, None)) for q in range(1, 258)}
REPORT_DUPLICATES_AT_CAP = {q: (SER1, (q + 1) // 2, None) for q in range(1, 513)}
REPORT_MIXED = {1: None, 2: None, 3: None, 4: ABSENT, 5: ABSENT}
REPORT_NUMBER_0 = dict(REPORT)
REPORT_NUMBER_0[4] = (SER2, 0, None)
REPORT_TWO_SERIES_DUPLICATES = {1: (SER1, 1, None), 2: (SER1, 1, None), 3: (SER2, 7, None), 4: (SER2, 7, None),
                                5: ABSENT}
REPORT_SERIES_PER_RECORD = {1: None, 2: (SER1, 1, None), 3: (SER2, 7, None), 4: ABSENT, 5: ABSENT}
# (bindings, range.from, range.to) of every report an accepting vector carries; tools that check the reports read this.
REPORTS = {"report": (REPORT, 2, 5), "corrections": (REPORT_CORRECTIONS, 2, 5),
           "missing_at_cap": (REPORT_MISSING_AT_CAP, 2, 5), "series_at_cap": (REPORT_SERIES_AT_CAP, 2, 257),
           "duplicates_at_cap": (REPORT_DUPLICATES_AT_CAP, 2, 512), "mixed": (REPORT_MIXED, 2, 5),
           "number_0": (REPORT_NUMBER_0, 2, 5), "two_series_duplicates": (REPORT_TWO_SERIES_DUPLICATES, 2, 5),
           "series_per_record": (REPORT_SERIES_PER_RECORD, 2, 5)}

# Rules each vector rests on, labelled as the format's own (the rules a ledger serving this format applies before it
# signs) or as this suite's. The runner pins the constants under "format"; these texts say what the vectors test.
RULES = {
    "parse": ("format", "The served body is JSON text; no object carries a member name twice; every number token is an "
              "integer in [-(2**53 - 1), 2**53 - 1] (a fraction or exponent token is not, even when its value is an "
              "integer); every string, member names included, is well-formed Unicode (a surrogate that is not half of a "
              "pair has no UTF-8 form). Otherwise parse. A body that is JSON text but not an object is refused by the "
              "envelope rule, as shape."),
    "raw_surrogate": ("suite", "The text is read as code points. A surrogate code point written raw in the text, not as "
                      "a \\u escape, is refused, even where an escaped surrogate next to it would complete a pair, so "
                      "either half of a pair written raw is refused; a character outside the Basic Multilingual Plane "
                      "written raw is one code point, not a surrogate, and is accepted. Otherwise parse. The format's parse "
                      "rule does not say whether the text is read as code points or as UTF-16 code units; JSON.parse, a "
                      "reader of UTF-16 code units, joins the two halves into a pair. A body served as UTF-8 cannot "
                      "carry a raw surrogate, so the rule changes no verdict on a served body; this suite fixes it so "
                      "that a reader of code points and a reader of UTF-16 code units agree."),
    "byte_order_mark": ("suite", "A byte-order mark (U+FEFF) before the JSON value is refused: it is not JSON "
                        "whitespace (RFC 8259 section 2). Otherwise parse. RFC 8259 section 8.1 forbids adding one to "
                        "a JSON text sent over a network and lets a parser ignore one; this suite refuses it, as "
                        "JavaScript's JSON.parse and Python's json.loads over text do, so that a reader that strips "
                        "the mark and one that does not agree. A ledger that follows section 8.1 serves no mark, so "
                        "the rule changes no verdict on such a body; it decides text a verifier is handed."),
    "depth": ("suite", "The body nests objects and arrays at most format.max_depth deep, the body object counting 1, "
              "counted on the text. Otherwise parse. The format sets no bound; this suite "
              "fixes one so that its engines agree on every input, where a reader without one decides deep nesting by "
              "wherever its parser stops, which differs between parsers and interpreters. A statement nests 8 deep at "
              "most, so the bound changes a reason, never a verdict. The vectors sit at the bound and at 3,000 levels, "
              "not between."),
    "envelope": ("format", "The body is an object with exactly the members {statement, statementDigest, signature, "
                 "signer} (a body that is JSON text but not an object, an array for example, is refused here), and "
                 "signer equals statement.ledger byte for byte. Otherwise shape."),
    "members": ("format", "The statement's members are exactly the fourteen in format.statement_members; schema, limits "
                "and commitmentSchema are the fixed values in format, compared byte for byte; ledger is 0x + 40 hex "
                "digits in either letter case. Otherwise shape."),
    "scope": ("format", "scope is a member whose value is one of format.scopes, compared exactly. A value outside the "
              "set, null and the empty string reject as scope; a statement without the member rejects as shape."),
    "chain": ("format", "chain is {sellerId} or {sellerId, key}; sellerId is a non-empty string (shape). key, when "
              "present, is 0x + 64 lower-case hex digits other than 32 zero bytes (chain_key)."),
    "range": ("format", "range is exactly {from, to} (shape) of integers with 1 <= from <= to and at most "
              "format.max_range records (range)."),
    "attachments": ("format", "attachments is exactly {version, entries} and version is the JSON integer 1 "
                    "(attachments_version); entries is an array (attachment_entry)."),
    "entries": ("format", "Each entry is exactly {position, type, binding}. position is an integer, 1 <= position <= "
                "range.to (it may lie before range.from), strictly ascending across entries. binding is one of "
                "format.bindings, compared exactly. Otherwise attachment_entry."),
    "entry_type": ("format", "type is 2-64 characters: a lower-case letter, then lower-case letters, digits and hyphens, "
                   "ending in a letter or digit; and a type made only of hex digits and hyphens that holds "
                   "format.type_hex_digits or more hex digits is refused (hyphens are not counted; one character "
                   "outside [0-9a-f-] takes a type outside this rule). Otherwise attachment_entry."),
    "sealed": ("format", "A sealed entry needs a v2 link at its position. The first v2 link of the range is at "
               "range.from + linkVersions.v1, so when linkVersions.v1 > 0 a sealed entry at any position below it, "
               "positions before range.from included, rejects as attachment_entry. When linkVersions.v1 is 0 the "
               "statement says nothing about links before range.from, and a sealed entry there is not checked."),
    "before_through": ("format", "before is {seq, head, acc}: seq an integer, head null or 0x + 64 lower-case hex, "
                       "acc 0x + 64 lower-case hex; through is {seq, head, acc}: seq an integer, head and acc 0x + 64 "
                       "lower-case hex (shape). before.seq = range.from - 1; "
                       "before.head is null exactly when before.seq is 0; at seq 0, before.acc is the commitment seed "
                       "keccak256(utf8(\"tersign-chain-commitment-v1\")); through.seq = range.to (consistency)."),
    "link_versions": ("format", "linkVersions is exactly {v1, v2} of non-negative integers (shape), and v1 + v2 counts "
                      "every record of the range (consistency)."),
    "issuer_seq": ("format", "issuerSeq is exactly {boundRecords, unboundRecords, absentRecords, listCap, series, "
                   "truncated}: non-negative integers, a boolean and an array (shape). listCap is format.list_cap; "
                   "unboundRecords = linkVersions.v1 and boundRecords + absentRecords = linkVersions.v2; with no bound "
                   "record there is no series; series, each series' missing numbers and its duplicates are each at "
                   "most listCap long; series ids ascend strictly and 0 <= min <= max; missing numbers are integers "
                   "ascending strictly within [min, max]; a duplicate names at least two ledger seqs, integers strictly "
                   "ascending, each from 1 to range.to (consistency). A series is exactly {series, min, max, missing, "
                   "duplicates}: series 0x + 64 lower-case hex, min and max integers, missing and duplicates arrays; a "
                   "duplicate is exactly {seq, correctionSeq, ledgerSeqs}: seq an integer, correctionSeq null or a "
                   "non-negative integer, ledgerSeqs an array (shape)."),
    "issuer_report": ("format", "The report is computed from the link bindings as the format defines it: the counts, "
                      "and each series' min and max, over the range; a series reported when a bound record in the range "
                      "names it; a number missing when no original (correctionSeq null) binding at or before range.to "
                      "names it; a duplicate a (seq, correctionSeq) named by two or more bindings at or before range.to, "
                      "one of them in the range. Four consequences of that definition are checked, each otherwise "
                      "consistency. After the list cap and before the first series: there are at most boundRecords "
                      "series, since a record names one series. After each duplicate's ledger-seq rule, in this order: "
                      "its seq lies within its series' [min, max], since one of its bindings is in the range; with "
                      "correctionSeq null, its seq is not listed missing, since an original binding makes its number "
                      "present; and none of its ledger seqs is named by an earlier duplicate, in its own series or "
                      "another, since a record binds one (series, seq, correctionSeq). The four are necessary, not "
                      "sufficient: a report can keep them and still be one that no bindings produce, for example one "
                      "bound record and a series whose min and max differ."),
    "anchor": ("format", "anchor is null (and then bridge is null) or exactly the eleven members in "
               "format.anchor_members: subjectSchema = commitmentSchema; seq an integer >= range.to; head, acc, "
               "subjectDigest and anchoredDigest 0x + 64 lower-case hex; batchRoot null or the same; status one of "
               "format.anchor_statuses; bitcoinBlockHeight null or a non-negative integer; subjectDigest = keccak256 "
               "over canonical({acc, head, schema: subjectSchema, seq}); id = \"seller:\" + subjectDigest; "
               "anchoredDigest = sha256 over the 32 subject-digest bytes; proofUrl a string ending "
               "/v1/anchors/<id>/proof.ots; an anchor at range.to commits through.acc and through.head. Otherwise "
               "anchor."),
    "bridge": ("format", "An anchor at range.to carries bridge null. An anchor more than format.bridge_cap records past "
               "range.to carries bridge null. Otherwise bridge is exactly {from: range.to + 1, to: anchor.seq, links}, "
               "one 0x + 64 lower-case hex link per record after range.to, and the links fold through.acc to anchor.acc "
               "(acc = keccak256(acc || link), the core's chain_commitment step). Otherwise anchor."),
    "digest": ("format", "statementDigest = keccak256 over the UTF-8 bytes of canonical(statement), the canonical form "
               "the core's digest_recompute pins. Otherwise digest."),
    "signature": ("format", "The signature is \"0x\" then 130 hex digits (r || s || v), v is 27 or 28, s <= n/2, 1 <= r "
                  "< n and s >= 1, decided on the bytes before recovery, and personal_sign recovery (the construction "
                  "the counter-signature profile's step 7 recovers) over the UTF-8 string format.signature_prefix + "
                  "statementDigest yields statement.ledger, compared case-insensitively. Otherwise signature."),
    "expected_signer": ("format", "When the relying party brings the ledger's key from elsewhere (expected_signer), it "
                        "equals statement.ledger, compared case-insensitively. Otherwise signer. Without it a valid "
                        "verdict says only that the key named in the statement signed it."),
    "records": ("format", "When the relying party brings the range's artifact digests (records, in ledger order), "
                "there is one 0x + 64 lower-case hex digest per record of the range, and folding them from before "
                "(link = keccak256(digest || prev or 32 zero bytes || uint64_be(seq)), acc = keccak256(acc || link)) "
                "ends at through.acc with through.head as the last digest. Otherwise records."),
    "check_order": ("suite", "The first rule broken decides the reason, in the order the runner lists (parse, envelope, "
                    "statement rules in the order of statement/verify_statement.py, signer = ledger, digest, signature, "
                    "expected signer, records). The order vectors (ids containing \"-order-\") each carry two faults, one "
                    "from each of two reason groups adjacent in that order, and expect the first group's reason; each "
                    "fault alone rejects with its own reason. Together they pin every adjacent pair of reason groups, "
                    "each by the one pair of rules its vector breaks, at the place in the statement where its two faults "
                    "sit. The order vectors from a series' shape to a duplicate's consistency put both faults in the "
                    "first series or in its first duplicate, so they pin the order inside one series or one duplicate; "
                    "the issuer-counts vector and the series-count vector (rules.issuer_report) put their series fault "
                    "in the second series, and one more vector pins one order across two series (the first series' "
                    "consistency before the second series' shape). They do "
                    "not pin other pairs of rules across a boundary, any other order across two series or two "
                    "duplicates, the order among rules that share a reason, or the order among the parse rules. Every "
                    "other vector "
                    "breaks one rule, except where its description names a second, and expects that rule's reason."),
    "input": ("suite", "A vector's input is {body_text, expected_signer?, records?}: the served body as text, and the "
              "two values a relying party may bring from elsewhere, read by key presence."),
    "twin": ("suite", "Every rejecting vector names an accepting vector of this set, its twin, and its description "
             "names what changed: one value; one logical change that moves values bound to each other (an anchor's "
             "derived members recomputed, a count with the count that must match it, a statement signed by another "
             "key); or, for the order vectors, two faults. The runner fails a set where a twin is missing or not "
             "valid."),
}


def main():
    a, b = Chain("a", 6), Chain("b", 3)
    A = build(a, "chain-a", 2, 5, anchor_seq=6)
    A_REC = a.digests[2:6]
    A_AT = build(a, "chain-a", 2, 6, anchor_seq=6)
    c = Chain("c", 512)
    C_SERIES = build(c, "chain-c", 2, 257)
    C_DUPLICATES = build(c, "chain-c", 2, 512)
    B = build(b, "chain-b", 1, 3)
    B_REC = b.digests[1:4]
    B_ONE = build(b, "chain-b", 1, 1, anchor_seq=1)
    X = {"expected_signer": LEDGER}

    acc_rows, rej_rows = [], []
    known = {}   # slug -> (statement or None, options, text)

    def add(side, slug, text, opts, desc, rule, twin=None, reason=None, st=None):
        inp = {"body_text": text}
        inp.update(opts)
        row = {"slug": slug, "input": inp, "description": desc, "rule": rule, "twin": twin, "reason": reason}
        (acc_rows if side == "valid" else rej_rows).append(row)
        if side == "valid":
            known[slug] = (st, dict(opts), text)

    def valid(slug, desc, rule, st, opts=X, text=None):
        add("valid", slug, text if text is not None else envelope(st), opts, desc, rule, st=st)

    def mutate(base, fn):
        st = copy.deepcopy(base)
        fn(st)
        return st

    def derived(slug, twin, reason, desc, rule, fn=None, opts=None, text=None):
        """A rejecting vector from accepting vector `twin`: its statement changed by fn and signed again, or a given
        text; the twin's expected signer and records unless opts replaces them."""
        tst, topts, _ = known[twin]
        if text is None:
            text = envelope(mutate(tst, fn))
        add("reject", slug, text, topts if opts is None else opts, desc, rule, twin=twin, reason=reason)

    def valid_from(slug, twin, desc, rule, fn):
        tst, topts, _ = known[twin]
        valid(slug, desc, rule, mutate(tst, fn), topts)

    def put(path, value):
        def fn(st):
            o = st
            for k in path[:-1]:
                o = o[k]
            if value is DELETE:
                del o[path[-1]]
            else:
                o[path[-1]] = value
        return fn

    def entries(es):
        return put(["attachments", "entries"], copy.deepcopy(es))

    def typed(t):
        return entries([{**E1, "type": t}])

    def report(name):
        bindings, frm, to = REPORTS[name]

        def fn(st):
            assert (st["range"]["from"], st["range"]["to"]) == (frm, to), name
            st["linkVersions"], st["issuerSeq"] = issuer_report(bindings, frm, to)
        return fn

    v2report = report("report")

    def then(*fns):
        def fn(st):
            for f in fns:
                f(st)
        return fn

    def mixed(position):
        def fn(st):
            report("mixed")(st)
            st["attachments"]["entries"] = [{"position": position, "type": "example-type", "binding": "sealed"}]
        return fn

    def reanchor(seq, head, acc, schema=V.COMMITMENT_SCHEMA):
        def fn(st):
            new = anchor_at(seq, head, acc, schema=schema)
            for k in ("status", "bitcoinBlockHeight", "batchRoot"):
                new[k] = st["anchor"][k]
            st["anchor"] = new
        return fn

    def at_max(n):
        def fn(st):
            st["range"] = {"from": 2, "to": n + 1}
            st["through"]["seq"] = n + 1
            st["linkVersions"] = {"v1": n, "v2": 0}
            st["issuerSeq"]["unboundRecords"] = n
            st["anchor"] = None
            st["bridge"] = None
        return fn

    RECS = {"records": A_REC, **X}

    # ---------------------------------------------------------------------------------------------- accepting bases
    valid("anchored-range-with-one-link-bridge", "A statement over seq 2..5 of a six-record chain with a confirmed "
          "anchor at seq 6 and the one bridge link that connects them, built member by member as a ledger serves it, "
          "with the ledger's key brought from elsewhere. The base most rejecting vectors change.", "anchor", A)
    valid("anchored-range-records-fold", "The first accepting vector with the relying party's records: the four "
          "artifact digests of seq 2..5 in ledger order fold from before to through.", "records", A, RECS,
          text=known["anchored-range-with-one-link-bridge"][2])
    valid("range-from-genesis-without-anchor", "A statement over seq 1..3 of a three-record chain with no anchor "
          "(anchor and bridge null), with its records: before is seq 0, head null, acc the commitment seed.",
          "before_through", B, {"records": B_REC, **X})
    valid("anchor-at-range-to", "A statement whose anchor sits at range.to: bridge is null, never an empty object.",
          "bridge", A_AT)
    valid("no-expected-signer", "The first accepting vector without the ledger's key from elsewhere: valid, and the "
          "verdict establishes only that the key the statement names signed it.", "expected_signer", A, {},
          text=known["anchored-range-with-one-link-bridge"][2])

    # ---------------------------------------------------------------------------------------------- scope
    derived("scope-unknown-value", "anchored-range-with-one-link-bridge", "scope", "scope set to \"x-unknown\", a "
            "value outside the closed set: refused, never read as \"range\".", "scope", put(["scope"], "x-unknown"))
    derived("scope-letter-case", "anchored-range-with-one-link-bridge", "scope", "scope set to \"Range\": compared "
            "exactly, letter case included.", "scope", put(["scope"], "Range"))
    derived("scope-null", "anchored-range-with-one-link-bridge", "scope", "scope set to null: a present member is a "
            "value of the set.", "scope", put(["scope"], None))
    derived("scope-empty-string", "anchored-range-with-one-link-bridge", "scope", "scope set to the empty string.",
            "scope", put(["scope"], ""))
    derived("scope-missing", "anchored-range-with-one-link-bridge", "shape", "scope removed: the member is required, "
            "so the member set is not the fourteen (shape, before the scope rule).", "members", put(["scope"], DELETE))

    # ---------------------------------------------------------------------------------------------- attachments
    valid_from("declared-entry-before-range", "anchored-range-with-one-link-bridge", "One declared entry at position "
               "1, before range.from (2): an entry may name a record before the range.", "entries", entries([E1]))
    valid_from("declared-entry-inside-range", "anchored-range-with-one-link-bridge", "One declared entry at position "
               "4, inside the range.", "entries", entries([E2]))
    valid_from("two-declared-entries", "anchored-range-with-one-link-bridge", "Two declared entries, positions 1 and "
               "4, ascending.", "entries", entries([E1, E2]))
    valid_from("sealed-entry-on-v2-range", "anchored-range-with-one-link-bridge", "A sealed entry at position 3 on a "
               "range whose links are all v2: linkVersions {v1: 0, v2: 4} and the issuer-numbering report computed from "
               "the bindings the issuer-numbering report vector names. Signed by the test key.", "sealed",
               then(v2report, entries([{"position": 3, "type": "example-type", "binding": "sealed"}])))
    valid_from("sealed-entry-at-first-v2-link", "anchored-range-with-one-link-bridge", "A mixed range 2..5 with "
               "{v1: 2, v2: 2} (seq 1 to 3 v1 links, seq 4 and 5 v2 links that bind no issuer number, so two unbound "
               "and two absent records): the first v2 link is at range.from + v1 = 4, and a sealed entry at 4 accepts.",
               "sealed", mixed(4))
    valid_from("sealed-entry-before-range-when-v1-is-zero", "anchored-range-with-one-link-bridge", "A sealed entry at "
               "position 1, before range.from, on the all-v2 range of the issuer-numbering report (seq 1 binds a number "
               "there too): with linkVersions.v1 = 0 the statement says nothing about links before range.from, so the "
               "position is not checked.", "sealed",
               then(v2report, entries([{"position": 1, "type": "example-type", "binding": "sealed"}])))
    derived("sealed-entry-without-v2-link", "declared-entry-inside-range", "attachment_entry", "The entry at position "
            "4 with binding sealed on a range with no v2 link (linkVersions.v2 = 0).", "sealed",
            entries([{**E2, "binding": "sealed"}]))
    derived("sealed-entry-on-v1-link-of-mixed-range", "sealed-entry-at-first-v2-link", "attachment_entry", "The mixed "
            "range with the sealed entry at 3, below range.from + v1 = 4: a v1 link.", "sealed", mixed(3))
    derived("sealed-entry-before-range-on-mixed-range", "sealed-entry-at-first-v2-link", "attachment_entry", "The "
            "mixed range with the sealed entry at 1, before range.from: below range.from + v1, so it rejects (a check "
            "that reads only positions from range.from on accepts it).", "sealed", mixed(1))
    derived("attachments-version-2", "anchored-range-with-one-link-bridge", "attachments_version", "attachments.version "
            "2, an unknown version.", "attachments", put(["attachments", "version"], 2))
    derived("attachments-version-string", "anchored-range-with-one-link-bridge", "attachments_version",
            "attachments.version as the string \"1\".", "attachments", put(["attachments", "version"], "1"))
    derived("attachments-version-true", "anchored-range-with-one-link-bridge", "attachments_version",
            "attachments.version true: a boolean is not the integer 1.", "attachments",
            put(["attachments", "version"], True))
    derived("attachments-version-0", "anchored-range-with-one-link-bridge", "attachments_version",
            "attachments.version 0.", "attachments", put(["attachments", "version"], 0))
    derived("attachments-null", "anchored-range-with-one-link-bridge", "attachments_version", "attachments null: the "
            "container is an object.", "attachments", put(["attachments"], None))
    derived("attachments-unknown-member", "anchored-range-with-one-link-bridge", "attachments_version", "attachments "
            "with a member beyond version and entries (x_unknown_2026: 1).", "attachments",
            put(["attachments", "x_unknown_2026"], 1))
    derived("attachments-entries-object", "anchored-range-with-one-link-bridge", "attachment_entry",
            "attachments.entries an object, not an array.", "attachments", put(["attachments", "entries"], {}))
    derived("entry-binding-outside-set", "declared-entry-before-range", "attachment_entry", "The entry's binding set "
            "to \"verified\", outside the closed set.", "entries", entries([{**E1, "binding": "verified"}]))
    derived("entry-binding-letter-case", "declared-entry-before-range", "attachment_entry", "The entry's binding "
            "\"Declared\": compared exactly.", "entries", entries([{**E1, "binding": "Declared"}]))
    derived("entry-binding-null", "declared-entry-before-range", "attachment_entry", "The entry's binding null.",
            "entries", entries([{**E1, "binding": None}]))
    derived("entry-unknown-member", "declared-entry-before-range", "attachment_entry", "The entry with a fourth "
            "member (x_unknown_2026: 1).", "entries", entries([{**E1, "x_unknown_2026": 1}]))
    derived("entry-unknown-member-null", "declared-entry-before-range", "attachment_entry", "The entry with a fourth "
            "member whose value is null: a member counts by its name.", "entries",
            entries([{**E1, "x_undefined": None}]))
    derived("entry-binding-missing", "declared-entry-before-range", "attachment_entry", "The entry without its "
            "binding.", "entries", entries([{"position": 1, "type": "example-type"}]))
    derived("entry-position-0", "declared-entry-before-range", "attachment_entry", "The entry at position 0.",
            "entries", entries([{**E1, "position": 0}]))
    valid_from("entry-position-at-range-to", "anchored-range-with-one-link-bridge", "One declared entry at position "
               "5 = range.to.", "entries", entries([{**E1, "position": 5}]))
    derived("entry-position-after-range-to", "entry-position-at-range-to", "attachment_entry", "The entry at position "
            "6, after range.to (5).", "entries", entries([{**E1, "position": 6}]))
    derived("entry-positions-repeat", "two-declared-entries", "attachment_entry", "The first entry's position 1 set "
            "to 4, so both entries are at position 4: positions ascend strictly.", "entries",
            entries([{**E1, "position": 4}, E2]))
    derived("entry-positions-inverted", "two-declared-entries", "attachment_entry", "The two entries in the order 4, 1.",
            "entries", entries([E2, E1]))
    derived("entry-position-string", "declared-entry-before-range", "attachment_entry", "The entry's position as the "
            "string \"1\".", "entries", entries([{**E1, "position": "1"}]))
    derived("entry-position-true", "declared-entry-before-range", "attachment_entry", "The entry's position true.",
            "entries", entries([{**E1, "position": True}]))
    derived("entry-type-letter-case", "declared-entry-before-range", "attachment_entry", "The entry's type "
            "\"Example-type\": lower-case only.", "entry_type", typed("Example-type"))
    derived("entry-type-empty", "declared-entry-before-range", "attachment_entry", "The entry's type empty.",
            "entry_type", typed(""))
    derived("entry-type-trailing-hyphen", "declared-entry-before-range", "attachment_entry", "The entry's type ending "
            "in a hyphen.", "entry_type", typed("example-type-"))
    derived("entry-type-underscore", "declared-entry-before-range", "attachment_entry", "The entry's type with an "
            "underscore, outside [a-z0-9-].", "entry_type", typed("example_type"))
    derived("entry-type-leading-digit", "declared-entry-before-range", "attachment_entry", "The entry's type starting "
            "with a digit.", "entry_type", typed("2-example-type"))
    valid_from("type-2-characters", "anchored-range-with-one-link-bridge", "An entry type of 2 characters, the "
               "minimum.", "entry_type", typed("ab"))
    derived("type-1-character", "type-2-characters", "attachment_entry", "An entry type of 1 character.", "entry_type",
            typed("a"))
    valid_from("type-64-characters", "anchored-range-with-one-link-bridge", "An entry type of 64 characters, the "
               "maximum.", "entry_type", typed("example-" + "x" * 54 + "-1"))
    derived("type-65-characters", "type-64-characters", "attachment_entry", "An entry type of 65 characters.",
            "entry_type", typed("example-" + "x" * 55 + "-1"))
    valid_from("type-ending-in-digit", "anchored-range-with-one-link-bridge", "An entry type with digits and hyphens, "
               "ending in a digit.", "entry_type", typed("example-type-2"))
    valid_from("type-31-hex-digits", "anchored-range-with-one-link-bridge", "An entry type of 31 hex digits (a "
               "letter a, then 30 zeros), under the limit.", "entry_type", typed("a" + "0" * 30))
    derived("type-32-hex-digits", "type-31-hex-digits", "attachment_entry", "An entry type of 32 hex digits (a 128-bit "
            "value written as hex).", "entry_type", typed("a" + "0" * 31))
    derived("type-64-hex-digits", "type-31-hex-digits", "attachment_entry", "An entry type of 64 hex digits (a 256-bit "
            "value written as hex).", "entry_type", typed("a" + "5" * 63))
    valid_from("type-31-hex-digits-split-by-hyphens", "anchored-range-with-one-link-bridge", "An entry type of 31 hex "
               "digits split by hyphens (35 characters): the limit counts hex digits, not characters.", "entry_type",
               typed("deadbeef-dead-beef-dead-beefdeadbee"))
    derived("type-32-hex-digits-split-by-hyphens", "type-31-hex-digits-split-by-hyphens", "attachment_entry", "An "
            "entry type of 32 hex digits split by hyphens.", "entry_type", typed("deadbeef-dead-beef-dead-beefdeadbeef"))
    valid_from("type-x-then-32-hex-digits", "anchored-range-with-one-link-bridge", "An entry type x followed by 32 hex "
               "digits: one character outside [0-9a-f-] takes the type outside the hex rule (a check that refuses "
               "any run of 32 hex digits rejects it).", "entry_type", typed("x" + "0" * 32))
    valid_from("type-32-hex-digits-then-x", "anchored-range-with-one-link-bridge", "An entry type of 32 hex digits "
               "followed by x.", "entry_type", typed("a" + "0" * 31 + "x"))

    # ---------------------------------------------------------------------------------------------- range
    valid_from("range-at-maximum", "anchored-range-with-one-link-bridge", "A range of 5,000 records (2..5001), the "
               "maximum, with counts, through.seq and a null anchor consistent with it. Hand-built: the head and acc "
               "values are not recomputed over 5,000 records, which no rule here reads.", "range", at_max(5000))
    derived("range-over-maximum", "range-at-maximum", "range", "A range of 5,001 records, otherwise consistent.",
            "range", at_max(5001))
    derived("range-from-0", "anchored-range-with-one-link-bridge", "range", "range.from 0.", "range",
            put(["range", "from"], 0))
    derived("range-from-after-to", "anchored-range-with-one-link-bridge", "range", "range.from 6 with range.to 5.",
            "range", put(["range", "from"], 6))
    derived("range-from-string", "anchored-range-with-one-link-bridge", "range", "range.from as the string \"2\".",
            "range", put(["range", "from"], "2"))
    derived("range-unknown-member", "anchored-range-with-one-link-bridge", "shape", "range with a third member, "
            "count: 4.", "range", put(["range", "count"], 4))

    # ---------------------------------------------------------------------------------------------- chain
    valid_from("chain-key-present", "anchored-range-with-one-link-bridge", "chain.key present and well-formed (0x + 64 "
               "lower-case hex, not zero).", "chain", put(["chain", "key"], "0x" + "ab" * 32))
    derived("chain-key-empty", "chain-key-present", "chain_key", "chain.key the empty string.", "chain",
            put(["chain", "key"], ""))
    derived("chain-key-null", "chain-key-present", "chain_key", "chain.key null: a present key is a value, not "
            "absence.", "chain", put(["chain", "key"], None))
    derived("chain-key-upper-case", "chain-key-present", "chain_key", "chain.key in upper-case hex.", "chain",
            put(["chain", "key"], "0x" + "AB" * 32))
    derived("chain-key-31-bytes", "chain-key-present", "chain_key", "chain.key of 31 bytes.", "chain",
            put(["chain", "key"], "0x" + "ab" * 31))
    derived("chain-key-33-bytes", "chain-key-present", "chain_key", "chain.key of 33 bytes.", "chain",
            put(["chain", "key"], "0x" + "ab" * 33))
    derived("chain-key-zero-bytes", "chain-key-present", "chain_key", "chain.key of 32 zero bytes.", "chain",
            put(["chain", "key"], "0x" + "00" * 32))
    derived("chain-unknown-member", "anchored-range-with-one-link-bridge", "shape", "chain with a member other than "
            "sellerId and key (x_unknown_2026: 1).", "chain", put(["chain", "x_unknown_2026"], 1))
    derived("chain-id-empty", "anchored-range-with-one-link-bridge", "shape", "chain.sellerId empty.", "chain",
            put(["chain", "sellerId"], ""))
    derived("chain-id-number", "anchored-range-with-one-link-bridge", "shape", "chain.sellerId the number 7.", "chain",
            put(["chain", "sellerId"], 7))
    derived("chain-id-missing", "anchored-range-with-one-link-bridge", "shape", "chain without sellerId.", "chain",
            put(["chain", "sellerId"], DELETE))

    # ---------------------------------------------------------------------------------------------- ledger
    valid_from("ledger-lower-case", "anchored-range-with-one-link-bridge", "statement.ledger written in lower case "
               "(and the envelope's signer with it): either letter case is accepted.", "members",
               lambda st: st.update(ledger=st["ledger"].lower()))
    derived("ledger-39-hex-digits", "anchored-range-with-one-link-bridge", "shape", "statement.ledger of 39 hex "
            "digits.", "members", lambda st: st.update(ledger=st["ledger"][:41]))
    derived("ledger-41-hex-digits", "anchored-range-with-one-link-bridge", "shape", "statement.ledger of 41 hex "
            "digits.", "members", lambda st: st.update(ledger=st["ledger"] + "0"))
    derived("ledger-without-0x", "anchored-range-with-one-link-bridge", "shape", "statement.ledger without 0x.",
            "members", lambda st: st.update(ledger=st["ledger"][2:]))
    derived("ledger-non-hex-character", "anchored-range-with-one-link-bridge", "shape", "statement.ledger with g as "
            "its last character.", "members", lambda st: st.update(ledger=st["ledger"][:41] + "g"))

    # ---------------------------------------------------------------------------------------------- fixed members
    derived("limits-text-altered", "anchored-range-with-one-link-bridge", "shape", "limits with \"not detectable\" "
            "changed to \"detectable\": the text is fixed, byte for byte.", "members",
            lambda st: st.update(limits=st["limits"].replace("not detectable", "detectable")))
    derived("unknown-top-level-member", "anchored-range-with-one-link-bridge", "shape", "The statement with a "
            "fifteenth member, x_unknown_2026: 1.", "members", put(["x_unknown_2026"], 1))
    derived("unknown-top-level-member-null", "anchored-range-with-one-link-bridge", "shape", "The statement with a "
            "fifteenth member whose value is null: a member counts by its name.", "members", put(["x_undefined"], None))
    derived("schema-v2", "anchored-range-with-one-link-bridge", "shape", "schema set to "
            "\"tersign-chain-statement-v2\", a version this profile does not define.", "members",
            put(["schema"], "tersign-chain-statement-v2"))
    derived("commitment-schema-v2", "range-from-genesis-without-anchor", "shape", "commitmentSchema set to "
            "\"tersign-chain-commitment-v2\" on a statement with no anchor, so the anchor's subjectSchema rule cannot "
            "reject it instead.", "members", put(["commitmentSchema"], "tersign-chain-commitment-v2"))
    derived("before-acc-upper-case", "anchored-range-with-one-link-bridge", "shape", "before.acc in upper-case hex.",
            "before_through", lambda st: st["before"].update(acc=upper(st["before"]["acc"])))
    derived("through-head-upper-case", "anchored-range-with-one-link-bridge", "shape", "through.head in upper-case "
            "hex.", "before_through", lambda st: st["through"].update(head=upper(st["through"]["head"])))
    derived("link-versions-v3", "anchored-range-with-one-link-bridge", "shape", "linkVersions with a third member, "
            "v3: 0.", "link_versions", put(["linkVersions", "v3"], 0))

    # ---------------------------------------------------------------------------------------------- consistency
    derived("before-seq-not-from-minus-one", "anchored-range-with-one-link-bridge", "consistency", "before.seq 2 "
            "where range.from is 2.", "before_through", put(["before", "seq"], 2))
    derived("link-versions-miscount", "anchored-range-with-one-link-bridge", "consistency", "linkVersions.v1 3 for a "
            "4-record range, with issuerSeq.unboundRecords 3 to match it, so only the count is wrong.",
            "link_versions", then(put(["linkVersions", "v1"], 3), put(["issuerSeq", "unboundRecords"], 3)))
    derived("issuer-counts-miscount", "anchored-range-with-one-link-bridge", "consistency",
            "issuerSeq.unboundRecords 3 where linkVersions.v1 is 4.", "issuer_seq",
            put(["issuerSeq", "unboundRecords"], 3))
    derived("before-acc-not-the-seed", "range-from-genesis-without-anchor", "consistency", "before.acc at seq 0 set to "
            "another value: at seq 0 it is the commitment seed.", "before_through", put(["before", "acc"], "0x" + "44" * 32))
    derived("before-head-null-after-seq-0", "anchored-range-with-one-link-bridge", "consistency", "before.head null "
            "where before.seq is 1.", "before_through", put(["before", "head"], None))
    derived("through-seq-not-range-to", "anchored-range-with-one-link-bridge", "consistency", "through.seq 6 where "
            "range.to is 5.", "before_through", put(["through", "seq"], 6))

    # ---------------------------------------------------------------------------------------------- issuer numbering
    valid_from("issuer-numbering-report", "anchored-range-with-one-link-bridge", "A v2 issuer-numbering report over seq "
               "2..5, computed from these link bindings: seq 1 and 2 both bind series 0x0a.. number 1, seq 3 binds "
               "0x0a.. number 3, seq 4 binds 0x0b.. number 7, and seq 5 is a v2 link that binds no number. So "
               "linkVersions {v1: 0, v2: 4}, three bound records and one absent; series 0x0a.. has min 1, max 3, number "
               "2 missing and number 1 named by ledger seqs 1 and 2 (a duplicate); series 0x0b.. has min and max 7. "
               "Signed by the test key.", "issuer_seq", v2report)

    def ser(i, **kv):
        return lambda st: st["issuerSeq"]["series"][i].update(kv)

    def ser_append(i, member, value):
        return lambda st: st["issuerSeq"]["series"][i][member].append(value)

    derived("series-without-bound-record", "anchored-range-with-one-link-bridge", "consistency", "A series on a "
            "statement with no bound record.", "issuer_seq", put(["issuerSeq", "series"],
                                                                 [{"series": SER1, "min": 1, "max": 1, "missing": [],
                                                                   "duplicates": []}]))
    derived("missing-number-outside-min-max", "issuer-numbering-report", "consistency", "Series 0x0a..'s missing "
            "numbers [2] replaced by [4], above its max 3.", "issuer_seq", ser(0, missing=[4]))
    derived("missing-numbers-repeat", "issuer-numbering-report", "consistency", "Series 0x0a..'s missing numbers [2] "
            "replaced by [2, 2].", "issuer_seq", ser(0, missing=[2, 2]))
    derived("series-ids-repeat", "issuer-numbering-report", "consistency", "The second series' id set to the first's: "
            "two series with one id.", "issuer_seq", ser(1, series=SER1))
    derived("series-min-above-max", "issuer-numbering-report", "consistency", "Series 0x0b..'s min set to 8, above its "
            "max 7.", "issuer_seq", ser(1, min=8))

    def dup(**kv):
        return lambda st: st["issuerSeq"]["series"][0]["duplicates"][0].update(kv)

    derived("duplicate-one-ledger-seq", "issuer-numbering-report", "consistency", "The duplicate's ledger seqs [1, 2] "
            "replaced by [2]: a duplicate names at least two.", "issuer_seq", dup(ledgerSeqs=[2]))
    derived("duplicate-ledger-seq-after-range", "issuer-numbering-report", "consistency", "The duplicate's ledger seqs "
            "[1, 2] replaced by [1, 6]: 6 is after range.to (5).", "issuer_seq", dup(ledgerSeqs=[1, 6]))
    derived("duplicate-correction-seq-negative", "issuer-numbering-report", "shape", "The duplicate's correctionSeq "
            "set to -1.", "issuer_seq", dup(correctionSeq=-1))
    derived("issuer-bound-plus-absent-miscount", "issuer-numbering-report", "consistency", "absentRecords 0, so bound "
            "+ absent (3) differs from linkVersions.v2 (4).", "issuer_seq", put(["issuerSeq", "absentRecords"], 0))
    derived("series-unknown-member", "issuer-numbering-report", "shape", "A series with a sixth member, note.",
            "issuer_seq", ser(1, note="x"))
    derived("list-cap-255", "anchored-range-with-one-link-bridge", "consistency", "issuerSeq.listCap 255.",
            "issuer_seq", put(["issuerSeq", "listCap"], 255))
    derived("list-cap-257", "anchored-range-with-one-link-bridge", "consistency", "issuerSeq.listCap 257.",
            "issuer_seq", put(["issuerSeq", "listCap"], 257))
    derived("truncated-string", "anchored-range-with-one-link-bridge", "shape", "issuerSeq.truncated the string "
            "\"false\".", "issuer_seq", put(["issuerSeq", "truncated"], "false"))

    valid("series-at-list-cap", "256 series, the list cap, over seq 2..257 of a 512-record chain: seq 1 is a v1 link, "
          "and each seq k from 2 to 257 is a v2 link binding number 1 of its own series, id k - 1 as 32 bytes. Each "
          "series has min and max 1, nothing missing and no duplicate; no anchor. Signed by the test key.", "issuer_seq",
          mutate(C_SERIES, report("series_at_cap")))
    derived("series-over-list-cap", "series-at-list-cap", "consistency", "A 257th series (id 257, min and max 1) "
            "appended: one more than the cap.", "issuer_seq",
            lambda st: st["issuerSeq"]["series"].append({"series": hex32(257), "min": 1, "max": 1, "missing": [],
                                                         "duplicates": []}))
    valid_from("missing-at-list-cap", "anchored-range-with-one-link-bridge", "256 missing numbers in one series: the "
               "bindings of the issuer-numbering report with seq 3 binding series 0x0a.. number 258 instead of 3, so "
               "the series runs from 1 to 258 and numbers 2 to 257 are missing. Signed by the test key.", "issuer_seq",
               report("missing_at_cap"))
    derived("missing-over-list-cap", "missing-at-list-cap", "consistency", "Number 258 appended to the 256 missing "
            "numbers: 257 in one series.", "issuer_seq", ser_append(0, "missing", 258))
    valid("duplicates-at-list-cap", "256 duplicates in one series, over seq 2..512 of a 512-record chain: seq 2k - 1 "
          "and seq 2k both bind series 0x0a.. number k, for k from 1 to 256, so the series runs from 1 to 256 with "
          "nothing missing and each number named by two ledger seqs; no anchor. Signed by the test key.", "issuer_seq",
          mutate(C_DUPLICATES, report("duplicates_at_cap")))
    derived("duplicates-over-list-cap", "duplicates-at-list-cap", "consistency", "A 257th duplicate appended (number "
            "256 with correctionSeq 0, ledger seqs 511 and 512): one more than the cap.", "issuer_seq",
            ser_append(0, "duplicates", {"seq": 256, "correctionSeq": 0, "ledgerSeqs": [511, 512]}))

    # ---------------------------------------------------------------------------------------------- anchor and bridge
    derived("bridge-link-replaced", "anchored-range-with-one-link-bridge", "anchor", "The bridge's one link replaced "
            "by another well-formed digest: it no longer folds through.acc to anchor.acc.", "bridge",
            lambda st: st["bridge"]["links"].__setitem__(0, "0x" + "55" * 32))

    def wrong_subject(st):
        wrong = "0x" + "66" * 32
        aid = "seller:" + wrong
        st["anchor"].update(subjectDigest=wrong, id=aid, proofUrl="%s/v1/anchors/%s/proof.ots" % (BASE, aid),
                            anchoredDigest="0x" + hashlib.sha256(bytes.fromhex(wrong[2:])).hexdigest())

    derived("anchor-subject-digest-wrong", "anchored-range-with-one-link-bridge", "anchor", "anchor.subjectDigest not "
            "the digest of {acc, head, schema, seq}; id, anchoredDigest and proofUrl follow the wrong digest, so only "
            "the subject digest is wrong.", "anchor", wrong_subject)
    derived("anchor-anchored-digest-wrong", "anchored-range-with-one-link-bridge", "anchor", "anchor.anchoredDigest "
            "not sha256 over the subject-digest bytes.", "anchor", put(["anchor", "anchoredDigest"], "0x" + "67" * 32))
    derived("anchor-status-outside-set", "anchored-range-with-one-link-bridge", "anchor", "anchor.status \"final\".",
            "anchor", put(["anchor", "status"], "final"))
    derived("anchor-within-cap-without-bridge", "anchored-range-with-one-link-bridge", "anchor", "An anchor one record "
            "past range.to with bridge null: within the cap the bridge travels with the statement.", "bridge",
            put(["bridge"], None))
    derived("bridge-without-anchor", "range-from-genesis-without-anchor", "anchor", "A bridge on a statement with no "
            "anchor.", "bridge", put(["bridge"], {"from": 4, "to": 3, "links": []}))
    derived("anchor-before-range-to", "anchored-range-with-one-link-bridge", "anchor", "An anchor at seq 4, before "
            "range.to (5): it does not cover the range. Its derived members are recomputed, and the bridge {from: 6, to: "
            "4, links: []} breaks the bridge rule as well; the seq rule comes first.", "anchor",
            then(reanchor(4, "0x" + "77" * 32, "0x" + "88" * 32), put(["bridge"], {"from": 6, "to": 4, "links": []})))

    def other_id(st):
        aid = "ledger:" + st["anchor"]["subjectDigest"]
        st["anchor"].update(id=aid, proofUrl="%s/v1/anchors/%s/proof.ots" % (BASE, aid))

    derived("anchor-id-wrong-prefix", "anchored-range-with-one-link-bridge", "anchor", "anchor.id \"ledger:\" + "
            "subjectDigest; proofUrl follows it.", "anchor", other_id)
    derived("anchor-proof-url-other-id", "anchored-range-with-one-link-bridge", "anchor", "anchor.proofUrl naming "
            "another id.", "anchor", put(["anchor", "proofUrl"], BASE + "/v1/anchors/other/proof.ots"))
    derived("anchor-at-range-to-other-head", "anchor-at-range-to", "anchor", "An anchor at range.to whose head is not "
            "through.head (acc equal; derived members recomputed).", "anchor",
            lambda st: reanchor(st["range"]["to"], "0x" + "89" * 32, st["through"]["acc"])(st))
    derived("anchor-at-range-to-with-empty-bridge", "anchor-at-range-to", "anchor", "An anchor at range.to with an "
            "empty bridge object {from: 7, to: 6, links: []} instead of null.", "bridge",
            put(["bridge"], {"from": 7, "to": 6, "links": []}))
    derived("anchor-height-negative", "anchored-range-with-one-link-bridge", "anchor", "anchor.bitcoinBlockHeight -1.",
            "anchor", put(["anchor", "bitcoinBlockHeight"], -1))
    valid_from("pending-anchor-with-batch-root", "anchored-range-with-one-link-bridge", "A pending anchor with no "
               "height and a batch root.", "anchor",
               lambda st: st["anchor"].update(status="pending", bitcoinBlockHeight=None, batchRoot="0x" + "ab" * 32))
    derived("anchor-batch-root-upper-case", "pending-anchor-with-batch-root", "anchor", "The pending anchor's batch "
            "root in upper-case hex.", "anchor", put(["anchor", "batchRoot"], "0x" + "AB" * 32))
    valid_from("anchor-past-bridge-cap", "anchored-range-with-one-link-bridge", "An anchor 1,001 records past "
               "range.to with bridge null (derived members recomputed; head and acc are values no rule folds).",
               "bridge", then(lambda st: reanchor(st["range"]["to"] + 1001, "0x" + "77" * 32, "0x" + "88" * 32)(st),
                              put(["bridge"], None)))
    derived("anchor-past-bridge-cap-with-bridge", "anchor-past-bridge-cap", "anchor", "The anchor 1,001 records past "
            "range.to with a bridge present.", "bridge",
            put(["bridge"], {"from": 6, "to": 1006, "links": ["0x" + "99" * 32]}))
    valid_from("anchor-at-bridge-cap", "anchored-range-with-one-link-bridge", "An anchor 1,000 records past range.to "
               "(the cap) carrying its 1,000 bridge links, which fold through.acc to anchor.acc (synthetic links; the "
               "derived members are recomputed over the folded acc).", "bridge",
               lambda st: _cap_bridge(st))
    derived("anchor-at-bridge-cap-without-bridge", "anchor-at-bridge-cap", "anchor", "The anchor 1,000 records past "
            "range.to with bridge null: at the cap the bridge still travels.", "bridge", put(["bridge"], None))
    derived("anchor-unknown-member", "anchored-range-with-one-link-bridge", "anchor", "anchor with a twelfth member "
            "(x_unknown_2026: 1).", "anchor", put(["anchor", "x_unknown_2026"], 1))
    derived("anchor-subject-schema-other", "anchored-range-with-one-link-bridge", "anchor", "anchor.subjectSchema "
            "\"tersign-chain-commitment-v2\", the subject digest still over the fixed schema.", "anchor",
            put(["anchor", "subjectSchema"], "tersign-chain-commitment-v2"))
    derived("anchor-subject-schema-other-recomputed", "anchored-range-with-one-link-bridge", "anchor",
            "anchor.subjectSchema \"tersign-chain-commitment-v2\" with the subject digest, id, anchoredDigest and "
            "proofUrl recomputed over it: subjectSchema must equal commitmentSchema.", "anchor",
            lambda st: reanchor(st["anchor"]["seq"], st["anchor"]["head"], st["anchor"]["acc"],
                                schema="tersign-chain-commitment-v2")(st))
    derived("anchor-head-upper-case", "anchored-range-with-one-link-bridge", "anchor", "anchor.head in upper-case hex, "
            "the derived members recomputed over it.", "anchor",
            lambda st: reanchor(st["anchor"]["seq"], upper(st["anchor"]["head"]), st["anchor"]["acc"])(st))
    derived("bridge-link-upper-case", "anchored-range-with-one-link-bridge", "anchor", "The bridge link in upper-case "
            "hex: the same bytes, refused by form.", "bridge",
            lambda st: st["bridge"]["links"].__setitem__(0, upper(st["bridge"]["links"][0])))

    # ---------------------------------------------------------------------------------------------- digest, signature, signer
    base_text = known["anchored-range-with-one-link-bridge"][2]
    genuine = json.loads(base_text)
    tampered = copy.deepcopy(A)
    tampered["through"]["head"] = "0x" + "99" * 32
    derived("tampered-head-original-digest", "anchored-range-with-one-link-bridge", "digest", "through.head changed, "
            "with the original statementDigest and signature.", "digest",
            text=js_text({"statement": tampered, "statementDigest": genuine["statementDigest"],
                          "signature": genuine["signature"], "signer": LEDGER}))
    derived("tampered-head-recomputed-digest", "anchored-range-with-one-link-bridge", "signature", "through.head "
            "changed, its digest recomputed, the original signature: it recovers some other address.", "signature",
            text=js_text({"statement": tampered, "statementDigest": digest_of(tampered),
                          "signature": genuine["signature"], "signer": LEDGER}))
    derived("signed-by-another-key-naming-ledger", "anchored-range-with-one-link-bridge", "signature", "The statement "
            "signed by the second test key while statement.ledger names the first.", "signature",
            text=envelope(A, KEY2))
    sig = genuine["signature"]
    r, s, v = sig[2:66], int(sig[66:130], 16), int(sig[130:], 16)
    high_s = "0x" + r + (S.N - s).to_bytes(32, "big").hex() + bytes([55 - v]).hex()
    derived("high-s-twin-of-genuine-signature", "anchored-range-with-one-link-bridge", "signature", "The genuine "
            "signature malleated to s' = n - s with v flipped: it recovers the same key, and is refused as a second "
            "encoding of one signature.", "signature",
            text=js_text({**genuine, "signature": high_s}))
    derived("recovery-id-0-or-1", "anchored-range-with-one-link-bridge", "signature", "The genuine signature with v "
            "written as the raw recovery id (%d) instead of %d: refused, never normalized." % (v - 27, v), "signature",
            text=js_text({**genuine, "signature": sig[:130] + bytes([v - 27]).hex()}))
    forged = copy.deepcopy(A)
    forged["ledger"] = OTHER
    forged_text = envelope(forged, KEY2)
    valid("another-key-without-expected-signer", "A statement naming and signed by the second test key, with no key "
          "brought from elsewhere: valid, and the verdict establishes only that the key it names signed it.",
          "expected_signer", forged, {}, text=forged_text)
    valid("another-key-as-expected-signer", "The same statement with the second test key brought from elsewhere.",
          "expected_signer", forged, {"expected_signer": OTHER}, text=forged_text)
    derived("self-consistent-statement-by-another-key", "another-key-as-expected-signer", "signer", "The same "
            "statement checked against the first test key brought from elsewhere: internally consistent, not signed by "
            "the expected key.", "expected_signer", text=forged_text, opts=X)
    valid("expected-signer-lower-case", "The first accepting vector with the expected signer written in lower case: "
          "compared case-insensitively.", "expected_signer", A, {"expected_signer": LEDGER.lower()}, text=base_text)
    derived("envelope-signer-not-ledger", "anchored-range-with-one-link-bridge", "shape", "The envelope's signer "
            "names the second test key while statement.ledger names the first.", "envelope",
            text=envelope(A, KEY1, signer=OTHER))
    derived("envelope-unknown-member", "anchored-range-with-one-link-bridge", "shape", "The envelope with a fifth "
            "member, x_unknown_2026: 1.", "envelope", text=envelope(A, KEY1, x_unknown_2026=1))

    # ---------------------------------------------------------------------------------------------- parse
    dup_text = base_text.replace('{"statement":{', '{"statement":{"scope":"x-unknown",', 1)
    assert dup_text != base_text
    derived("duplicate-member-first-reads-otherwise", "anchored-range-with-one-link-bridge", "parse", "scope written "
            "twice in the statement: the first says \"x-unknown\", the signed last says \"range\". A reader that keeps "
            "the last value reads a valid statement; one that keeps the first reads another.", "parse", text=dup_text)
    float_text = base_text.replace('"attachments":{"version":1,', '"attachments":{"version":1.0,', 1)
    assert float_text != base_text
    derived("attachments-version-token-1-0", "anchored-range-with-one-link-bridge", "parse", "attachments.version "
            "written as the token 1.0: a reader that turns it into 1 finds the digest and signature still match.",
            "parse", text=float_text)
    big_text = base_text.replace('"through":{"seq":5,', '"through":{"seq":9007199254740993,', 1)
    assert big_text != base_text
    derived("integer-beyond-2-53", "anchored-range-with-one-link-bridge", "parse", "through.seq written as "
            "9007199254740993, beyond 2**53 - 1 (a double reads it as 9007199254740992).", "parse", text=big_text)
    pair_st = mutate(A, put(["chain", "sellerId"], "chain-a\U0001F600"))
    pair_text = envelope(pair_st).replace("chain-a\U0001F600", "chain-a\\ud83d\\ude00")
    assert "chain-a\\ud83d\\ude00" in pair_text
    valid("surrogate-pair-as-escapes", "chain.sellerId ending in a character outside the Basic Multilingual Plane, "
          "written in the served text as a pair of JSON escapes: well-formed, valid.", "parse", pair_st, X,
          text=pair_text)
    derived("lone-high-surrogate-in-chain-id", "surrogate-pair-as-escapes", "parse", "chain.sellerId ending in a high "
            "surrogate escape with no low half: no UTF-8 form, so no canonical bytes (signed over the escaped form a "
            "JavaScript signer computes).", "parse", fn=put(["chain", "sellerId"], "chain-a\ud800"))
    derived("lone-low-surrogate-in-proof-url", "anchored-range-with-one-link-bridge", "parse", "anchor.proofUrl "
            "starting with a low surrogate escape with no high half.", "parse",
            fn=lambda st: st["anchor"].update(proofUrl="\udc00" + st["anchor"]["proofUrl"]))

    # ---------------------------------------------------------------------------------------------- records
    derived("record-swapped", "anchored-range-records-fold", "records", "The relying party's records with the second "
            "and third swapped.", "records", text=base_text, opts={**RECS, "records": [A_REC[0], A_REC[2], A_REC[1],
                                                                                       A_REC[3]]})
    derived("record-left-out", "anchored-range-records-fold", "records", "Three records for a four-record range.",
            "records", text=base_text, opts={**RECS, "records": A_REC[:3]})
    derived("record-of-another-chain", "anchored-range-records-fold", "records", "The last record replaced by a record "
            "of another chain.", "records", text=base_text, opts={**RECS, "records": A_REC[:3] + [b.digests[1]]})
    derived("record-appended-after-range", "anchored-range-records-fold", "records", "Five records for a four-record "
            "range: the four that fold, then the record after range.to. A check that folds only as many records as the "
            "range holds accepts it.", "records", text=base_text, opts={**RECS, "records": A_REC + [a.digests[6]]})
    derived("record-upper-case", "anchored-range-records-fold", "records", "The first record in upper-case hex: the "
            "same bytes, refused by form.", "records", text=base_text,
            opts={**RECS, "records": [upper(A_REC[0])] + A_REC[1:]})

    # ---------------------------------------------------------------------------------------------- envelope encodings
    valid("signature-upper-case-hex-digits", "The genuine signature with its hex digits in upper case after 0x: the "
          "same 65 bytes, accepted (a check that admits only lower-case digits rejects it).", "signature", A, X,
          text=js_text({**genuine, "signature": "0x" + sig[2:].upper()}))
    derived("signature-0X-prefix", "signature-upper-case-hex-digits", "signature", "The upper-case signature with a "
            "0X prefix: the prefix is exactly 0x.", "signature",
            text=js_text({**genuine, "signature": "0X" + sig[2:].upper()}))
    derived("signature-trailing-newline", "anchored-range-with-one-link-bridge", "signature", "The genuine signature "
            "followed by a newline (a pattern anchored with a $ that matches before a final newline accepts it).",
            "signature", text=js_text({**genuine, "signature": sig + "\n"}))
    derived("statement-digest-upper-case", "anchored-range-with-one-link-bridge", "digest", "statementDigest with its "
            "hex digits in upper case: compared exactly with the lower-case digest (a check that compares the bytes "
            "accepts it).", "digest", text=js_text({**genuine, "statementDigest": "0x" + genuine["statementDigest"][2:].upper()}))
    derived("envelope-signer-letter-case", "anchored-range-with-one-link-bridge", "shape", "The envelope's signer "
            "written in lower case while statement.ledger is in mixed case: compared byte for byte.", "envelope",
            text=js_text({**genuine, "signer": genuine["signer"].lower()}))

    # ---------------------------------------------------------------------------------------------- found by the differential
    derived("before-head-upper-case", "anchored-range-with-one-link-bridge", "shape", "before.head in upper-case hex "
            "(a check that lower-cases a digest before reading it accepts it).", "before_through",
            lambda st: st["before"].update(head=upper(st["before"]["head"])))
    derived("anchor-height-true", "anchored-range-with-one-link-bridge", "anchor", "anchor.bitcoinBlockHeight true: a "
            "boolean is not a non-negative integer (a reader that takes true for 1 accepts it).", "anchor",
            put(["anchor", "bitcoinBlockHeight"], True))

    # ---------------------------------------------------------------------------------------------- rule parts no vector reached
    valid_from("issuer-numbering-corrections", "anchored-range-with-one-link-bridge", "A v2 issuer-numbering report "
               "with corrections, over seq 2..5, computed from these link bindings: seq 1 binds series 0x0a.. number 1, "
               "seq 2 and 3 both bind number 2 with correctionSeq 0, and seq 4 and 5 both bind number 3 with "
               "correctionSeq 1. Only seq 1 is an original, so numbers 2 and 3, the series' min and max, are both "
               "missing, and each is a duplicate: correctionSeq 0 and a positive correctionSeq, a missing number equal "
               "to min and one equal to max. Signed by the test key.", "issuer_seq", report("corrections"))
    valid_from("anchor-height-0", "anchored-range-with-one-link-bridge", "anchor.bitcoinBlockHeight 0, the least "
               "non-negative integer.", "anchor", put(["anchor", "bitcoinBlockHeight"], 0))
    valid_from("anchor-height-2-53-minus-1", "anchored-range-with-one-link-bridge", "anchor.bitcoinBlockHeight "
               "2**53 - 1, the greatest integer the parse rule admits.", "anchor",
               put(["anchor", "bitcoinBlockHeight"], 2 ** 53 - 1))
    derived("before-head-at-seq-0", "range-from-genesis-without-anchor", "consistency", "before.head set to a digest "
            "where before.seq is 0: head is null exactly when seq is 0, in both directions. A check that reads only a "
            "null head after seq 0 passes the statement rules, and the relying party's records, which fold from that "
            "head, then reject it as records instead.", "before_through", put(["before", "head"], "0x" + "12" * 32))
    derived("anchor-at-range-to-other-acc", "anchor-at-range-to", "anchor", "An anchor at range.to whose acc is not "
            "through.acc (head equal; derived members recomputed). A check that compares only the head accepts it.",
            "anchor", lambda st: reanchor(st["range"]["to"], st["through"]["head"], "0x" + "34" * 32)(st))

    def empty_bridge_folding(st):
        reanchor(st["anchor"]["seq"], st["anchor"]["head"], st["through"]["acc"])(st)
        st["bridge"]["links"] = []

    derived("bridge-without-links-folding-to-anchor", "anchored-range-with-one-link-bridge", "anchor", "One logical "
            "change: the anchor's acc set to through.acc (derived members recomputed) and the bridge's one link "
            "removed. Folding no link then ends at anchor.acc, so only the link count, one per record after range.to, "
            "rejects it.", "bridge", empty_bridge_folding)
    derived("bridge-from-not-after-range-to", "anchored-range-with-one-link-bridge", "anchor", "bridge.from 7, not "
            "range.to + 1 (6). The link still folds to anchor.acc.", "bridge",
            put(["bridge", "from"], 7))
    derived("bridge-to-not-anchor-seq", "anchored-range-with-one-link-bridge", "anchor", "bridge.to 7 where anchor.seq "
            "is 6. The link count and the fold still hold.", "bridge", put(["bridge", "to"], 7))
    derived("anchor-before-range-to-without-bridge", "anchored-range-with-one-link-bridge", "anchor", "An anchor at "
            "seq 4, before range.to (5), derived members recomputed, with bridge null. It breaks the seq rule and the "
            "bridge rule, as every anchor before range.to does (bridge.to would have to be anchor.seq with fewer than "
            "zero links). A check that treats an anchor at or before range.to like one at range.to accepts it.",
            "anchor", then(reanchor(4, "0x" + "77" * 32, "0x" + "88" * 32), put(["bridge"], None)))
    derived("before-unknown-member", "anchored-range-with-one-link-bridge", "shape", "before with a fourth member "
            "(x_unknown_2026: 1).", "before_through", put(["before", "x_unknown_2026"], 1))
    derived("through-unknown-member", "anchored-range-with-one-link-bridge", "shape", "through with a fourth member "
            "(x_unknown_2026: 1).", "before_through", put(["through", "x_unknown_2026"], 1))
    derived("issuer-seq-unknown-member", "anchored-range-with-one-link-bridge", "shape", "issuerSeq with a seventh "
            "member (x_unknown_2026: 1).", "issuer_seq", put(["issuerSeq", "x_unknown_2026"], 1))
    derived("duplicate-unknown-member", "issuer-numbering-report", "shape", "The duplicate with a fourth member "
            "(x_unknown_2026: 1).", "issuer_seq", dup(x_unknown_2026=1))
    derived("bridge-unknown-member", "anchored-range-with-one-link-bridge", "anchor", "The bridge with a fourth member "
            "(x_unknown_2026: 1).", "bridge", put(["bridge", "x_unknown_2026"], 1))
    derived("before-head-missing", "range-from-genesis-without-anchor", "shape", "before without its head, where the "
            "head is null at seq 0: a member that is absent is not a member whose value is null.", "before_through",
            put(["before", "head"], DELETE))
    derived("anchor-batch-root-missing", "anchored-range-with-one-link-bridge", "anchor", "The anchor without its "
            "batchRoot, which is null in the twin.", "anchor", put(["anchor", "batchRoot"], DELETE))
    derived("anchor-height-missing", "pending-anchor-with-batch-root", "anchor", "The pending anchor without its "
            "bitcoinBlockHeight, which is null in the twin.", "anchor", put(["anchor", "bitcoinBlockHeight"], DELETE))
    derived("duplicate-correction-seq-missing", "issuer-numbering-report", "shape", "The duplicate without its "
            "correctionSeq, which is null in the twin.", "issuer_seq",
            lambda st: st["issuerSeq"]["series"][0]["duplicates"][0].pop("correctionSeq"))

    # ---------------------------------------------------------------------------------------------- the served text
    raw_high = pair_text.replace("\\ud83d", chr(0xD83D), 1)
    raw_low = pair_text.replace("\\ude00", chr(0xDE00), 1)
    assert raw_high != pair_text and raw_low != pair_text
    derived("surrogate-raw-high-then-escaped-low", "surrogate-pair-as-escapes", "parse", "The pair's high surrogate "
            "written raw in the text and its low half as the escape \\ude00. Read as code points these are two lone "
            "surrogates (a body served as UTF-8 cannot carry the raw half); a reader of UTF-16 code units that decodes "
            "the escape first sees a pair.", "raw_surrogate", text=raw_high)
    derived("surrogate-escaped-high-then-raw-low", "surrogate-pair-as-escapes", "parse", "The mirror: the high "
            "surrogate as the escape \\ud83d and the low half written raw.", "raw_surrogate", text=raw_low)

    def nested(depth):
        text = base_text.replace('"scope":"range"', '"scope":' + "[" * (depth - 2) + "]" * (depth - 2), 1)
        assert text != base_text and V._depth(text) == depth
        return text

    derived("nesting-at-bound", "anchored-range-with-one-link-bridge", "scope", "scope replaced by 62 nested arrays, "
            "so the body nests 64 deep, the bound: it is read, and scope is not one of the set.", "depth",
            text=nested(V.MAX_DEPTH))
    derived("nesting-past-bound", "anchored-range-with-one-link-bridge", "parse", "scope replaced by 2,998 nested "
            "arrays, so the body nests 3,000 deep, past the bound: refused.", "depth", text=nested(3000))

    # ---------------------------------------------------------------------------------------------- check order
    def render(st, body_fns, text_fns):
        d = digest_of(st)
        body = {"statement": st, "statementDigest": d, "signature": sign(V.signature_message_hash(d), KEY1),
                "signer": st["ledger"]}
        for f in body_fns:
            body = f(body)
        text = js_text(body)
        for f in text_fns:
            changed = f(text)
            assert changed != text
            text = changed
        return text

    def faulted(twin, faults):
        tst, topts, _ = known[twin]
        st, opts, body_fns, text_fns = copy.deepcopy(tst), dict(topts), [], []
        for kind, fn in faults:
            if kind == "statement":
                fn(st)
            elif kind == "body":
                body_fns.append(fn)
            elif kind == "text":
                text_fns.append(fn)
            else:
                opts = fn(opts)
        return render(st, body_fns, text_fns), opts

    def ordered(slug, twin, first, second):
        """A vector with two faults from adjacent reason groups; each fault alone must reject with its own reason."""
        (r1, d1, f1), (r2, d2, f2) = first, second
        assert r1 != r2
        for faults, want in (([f1], r1), ([f2], r2), ([f1, f2], r1)):
            text, opts = faulted(twin, faults)
            got = V.check(dict(opts, body_text=text))
            assert got == ("reject", want), (slug, want, got)
        text, opts = faulted(twin, [f1, f2])
        add("reject", "order-" + slug, text, opts, "Two faults: %s, which alone rejects as %s; and %s, which alone "
            "rejects as %s. The %s rule comes first in the check order and decides." % (d1, r1, d2, r2, r1),
            "check_order", twin=twin, reason=r1)

    def high_s_body(body):
        old = body["signature"]
        rr, ss, vv = old[2:66], int(old[66:130], 16), int(old[130:], 16)
        return dict(body, signature="0x" + rr + (S.N - ss).to_bytes(32, "big").hex() + bytes([55 - vv]).hex())

    def in_statement(fn):
        return ("statement", fn)

    def in_body(fn):
        return ("body", fn)

    def in_text(fn):
        return ("text", fn)

    def in_opts(fn):
        return ("opts", fn)

    token = ("parse", "attachments.version written as the token 1.0",
             in_text(lambda t: t.replace('"attachments":{"version":1,', '"attachments":{"version":1.0,', 1)))
    envelope_member = ("shape", "a fifth envelope member", in_body(lambda bd: dict(bd, x_unknown_2026=1)))
    schema_v2 = ("shape", "schema tersign-chain-statement-v2", in_statement(put(["schema"], "tersign-chain-statement-v2")))
    scope_unknown = ("scope", "scope \"x-unknown\"", in_statement(put(["scope"], "x-unknown")))
    seller_empty = ("shape", "chain.sellerId empty", in_statement(put(["chain", "sellerId"], "")))
    key_upper = ("chain_key", "chain.key in upper-case hex", in_statement(put(["chain", "key"], "0x" + "AB" * 32)))
    range_member = ("shape", "range with a third member", in_statement(put(["range", "count"], 4)))
    from_0 = ("range", "range.from 0", in_statement(put(["range", "from"], 0)))
    from_string = ("range", "range.from the string \"2\"", in_statement(put(["range", "from"], "2")))
    version_2 = ("attachments_version", "attachments.version 2", in_statement(put(["attachments", "version"], 2)))
    entries_object = ("attachment_entry", "attachments.entries an object",
                      in_statement(put(["attachments", "entries"], {})))
    binding_verified = ("attachment_entry", "the entry's binding \"verified\"",
                        in_statement(lambda st: st["attachments"]["entries"][0].update(binding="verified")))
    before_acc_upper = ("shape", "before.acc in upper-case hex",
                        in_statement(lambda st: st["before"].update(acc=upper(st["before"]["acc"]))))
    through_seq = ("consistency", "through.seq 6 where range.to is 5", in_statement(put(["through", "seq"], 6)))
    before_seq = ("consistency", "before.seq 2 where range.from is 2", in_statement(put(["before", "seq"], 2)))
    lv_member = ("shape", "linkVersions with a third member, v3", in_statement(put(["linkVersions", "v3"], 0)))
    lv_count = ("consistency", "linkVersions.v1 3 for a 4-record range, with unboundRecords 3 to match",
                in_statement(then(put(["linkVersions", "v1"], 3), put(["issuerSeq", "unboundRecords"], 3))))
    lv_count_mixed = ("consistency", "linkVersions.v2 1 on the 4-record mixed range, with absentRecords 1 to match",
                      in_statement(then(put(["linkVersions", "v2"], 1), put(["issuerSeq", "absentRecords"], 1))))
    sealed_on_v1 = ("attachment_entry", "the sealed entry moved to position 3, a v1 link",
                    in_statement(lambda st: st["attachments"]["entries"][0].update(position=3)))
    truncated_string = ("shape", "issuerSeq.truncated the string \"false\"",
                        in_statement(put(["issuerSeq", "truncated"], "false")))
    list_cap = ("consistency", "issuerSeq.listCap 255", in_statement(put(["issuerSeq", "listCap"], 255)))
    absent_0 = ("consistency", "absentRecords 0, so bound + absent differs from linkVersions.v2",
                in_statement(put(["issuerSeq", "absentRecords"], 0)))
    second_series_member = ("shape", "the second series given a sixth member", in_statement(ser(1, note="x")))
    first_series_member = ("shape", "the first series given a sixth member", in_statement(ser(0, note="x")))
    first_series_min = ("consistency", "the first series' min set to 4, above its max 3", in_statement(ser(0, min=4)))
    missing_repeat = ("consistency", "the first series' missing numbers [2, 2]", in_statement(ser(0, missing=[2, 2])))
    duplicate_member = ("shape", "the duplicate given a fourth member", in_statement(dup(note="x")))
    duplicate_one = ("consistency", "the duplicate's ledger seqs [2]", in_statement(dup(ledgerSeqs=[2])))
    status_final = ("anchor", "anchor.status \"final\"", in_statement(put(["anchor", "status"], "final")))
    signer_other = ("shape", "the envelope's signer naming the second test key",
                    in_body(lambda bd: dict(bd, signer=OTHER)))
    signer_lower = ("shape", "the envelope's signer in lower case",
                    in_body(lambda bd: dict(bd, signer=bd["signer"].lower())))
    digest_upper = ("digest", "statementDigest in upper-case hex",
                    in_body(lambda bd: dict(bd, statementDigest="0x" + bd["statementDigest"][2:].upper())))
    high_s_sig = ("signature", "the signature replaced by its high-s twin", in_body(high_s_body))
    expected_other = ("signer", "the second test key brought as the expected signer",
                      in_opts(lambda o: dict(o, expected_signer=OTHER)))
    records_swapped = ("records", "the second and third records swapped",
                       in_opts(lambda o: dict(o, records=[o["records"][i] for i in (0, 2, 1, 3)])))

    base, keyed, entry, mixed_range, report_twin, with_records = (
        "anchored-range-with-one-link-bridge", "chain-key-present", "declared-entry-before-range",
        "sealed-entry-at-first-v2-link", "issuer-numbering-report", "anchored-range-records-fold")
    ordered("parse-then-envelope-shape", base, token, envelope_member)
    ordered("statement-shape-then-scope", base, schema_v2, scope_unknown)
    ordered("scope-then-chain-shape", base, scope_unknown, seller_empty)
    ordered("chain-shape-then-chain-key", keyed, seller_empty, key_upper)
    ordered("chain-key-then-range-shape", keyed, key_upper, range_member)
    ordered("range-shape-then-range", base, range_member, from_0)
    ordered("range-then-attachments-version", base, from_string, version_2)
    ordered("attachments-version-then-attachment-entry", base, version_2, entries_object)
    ordered("attachment-entry-then-before-shape", entry, binding_verified, before_acc_upper)
    ordered("before-shape-then-consistency", base, before_acc_upper, through_seq)
    ordered("before-consistency-then-link-versions-shape", base, before_seq, lv_member)
    ordered("link-versions-shape-then-count", base, lv_member, lv_count)
    ordered("link-versions-count-then-sealed-entry", mixed_range, lv_count_mixed, sealed_on_v1)
    ordered("sealed-entry-then-issuer-seq-shape", mixed_range, sealed_on_v1, truncated_string)
    ordered("issuer-seq-shape-then-consistency", base, truncated_string, list_cap)
    ordered("issuer-counts-then-series-shape", report_twin, absent_0, second_series_member)
    ordered("series-shape-then-consistency", report_twin, first_series_member, first_series_min)
    ordered("series-consistency-then-duplicate-shape", report_twin, missing_repeat, duplicate_member)
    ordered("duplicate-shape-then-consistency", report_twin, duplicate_member, duplicate_one)
    ordered("duplicate-consistency-then-anchor", report_twin, duplicate_one, status_final)
    ordered("anchor-then-envelope-signer", base, status_final, signer_other)
    ordered("envelope-signer-then-digest", base, signer_lower, digest_upper)
    ordered("digest-then-signature", base, digest_upper, high_s_sig)
    ordered("signature-then-signer", base, high_s_sig, expected_other)
    ordered("signer-then-records", with_records, expected_other, records_swapped)

    # ---------------------------------------------------------------------------------------------- found by re-running the sweep
    valid("anchor-at-range-to-of-one-record", "A statement over seq 1..1 of the three-record chain with its anchor at "
          "seq 1 = range.to: before is the seed, the anchor commits through.head and through.acc, bridge null.",
          "anchor", B_ONE)
    derived("anchor-seq-true-at-range-to", "anchor-at-range-to-of-one-record", "anchor", "anchor.seq true, the "
            "derived members recomputed over it: a boolean is not an integer. A check that compares seq by value "
            "without its type reads true as equal to range.to (1) and accepts it.", "anchor",
            lambda st: reanchor(True, st["anchor"]["head"], st["anchor"]["acc"])(st))

    # ---------------------------------------------------------------------------------------------- clauses no vector isolated
    valid("character-outside-bmp-written-raw", "chain.sellerId ending in a character outside the Basic Multilingual "
          "Plane (U+1F600) written raw in the served text: one code point, not a surrogate, so it is well-formed and "
          "valid. The vector that writes it as a pair of escapes carries the same statement. A check that refuses "
          "every surrogate code unit of the text read as UTF-16 rejects this one.", "raw_surrogate", pair_st, X,
          text=envelope(pair_st))
    valid_from("issuer-number-0", "anchored-range-with-one-link-bridge", "The bindings of the issuer-numbering report "
               "with seq 4 binding series 0x0b.. number 0 instead of 7, so that series has min and max 0, the least "
               "the rules admit. Signed by the test key.", "issuer_seq", report("number_0"))
    derived("issuer-counts-negative", "anchored-range-with-one-link-bridge", "shape", "One logical change, a count "
            "with the count that must match it: issuerSeq.boundRecords -1 and absentRecords 1, so bound + absent still "
            "equals linkVersions.v2 (0). The counts are non-negative integers; a check that compares only the sums "
            "accepts it.", "issuer_seq",
            then(put(["issuerSeq", "boundRecords"], -1), put(["issuerSeq", "absentRecords"], 1)))
    derived("series-min-negative", "issuer-number-0", "consistency", "Series 0x0b..'s min 0 set to -1 (its max stays "
            "0): min is at least 0.", "issuer_seq", ser(1, min=-1))
    derived("missing-number-below-min", "issuer-numbering-report", "consistency", "Series 0x0a..'s missing numbers "
            "[2] replaced by [0], below its min 1.", "issuer_seq", ser(0, missing=[0]))
    derived("duplicate-ledger-seq-0", "issuer-numbering-report", "consistency", "The duplicate's ledger seqs [1, 2] "
            "replaced by [0, 2]: ledger seqs start at 1.", "issuer_seq", dup(ledgerSeqs=[0, 2]))
    derived("duplicate-ledger-seqs-descending", "issuer-numbering-report", "consistency", "The duplicate's ledger "
            "seqs [1, 2] in the order [2, 1]: they ascend (a check that refuses only a repeated seq accepts it).",
            "issuer_seq", dup(ledgerSeqs=[2, 1]))
    derived("duplicate-ledger-seqs-repeat", "issuer-numbering-report", "consistency", "The duplicate's ledger seqs "
            "[1, 2] replaced by [2, 2]: they ascend strictly.", "issuer_seq", dup(ledgerSeqs=[2, 2]))
    derived("series-id-upper-case", "issuer-numbering-report", "shape", "The second series' id replaced by 0x and 64 "
            "upper-case hex digits (0xBB..): an id is 0x + 64 lower-case hex digits. The ids still ascend as strings, "
            "so a check without the form rule accepts it.", "issuer_seq", ser(1, series="0x" + "BB" * 32))
    derived("series-ids-descending", "issuer-numbering-report", "consistency", "The two series in the order 0x0b.., "
            "0x0a..: series ids ascend (a check that refuses only a repeated id accepts it).", "issuer_seq",
            lambda st: st["issuerSeq"]["series"].reverse())
    derived("missing-numbers-descending", "issuer-numbering-corrections", "consistency", "The series' missing numbers "
            "[2, 3] in the order [3, 2]: they ascend (a check that refuses only a repeated number accepts it).",
            "issuer_seq", ser(0, missing=[3, 2]))
    derived("anchor-missing", "range-from-genesis-without-anchor", "shape", "The statement without its anchor, which "
            "is null in the twin: a member that is absent is not a member whose value is null.", "members",
            put(["anchor"], DELETE))
    derived("bridge-missing", "anchor-at-range-to", "shape", "The statement without its bridge, which is null in the "
            "twin.", "members", put(["bridge"], DELETE))
    derived("anchor-height-least-integer", "anchored-range-with-one-link-bridge", "anchor", "anchor.bitcoinBlockHeight "
            "-(2**53 - 1), the least integer the parse rule admits: it is read, and the height rule refuses it (a parse "
            "rule whose lower bound is exclusive refuses it as parse).", "parse",
            put(["anchor", "bitcoinBlockHeight"], -(2 ** 53 - 1)))
    low_text = base_text.replace('"bitcoinBlockHeight":%d,' % HEIGHT, '"bitcoinBlockHeight":-9007199254740992,', 1)
    assert low_text != base_text
    derived("anchor-height-below-least-integer", "anchored-range-with-one-link-bridge", "parse", "anchor."
            "bitcoinBlockHeight written as -9007199254740992 (-2**53), below -(2**53 - 1), with the twin's digest and "
            "signature: refused by the parse rules (a parse rule without a lower bound admits it, and the "
            "height rule then refuses it as anchor).", "parse", text=low_text)
    derived("body-an-array", "anchored-range-with-one-link-bridge", "shape", "The served body wrapped in an array: "
            "JSON text the parse rules accept, but not an object, so the envelope rule refuses it (a check that reads "
            "the parse rule as requiring an object refuses it as parse).", "envelope", text="[" + base_text + "]")
    ordered("series-consistency-then-next-series-shape", report_twin, first_series_min, second_series_member)

    # type checks: each value of another JSON type, or of the right type in another form
    derived("ledger-not-a-string", "anchored-range-with-one-link-bridge", "shape", "statement.ledger the number 7 "
            "(and the envelope's signer with it).", "members", put(["ledger"], 7))
    derived("chain-null", "anchored-range-with-one-link-bridge", "shape", "chain null.", "chain", put(["chain"], None))
    derived("before-seq-string", "anchored-range-with-one-link-bridge", "shape", "before.seq as the string \"1\".",
            "before_through", put(["before", "seq"], "1"))
    derived("through-seq-string", "anchored-range-with-one-link-bridge", "shape", "through.seq as the string \"5\".",
            "before_through", put(["through", "seq"], "5"))
    derived("through-acc-upper-case", "anchored-range-with-one-link-bridge", "shape", "through.acc in upper-case hex: "
            "the same bytes, refused by form (a check without the form rule folds the bridge link from it and accepts "
            "it).", "before_through", lambda st: st["through"].update(acc=upper(st["through"]["acc"])))
    derived("link-versions-v1-string", "anchored-range-with-one-link-bridge", "shape", "linkVersions.v1 as the string "
            "\"4\".", "link_versions", put(["linkVersions", "v1"], "4"))
    derived("link-versions-v2-string", "anchored-range-with-one-link-bridge", "shape", "linkVersions.v2 as the string "
            "\"0\".", "link_versions", put(["linkVersions", "v2"], "0"))
    derived("link-versions-v1-negative", "anchored-range-with-one-link-bridge", "shape", "linkVersions.v1 -1.",
            "link_versions", put(["linkVersions", "v1"], -1))
    derived("link-versions-v2-negative", "anchored-range-with-one-link-bridge", "shape", "linkVersions.v2 -1.",
            "link_versions", put(["linkVersions", "v2"], -1))
    derived("issuer-series-object", "anchored-range-with-one-link-bridge", "shape", "issuerSeq.series an object, not "
            "an array.", "issuer_seq", put(["issuerSeq", "series"], {}))
    derived("series-min-string", "issuer-numbering-report", "shape", "Series 0x0b..'s min as the string \"7\".",
            "issuer_seq", ser(1, min="7"))
    derived("series-max-string", "issuer-numbering-report", "shape", "Series 0x0b..'s max as the string \"7\".",
            "issuer_seq", ser(1, max="7"))
    derived("series-missing-object", "issuer-numbering-report", "shape", "Series 0x0a..'s missing numbers an object, "
            "not an array.", "issuer_seq", ser(0, missing={}))
    derived("series-duplicates-object", "issuer-numbering-report", "shape", "Series 0x0a..'s duplicates an object, not "
            "an array.", "issuer_seq", ser(0, duplicates={}))
    derived("missing-number-string", "issuer-numbering-report", "consistency", "Series 0x0a..'s missing number 2 as the "
            "string \"2\".", "issuer_seq", ser(0, missing=["2"]))
    derived("duplicate-seq-string", "issuer-numbering-report", "shape", "The duplicate's seq as the string \"1\".",
            "issuer_seq", dup(seq="1"))
    derived("duplicate-ledger-seqs-object", "issuer-numbering-report", "shape", "The duplicate's ledger seqs an "
            "object, not an array.", "issuer_seq", dup(ledgerSeqs={}))
    derived("anchor-proof-url-not-a-string", "anchored-range-with-one-link-bridge", "anchor", "anchor.proofUrl the "
            "number 7.", "anchor", put(["anchor", "proofUrl"], 7))
    derived("bridge-links-object", "anchored-range-with-one-link-bridge", "anchor", "bridge.links an object whose one "
            "member name is the bridge link, not an array (a check that iterates it without the type rule folds the "
            "member name and accepts it).", "bridge",
            lambda st: st["bridge"].update(links={st["bridge"]["links"][0]: 1}))
    derived("range-to-string", "anchored-range-with-one-link-bridge", "range", "range.to as the string \"5\".",
            "range", put(["range", "to"], "5"))
    for member, value in (("boundRecords", "0"), ("unboundRecords", "4"), ("absentRecords", "0"), ("listCap", "256")):
        derived("issuer-%s-string" % "".join("-" + c.lower() if c.isupper() else c for c in member),
                "anchored-range-with-one-link-bridge", "shape", "issuerSeq.%s as the string \"%s\"." % (member, value),
                "issuer_seq", put(["issuerSeq", member], value))
    derived("duplicate-correction-seq-string", "issuer-numbering-corrections", "shape", "The first duplicate's "
            "correctionSeq 0 as the string \"0\".", "issuer_seq", dup(correctionSeq="0"))
    derived("duplicate-ledger-seq-string", "issuer-numbering-report", "consistency", "The duplicate's ledger seqs [1, 2] "
            "with the first as the string \"1\".", "issuer_seq", dup(ledgerSeqs=["1", 2]))

    # member names and JSON syntax
    derived("lone-surrogate-in-member-name", "anchored-range-with-one-link-bridge", "parse", "chain's member name "
            "sellerId with a high surrogate escape and no low half appended: a member name is a string and is "
            "well-formed Unicode too (sn118 and sn119 carry their lone surrogates in values). A check that tests only "
            "values reads the name and refuses the statement as shape, for the member it does not define.", "parse",
            lambda st: st.update(chain={"sellerId\ud800": st["chain"]["sellerId"]}))
    derived("body-not-json-text", "anchored-range-with-one-link-bridge", "parse", "The served text with its final "
            "closing brace removed: not JSON text. A check that reads a syntax error as a fault of shape refuses it as "
            "shape.", "parse", text=base_text[:-1])
    derived("lone-surrogate-in-bridge-link", "anchored-range-with-one-link-bridge", "parse", "The bridge link with a "
            "low surrogate escape appended: a string inside an array is read too (a check that does not descend into "
            "arrays refuses the link as anchor, by its form).", "parse",
            lambda st: st["bridge"]["links"].__setitem__(0, st["bridge"]["links"][0] + "\udc00"))
    derived("lone-surrogate-in-envelope-signer", "anchored-range-with-one-link-bridge", "parse", "The envelope's "
            "signer with a low surrogate escape appended, with the twin's digest and signature: the parse rules cover "
            "the whole body, not only the statement (a check that tests only the statement refuses it as shape, for "
            "the signer that is not the ledger).", "parse",
            text=js_text({**genuine, "signer": genuine["signer"] + "\udc00"}))

    # the remaining type and records checks
    derived("entry-type-array", "declared-entry-before-range", "attachment_entry", "The entry's type the array "
            "[\"example-type\"], not a string (a check that tests its pattern on the array's text form, as a "
            "JavaScript RegExp does, accepts it).", "entry_type", typed(["example-type"]))
    derived("signature-not-a-string", "anchored-range-with-one-link-bridge", "signature", "The envelope's signature "
            "the number 7, with the twin's digest.", "signature", text=js_text({**genuine, "signature": 7}))
    derived("records-last-not-through-head", "anchored-range-records-fold", "records", "through.head replaced by "
            "another digest and the statement signed again, with the relying party's records: they fold to "
            "through.acc, but the last of them is not through.head (a check that compares only the fold accepts "
            "it).", "records", put(["through", "head"], "0x" + "99" * 32))

    # ---------------------------------------------------------------------------------------------- the report's definition
    valid_from("issuer-numbering-duplicates-in-two-series", "anchored-range-with-one-link-bridge", "A v2 "
               "issuer-numbering report over seq 2..5 with a duplicate in each of two series, computed from these link "
               "bindings: seq 1 and 2 both bind series 0x0a.. number 1, seq 3 and 4 both bind series 0x0b.. number 7, "
               "and seq 5 is a v2 link that binds no number. So three bound records and one absent; series 0x0a.. has "
               "min and max 1 and number 1 named by ledger seqs 1 and 2; series 0x0b.. has min and max 7 and number 7 "
               "named by ledger seqs 3 and 4. No ledger seq is in two duplicates. Signed by the test key.",
               "issuer_report", report("two_series_duplicates"))
    valid_from("issuer-numbering-one-series-per-bound-record", "anchored-range-with-one-link-bridge", "A v2 "
               "issuer-numbering report over seq 2..5 with as many series as bound records, computed from these link "
               "bindings: seq 1 is a v1 link, seq 2 binds series 0x0a.. number 1, seq 3 binds series 0x0b.. number 7, "
               "and seq 4 and 5 are v2 links that bind no number. So two bound records, two absent and two series, each "
               "with min and max equal, nothing missing and no duplicate. Signed by the test key.", "issuer_report",
               report("series_per_record"))

    def dup_at(i, **kv):
        return lambda st: st["issuerSeq"]["series"][0]["duplicates"][i].update(kv)

    derived("duplicate-seq-above-max", "issuer-numbering-corrections", "consistency", "The second duplicate's number 3, "
            "the series' max, replaced by 4, above max 3: one of a duplicate's bindings is in the range, over which "
            "min and max are taken.", "issuer_report", dup_at(1, seq=4))
    derived("duplicate-seq-below-min", "issuer-numbering-corrections", "consistency", "The first duplicate's number 2, "
            "the series' min, replaced by 1, below min 2.", "issuer_report", dup_at(0, seq=1))
    derived("duplicate-original-of-missing-number", "issuer-numbering-corrections", "consistency", "The first "
            "duplicate's correctionSeq 0 replaced by null, so it names original bindings of number 2, which the series "
            "lists as missing: an original binding makes its number present.", "issuer_report",
            dup_at(0, correctionSeq=None))
    derived("ledger-seq-in-two-duplicates-of-one-series", "issuer-numbering-corrections", "consistency", "The second "
            "duplicate's ledger seqs [4, 5] replaced by [3, 5]: ledger seq 3 is also in the first duplicate, [2, 3], "
            "and a record binds one (series, seq, correctionSeq).", "issuer_report", dup_at(1, ledgerSeqs=[3, 5]))
    derived("ledger-seq-in-duplicates-of-two-series", "issuer-numbering-duplicates-in-two-series", "consistency",
            "Series 0x0b..'s duplicate ledger seqs [3, 4] replaced by [2, 4]: ledger seq 2 is also in series 0x0a..'s "
            "duplicate, [1, 2], and a record binds one series (a check that compares ledger seqs only within one "
            "series accepts it).", "issuer_report",
            lambda st: st["issuerSeq"]["series"][1]["duplicates"][0].update(ledgerSeqs=[2, 4]))
    two_series_one_bound = then(put(["issuerSeq", "boundRecords"], 1), put(["issuerSeq", "absentRecords"], 3))
    derived("more-series-than-bound-records", "issuer-numbering-one-series-per-bound-record", "consistency", "One "
            "logical change, a count with the count that must match it: boundRecords 1 and absentRecords 3, so bound + "
            "absent still equals linkVersions.v2 (4), under two series: a series is reported only when a bound record "
            "in the range names it.", "issuer_report", two_series_one_bound)
    ordered("series-count-then-series-shape", "issuer-numbering-one-series-per-bound-record",
            ("consistency", "boundRecords 1 and absentRecords 3, so two series over one bound record",
             in_statement(two_series_one_bound)), second_series_member)
    derived("byte-order-mark-before-body", "anchored-range-with-one-link-bridge", "parse", "The served text with a "
            "byte-order mark (U+FEFF) before it, with the twin's digest and signature (a reader that strips the mark "
            "accepts it).", "byte_order_mark", text=chr(0xFEFF) + base_text)

    write(acc_rows, rej_rows)
    return verify_written()


DELETE = object()


def _cap_bridge(st):
    to = st["range"]["to"]
    links = ["0x" + keccak256(("statement-profile bridge link %d" % i).encode()).hex() for i in range(1, V.BRIDGE_CAP + 1)]
    acc = st["through"]["acc"]
    for link in links:
        acc = chain_acc_step(acc, link)
    head = "0x" + keccak256(b"statement-profile bridge head").hex()
    new = anchor_at(to + V.BRIDGE_CAP, head, acc)
    st["anchor"] = new
    st["bridge"] = {"from": to + 1, "to": to + V.BRIDGE_CAP, "links": links}


def write(acc_rows, rej_rows):
    ids = {}
    for prefix, rows in (("sp", acc_rows), ("sn", rej_rows)):
        for i, row in enumerate(rows, 1):
            assert row["slug"] not in ids, row["slug"]
            ids[row["slug"]] = "%s%d-%s" % (prefix, i, row["slug"])
    out = os.path.join(HERE, "vectors")
    os.makedirs(out, exist_ok=True)
    for f in os.listdir(out):
        os.remove(os.path.join(out, f))
    entries = []
    for row in acc_rows + rej_rows:
        vid = ids[row["slug"]]
        v = {"id": vid, "kind": V.KIND, "expect": "reject" if row["reason"] else "valid"}
        if row["reason"]:
            v["reject_reason"] = row["reason"]
            v["twin"] = ids[row["twin"]]
        desc = row["description"]
        if row["twin"]:
            desc += " Accepting twin: %s." % ids[row["twin"]].split("-")[0]
        v["description"] = desc + " Rests on rules.%s (%s) in statement/MANIFEST.json." % (row["rule"],
                                                                                         RULES[row["rule"]][0])
        v["input"] = row["input"]
        with open(os.path.join(out, vid + ".json"), "w", encoding="utf-8") as fh:
            fh.write(json.dumps(v, indent=2) + "\n")
        e = {"file": vid + ".json", "kind": V.KIND, "expect": v["expect"]}
        if row["reason"]:
            e["reason"] = row["reason"]
            e["twin"] = v["twin"]
        e["author"] = AUTHOR
        e["origin"] = {"class": "synthetic", "source": "statement/gen_statement_vectors.py: synthetic chains, signed by "
                                                       "the published test keys"}
        entries.append(e)
    man = {
        "version": VERSION,
        "profile": "chain statement (tersign-chain-statement-v1)",
        "runner": "statement/verify_statement.py",
        "second_engine": "tools/cross_check_statement.mjs",
        "differential": "tools/differential_statement.py",
        "generator": "statement/gen_statement_vectors.py",
        "licence": "Apache-2.0, as the repository (LICENSE)",
        "format": V.PINNED,
        "rules": {k: {"source": src, "rule": text} for k, (src, text) in RULES.items()},
        "reject_reasons": list(V.REJECT_REASONS),
        "test_key_address": LEDGER,
        "test_key_derivation": KEY1_DERIVATION + " (the counter-signature profile's test key, crypto/MANIFEST.json)",
        "second_test_key_address": OTHER,
        "second_test_key_derivation": KEY2_DERIVATION,
        "test_nonce_derivation": NONCE_DERIVATION,
        "vector_provenance": "every entry names author and origin = {class, source}, origin.class from the core's "
                             "closed set; every vector here is synthetic. No vector carries a record, key or anchor of "
                             "a live ledger, and proofUrl values use the reserved host ledger.example.",
        "vectors": entries,
    }
    with open(os.path.join(HERE, "MANIFEST.json"), "w", encoding="utf-8") as fh:
        fh.write(json.dumps(man, indent=1, ensure_ascii=False) + "\n")


def verify_written():
    vecs, problems = V.load_set()
    for p in problems:
        print("SET  ", p)
    bad = len(problems)
    for vid in sorted(vecs, key=V._order):
        v = vecs[vid]
        got = V.check(v["input"])
        ok = got == (v["expect"], v.get("reject_reason"))
        bad += not ok
        if not ok:
            print("FAIL", vid, got)
    print("wrote %d chain-statement vectors + statement/MANIFEST.json; %d disagree with the runner"
          % (len(vecs), bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
