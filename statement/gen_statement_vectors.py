#!/usr/bin/env python3
"""Generates every chain-statement vector (statement/vectors/) and statement/MANIFEST.json, byte for byte. Stdlib only.
    python3 statement/gen_statement_vectors.py      (CI regenerates and requires byte-identical output)

Material: two synthetic chains whose record digests are keccak256 of fixed labels, statements built from them member by
member in the order a ledger serves them, and signatures by two published test keys with a nonce derived per signature,
all in this file. No vector carries a record, a key or an anchor of any live ledger, so no vector says anything about a
live ledger's key: a valid verdict here establishes only that the published test key signed the bytes.

Every rejecting vector is built from an accepting vector of this set, its twin, by one change; where the change is to
the statement, the twin's key signs the changed statement again, so the digest and signature checks cannot be what
rejects it (the digest, signature and signer vectors exist to test those)."""
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

# Rules each vector rests on, labelled as the format's own (the rules a ledger serving this format applies before it
# signs) or as this suite's. The runner pins the constants under "format"; these texts say what the vectors test.
RULES = {
    "parse": ("format", "The served body is one JSON object; no object carries a member name twice; every number token "
              "is an integer in [-(2**53 - 1), 2**53 - 1] (a fraction or exponent token is not, even when its value is "
              "an integer); every string, member names included, is well-formed Unicode (a surrogate that is not half of "
              "a pair has no UTF-8 form). Otherwise parse."),
    "envelope": ("format", "The body is exactly {statement, statementDigest, signature, signer}, and signer equals "
                 "statement.ledger byte for byte. Otherwise shape."),
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
    "before_through": ("format", "before is {seq, head, acc} with head null or 0x + 64 lower-case hex; through is "
                       "{seq, head, acc} with both digests 0x + 64 lower-case hex (shape). before.seq = range.from - 1; "
                       "before.head is null exactly when before.seq is 0; at seq 0, before.acc is the commitment seed "
                       "keccak256(utf8(\"tersign-chain-commitment-v1\")); through.seq = range.to (consistency)."),
    "link_versions": ("format", "linkVersions is exactly {v1, v2} of non-negative integers (shape), and v1 + v2 counts "
                      "every record of the range (consistency)."),
    "issuer_seq": ("format", "issuerSeq is exactly {boundRecords, unboundRecords, absentRecords, listCap, series, "
                   "truncated}: non-negative integers, a boolean and an array (shape). listCap is format.list_cap; "
                   "unboundRecords = linkVersions.v1 and boundRecords + absentRecords = linkVersions.v2; with no bound "
                   "record there is no series; series, each series' missing numbers and its duplicates are each at "
                   "most listCap long; series ids ascend strictly and 0 <= min <= max; missing numbers ascend strictly "
                   "within [min, max]; a duplicate names at least two ledger seqs, ascending, each from 1 to range.to "
                   "(consistency). A series is exactly {series, min, max, missing, duplicates} and a duplicate exactly "
                   "{seq, correctionSeq, ledgerSeqs}, correctionSeq null or a non-negative integer (shape)."),
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
                    "expected signer, records). Every vector here breaks one rule, except where its description names "
                    "a second, and expects the reason of the first in this order."),
    "input": ("suite", "A vector's input is {body_text, expected_signer?, records?}: the served body as text, and the "
              "two values a relying party may bring from elsewhere, read by key presence."),
    "twin": ("suite", "Every rejecting vector names an accepting vector of this set, its twin, from which it differs by "
             "one change; the runner fails a set where a twin is missing or not valid."),
}


def main():
    a, b = Chain("a", 6), Chain("b", 3)
    A = build(a, "chain-a", 2, 5, anchor_seq=6)
    A_REC = a.digests[2:6]
    A_AT = build(a, "chain-a", 2, 6, anchor_seq=6)
    B = build(b, "chain-b", 1, 3)
    B_REC = b.digests[1:4]
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

    def v2report(st):
        st["linkVersions"] = {"v1": 0, "v2": 4}
        st["issuerSeq"].update({"boundRecords": 3, "unboundRecords": 0, "absentRecords": 1, "series": [
            {"series": SER1, "min": 1, "max": 5, "missing": [3], "duplicates": [{"seq": 2, "correctionSeq": None,
                                                                                 "ledgerSeqs": [2, 3]}]},
            {"series": SER2, "min": 7, "max": 7, "missing": [], "duplicates": []}]})

    def then(*fns):
        def fn(st):
            for f in fns:
                f(st)
        return fn

    def mixed(position):
        def fn(st):
            st["linkVersions"] = {"v1": 2, "v2": 2}
            st["issuerSeq"].update({"boundRecords": 0, "unboundRecords": 2, "absentRecords": 2, "series": []})
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
               "range whose links are all v2 (linkVersions {v1: 0, v2: 4}, an issuer-numbering report consistent with "
               "it). Hand-built and signed by the test key.", "sealed",
               then(v2report, entries([{"position": 3, "type": "example-type", "binding": "sealed"}])))
    valid_from("sealed-entry-at-first-v2-link", "anchored-range-with-one-link-bridge", "A mixed range 2..5 with "
               "{v1: 2, v2: 2}: the first v2 link is at range.from + v1 = 4, and a sealed entry at 4 accepts.",
               "sealed", mixed(4))
    valid_from("sealed-entry-before-range-when-v1-is-zero", "anchored-range-with-one-link-bridge", "A sealed entry at "
               "position 1, before range.from, on a range with linkVersions.v1 = 0: the statement says nothing about "
               "links before range.from, so the position is not checked.", "sealed",
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
    derived("entry-positions-repeat", "two-declared-entries", "attachment_entry", "Two entries at position 4: "
            "positions ascend strictly.", "entries", entries([E2, {**E1, "position": 4}]))
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
    valid_from("issuer-numbering-report", "anchored-range-with-one-link-bridge", "A v2 issuer-numbering report: "
               "linkVersions {v1: 0, v2: 4}, three bound records and one absent, two series, one gap and one duplicate. "
               "Hand-built and signed by the test key.", "issuer_seq", v2report)

    def v2with(fn):
        return then(v2report, fn)

    def ser(i, **kv):
        return lambda st: st["issuerSeq"]["series"][i].update(kv)

    derived("series-without-bound-record", "anchored-range-with-one-link-bridge", "consistency", "A series on a "
            "statement with no bound record.", "issuer_seq", put(["issuerSeq", "series"],
                                                                 [{"series": SER1, "min": 1, "max": 1, "missing": [],
                                                                   "duplicates": []}]))
    derived("missing-number-outside-min-max", "issuer-numbering-report", "consistency", "A missing number 6 in a "
            "series whose max is 5.", "issuer_seq", v2with(ser(0, missing=[6])))
    derived("missing-numbers-repeat", "issuer-numbering-report", "consistency", "Missing numbers 3, 3.",
            "issuer_seq", v2with(ser(0, missing=[3, 3])))
    derived("series-ids-repeat", "issuer-numbering-report", "consistency", "Two series with one id.", "issuer_seq",
            v2with(ser(1, series=SER1)))
    derived("series-min-above-max", "issuer-numbering-report", "consistency", "A series with min 8 and max 7.",
            "issuer_seq", v2with(ser(1, min=8)))

    def dup(**kv):
        return lambda st: st["issuerSeq"]["series"][0]["duplicates"][0].update(kv)

    derived("duplicate-one-ledger-seq", "issuer-numbering-report", "consistency", "A duplicate naming one ledger seq.",
            "issuer_seq", v2with(dup(ledgerSeqs=[2])))
    derived("duplicate-ledger-seq-after-range", "issuer-numbering-report", "consistency", "A duplicate naming ledger "
            "seq 6, after range.to (5).", "issuer_seq", v2with(dup(ledgerSeqs=[2, 6])))
    derived("duplicate-correction-seq-negative", "issuer-numbering-report", "shape", "A duplicate with correctionSeq "
            "-1.", "issuer_seq", v2with(dup(correctionSeq=-1)))
    derived("issuer-bound-plus-absent-miscount", "issuer-numbering-report", "consistency", "absentRecords 0, so bound "
            "+ absent (3) differs from linkVersions.v2 (4).", "issuer_seq",
            v2with(put(["issuerSeq", "absentRecords"], 0)))
    derived("series-unknown-member", "issuer-numbering-report", "shape", "A series with a sixth member, note.",
            "issuer_seq", v2with(ser(1, note="x")))
    derived("list-cap-255", "anchored-range-with-one-link-bridge", "consistency", "issuerSeq.listCap 255.",
            "issuer_seq", put(["issuerSeq", "listCap"], 255))
    derived("list-cap-257", "anchored-range-with-one-link-bridge", "consistency", "issuerSeq.listCap 257.",
            "issuer_seq", put(["issuerSeq", "listCap"], 257))
    derived("truncated-string", "anchored-range-with-one-link-bridge", "shape", "issuerSeq.truncated the string "
            "\"false\".", "issuer_seq", put(["issuerSeq", "truncated"], "false"))

    def n_series(n):
        return v2with(put(["issuerSeq", "series"], [{"series": hex32(i + 1), "min": 1, "max": 1, "missing": [],
                                                     "duplicates": []} for i in range(n)]))

    def n_missing(n):
        return v2with(ser(0, max=1000, missing=list(range(1, n + 1))))

    def n_duplicates(n):
        return v2with(ser(0, duplicates=[{"seq": i + 1, "correctionSeq": None, "ledgerSeqs": [2, 3]}
                                         for i in range(n)]))

    valid_from("series-at-list-cap", "anchored-range-with-one-link-bridge", "256 series, the list cap.", "issuer_seq",
               n_series(256))
    derived("series-over-list-cap", "series-at-list-cap", "consistency", "257 series.", "issuer_seq", n_series(257))
    valid_from("missing-at-list-cap", "anchored-range-with-one-link-bridge", "256 missing numbers in one series.",
               "issuer_seq", n_missing(256))
    derived("missing-over-list-cap", "missing-at-list-cap", "consistency", "257 missing numbers in one series.",
            "issuer_seq", n_missing(257))
    valid_from("duplicates-at-list-cap", "anchored-range-with-one-link-bridge", "256 duplicates in one series.",
               "issuer_seq", n_duplicates(256))
    derived("duplicates-over-list-cap", "duplicates-at-list-cap", "consistency", "257 duplicates in one series.",
            "issuer_seq", n_duplicates(257))

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
