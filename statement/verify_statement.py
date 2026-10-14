#!/usr/bin/env python3
"""Chain-statement profile (tersign-chain-statement-v1). Stdlib only: the suite's keccak.py, the core's canonical form
(verify.py `canonical`, the form digest_recompute pins) and the counter-signature profile's secp256k1 recovery.

A chain statement is a ledger-signed object over one range of one record chain. A vector's input is the statement as
served, as TEXT, plus what a relying party may bring from elsewhere:

    {"body_text": "<the served body>", "expected_signer": "0x...", "records": ["0x...", ...]}

`expected_signer` (the ledger key obtained out of band) and `records` (the artifact digests of the range, in ledger
order) are optional and read by key presence. The check, in this order; the first rule broken decides the reason:

  1 parse              one JSON object; no member name twice in any object; every number token an integer in
                       [-(2**53 - 1), 2**53 - 1]; every string, member names included, well-formed Unicode
  2 shape              the body is exactly {statement, statementDigest, signature, signer}
  3 statement rules    the closed sets and consistency rules over `statement` (statement_refusal below), with the
                       reasons shape, scope, chain_key, range, attachments_version, attachment_entry, consistency
                       and anchor
  4 shape              `signer` equals `statement.ledger`, byte for byte
  5 digest             statementDigest = keccak256 over the UTF-8 bytes of canonical(statement)
  6 signature          the one accepted encoding (0x + 130 hex digits, v 27 or 28, s <= n/2, 1 <= r < n, s >= 1),
                       then personal_sign recovery over the UTF-8 string "tersign-chain-statement-v1:" +
                       statementDigest equals statement.ledger, compared case-insensitively
  7 signer             with expected_signer: it equals statement.ledger, compared case-insensitively
  8 records            with records: one 0x + 64 lower-case hex digest per record of the range, folding from
                       `before` to `through`

A valid verdict opens no attachment entry and checks no time-stamp proof (README, Chain statements).

    python3 statement/verify_statement.py            # every vector in statement/MANIFEST.json
    python3 statement/verify_statement.py --mutants  # each one-site broken verifier must fail its named vector
"""
import glob
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "crypto"))
from keccak import keccak256  # noqa: E402
from verify import canonical, chain_link_digest, chain_acc_step, ACC_GENESIS  # noqa: E402
import secp256k1_recover as S  # noqa: E402

SCHEMA = "tersign-chain-statement-v1"
COMMITMENT_SCHEMA = "tersign-chain-commitment-v1"
SIGNATURE_PREFIX = SCHEMA + ":"
LIMITS = (
    "This statement covers only records counter-signed on this chain at ledger seq from..to, and the attachment "
    "entries it lists. Records never submitted to this ledger are outside it, and nothing here says the issuer issued "
    "no other records. An attachment entry names the position of a record on this chain at or before seq to; Tersign "
    "lists entries and does not verify them. Binding declared: the attachment is the record at that position, bound by "
    "the counter-signed link at that position. Binding sealed: the attachment is sealed inside the v2 chain link at "
    "that position. Issuer-sequence gaps and duplicates are reported only for records whose counter-signed link binds "
    "the issuer seq, only between the lowest and highest such seq in the range, and only against records "
    "counter-signed at or before seq to; an omission after the highest bound seq is not detectable. It restates the "
    "ledger's contemporaneous counter-signatures and the anchor named, and its own signature adds no earlier time. It "
    "is not a statement about record content, tax treatment or compliance with any law."
)
SCOPES = ("range",)
ATTACHMENTS_VERSION = 1
BINDINGS = ("declared", "sealed")
ANCHOR_STATUSES = ("pending", "confirmed")
MAX_RANGE = 5000
LIST_CAP = 256
BRIDGE_CAP = 1000
TYPE_HEX_DIGITS = 32
SAFE = 2 ** 53 - 1
ZERO32 = "0x" + "00" * 32
REJECT_REASONS = ("parse", "shape", "scope", "attachments_version", "attachment_entry", "range", "chain_key",
                  "consistency", "anchor", "digest", "signature", "signer", "records")
ENVELOPE = ("statement", "statementDigest", "signature", "signer")
MEMBERS = ("anchor", "attachments", "before", "bridge", "chain", "commitmentSchema", "issuerSeq", "ledger", "limits",
           "linkVersions", "range", "schema", "scope", "through")
ANCHOR_MEMBERS = ("acc", "anchoredDigest", "batchRoot", "bitcoinBlockHeight", "head", "id", "proofUrl", "seq", "status",
                  "subjectDigest", "subjectSchema")
ISSUER_COUNTS = ("boundRecords", "unboundRecords", "absentRecords", "listCap")
INPUT_KEYS = ("body_text", "expected_signer", "records")

HEX32_RE = re.compile(r"0x[0-9a-f]{64}")
ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
SIGNATURE_RE = re.compile(r"0x[0-9a-fA-F]{130}")
TYPE_RE = re.compile(r"[a-z][a-z0-9-]{0,62}[a-z0-9]")
HEXLIKE_TYPE_RE = re.compile(r"[0-9a-f-]+")


class Reject(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _int(v, mut=None):
    if mut == "bool_as_int" and type(v) is bool:
        return True
    return type(v) is int and -SAFE <= v <= SAFE


def _hex32(v):
    return isinstance(v, str) and HEX32_RE.fullmatch(v) is not None


def _exactly(o, members, mut=None):
    if not isinstance(o, dict):
        return False
    if mut == "extra_members_ignored":
        return set(members) <= set(o)
    return sorted(o) == sorted(members)


def _ill_formed(v):
    """True when a string in v, member names included, holds a surrogate that is not half of a pair (it has no UTF-8
    form, so the statement has no canonical bytes)."""
    if isinstance(v, str):
        try:
            v.encode("utf-8")
        except UnicodeEncodeError:
            return True
        return False
    if isinstance(v, list):
        return any(_ill_formed(x) for x in v)
    if isinstance(v, dict):
        return any(_ill_formed(k) or _ill_formed(x) for k, x in v.items())
    return False


def type_ok(t, mut=None):
    """2-64 characters: a lower-case letter, then lower-case letters, digits and hyphens, ending in a letter or digit;
    and not a type made only of hex digits and hyphens that holds 32 or more hex digits."""
    if not isinstance(t, str) or TYPE_RE.fullmatch(t) is None:
        return False
    if mut == "type_hex_rule_counts_characters":
        return not (HEXLIKE_TYPE_RE.fullmatch(t) is not None and len(t) >= TYPE_HEX_DIGITS)
    if mut == "type_hex_rule_any_run":
        return re.search(r"[0-9a-f]{%d}" % TYPE_HEX_DIGITS, t) is None
    return not (HEXLIKE_TYPE_RE.fullmatch(t) is not None and len(t.replace("-", "")) >= TYPE_HEX_DIGITS)


def parse(text, mut=None):
    def no_float(tok):
        if mut == "float_token_as_int" and float(tok).is_integer():
            return int(float(tok))
        raise Reject("parse")

    def bounded(tok):
        v = int(tok)
        if mut != "no_integer_bound" and not -SAFE <= v <= SAFE:
            raise Reject("parse")
        return v

    def pairs(ps):
        out = {}
        for k, v in ps:
            if k in out and mut != "duplicate_last_wins":
                raise Reject("parse")
            out[k] = v
        return out

    def constant(tok):
        raise Reject("parse")

    if not isinstance(text, str):
        raise Reject("parse")
    try:
        body = json.loads(text, object_pairs_hook=pairs, parse_float=no_float, parse_int=bounded,
                          parse_constant=constant)
    except Reject:
        raise
    except (ValueError, TypeError, RecursionError):
        raise Reject("parse") from None
    try:
        ill = _ill_formed(body)
    except RecursionError:
        raise Reject("parse") from None
    if ill and mut != "lone_surrogate_accepted":
        raise Reject("parse")
    return body


def statement_refusal(st, mut=None):
    """None, or the reason of the FIRST rule `st` breaks, in the order of the rules below."""
    if _ill_formed(st) and mut != "lone_surrogate_accepted":
        return "parse"
    if not _exactly(st, MEMBERS, mut if mut == "extra_members_ignored" else None):
        return "shape"
    if st["schema"] != SCHEMA:
        return "shape"
    if st["limits"] != LIMITS and mut != "limits_not_compared":
        return "shape"
    if st["commitmentSchema"] != COMMITMENT_SCHEMA:
        return "shape"
    if not isinstance(st["ledger"], str) or ADDRESS_RE.fullmatch(st["ledger"]) is None:
        return "shape"
    scope = st["scope"]
    if mut == "scope_case_folded" and isinstance(scope, str):
        scope = scope.lower()
    if not (isinstance(scope, str) and scope in SCOPES) and mut != "scope_unchecked":
        return "scope"

    chain = st["chain"]
    if not isinstance(chain, dict) or "sellerId" not in chain or not set(chain) <= {"sellerId", "key"}:
        return "shape"
    if not isinstance(chain["sellerId"], str) or chain["sellerId"] == "":
        return "shape"
    if "key" in chain:
        key = chain["key"]
        if mut == "chain_key_null_as_absent" and key is None:
            pass
        elif mut == "chain_key_case_folded" and isinstance(key, str) and _hex32(key.lower()) and key.lower() != ZERO32:
            pass
        elif not _hex32(key) or (key == ZERO32 and mut != "chain_key_zero_allowed"):
            return "chain_key"

    rng = st["range"]
    if not _exactly(rng, ("from", "to")):
        return "shape"
    frm, to = rng["from"], rng["to"]
    if not (_int(frm) and _int(to)) or frm < 1 or frm > to:
        return "range"
    cap = {"range_cap_4999": 4999, "range_uncapped": float("inf")}.get(mut, MAX_RANGE)
    if to - frm + 1 > cap:
        return "range"
    count = to - frm + 1

    att = st["attachments"]
    if not _exactly(att, ("version", "entries")):
        return "attachments_version"
    version = att["version"]
    if mut == "attachments_version_string" and version == "1":
        version = 1
    if not (_int(version, mut) and version == ATTACHMENTS_VERSION):
        return "attachments_version"
    if not isinstance(att["entries"], list):
        return "attachment_entry"
    last = 0
    for e in att["entries"]:
        if not _exactly(e, ("position", "type", "binding"), mut if mut == "extra_members_ignored" else None):
            if mut != "entry_members_open" or not (isinstance(e, dict) and {"position", "type", "binding"} <= set(e)):
                return "attachment_entry"
        pos = e["position"]
        lower = (frm if mut == "position_from_range_from" else 1)
        if not _int(pos) or pos < lower or (pos < last if mut == "positions_non_strict" else pos <= last) or pos > to:
            return "attachment_entry"
        last = pos
        if not type_ok(e["type"], mut):
            return "attachment_entry"
        binding = e["binding"]
        if mut == "binding_case_folded" and isinstance(binding, str):
            binding = binding.lower()
        if not (isinstance(binding, str) and (binding in BINDINGS or mut == "binding_open")):
            return "attachment_entry"

    before, through = st["before"], st["through"]
    head = before.get("head") if isinstance(before, dict) else None
    if mut == "before_head_case_folded" and isinstance(head, str):
        head = head.lower()
    if not (_exactly(before, ("seq", "head", "acc")) and _int(before["seq"]) and _hex32(before["acc"])
            and (head is None or _hex32(head))):
        return "shape"
    if not (_exactly(through, ("seq", "head", "acc")) and _int(through["seq"]) and _hex32(through["acc"])
            and _hex32(through["head"])):
        return "shape"
    if before["seq"] != frm - 1 and mut != "before_seq_unchecked":
        return "consistency"
    if (before["seq"] == 0) != (before["head"] is None):
        return "consistency"
    if before["seq"] == 0 and before["acc"] != ACC_GENESIS and mut != "seed_unchecked":
        return "consistency"
    if through["seq"] != to:
        return "consistency"

    lv = st["linkVersions"]
    if not (_exactly(lv, ("v1", "v2"), mut if mut == "extra_members_ignored" else None) and _int(lv["v1"])
            and _int(lv["v2"]) and lv["v1"] >= 0 and lv["v2"] >= 0):
        return "shape"
    if lv["v1"] + lv["v2"] != count and mut != "link_versions_uncounted":
        return "consistency"
    first_v2 = frm + lv["v1"]
    if mut != "sealed_unchecked" and lv["v1"] > 0:
        for e in att["entries"]:
            if e["binding"] != "sealed":
                continue
            if mut == "sealed_checked_only_from_range_from" and e["position"] < frm:
                continue
            if mut == "sealed_checked_only_without_v2" and lv["v2"] > 0:
                continue
            if e["position"] < first_v2:
                return "attachment_entry"

    iq = st["issuerSeq"]
    if not (_exactly(iq, ISSUER_COUNTS + ("series", "truncated"))
            and all(_int(iq[k]) and iq[k] >= 0 for k in ISSUER_COUNTS)
            and type(iq["truncated"]) is bool and isinstance(iq["series"], list)):
        return "shape"
    if iq["listCap"] != LIST_CAP and mut != "list_cap_unchecked":
        return "consistency"
    if (iq["unboundRecords"] != lv["v1"] or iq["boundRecords"] + iq["absentRecords"] != lv["v2"]) \
            and mut != "issuer_counts_unchecked":
        return "consistency"
    series = iq["series"]
    if iq["boundRecords"] == 0 and len(series) != 0:
        return "consistency"
    list_cap = LIST_CAP - 1 if mut == "list_cap_off_by_one" else LIST_CAP
    if len(series) > list_cap:
        return "consistency"
    last_series = ""
    for s in series:
        if not (_exactly(s, ("series", "min", "max", "missing", "duplicates")) and _hex32(s["series"])
                and _int(s["min"]) and _int(s["max"]) and isinstance(s["missing"], list)
                and isinstance(s["duplicates"], list)):
            return "shape"
        if s["series"] <= last_series or s["min"] < 0 or s["min"] > s["max"]:
            return "consistency"
        last_series = s["series"]
        prev = -1
        for m in s["missing"]:
            if not _int(m) or m <= prev or ((m < s["min"] or m > s["max"]) and mut != "missing_unbounded"):
                return "consistency"
            prev = m
        if len(s["missing"]) > list_cap or len(s["duplicates"]) > list_cap:
            return "consistency"
        for d in s["duplicates"]:
            if not (_exactly(d, ("seq", "correctionSeq", "ledgerSeqs")) and _int(d["seq"])
                    and (d["correctionSeq"] is None or (_int(d["correctionSeq"]) and d["correctionSeq"] >= 0))
                    and isinstance(d["ledgerSeqs"], list)):
                return "shape"
            ls = d["ledgerSeqs"]
            hi = float("inf") if mut == "duplicate_ledger_seqs_unbounded" else to
            if len(ls) < 2 or not all(_int(q) and 1 <= q <= hi and (i == 0 or q > ls[i - 1]) for i, q in enumerate(ls)):
                return "consistency"

    a, bridge = st["anchor"], st["bridge"]
    if a is None:
        return "anchor" if bridge is not None else None
    if not _exactly(a, ANCHOR_MEMBERS, mut if mut == "extra_members_ignored" else None):
        return "anchor"
    if a["subjectSchema"] != st["commitmentSchema"] and mut != "subject_schema_unchecked":
        return "anchor"
    if not _int(a["seq"]) or a["seq"] < to:
        return "anchor"
    if not all(_hex32(a[k]) for k in ("head", "acc", "subjectDigest", "anchoredDigest")):
        return "anchor"
    if not (a["batchRoot"] is None or _hex32(a["batchRoot"])):
        return "anchor"
    if not (isinstance(a["status"], str) and (a["status"] in ANCHOR_STATUSES or mut == "anchor_status_open")):
        return "anchor"
    if not (a["bitcoinBlockHeight"] is None or (_int(a["bitcoinBlockHeight"], "bool_as_int" if mut == "height_bool_as_int" else None)
                                                and a["bitcoinBlockHeight"] >= 0)):
        return "anchor"
    subject = {"acc": a["acc"], "head": a["head"], "schema": a["subjectSchema"], "seq": a["seq"]}
    if a["subjectDigest"] != "0x" + keccak256(canonical(subject).encode("utf-8")).hex() and mut != "subject_digest_unchecked":
        return "anchor"
    if a["id"] != "seller:" + a["subjectDigest"]:
        return "anchor"
    if a["anchoredDigest"] != "0x" + hashlib.sha256(bytes.fromhex(a["subjectDigest"][2:])).hexdigest() \
            and mut != "anchored_digest_unchecked":
        return "anchor"
    if not isinstance(a["proofUrl"], str) or not a["proofUrl"].endswith("/v1/anchors/%s/proof.ots" % a["id"]):
        return "anchor"
    if a["seq"] == to and (a["acc"] != through["acc"] or a["head"] != through["head"]):
        return "anchor"
    if a["seq"] == to:
        if mut == "empty_bridge_at_anchor" and isinstance(bridge, dict) and bridge.get("links") == []:
            return None
        return "anchor" if bridge is not None else None
    bridge_cap = {"bridge_cap_1001": BRIDGE_CAP + 1, "bridge_cap_999": BRIDGE_CAP - 1}.get(mut, BRIDGE_CAP)
    if a["seq"] - to > bridge_cap:
        return "anchor" if bridge is not None else None
    if bridge is None and mut == "bridge_optional":
        return None
    if not (_exactly(bridge, ("from", "to", "links")) and _int(bridge["from"]) and bridge["from"] == to + 1
            and _int(bridge["to"]) and bridge["to"] == a["seq"] and isinstance(bridge["links"], list)):
        return "anchor"
    links = bridge["links"]
    if len(links) != a["seq"] - to or not all(_hex32(x) for x in links):
        return "anchor"
    if mut == "bridge_not_folded":
        return None
    acc = through["acc"]
    for link in links:
        acc = chain_acc_step(acc, link)
    return None if acc == a["acc"] else "anchor"


def signature_message_hash(statement_digest):
    return S.personal_sign_hash((SIGNATURE_PREFIX + statement_digest).encode("utf-8"))


def recover_signer(statement_digest, signature, mut=None):
    """The recovered address (lower case), or None when the signature is not the one accepted encoding or defines no
    public key."""
    if mut == "signature_trailing_newline_accepted" and isinstance(signature, str) and signature.endswith("\n"):
        signature = signature[:-1]
    shape = re.compile(r"0x[0-9a-f]{130}") if mut == "signature_lower_case_only" else SIGNATURE_RE
    if not isinstance(signature, str) or shape.fullmatch(signature) is None:
        return None
    b = bytes.fromhex(signature[2:])
    v = b[64]
    if mut == "recovery_id_normalized" and v in (0, 1):
        v += 27
    if v not in (27, 28):
        return None
    r, s = int.from_bytes(b[:32], "big"), int.from_bytes(b[32:64], "big")
    if s > S.N // 2 and mut != "high_s_accepted":
        return None
    if not (1 <= r < S.N and 1 <= s < S.N):
        return None
    q = S.recover(signature_message_hash(statement_digest), r, s, v - 27)
    return None if q is None else S.address(q)


def check(inp, mut=None):
    """-> ("valid", None) or ("reject", reason). `mut` names a one-site broken verifier (MUTANTS); None is the profile."""
    try:
        body = parse(inp["body_text"], mut)
    except Reject as r:
        return "reject", r.reason
    if not _exactly(body, ENVELOPE, mut if mut == "extra_members_ignored" else None):
        return "reject", "shape"
    st = body["statement"]
    why = statement_refusal(st, mut)
    if why is not None:
        return "reject", why
    signer = body["signer"]
    if mut == "envelope_signer_case_folded" and isinstance(signer, str) and signer.lower() == st["ledger"].lower():
        signer = st["ledger"]
    if signer != st["ledger"] and mut != "envelope_signer_unchecked":
        return "reject", "shape"
    digest = "0x" + keccak256(canonical(st).encode("utf-8")).hex()
    presented = body["statementDigest"]
    if mut == "digest_case_folded" and isinstance(presented, str):
        presented = presented.lower()
    if presented != digest and mut != "digest_unchecked":
        return "reject", "digest"
    who = recover_signer(body["statementDigest"] if mut == "digest_unchecked" else digest, body["signature"], mut)
    if who is None or who != st["ledger"].lower():
        return "reject", "signature"
    if "expected_signer" in inp and mut != "expected_signer_ignored":
        expected = inp["expected_signer"]
        if mut != "expected_signer_case_sensitive":
            expected = expected.lower()
            if expected != st["ledger"].lower():
                return "reject", "signer"
        elif expected != st["ledger"]:
            return "reject", "signer"
    if "records" in inp and mut != "records_unchecked":
        recs = inp["records"]
        frm, to = st["range"]["from"], st["range"]["to"]
        if mut == "records_extra_ignored":
            recs = recs[:to - frm + 1]
        if len(recs) != to - frm + 1 or not all(_hex32(d) for d in recs):
            return "reject", "records"
        acc, prev = st["before"]["acc"], st["before"]["head"]
        for i, d in enumerate(recs):
            acc = chain_acc_step(acc, chain_link_digest(d, prev, frm + i))
            prev = d
        if acc != st["through"]["acc"] or prev != st["through"]["head"]:
            return "reject", "records"
    return "valid", None


MANIFEST = os.path.join(HERE, "MANIFEST.json")
VECTORS = os.path.join(HERE, "vectors")
ORIGIN_CLASSES = ("synthetic", "live-ledger", "live-ledger-derived", "contributed")
KIND = "chain_statement"
# The rules this runner pins, compared with the manifest: a manifest that says otherwise fails the run.
PINNED = {"schema": SCHEMA, "commitment_schema": COMMITMENT_SCHEMA, "signature_prefix": SIGNATURE_PREFIX,
          "limits": LIMITS, "scopes": list(SCOPES), "attachments_version": ATTACHMENTS_VERSION,
          "bindings": list(BINDINGS), "anchor_statuses": list(ANCHOR_STATUSES), "max_range": MAX_RANGE,
          "list_cap": LIST_CAP, "bridge_cap": BRIDGE_CAP, "type_hex_digits": TYPE_HEX_DIGITS,
          "statement_members": list(MEMBERS), "anchor_members": list(ANCHOR_MEMBERS), "envelope": list(ENVELOPE)}

MUTANTS = {   # each a plausible one-site broken verifier; the suite must fail it on the named vector
    "duplicate_last_wins": "sn115-duplicate-member-first-reads-otherwise",
    "float_token_as_int": "sn116-attachments-version-token-1-0",
    "no_integer_bound": "sn117-integer-beyond-2-53",
    "lone_surrogate_accepted": "sn118-lone-high-surrogate-in-chain-id",
    "extra_members_ignored": "sn58-unknown-top-level-member",
    "limits_not_compared": "sn57-limits-text-altered",
    "scope_unchecked": "sn1-scope-unknown-value",
    "scope_case_folded": "sn2-scope-letter-case",
    "chain_key_null_as_absent": "sn44-chain-key-null",
    "chain_key_case_folded": "sn45-chain-key-upper-case",
    "chain_key_zero_allowed": "sn48-chain-key-zero-bytes",
    "range_cap_4999": "sp20-range-at-maximum",
    "range_uncapped": "sn38-range-over-maximum",
    "attachments_version_string": "sn10-attachments-version-string",
    "bool_as_int": "sn11-attachments-version-true",
    "entry_members_open": "sn19-entry-unknown-member",
    "position_from_range_from": "sp6-declared-entry-before-range",
    "positions_non_strict": "sn24-entry-positions-repeat",
    "type_hex_rule_counts_characters": "sp17-type-31-hex-digits-split-by-hyphens",
    "type_hex_rule_any_run": "sp18-type-x-then-32-hex-digits",
    "binding_open": "sn16-entry-binding-outside-set",
    "binding_case_folded": "sn17-entry-binding-letter-case",
    "sealed_unchecked": "sn6-sealed-entry-without-v2-link",
    "sealed_checked_only_from_range_from": "sn8-sealed-entry-before-range-on-mixed-range",
    "sealed_checked_only_without_v2": "sn7-sealed-entry-on-v1-link-of-mixed-range",
    "before_seq_unchecked": "sn65-before-seq-not-from-minus-one",
    "seed_unchecked": "sn68-before-acc-not-the-seed",
    "link_versions_uncounted": "sn66-link-versions-miscount",
    "issuer_counts_unchecked": "sn67-issuer-counts-miscount",
    "list_cap_unchecked": "sn81-list-cap-255",
    "list_cap_off_by_one": "sp24-series-at-list-cap",
    "missing_unbounded": "sn72-missing-number-outside-min-max",
    "duplicate_ledger_seqs_unbounded": "sn77-duplicate-ledger-seq-after-range",
    "subject_schema_unchecked": "sn104-anchor-subject-schema-other-recomputed",
    "subject_digest_unchecked": "sn88-anchor-subject-digest-wrong",
    "anchored_digest_unchecked": "sn89-anchor-anchored-digest-wrong",
    "anchor_status_open": "sn90-anchor-status-outside-set",
    "empty_bridge_at_anchor": "sn97-anchor-at-range-to-with-empty-bridge",
    "bridge_cap_1001": "sp28-anchor-past-bridge-cap",
    "bridge_cap_999": "sp29-anchor-at-bridge-cap",
    "bridge_optional": "sn91-anchor-within-cap-without-bridge",
    "bridge_not_folded": "sn87-bridge-link-replaced",
    "digest_unchecked": "sn107-tampered-head-original-digest",
    "high_s_accepted": "sn110-high-s-twin-of-genuine-signature",
    "recovery_id_normalized": "sn111-recovery-id-0-or-1",
    "envelope_signer_unchecked": "sn113-envelope-signer-not-ledger",
    "expected_signer_ignored": "sn112-self-consistent-statement-by-another-key",
    "expected_signer_case_sensitive": "sp32-expected-signer-lower-case",
    "records_unchecked": "sn120-record-swapped",
    "signature_lower_case_only": "sp34-signature-upper-case-hex-digits",
    "signature_trailing_newline_accepted": "sn126-signature-trailing-newline",
    "digest_case_folded": "sn127-statement-digest-upper-case",
    "envelope_signer_case_folded": "sn128-envelope-signer-letter-case",
    "before_head_case_folded": "sn129-before-head-upper-case",
    "height_bool_as_int": "sn130-anchor-height-true",
    "records_extra_ignored": "sn123-record-appended-after-range",
}


def _strict_pairs(ps):
    seen = {}
    for k, v in ps:
        if k in seen:
            raise ValueError("duplicate key %r" % k)
        seen[k] = v
    return seen


def load_strict(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh, object_pairs_hook=_strict_pairs)


def load_set():
    """-> (vectors by id, problems). Reads statement/MANIFEST.json, never a directory listing alone."""
    m = load_strict(MANIFEST)
    vecs, problems = {}, []
    for key, want in PINNED.items():
        if m.get("format", {}).get(key) != want:
            problems.append("MANIFEST format.%s differs from the value pinned in this runner" % key)
    if tuple(m.get("reject_reasons", ())) != REJECT_REASONS:
        problems.append("MANIFEST reject_reasons %r != the runner's pinned closure %r" % (m.get("reject_reasons"),
                                                                                          REJECT_REASONS))
    listed = [e["file"] for e in m["vectors"]]
    on_disk = {os.path.basename(f) for f in glob.glob(os.path.join(VECTORS, "*.json"))}
    problems += ["on disk, not in MANIFEST: %s" % f for f in sorted(on_disk - set(listed))]
    problems += ["in MANIFEST, not on disk: %s" % f for f in sorted(set(listed) - on_disk)]
    problems += ["listed more than once in MANIFEST: %s" % f for f in sorted({f for f in listed if listed.count(f) > 1})]
    entries = {}
    for e in m["vectors"]:
        if e["file"] not in on_disk:
            continue
        try:
            v = load_strict(os.path.join(VECTORS, e["file"]))
        except ValueError as exc:
            problems.append("%s: %s" % (e["file"], exc))
            continue
        stem = e["file"][:-len(".json")]
        if v.get("id") != stem:
            problems.append("%s: id %r != file stem" % (e["file"], v.get("id")))
        if (v.get("kind"), v.get("expect"), v.get("reject_reason")) != (KIND, e["expect"], e.get("reason")):
            problems.append("%s: kind, expect or reason disagrees with MANIFEST" % e["file"])
        if e["expect"] not in ("valid", "reject") or (e["expect"] == "valid") != ("reason" not in e):
            problems.append("%s: a valid vector has no reason and a reject has one" % e["file"])
        if e.get("origin", {}).get("class") not in ORIGIN_CLASSES or not e.get("author"):
            problems.append("%s: author and origin.class (one of %s) are required" % (e["file"], ORIGIN_CLASSES))
        inp = v.get("input")
        if not (isinstance(inp, dict) and "body_text" in inp and set(inp) <= set(INPUT_KEYS)
                and isinstance(inp["body_text"], str)
                and ("expected_signer" not in inp or isinstance(inp["expected_signer"], str))
                and ("records" not in inp or isinstance(inp["records"], list))):
            problems.append("%s: input must be {body_text: string, expected_signer?: string, records?: array}" % e["file"])
            continue
        vecs[stem] = v
        entries[stem] = e
    if not vecs:
        problems.append("empty vector set")
    # Two-sided per class: every reject names an accepting twin in this set, and the twin is valid.
    for vid, e in entries.items():
        if e["expect"] == "reject":
            twin = e.get("twin")
            if twin not in entries or entries[twin]["expect"] != "valid" or vecs[vid].get("twin") != twin:
                problems.append("%s: twin %r is not an accepting vector of this set" % (vid, twin))
        elif "twin" in e:
            problems.append("%s: an accepting vector names no twin" % vid)
    expects = {e["expect"] for e in entries.values()}
    if expects != {"valid", "reject"}:
        problems.append("the set is one-sided: %s" % sorted(expects))
    used = {e.get("reason") for e in entries.values() if e["expect"] == "reject"}
    problems += ["reject reason never exercised: %s" % r for r in REJECT_REASONS if r not in used]
    problems += ["vector uses an undeclared reason: %s" % r for r in sorted(used - set(REJECT_REASONS))]
    problems += ["mutant %s names a missing vector %s" % (n, vid) for n, vid in MUTANTS.items() if vid not in vecs]
    return vecs, problems


def _order(vid):
    return (vid[:2], int(re.match(r"s[pn](\d+)", vid).group(1)))


def mutants():
    vecs, problems = load_set()
    bad = len(problems)
    for p in problems:
        print("SET  ", p)
    for name, vid in MUTANTS.items():
        if vid not in vecs:
            continue
        v = vecs[vid]
        try:
            got, why = check(v["input"], name)
        except Exception as exc:   # a crash is not a verdict: the mutant fails the vector
            got, why = "crash", type(exc).__name__
        killed = (got, why) != (v["expect"], v.get("reject_reason"))
        bad += not killed
        print("%s mutant %-38s by %s (mutant says %s%s)" % ("killed  " if killed else "SURVIVED", name, vid, got,
                                                            " " + why if why else ""))
    print(("%d/%d mutants killed" % (len(MUTANTS) - bad, len(MUTANTS))) if not problems else "set problems above")
    return 1 if bad else 0


def main():
    if "--mutants" in sys.argv:
        return mutants()
    vecs, problems = load_set()
    bad = len(problems)
    for p in problems:
        print("SET  ", p)
    for vid in sorted(vecs, key=_order):
        v = vecs[vid]
        try:
            got, why = check(v["input"])
        except Exception as exc:   # a crash is not a verdict
            got, why = "crash", type(exc).__name__
        ok = (got, why) == (v["expect"], v.get("reject_reason"))
        bad += not ok
        print("%s %-58s expect=%-6s got=%s%s" % ("ok  " if ok else "FAIL", vid, v["expect"], got,
                                                 " (" + why + ")" if why else ""))
    n = len(load_strict(MANIFEST)["vectors"])
    accept = sum(1 for v in vecs.values() if v["expect"] == "valid")
    print("%d/%d chain-statement vectors match (%d accept, %d reject; %d reject reasons exercised)%s"
          % (len(vecs) - (bad - len(problems)), n, accept, len(vecs) - accept, len(REJECT_REASONS),
             "" if not problems else "; %d set problem(s)" % len(problems)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
