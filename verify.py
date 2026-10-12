#!/usr/bin/env python3
"""evidence-record-conformance verifier — stdlib-only, no dependencies, no network.

Usage:  python3 verify.py            # runs every vector in MANIFEST.json
Exit 0 only if: every vector produces its expected verdict AND the run observed both
verdicts (valid + reject) AND every reject reason code in the manifest was exercised.
A green run therefore demonstrates the verifier *discriminates*, not merely accepts.

Layer under test: the EVIDENCE RECORD — the layer whose properties must survive the
record being held by an interested party. Checks implemented, each with at least one
adversarial vector for its known failure class:

  digest_recompute      canonical form -> keccak256 content address (UTF-8 of the canonical
                        text, code points as is, never normalized; an unpaired surrogate has
                        no canonical form)
  canonical_bytes       claimed canonical bytes actually canonical (RFC 8785 key order,
                        incl. the integer-key ordering class that breaks naive impls,
                        and the supplementary-plane class where UTF-16 code-unit order
                        diverges from code-point order)
  chain_link            link digest binds artifact + prev + sequence number (an integer
                        token in [1, 2^53-1]; seq 1 is the genesis link)
  chain_set             per-seller continuity AND completeness (no silent omission),
                        incl. per-record link recomputation where links are presented
  chain_commitment      a chain_set-valid prefix whose head carries an accumulator over
                        EVERY recomputed link (acc_0 = keccak256("tersign-chain-commitment-v1"),
                        acc_n = keccak256(acc_{n-1} || link_n)); the anchored subject in
                        production is a digest over {acc, head, schema, seq}, so one anchor
                        commits the whole prefix — a substituted prefix presented with the
                        real accumulator, or a last-link-only accumulator, rejects
  anchor_relation       anchoredDigest = SHA-256(subjectDigest bytes) — the existence bound
  phase_claim           a record of one economic phase must not verify as any other phase,
                        later or earlier (closed vocabulary of exact strings; a record with
                        no phase verifies as none)
  independence_claim    a record attested only by parties to the transaction MUST NOT
                        count as an independent/neutral finding
  offer_binding         a receipt that does not commit to the accepted offer's canonical
                        digest MUST NOT be evaluated as proof that a specific offer's
                        terms were paid (the offer-substitution class)
  decision_evidence_binding
                        a protected record presented as evidence of an authority decision
                        must commit to the exact canonical decision-evidence object; an
                        unbound or substituted requested-to-effective reduction rejects
  boundary_binding      a boundary event that changes a stream's verification parameters
                        must bind the prefix it extends AND its own position in that
                        prefix's continuation — naming the prefix alone is satisfiable by
                        two conflicting continuations at once; coverage claimed over
                        an empty attested prefix is a downgrade, not a pass; and an attested
                        prefix length, wherever present, is an integer in [0, len(prefix)]

DEFINED MEMBERS (v0.5.8, issue #17): every kind's `input` is a closed object, and so are the
objects DEFINED_MEMBERS lists for that kind (the chain `head` and each `records` entry, and each
independence `attestations` entry). A member whose name is not listed rejects the record with
unknown_member_reject, whatever its value, before the kind's criterion runs. Names compare as
exact strings. The lists are pinned here and in tools/cross_check_ts.mjs, and the run fails if
MANIFEST.json's `defined_members` differs from them.

SCOPE BOUNDARY (stated, not implied): this stdlib core decides the STRUCTURAL predicate —
digests, canonical bytes, sequence closure, link arithmetic, declared-claim evaluation.
It does not recover counter-signatures. A structurally complete set whose head and links
were all recomputed by a single forging party passes the structural predicate; what
prevents that in production is that every link is counter-signed at transaction time by
a party outside the transaction and the head is anchored. Signature recovery over the
links (secp256k1 personal_sign; signer published at https://tersign.ai/v1/ledger) is the
crypto profile, deliberately outside this stdlib core — the digests, chain, completeness,
existence and criteria checks above require no cryptography beyond hashing.
"""

import hashlib
import json
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from keccak import keccak256  # vendored; self-checked at import against measured KATs

HERE = os.path.dirname(os.path.abspath(__file__))

# A JSON integer token of any length is an integer. CPython 3.11+ (and the 3.10.7/3.9.14 security
# releases) refuses to convert one longer than 4300 digits by default, so this verifier's loader
# raised on such a token and reported the input malformed, where the TypeScript engine reads it as
# a number past the domain and lets the criterion reject it (an `attestedPrefixLength` of 5000
# digits: boundary_reject; v0.5.9 review). The limit is lifted for this process, so the loader reads
# the token as the integer it is. No vector carries one; tools/differential.py compares both engines.
if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(0)


# ---------------------------------------------------------------- canonical form (JCS)
class NotIJSONText(ValueError):
    """JSON outside I-JSON (RFC 7493): no RFC 8785 canonical form exists for it."""


def _well_formed(s):
    """The string as UTF-16 reads it, or NotIJSONText if it holds a surrogate that is not half
    of a pair (v0.5.5; p44/n81-n84). RFC 7493 §2.1 forbids unpaired surrogates in names and
    values ("\\uDEAD" is invalid, "\\uD800\\uDEAD" legal), and RFC 8785 §3.2.2.2 requires a
    canonicalizer to terminate on one: such a string has no UTF-8 form, so it has no canonical
    bytes. Checked through a UTF-16 round trip, so a pair held as two code points reads as the
    one code point it is, exactly as a JavaScript string does. json joins an escaped pair into
    one code point, but a pair written with one half raw and the other escaped decodes to two
    (n93), as does a Python string built by hand."""
    try:
        return s.encode("utf-16-be", "surrogatepass").decode("utf-16-be")
    except UnicodeDecodeError:
        raise NotIJSONText("a name or string value holds a surrogate that is not half of a pair "
                           "(RFC 7493 §2.1) — no canonical form (RFC 8785 §3.2.2.2)") from None


def canonical(value):
    """RFC 8785 (JCS) serialization for the vector domain (I-JSON, integer numerics).

    Keys sort by UTF-16 code units (encode to UTF-16BE and compare bytes — identical
    ordering, done explicitly rather than trusting the host language's default sort).
    Every code point outside the control range is written as is (`ensure_ascii=False`;
    §3.2.2.2), never normalized (§3.1), and digest_of hashes the text as UTF-8 (§3.2.4):
    p39-p42 accept, n71-n74 reject. A name or value with an unpaired surrogate raises
    NotIJSONText before any of that (n81-n84).
    """
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(_well_formed(value), ensure_ascii=False)
    if isinstance(value, int):
        if abs(value) > 2**53 - 1:
            raise ValueError("outside the I-JSON interoperable range (|n| > 2^53-1)")
        return str(value)
    if isinstance(value, float):
        raise ValueError("non-integer JSON number in the digest domain")
    if isinstance(value, list):
        return "[" + ",".join(canonical(v) for v in value) + "]"
    if isinstance(value, dict):
        # Names are checked before they are sorted: the UTF-16 sort key cannot encode an
        # unpaired surrogate, and until v0.5.5 the sort raised a UnicodeEncodeError that the
        # callers read as a number-domain error (n82).
        items = sorted(((_well_formed(k), v) for k, v in value.items()),
                       key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(
            json.dumps(k, ensure_ascii=False) + ":" + canonical(v) for k, v in items
        ) + "}"
    raise TypeError(f"non-JSON value in vector: {type(value)}")


def digest_of(value):
    return "0x" + keccak256(canonical(value).encode("utf-8")).hex()


GENESIS_PREV = "0x" + "00" * 32

# The chain_link sequence domain, [1, SEQ_MAX] (v0.5.5): the I-JSON integer bound.
SEQ_MAX = 2**53 - 1


def chain_link_digest(artifact_digest, prev_digest, seq):
    a = bytes.fromhex(artifact_digest[2:])
    p = bytes.fromhex((prev_digest or GENESIS_PREV)[2:])
    return "0x" + keccak256(a + p + seq.to_bytes(8, "big")).hex()


# Chain-commitment accumulator (v0.5.0). The seed is a TAGGED digest, never the 32-zero-byte
# link-genesis sentinel: link preimages are 72 raw bytes, accumulator preimages 64 raw bytes,
# every JCS digest is UTF-8 text starting "{" — domain separation by construction.
ACC_GENESIS = "0x" + keccak256(b"tersign-chain-commitment-v1").hex()


def chain_acc_step(acc, link):
    return "0x" + keccak256(bytes.fromhex(acc[2:]) + bytes.fromhex(link[2:])).hex()


# -------------------------------------------------------- identifier normalization
# Identity comparison must not depend on incidental byte forms: EIP-55 mixed case is
# the same address, and " 0xabc… " with trailing whitespace is the same address — but a
# string this verifier cannot parse AS an address is not an address it can evaluate.
# Normalize (strip + lowercase), then validate; unparseable fails closed. Without this,
# a party could relabel itself as "outside the parties" by appending a space or an
# invisible format character to its own address — an alias bypass of the independence
# criterion, the exact fail-open class this suite exists to reject.
ADDR_RE = re.compile(r"^0x[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^0x[0-9a-f]{64}$")
# A second identity syntax, added 2026-08-19 — the independence criterion compares attestor
# identity, and a criterion bound to ONE identity syntax cannot decide records from schemes
# that name parties differently. Found against a foreign corpus (AXES Golden Trace v2 custody
# twins, axes#6): under `org:…` / `agent:…` identities the criterion rejected the accepting
# twin on the identifier alone. The grammar is deliberately strict so the aliasing defence
# (n13 whitespace, n14 unparseable, the zero-width-space vector) still holds: a lowercase
# alnum scheme, one colon, then printable non-space ASCII — no whitespace, no format chars,
# no format chars. Case and trailing punctuation are then FOLDED AWAY (see _norm_addr) so a
# party cannot alias itself outside the transaction with a case variant or a trailing slash.
URN_RE = re.compile(r"^[a-z][a-z0-9+.-]*:[\x21-\x7e]+$")
# v0.5.4: the grammar is checked BEFORE case folding in either case (letter case folds toward
# the same party, the scheme's included — RFC 3986 §3.1 schemes are case-insensitive; n58), and
# the lowercase form must still match URN_RE AFTER normalization (a non-empty path; n51).
URN_ANY_CASE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[\x21-\x7e]+$")
PCT_RE = re.compile(r"%([0-9A-Fa-f]{2})")
UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")

# The whitespace stripped from identifiers and digests, and the whitespace a `transaction` or
# `network` string must contain something besides: the Unicode White_Space property (PropList),
# enumerated, never the host language's strip()/trim(). Python's str.strip() also removes
# U+001C-U+001F (control characters); JavaScript's trim() also removes U+FEFF (a format
# character) and does not remove U+0085. Neither extra is whitespace, and the two engines forked
# on exactly those inputs until v0.5.4. A character without the property at the edge of an
# identifier (U+FEFF, a format character; U+001C, a control character) leaves it unparseable, as
# one inside it does (n14, n52, n53). Some control characters (U+0009-U+000D, U+0085) do have the
# property and are stripped.
WHITESPACE = "".join(chr(c) for c in (
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0x85, 0xA0, 0x1680,
    *range(0x2000, 0x200B), 0x2028, 0x2029, 0x202F, 0x205F, 0x3000,
))


def _strip_ws(s):
    return s.strip(WHITESPACE)


def _decode_unreserved(s):
    """Decode percent-encoded UNRESERVED characters only (RFC 3986 §6.2.2.2): one left-to-right
    pass, either hex case. A triplet encoding anything else (a reserved character, `%` itself,
    a non-ASCII octet) is left in place, and its `%` then makes the identifier unparseable."""
    def one(m):
        ch = chr(int(m.group(1), 16))
        return ch if ch in UNRESERVED else m.group(0)
    return PCT_RE.sub(one, s)


def _norm_addr(a):
    """A canonical party identifier, or None if not parseable as one.

    Two syntaxes: a 0x-address (lowercased — EIP-55 mixed case is the same address) or a
    scheme-qualified identifier. The URN branch normalises AGGRESSIVELY toward "same party",
    in this order (v0.5.4): percent-encoded unreserved characters decoded, once (n55, n56); any
    `%` left over fails closed; a `?` anywhere, or a dot-segment (`.` or `..`) in the path, fails
    closed (n59-n61); case-folded; every trailing `/` `.` `#` stripped; a `#` left after that (a
    non-empty fragment) fails closed (n62); the result must still parse.
    The verifier does not own any scheme's equivalence rules, so where two identifiers MIGHT
    denote one party it must treat them as one — a deployer writing `org:caldera-robotics/`,
    `org:Caldera-robotics` or `org:caldera%2Drobotics` is otherwise "outside the transaction"
    for free, which is n13's alias bypass one syntax over (n31, n45-n49). Where it cannot tell
    at all (`%2F`, which some schemes read as `/` and RFC 3986 does not), the identifier is not
    evaluable (n50). Decoding runs BEFORE the trailing strip, so an encoded trailing `.` is
    stripped too (n49). The cost is that a genuinely distinct party whose identifier differs
    only by these folds is read as the same party and the claim rejects; for a disqualification
    that is the correct direction to be wrong in."""
    if not isinstance(a, str):
        return None
    a = _strip_ws(a)
    low = a.lower()
    if ADDR_RE.fullmatch(low):
        return low
    if not URN_ANY_CASE_RE.fullmatch(a):
        return None
    ident = _decode_unreserved(a)
    if "%" in ident or "?" in ident:
        return None
    # RFC 3986 §3.3 dot-segments: the complete segments `.` and `..` of the path, which runs from
    # the scheme's colon to the first `?` or `#`. A normalizer may resolve them (§6.2.2.3); this
    # verifier does not own the scheme's resolution rules, so it cannot evaluate them (n59/n60;
    # n67 and n70 at the path's first segment).
    # Checked BEFORE the trailing strip, which would otherwise turn `…/witness/..` into
    # `…/witness`, a different identifier from the `…/` it resolves to.
    path = re.split(r"[?#]", ident.split(":", 1)[1], maxsplit=1)[0]
    if any(seg in (".", "..") for seg in path.split("/")):
        return None
    ident = ident.lower().rstrip("/.#")
    if "#" in ident:
        return None
    return ident if URN_RE.fullmatch(ident) else None


def _address_key(ident):
    """The 0x-address a normalized identifier names, or None (v0.5.4, n63-n66/n69/p37/p38).

    A 0x-address is its own key. A scheme-qualified identifier whose final colon-separated
    component is a 0x-address, whatever the scheme (the CAIP-10 account eip155:8453:0x…,
    did:pkh:eip155:1:0x…, did:ethr:0x…, ethereum:0x…, acct:0x…), names that address in another
    namespace, so it keys to it. Two identifiers with one key are one party, whichever side
    carries which form and whatever the chain reference: the verifier does not know which
    chains a key holder controls, and folding toward same party is the direction it can afford
    to be wrong in."""
    if ADDR_RE.fullmatch(ident):
        return ident
    last = ident.rsplit(":", 1)[-1]
    return last if ADDR_RE.fullmatch(last) else None

def _norm_digest(x):
    """Lowercased 0x-32-byte digest, or None if not parseable as one."""
    if not isinstance(x, str):
        return None
    x = _strip_ws(x).lower()
    return x if DIGEST_RE.fullmatch(x) else None


def _is_seq(x):
    """A sequence number is an int and not a bool (bool is an int subclass in Python)."""
    return isinstance(x, int) and not isinstance(x, bool)


# ------------------------------------------------------------------------ vector kinds
def check_digest_recompute(inp):
    try:
        got = digest_of(inp["payload"])
    except NotIJSONText as exc:
        # A name or value with an unpaired surrogate has no canonical form, so no digest of it
        # exists to compare, whatever digest is claimed (v0.5.5, n83, n84). Until v0.5.5 the UTF-8
        # encode raised a UnicodeEncodeError, a ValueError, and landed in the branch below.
        return "reject", "canonicalization_reject", str(exc)
    except ValueError as exc:
        # The digest domain is I-JSON with integer numerics. A non-integer number, or an
        # integer beyond 2^53-1, produces digests other implementations cannot reproduce
        # (RFC 8785 §3.2.2.3 routes numbers through ECMAScript Number::toString over IEEE
        # 754 doubles) — refused rather than silently serialized.
        return "reject", "number_domain_reject", str(exc)
    expected = _norm_digest(inp.get("expected_digest"))
    if expected is None:
        return "reject", "recompute_mismatch", "expected digest is not a parseable 32-byte hex digest"
    if got != expected:
        return "reject", "recompute_mismatch", f"recomputed {got}"
    return "valid", None, got


def _reject_duplicate_names(pairs):
    """object_pairs_hook: duplicate object names are outside I-JSON (RFC 7493 §2.3; RFC 8785
    §3.1). Compares DECODED names, so {"a":1,"\\u0061":2} is a duplicate (n42), and compares
    them as UTF-16 code units, as JSON.parse holds them (v0.5.5, n93): json joins only an
    ESCAPED surrogate pair into one code point, so a pair written with its high half raw and
    its low half escaped decodes to two code points, and a code-point comparison reads it as a
    different name from the same pair written as two escapes."""
    keys = [k.encode("utf-16-be", "surrogatepass") for k, _ in pairs]
    if len(keys) != len(set(keys)):
        dupes = sorted({k for (k, _), u in zip(pairs, keys) if keys.count(u) > 1})
        raise NotIJSONText(f"duplicate object name(s) {dupes} — not valid I-JSON")
    return dict(pairs)


def _reject_constant(token):
    """parse_constant: Python's json accepts NaN / Infinity / -Infinity; RFC 8259 has no such tokens."""
    raise NotIJSONText(f"{token} is not a JSON token")


def _parse_ijson_text(text):
    """Two passes, so the text's shape is decided before its numbers, as in the TS engine.

    Pass 1 keeps every number token as text (`parse_int=str`, `parse_float=str`), so nothing
    about a number can raise before a duplicate name or a non-JSON constant anywhere in the
    text is found: without it, `{"a":<5000 digits>,"a":1}` read number_domain_reject here and
    canonicalization_reject in TS. Pass 2 then parses numbers for the digest-domain check.
    An unpaired surrogate in a name or a string value is part of the text's shape (v0.5.5): it
    is found on pass 1's tree, before any number, as the TS engine finds it on its first parse.
    Found later, during canonical(), it raced the number tokens in key order, and the two
    engines named different reasons for one text."""
    if not isinstance(text, str):
        raise NotIJSONText(f"payload_text must be a JSON string, got {type(text).__name__}")
    try:
        shape = json.loads(text, object_pairs_hook=_reject_duplicate_names, parse_constant=_reject_constant,
                           parse_int=str, parse_float=str)
    except json.JSONDecodeError as exc:
        raise NotIJSONText(f"payload_text is not JSON text: {exc}") from None
    _check_strings(shape)
    return json.loads(text)


def _check_strings(node):
    """_well_formed over every name and string value of a parsed tree (pass 1's number tokens
    are ASCII digit strings and pass trivially)."""
    if isinstance(node, str):
        _well_formed(node)
    elif isinstance(node, list):
        for x in node:
            _check_strings(x)
    elif isinstance(node, dict):
        for k, v in node.items():
            _well_formed(k)
            _check_strings(v)


def check_canonical_bytes(inp):
    # `payload_text` carries the payload as raw JSON text where the distinction under
    # test cannot survive a JSON load in every language: plain JSON.parse erases the token
    # 2.0 to the value 2 (this repo's TypeScript vector loader did until v0.5.1; its reviver
    # now maps such a token to NaN), while Python's json keeps 2.0 a float; `payload_text`
    # carries the distinction to both engines.
    # Key presence, not sentinel, per the cross-language guard convention. The raw-text
    # pathway is the one place JSON text is parsed after load, so
    # it carries the loader's rules itself (v0.5.4, issue #10): text with a duplicate name,
    # a non-JSON constant, text that is not JSON, or a value that is not a string has no
    # canonical form -> canonicalization_reject (p30/n41-n44). Boundary: a number TOKEN with
    # a fraction or exponent part is outside the digest domain even when integer-valued ->
    # number_domain_reject (p25/n35).
    try:
        payload = _parse_ijson_text(inp["payload_text"]) if "payload_text" in inp else inp["payload"]
        got = canonical(payload)
    except NotIJSONText as exc:
        return "reject", "canonicalization_reject", str(exc)
    except ValueError as exc:
        return "reject", "number_domain_reject", str(exc)
    if got != inp["claimed_canonical"]:
        return "reject", "canonicalization_reject", f"canonical form is {got!r}"
    return "valid", None, "canonical bytes confirmed"


def check_chain_link(inp):
    artifact = _norm_digest(inp.get("artifact_digest"))
    if artifact is None:
        return "reject", "continuity_reject", "unparseable artifact digest"
    prev_raw = inp.get("prev_digest")
    if prev_raw is None:
        prev = None
    else:
        prev = _norm_digest(prev_raw)
        if prev is None:
            return "reject", "continuity_reject", "unparseable prev digest"
    # The sequence domain is the integer tokens in [1, 2^53-1] (v0.5.5): seq 1 is the genesis
    # link (n75 rejects 0), and past 2^53-1 two JSON engines can read one token as different
    # integers, so they would recompute different links (n76; p43 accepts the bound). A seq
    # that is not an integer token (n77, the token 1.0) rejects too. Bounded here, before the
    # 8-byte encoding, so 2^64 and beyond reject rather than raise.
    if not _is_seq(inp.get("seq")) or not 1 <= inp["seq"] <= SEQ_MAX:
        return "reject", "continuity_reject", "sequence number is not an integer in [1, 2^53-1]"
    expected = _norm_digest(inp.get("expected_link"))
    if expected is None:
        return "reject", "continuity_reject", "unparseable expected link digest"
    got = chain_link_digest(artifact, prev, inp["seq"])
    if got != expected:
        return "reject", "continuity_reject", f"recomputed link {got}"
    return "valid", None, got


GENESIS_PREV_FORMS = {None, GENESIS_PREV}

# Claim strings that assert nothing about independence. A record is free to stay
# silent; what it may not do is assert something this verifier cannot evaluate and
# have that pass (see check_independence_claim).
NO_CLAIM = frozenset({"", "none", "issuer_attested"})

# Economic phases this verifier understands. A phase token outside this vocabulary is
# not interpretable — and an uninterpretable phase must not verify as ANY phase, for
# the same reason an uninterpretable independence claim must not pass: the check would
# switch off exactly where the record asserts something new.
PHASES = ("funding", "delivery", "settlement", "refund", "reversal")

# Suite-profile bound on head.seq: completeness is checked by materializing the
# committed range, so an absurd head is refused rather than allowed to exhaust memory.
MAX_HEAD_SEQ = 100_000


def _norm_prev(p):
    """Wire form of a genesis predecessor is null; the 32-zero-byte digest is the
    hashing-time substitution (see chain_link_digest) and normalizes to the same thing.
    Returns None (genesis), a normalized digest, or the sentinel "invalid"."""
    if p is None:
        return None
    d = _norm_digest(p)
    if d is None:
        return "invalid"
    return None if d == GENESIS_PREV else d


def check_chain_set(inp):
    head = inp.get("head")
    if not isinstance(head, dict):
        return "reject", "completeness_reject", "head is not an object"
    if not _is_seq(head.get("seq")) or head["seq"] < 1:
        return "reject", "completeness_reject", "head commits no records (seq < 1 or not an integer)"
    if head["seq"] > MAX_HEAD_SEQ:
        return "reject", "completeness_reject", f"head.seq exceeds the suite profile bound ({MAX_HEAD_SEQ})"
    head_digest = _norm_digest(head.get("digest"))
    if head_digest is None:
        return "reject", "completeness_reject", "head digest is not a parseable 32-byte hex digest"

    raw_records = inp.get("records")
    if not isinstance(raw_records, list):
        return "reject", "completeness_reject", "records is not an array"
    records = []
    for r in raw_records:
        if not isinstance(r, dict) or not _is_seq(r.get("seq")):
            return "reject", "completeness_reject", "record entry is not an object with an integer seq"
        records.append(r)
    records.sort(key=lambda r: r["seq"])

    seqs = [r["seq"] for r in records]
    counts = Counter(seqs)
    expected = list(range(1, head["seq"] + 1))
    if seqs != expected:
        missing = sorted(set(expected) - set(seqs))
        dupes = sorted(s for s, c in counts.items() if c > 1)
        extra = sorted(set(seqs) - set(expected))
        parts = [f"missing seq {missing}"] if missing else []
        parts += [f"duplicate seq {dupes}"] if dupes else []
        parts += [f"out-of-range seq {extra}"] if extra else []
        return "reject", "completeness_reject", " + ".join(parts) + " under committed head"

    prev = None
    for r in records:
        artifact = _norm_digest(r.get("artifact_digest"))
        if artifact is None:
            return "reject", "continuity_reject", f"unparseable artifact digest at seq {r['seq']}"
        r_prev = _norm_prev(r.get("prev_digest"))
        if r_prev == "invalid":
            return "reject", "continuity_reject", f"unparseable prev digest at seq {r['seq']}"
        if r_prev != prev:
            return "reject", "continuity_reject", f"prev mismatch at seq {r['seq']}"
        if "link" in r:
            # Per-record links, where presented, must be the chain-link arithmetic over
            # this record's own artifact, predecessor, and sequence number. This is what
            # catches renumbering: a record relabeled to hide an omission carries a link
            # computed for its ORIGINAL position, and the recomputation diverges. (In
            # production each link is counter-signed at transaction time, so a forger
            # cannot simply recompute them — see the scope boundary in the module doc.)
            claimed_link = _norm_digest(r["link"])
            if claimed_link is None:
                return "reject", "continuity_reject", f"unparseable link digest at seq {r['seq']}"
            if chain_link_digest(artifact, prev, r["seq"]) != claimed_link:
                return "reject", "continuity_reject", f"link mismatch at seq {r['seq']}"
        prev = artifact
    if prev != head_digest:
        return "reject", "continuity_reject", "head digest does not match final record"
    return "valid", None, f"complete 1..{head['seq']} under head (structural predicate; counter-signature profile out of stdlib scope)"


def check_chain_commitment(inp):
    """A chain_set-valid prefix whose head ALSO carries an accumulator over every link.

    chain_set decides continuity and completeness against a committed head; what it cannot
    decide is whether the presented prefix is THE prefix the anchor was built over. A head
    digest binds the last record only (a_N), so two prefixes ending in the same record — the
    real one and one whose earlier rows were substituted, with prevs and links recomputed —
    both pass chain_set and both sit under the same anchored head. The accumulator closes
    that: acc_0 = keccak256(utf8("tersign-chain-commitment-v1")), acc_n = keccak256(acc_{n-1}
    || link_n) over the RECOMPUTED links (prev = previous artifact digest), and head.acc must
    equal acc_{head.seq}. Any omission, insertion, reordering or rewrite below N changes
    acc_N. Production anchors keccak256(utf8(canonical({acc, head, schema, seq}))) rather
    than a_N, so one anchored digest commits the whole prefix; a head.acc that folds only the
    last link — the "anchor commits to the last record" shape — is exactly what rejects here.
    Structural profile only: the counter-signatures over each link and the anchor over the
    commitment are the crypto and existence profiles, outside this stdlib core.
    """
    verdict, reason, detail = check_chain_set(inp)
    if verdict != "valid":
        return verdict, reason, detail
    head = inp["head"]
    claimed = _norm_digest(head.get("acc"))
    if claimed is None:
        return "reject", "continuity_reject", "head accumulator is not a parseable 32-byte digest"
    records = sorted(inp["records"], key=lambda r: r["seq"])
    acc = ACC_GENESIS
    prev = None
    for r in records:
        artifact = _norm_digest(r["artifact_digest"])
        acc = chain_acc_step(acc, chain_link_digest(artifact, prev, r["seq"]))
        prev = artifact
    if acc != claimed:
        return "reject", "continuity_reject", "accumulator mismatch: head.acc does not commit to the presented prefix"
    return "valid", None, f"complete 1..{head['seq']} and head.acc commits the whole prefix (structural predicate; counter-signature and anchor profiles out of stdlib scope)"


def check_anchor_relation(inp):
    subject = _norm_digest(inp.get("subject_digest"))
    if subject is None:
        return "reject", "existence_reject", "unparseable subject digest"
    anchored = _norm_digest(inp.get("anchored_digest"))
    if anchored is None:
        return "reject", "existence_reject", "unparseable anchored digest"
    got = "0x" + hashlib.sha256(bytes.fromhex(subject[2:])).hexdigest()
    if got != anchored:
        return "reject", "existence_reject", f"sha256(subject) = {got}"
    return "valid", None, "anchored digest binds subject"


def check_phase_claim(inp):
    record = inp.get("record")
    if not isinstance(record, dict) or "economic_phase" not in record:
        return "reject", "phase_reject", "record carries no economic_phase"
    phase = record["economic_phase"]
    presented = inp.get("presented_as")
    if phase not in PHASES:
        return "reject", "phase_reject", f"unrecognized economic phase {phase!r}: not interpretable by this verifier"
    if presented not in PHASES:
        return "reject", "phase_reject", f"unrecognized presented phase {presented!r}: not interpretable by this verifier"
    if phase != presented:
        return "reject", "phase_reject", f"{phase} record presented as {presented} evidence"
    return "valid", None, f"phase {phase} consistent"


_MISSING = object()


def _check_object_binding(
    carrier,
    digest_field,
    presented,
    label,
    *,
    carrier_label="carrier",
    object_required=False,
    missing_detail=None,
    missing_presented_detail=None,
    valid_detail=None,
):
    """Shared binding arithmetic without conflating the bound objects' semantics."""
    if not isinstance(carrier, dict):
        return "reject", "binding_reject", f"{carrier_label} is not an object"
    if object_required and not isinstance(presented, dict):
        return "reject", "binding_reject", f"presented {label} is not an object"
    committed = _norm_digest(carrier.get(digest_field))
    if committed is None:
        detail = missing_detail or f"{carrier_label} commits to no parseable {label} digest"
        return "reject", "binding_reject", detail
    if presented is _MISSING:
        return "reject", "binding_reject", missing_presented_detail or f"{label} is missing"
    try:
        got = digest_of(presented)
    except (ValueError, TypeError, KeyError) as exc:
        return "reject", "binding_reject", f"{label} not canonicalizable: {exc}"
    if got != committed:
        return "reject", "binding_reject", f"presented {label} digests to {got}, {carrier_label} commits to {committed}"
    return "valid", None, valid_detail or f"{carrier_label} binds the presented {label}"


def check_offer_binding(inp):
    """A receipt proves the terms it COMMITS to. A receipt that carries no digest of the
    accepted offer cannot bind amount/asset/payTo/scheme, so two offers sharing
    resourceUrl/network/payer become interchangeable behind a valid signature — the
    substitution class reported upstream (x402-foundation/x402#3006). The check is the
    binding arithmetic: the presented offer's canonical digest must equal the digest the
    receipt commits to; changing ANY term changes the canonical bytes, hence the digest."""
    return _check_object_binding(
        inp.get("receipt"),
        "offerDigest",
        inp["offer"] if "offer" in inp else _MISSING,
        "offer",
        carrier_label="receipt",
        missing_detail="receipt commits to no parseable offer digest — terms are unbound",
        missing_presented_detail="offer not canonicalizable: 'offer'",
        valid_detail="receipt binds the presented offer's exact terms",
    )


def check_decision_evidence_binding(inp):
    """Bind the exact authority-decision evidence object to the protected record.

    This criterion deliberately decides only structural distinguishability. It does not
    validate the authority intersection, authenticate the producer, establish historical
    position, or prescribe where a future protocol stores the commitment.
    """
    return _check_object_binding(
        inp.get("record"),
        "decisionEvidenceDigest",
        inp.get("decision_evidence"),
        "decision-evidence object",
        carrier_label="record",
        object_required=True,
    )


def check_boundary_binding(inp):
    """A record stream may change its own verification parameters — which witness, which
    signature suite, which canonical form — and it does so with a BOUNDARY EVENT inside the
    stream rather than by rewriting the records that predate the change. The question this
    criterion settles is what such an event must bind for a verifier holding only the stream
    to be able to check it.

    Naming the prefix it extends is NOT sufficient. Two conflicting continuations of the same
    prefix can both name that prefix truthfully, so a verifier accepts either and cannot tell
    which the deployment committed to — demonstrated against a live implementation and
    reproduced four independent ways in modelcontextprotocol/modelcontextprotocol#3004
    (2026-08-08/09). A boundary event must therefore bind BOTH the digest of the prefix it
    extends AND its own position in that prefix's continuation.

    The second failure this pins is the downgrade: a verifier that cannot find the attestation
    falls back to a weaker path — digest and link arithmetic alone — and reports success while
    its own report says the attested prefix was empty. An offline snapshot is then
    indistinguishable from a verified stream. Coverage that is claimed must be coverage that
    was checked, so a claim of coverage over an empty attested prefix rejects.

    Stated at the record layer, deliberately: the shape is a stream of records, a boundary
    event, and a claimed covered prefix. Nothing here depends on a particular file format,
    witness kind, or signature suite."""
    event = inp.get("boundary_event")
    if not isinstance(event, dict):
        return "reject", "boundary_reject", "boundary event is not an object"

    prefix = inp.get("prefix")
    if not isinstance(prefix, list) or not prefix:
        return "reject", "boundary_reject", "the prefix a boundary event extends is not an evaluable sequence"

    # (a) Does it bind the prefix it extends, and truthfully?
    claimed_prefix = _norm_digest(event.get("prefixDigest"))
    if claimed_prefix is None:
        return "reject", "boundary_reject", "boundary event binds no parseable digest of the prefix it extends"
    try:
        actual_prefix = digest_of(prefix)
    except (ValueError, TypeError) as exc:
        return "reject", "boundary_reject", f"prefix not canonicalizable: {exc}"
    if claimed_prefix != actual_prefix:
        return "reject", "boundary_reject", f"boundary event names prefix {claimed_prefix}, presented prefix digests to {actual_prefix}"

    # (b) Does it bind its OWN position in that prefix's continuation? A truthful (a) with no
    # (b) is the fabricated-boundary case: an event appended later, claiming an earlier
    # effective point, is indistinguishable from one that was always there.
    position = event.get("position")
    if not isinstance(position, int) or isinstance(position, bool):
        return "reject", "boundary_reject", "boundary event binds the prefix it extends but not its own position in the continuation — a later append claiming an earlier point is indistinguishable from an original"
    if position != len(prefix):
        return "reject", "boundary_reject", f"boundary event claims position {position}, the presented prefix ends at {len(prefix)}"

    # v0.5.9 (issue #9): an attested prefix length is read wherever the member is present, with
    # or without coverage claimed, and it is an integer token from 0 to the presented prefix's
    # length. Until v0.5.9 it was read only beside `covered_through`, so -1, 99 or a length past
    # the prefix passed whenever no coverage was claimed, and a length past the prefix passed
    # beside any coverage up to it. 0 with no coverage claimed is an attestation that reaches
    # nothing and claims nothing, and stays valid (p63). Key PRESENCE, so a null rejects (n158).
    if "attestedPrefixLength" in event:
        attested = event["attestedPrefixLength"]
        if not isinstance(attested, int) or isinstance(attested, bool) or not 0 <= attested <= len(prefix):
            return "reject", "boundary_reject", (f"attestedPrefixLength {attested!r} is not an integer from 0 to "
                                                 f"the presented prefix's length, {len(prefix)}")

    # The downgrade: coverage claimed over an empty attested prefix. A verifier that reports
    # success here has checked nothing and said so in the same breath.
    # Key PRESENCE here too (v0.5.9 review), so a present `covered_through: null` is a value, not
    # absence, and rejects (n171): the same rule as for `attestedPrefixLength` (n158).
    if "covered_through" in inp:
        covered = inp["covered_through"]
        if not isinstance(covered, int) or isinstance(covered, bool) or covered < 0:
            return "reject", "boundary_reject", "claimed coverage is not an evaluable position"
        attested = event.get("attestedPrefixLength")
        if not isinstance(attested, int) or isinstance(attested, bool):
            return "reject", "boundary_reject", "coverage is claimed but the attested prefix length is not stated — unattested is not a pass"
        if attested <= 0 < covered:
            return "reject", "boundary_reject", f"coverage claimed through {covered} while the attested prefix is empty — an offline snapshot is indistinguishable from a verified stream"
        if covered > attested:
            return "reject", "boundary_reject", f"coverage claimed through {covered}, attestation reaches only {attested}"

    return "valid", None, f"boundary event binds prefix {actual_prefix[:12]}… at position {position}"


def derive_settlement_commits(result):
    """What a settlement result actually commits to, read off the result rather than declared.

    Returns the fact classes an evaluator may let an independence claim reach. `settlement` is
    committed only when the result both claims success AND carries a transaction reference that
    resolves to something: an empty `transaction` is the spec's own encoding of a failed
    settlement, so a record carrying it commits to no settlement at all.
    """
    commits = []
    if not isinstance(result, dict):
        return commits
    tx = result.get("transaction")
    if result.get("success") is True and isinstance(tx, str) and _strip_ws(tx) != "":
        commits.append("settlement")
    if isinstance(result.get("network"), str) and _strip_ws(result["network"]) != "":
        commits.append("network")
    return commits


def derive_delivery_commits(inp):
    """What a record's delivery fields commit to, read off the record rather than declared.

    None when the record presents no delivery commitment to evaluate — neither key present,
    tested by key PRESENCE so both engines read an explicit null the same way (the
    `record_commits` lesson, n23). Otherwise a list: `["delivery"]` when the deliverable
    digest the record carries recomputes from the deliverable bytes it presents,
    keccak256(utf8(bytes)) == digest, and `[]` when it does not. A digest carried beside
    bytes that do not hash to it is the delivery-side twin of `transaction: ""`: a
    well-formed field committing to nothing a reader can check — evaluated, and empty.

    WHO delivered is deliberately not read here. `deliverable_signer` names a position, and
    position is the INDEPENDENCE axis, decided upstream by the parties/attestations count
    (the position/faculty distinction, p17/n21). Folding the signer in would let one axis do
    the other's work and the reject would name the wrong defect. Enumerated by @0rkz against
    issue #3; p22/n32 anticipated this derivation and must not move under it; p23/n33 drive it.
    """
    if "deliverable_bytes" not in inp and "deliverable_digest" not in inp:
        return None
    presented = inp.get("deliverable_bytes")
    declared = _norm_digest(inp.get("deliverable_digest"))
    if not isinstance(presented, str) or declared is None:
        return []
    try:
        # A lone surrogate is valid JSON text with no UTF-8 form: Python raises here, a JS
        # TextEncoder substitutes U+FFFD and hashes on — two engines, two verdicts. Both
        # now read it as bytes that cannot be the digested bytes: presented, and empty.
        encoded = presented.encode("utf-8")
    except UnicodeEncodeError:
        return []
    if "0x" + keccak256(encoded).hex() == declared:
        return ["delivery"]
    return []


def derive_record_commits(inp):
    """Every fact class the record commits to, composed from the per-fact derivations.

    Settlement and network come off the settlement result; delivery comes off the presented
    bytes. None when the record presents nothing derivable at all — distinct from an empty
    list, which is a record that presented commitments and was found to commit to nothing.
    """
    parts = []
    if isinstance(inp.get("settlement_result"), dict):
        parts.append(derive_settlement_commits(inp["settlement_result"]))
    delivery = derive_delivery_commits(inp)
    if delivery is not None:
        parts.append(delivery)
    if not parts:
        return None
    return [c for part in parts for c in part]


def check_independence_claim(inp):
    claimed = inp.get("claimed")
    if claimed is None:
        return "valid", None, "no independence claimed"
    # Membership must not depend on the value being hashable: a list or dict claim
    # raised TypeError here, which produces no verdict at all — the criterion did not
    # fail closed, it threw. An array is also the shape a CLAIM SET lands on, i.e. the
    # one shape we said this field should move toward. Reported by @Rul1an (issue #1).
    if isinstance(claimed, str):
        if claimed in NO_CLAIM:
            return "valid", None, "no independence claimed"
        if claimed == "independent":
            claimed_set = {claimed}
        else:
            claimed_set = None
    elif isinstance(claimed, list) and all(isinstance(c, str) for c in claimed):
        claimed_set = {c for c in claimed if c not in NO_CLAIM}
        if not claimed_set:
            return "valid", None, "no independence claimed"
        if claimed_set - {"independent"}:
            claimed_set = None
    else:
        claimed_set = None
    if claimed_set is None:
        # Fail closed on a claim this verifier cannot interpret — including a STRONGER
        # one. An exact-equality trigger silently returned "valid" for any other value,
        # turning the check off precisely where more was asserted. Silence is a valid
        # state; an unintelligible assertion is not.
        return "reject", "independence_reject", f"unrecognized claim {claimed!r}: not interpretable by this verifier"

    # From here the record CLAIMS independence, so the claim must be evaluable: the
    # parties and attestations must exist, have evaluable shapes, and carry parseable
    # identities. Failing closed also means returning a verdict for every shape — a
    # missing key or a non-object attestation is a reject, not an exception.
    raw_parties = inp.get("parties")
    if not isinstance(raw_parties, list) or not raw_parties:
        return "reject", "independence_reject", "independence claimed but parties are not evaluable"
    parties = set()
    party_keys = set()
    for p in raw_parties:
        norm = _norm_addr(p)
        if norm is None:
            return "reject", "independence_reject", f"unparseable party identifier {p!r}"
        parties.add(norm)
        if _address_key(norm) is not None:
            party_keys.add(_address_key(norm))
    raw_attestations = inp.get("attestations")
    if not isinstance(raw_attestations, list) or not raw_attestations:
        return "reject", "independence_reject", "independence claimed with no evaluable attestations"
    outside = 0
    for a in raw_attestations:
        if not isinstance(a, dict) or "by" not in a:
            return "reject", "independence_reject", "attestation is not an object naming its attestor"
        by = _norm_addr(a["by"])
        if by is None:
            return "reject", "independence_reject", f"unparseable attestor identifier {a['by']!r}"
        if by not in parties and _address_key(by) not in party_keys:
            outside += 1
    if not outside:
        return "reject", "independence_reject", "attested only by parties to the transaction"

    # DERIVED, never declared — and the declared field's PRESENCE is itself the reject,
    # scope assertion or no. A declared commitment list lets a record assert the very scope
    # the commitment-scope rule exists to bound; leaving the declared path in as a fallback
    # made the derivation decorative (a record carrying both fields was scored on the
    # declaration — the override attack). An explicit null is a declaration too: one that
    # evaluates to nothing, which is the same shape as an unrecognized claim string, and it
    # fails closed for the same reason. The guard is KEY PRESENCE, not a value sentinel —
    # `is None` here and `=== undefined` in the TS cross-check read an explicit JSON null
    # differently, and the two engines forked on exactly that input. `in` has identical
    # semantics in both languages, which makes the fork unrepresentable rather than merely
    # untested. Both reported against this suite by @Rul1an (issue #4, second report).
    if "record_commits" in inp:
        return "reject", "independence_reject", "commitment scope must be derived from the record, not declared alongside it"

    # Commitment scope: an independence claim MUST NOT be read as covering any fact the
    # record does not itself commit to. A record whose committed content is a settlement
    # digest carries, at most, independent evidence OF THAT SETTLEMENT — nothing its
    # attestation did not cover, however independent the attestor. Absent a scope
    # assertion, the claim reads as scoped to the committed facts and nothing more.
    covers = inp.get("covers")
    if covers is not None:
        if isinstance(covers, str):
            covers = [covers]
        if not isinstance(covers, list) or not covers or not all(isinstance(c, str) for c in covers):
            return "reject", "independence_reject", "scope assertion is not evaluable"
        # x402 v2 §5.3.2 defines the empty string as what `transaction` carries when
        # settlement failed, and the type only requires a string — so `success: true`
        # with `transaction: ""` is well formed and commits to no settlement anyone can
        # resolve. Deriving the commitments off the record is what makes the
        # commitment-scope rule bite without resolving anything on-chain, and it is why
        # `delivery` is now a scope a record can actually reach: before this, no record
        # could commit to it, so n20 rejected for a structural reason that happened to be
        # correct for the wrong cause (@0rkz, issue #3).
        committed = derive_record_commits(inp)
        if not isinstance(committed, list) or not all(isinstance(c, str) for c in committed):
            return "reject", "independence_reject", "independence claimed over a scope, but the record's commitments are not evaluable"
        uncovered = sorted(set(covers) - set(committed))
        if uncovered:
            return "reject", "independence_reject", f"claim covers {uncovered} — fact(s) the record does not commit to"
    return "valid", None, f"{outside} non-party attestation(s)"


# ------------------------------------------------------------------- defined members
# v0.5.8 (issue #17, 2026-10-11): every `valid` vector stayed valid with a member the suite does
# not define added to its input, and nothing said what a verifier does with one. The ruling:
# reject it. Per kind, the closed objects and the exact names each one defines. `input` is
# closed in every kind; inside it, the chain `head` and each object in `records` (chain_set,
# chain_commitment) and each object in `attestations` (independence_claim) are closed too.
# Members permitted and not read are listed and their contents are not examined: `witness` and
# `attestations` beside a chain set, an attestation's `role`, `deliverable_signer` and `payTo`.
# `record_commits` is listed because the suite defines it: in a record that claims independence
# its presence is the independence reject (n22-n24). Every other object is open: digested whole (payload, offer,
# decision_evidence, each prefix entry), or another protocol's or the record's own (a phase or
# decision `record`, `receipt`, `settlement_result`, `boundary_event`).
# Pinned in code, as the reject-reason closure is; main() fails if MANIFEST.json says otherwise.
_CHAIN_INPUT = frozenset({"head", "records", "witness", "attestations"})
_CHAIN_ROW = frozenset({"seq", "artifact_digest", "prev_digest", "link"})
DEFINED_MEMBERS = {
    "digest_recompute": {"input": frozenset({"payload", "expected_digest"})},
    "canonical_bytes": {"input": frozenset({"payload", "payload_text", "claimed_canonical"})},
    "chain_link": {"input": frozenset({"artifact_digest", "prev_digest", "seq", "expected_link"})},
    "chain_set": {"input": _CHAIN_INPUT, "input.head": frozenset({"seq", "digest"}),
                  "input.records[]": _CHAIN_ROW},
    "chain_commitment": {"input": _CHAIN_INPUT, "input.head": frozenset({"seq", "digest", "acc"}),
                         "input.records[]": _CHAIN_ROW},
    "anchor_relation": {"input": frozenset({"subject_digest", "anchored_digest"})},
    "phase_claim": {"input": frozenset({"record", "presented_as"})},
    "independence_claim": {
        "input": frozenset({"claimed", "parties", "attestations", "covers", "settlement_result",
                            "deliverable_bytes", "deliverable_digest", "deliverable_signer", "payTo",
                            "record_commits"}),
        "input.attestations[]": frozenset({"by", "role"}),
    },
    "offer_binding": {"input": frozenset({"offer", "receipt"})},
    "decision_evidence_binding": {"input": frozenset({"record", "decision_evidence"})},
    "boundary_binding": {"input": frozenset({"prefix", "boundary_event", "covered_through"})},
}


def _closed_objects(kind, inp):
    """(path, object, defined names) for `input` and every closed object inside it, every array
    entry included, whoever its attestor and whatever the claim (n146-n148). A closed object that
    is not a JSON object has no members to read; the kind's criterion decides it (n16, p62)."""
    for path, names in DEFINED_MEMBERS[kind].items():
        if path == "input":
            yield path, inp, names
            continue
        key = path[len("input."):]
        if key.endswith("[]"):
            entries = inp.get(key[:-2])
            if isinstance(entries, list):
                for i, entry in enumerate(entries):
                    if isinstance(entry, dict):
                        yield f"input.{key[:-2]}[{i}]", entry, names
        elif isinstance(inp.get(key), dict):
            yield path, inp[key], names


def check_defined_members(kind, inp):
    """unknown_member_reject for a member a closed object does not define, else None.

    A member counts by its NAME: a null, an empty string or an empty object rejects like any
    other value (n123-n125). Names compare as exact strings — no case folding, no trimming, no
    Unicode normalization, no confusable mapping (n126-n128, n149) — against the list for THIS
    kind and THIS object (n129, n130). Decided before the criterion, in every kind and inside the
    closed objects too (n133-n145, n150-n152)."""
    if not isinstance(inp, dict):
        return None
    for path, obj, names in _closed_objects(kind, inp):
        unknown = [name for name in obj if name not in names]
        if unknown:
            return ("reject", "unknown_member_reject",
                    f"{path} carries {', '.join(repr(n) for n in unknown)}, which {kind} does not define there")
    return None


CRITERIA = {
    "digest_recompute": check_digest_recompute,
    "canonical_bytes": check_canonical_bytes,
    "chain_link": check_chain_link,
    "chain_set": check_chain_set,
    "chain_commitment": check_chain_commitment,
    "anchor_relation": check_anchor_relation,
    "phase_claim": check_phase_claim,
    "independence_claim": check_independence_claim,
    "offer_binding": check_offer_binding,
    "decision_evidence_binding": check_decision_evidence_binding,
    "boundary_binding": check_boundary_binding,
}


def _with_defined_members(kind, criterion):
    def check(inp):
        return check_defined_members(kind, inp) or criterion(inp)
    check.__name__, check.__doc__ = criterion.__name__, criterion.__doc__
    return check


# The conformance entry point for every kind: the member check, then the criterion.
# chain_commitment calls the chain_set CRITERION directly, so its head's `acc` is read against
# chain_commitment's list, never chain_set's.
CHECKS = {kind: _with_defined_members(kind, criterion) for kind, criterion in CRITERIA.items()}
if set(DEFINED_MEMBERS) != set(CRITERIA):
    sys.exit("DEFINED_MEMBERS must list every kind in CRITERIA")


# ------------------------------------------------------------------------------ runner
# The reason-code closure is PINNED IN CODE, not derived from the manifest — a fork that
# quietly drops a reject class from MANIFEST.json must go red, not stay green.
REQUIRED_REASONS = frozenset({
    "recompute_mismatch", "canonicalization_reject", "continuity_reject",
    "completeness_reject", "existence_reject", "phase_reject", "independence_reject",
    "number_domain_reject", "binding_reject", "boundary_reject", "unknown_member_reject",
})


def defined_members_table():
    """DEFINED_MEMBERS as MANIFEST.json writes it: kind -> path -> sorted names."""
    return {kind: {path: sorted(names) for path, names in table.items()}
            for kind, table in DEFINED_MEMBERS.items()}


def _load_strict(path):
    """json load that REJECTS duplicate object names (RFC 7493 / RFC 8785 precondition)."""
    with open(path, encoding="utf-8") as f:
        return json.load(f, object_pairs_hook=_reject_duplicate_names)


def main():
    manifest = _load_strict(os.path.join(HERE, "MANIFEST.json"))

    failures, verdicts_seen, reasons_seen, kinds_seen = [], set(), set(), set()
    # Per-kind verdict sets. The README's second design rule — every criterion is two-sided,
    # so an unconditional rejector fails as hard as an unconditional accepter — was stated as
    # run-enforced and was not: the gate below checked {valid, reject} over the WHOLE run, so a
    # criterion whose accepting vectors all disappeared stayed green as long as some other
    # criterion contributed a valid somewhere. Reported by @Rul1an (issue #1, 2026-08-12).
    # The case that made it concrete: d50545a (identity aliasing fail-closed) silently moved
    # the independence criterion from deciding to not-deciding under URN identities — every
    # URN input rejected on the identifier, so the criterion could no longer return valid for
    # that syntax — and nothing in the run said so. A per-kind gate catches that at the commit.
    verdicts_by_kind = {}
    expected_reasons = {v["reason"] for v in manifest["vectors"]
                        if v.get("expect") == "reject" and "reason" in v}

    for entry in manifest["vectors"]:
        try:
            vector = _load_strict(os.path.join(HERE, "vectors", entry["file"]))
            if vector["kind"] != entry["kind"]:
                raise ValueError(f"kind mismatch: manifest says {entry['kind']}, vector says {vector['kind']}")
            verdict, reason, detail = CHECKS[vector["kind"]](vector["input"])
        except Exception as exc:  # a malformed vector is a controlled failure, not a crash
            verdict, reason, detail = "malformed", None, f"{type(exc).__name__}: {exc}"
        verdicts_seen.add(verdict)
        kinds_seen.add(entry["kind"])
        verdicts_by_kind.setdefault(entry["kind"], set()).add(verdict)
        if reason:
            reasons_seen.add(reason)
        ok = verdict == entry["expect"] and (verdict == "valid" or reason == entry.get("reason"))
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {entry['file']:44s} -> {verdict}{'/' + reason if reason else ''}  ({detail})")
        if not ok:
            failures.append(entry["file"])

    print()
    if failures:
        print(f"NON-CONFORMANT: {len(failures)} vector(s) produced the wrong verdict: {failures}")
        return 1
    if verdicts_seen != {"valid", "reject"}:
        print(f"NON-CONFORMANT: run must observe BOTH verdicts; saw {sorted(verdicts_seen)}")
        return 1
    if expected_reasons != REQUIRED_REASONS or reasons_seen != REQUIRED_REASONS:
        print(f"NON-CONFORMANT: reject-reason closure is pinned to {sorted(REQUIRED_REASONS)}; "
              f"manifest covers {sorted(expected_reasons)}, run exercised {sorted(reasons_seen)}")
        return 1
    declared = manifest.get("defined_members")
    if not isinstance(declared, dict) or declared.get("closed") != defined_members_table():
        print("NON-CONFORMANT: MANIFEST.json `defined_members.closed` must equal the member lists "
              "pinned in this verifier (DEFINED_MEMBERS)")
        return 1
    if kinds_seen != set(CHECKS):
        print(f"NON-CONFORMANT: every vector kind must be exercised; missing {sorted(set(CHECKS) - kinds_seen)}")
        return 1
    one_sided = sorted(k for k, vs in verdicts_by_kind.items() if vs != {"valid", "reject"})
    if one_sided:
        detail = ", ".join(f"{k} saw only {sorted(verdicts_by_kind[k])}" for k in one_sided)
        print(f"NON-CONFORMANT: every criterion must be two-sided IN THIS RUN — an unconditional "
              f"rejector fails as hard as an unconditional accepter; {detail}")
        return 1
    print(f"CONFORMANT: {len(manifest['vectors'])} vectors, both verdicts observed per kind, "
          f"all {len(REQUIRED_REASONS)} reject reasons and all {len(CHECKS)} kinds exercised.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
