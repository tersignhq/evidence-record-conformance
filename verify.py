#!/usr/bin/env python3
"""evidence-record-conformance verifier — stdlib-only, no dependencies, no network.

Usage:  python3 verify.py            # runs every vector in MANIFEST.json
Exit 0 only if: every vector produces its expected verdict AND the run observed both
verdicts (valid + reject) AND every reject reason code in the manifest was exercised.
A green run therefore demonstrates the verifier *discriminates*, not merely accepts.

Layer under test: the EVIDENCE RECORD — the layer whose properties must survive the
record being held by an interested party. Checks implemented, each with at least one
adversarial vector for its known failure class:

  digest_recompute      canonical form -> keccak256 content address
  canonical_bytes       claimed canonical bytes actually canonical (RFC 8785 key order,
                        incl. the integer-key ordering class that breaks naive impls)
  chain_link            link digest binds artifact + prev + sequence number
  chain_set             per-seller continuity AND completeness (no silent omission)
  anchor_relation       anchoredDigest = SHA-256(subjectDigest bytes) — the existence bound
  phase_claim           a record of one economic phase must not verify as a later phase
  independence_claim    a record attested only by parties to the transaction MUST NOT
                        count as an independent/neutral finding

Counter-signatures in the live vectors are secp256k1 personal_sign material (signer
published at https://tersign.ai/v1/ledger); recovering them needs an EVM crypto lib and
is deliberately outside this stdlib core — the digests, chain, completeness, existence
and criteria checks above require no cryptography beyond hashing.
"""

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from keccak import keccak256  # vendored; self-checked at import against measured KATs

HERE = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------- canonical form (JCS)
def canonical(value):
    """RFC 8785 (JCS) serialization for the vector domain (I-JSON, integer numerics).

    Keys sort by UTF-16 code units (encode to UTF-16BE and compare bytes — identical
    ordering, done explicitly rather than trusting the host language's default sort).
    """
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, int):
        if abs(value) > 2**53 - 1:
            raise ValueError("outside the I-JSON interoperable range (|n| > 2^53-1)")
        return str(value)
    if isinstance(value, float):
        raise ValueError("vector domain is integer-numeric; float encountered")
    if isinstance(value, list):
        return "[" + ",".join(canonical(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(
            json.dumps(k, ensure_ascii=False) + ":" + canonical(v) for k, v in items
        ) + "}"
    raise TypeError(f"non-JSON value in vector: {type(value)}")


def digest_of(value):
    return "0x" + keccak256(canonical(value).encode("utf-8")).hex()


GENESIS_PREV = "0x" + "00" * 32


def chain_link_digest(artifact_digest, prev_digest, seq):
    a = bytes.fromhex(artifact_digest[2:])
    p = bytes.fromhex((prev_digest or GENESIS_PREV)[2:])
    return "0x" + keccak256(a + p + seq.to_bytes(8, "big")).hex()


# ------------------------------------------------------------------------ vector kinds
def check_digest_recompute(inp):
    got = digest_of(inp["payload"])
    if got != inp["expected_digest"].lower():
        return "reject", "recompute_mismatch", f"recomputed {got}"
    return "valid", None, got


def check_canonical_bytes(inp):
    got = canonical(inp["payload"])
    if got != inp["claimed_canonical"]:
        return "reject", "canonicalization_reject", f"canonical form is {got!r}"
    return "valid", None, "canonical bytes confirmed"


def check_chain_link(inp):
    got = chain_link_digest(inp["artifact_digest"], inp.get("prev_digest"), inp["seq"])
    if got != inp["expected_link"].lower():
        return "reject", "continuity_reject", f"recomputed link {got}"
    return "valid", None, got


GENESIS_PREV_FORMS = {None, GENESIS_PREV}

# Claim strings that assert nothing about independence. A record is free to stay
# silent; what it may not do is assert something this verifier cannot evaluate and
# have that pass (see check_independence_claim).
NO_CLAIM = frozenset({"", "none", "issuer_attested"})


def _norm_prev(p):
    """Wire form for a genesis predecessor is null; the 32-zero-byte digest is the
    hashing-time substitution (see chain_link_digest) and normalizes to the same thing."""
    return None if p in GENESIS_PREV_FORMS else p


def check_chain_set(inp):
    head, records = inp["head"], sorted(inp["records"], key=lambda r: r["seq"])
    if not isinstance(head.get("seq"), int) or head["seq"] < 1 or not str(head.get("digest", "")).startswith("0x"):
        return "reject", "completeness_reject", "head commits no records (seq < 1 or missing digest)"
    seqs = [r["seq"] for r in records]
    expected = list(range(1, head["seq"] + 1))
    if seqs != expected:
        missing = sorted(set(expected) - set(seqs))
        dupes = sorted({s for s in seqs if seqs.count(s) > 1})
        extra = sorted(set(seqs) - set(expected))
        parts = [f"missing seq {missing}"] if missing else []
        parts += [f"duplicate seq {dupes}"] if dupes else []
        parts += [f"out-of-range seq {extra}"] if extra else []
        return "reject", "completeness_reject", " + ".join(parts) + " under committed head"
    prev = None
    for r in records:
        if _norm_prev(r.get("prev_digest")) != prev:
            return "reject", "continuity_reject", f"prev mismatch at seq {r['seq']}"
        prev = r["artifact_digest"]
    if prev != head["digest"]:
        return "reject", "continuity_reject", "head digest does not match final record"
    return "valid", None, f"complete 1..{head['seq']} under head"


def check_anchor_relation(inp):
    got = "0x" + hashlib.sha256(bytes.fromhex(inp["subject_digest"][2:])).hexdigest()
    if got != inp["anchored_digest"].lower():
        return "reject", "existence_reject", f"sha256(subject) = {got}"
    return "valid", None, "anchored digest binds subject"


def check_phase_claim(inp):
    phase = inp["record"]["economic_phase"]
    if phase != inp["presented_as"]:
        return "reject", "phase_reject", f"{phase} record presented as {inp['presented_as']} evidence"
    return "valid", None, f"phase {phase} consistent"


def check_independence_claim(inp):
    claimed = inp.get("claimed")
    if claimed is None or claimed in NO_CLAIM:
        return "valid", None, "no independence claimed"
    if claimed != "independent":
        # Fail closed on a claim this verifier cannot interpret. An exact-equality
        # trigger silently returns "valid" for any other claim string — including a
        # STRONGER one — which turns the check off precisely where more is asserted.
        # Reported by @Rul1an (issue #1); silence is a valid state, an unintelligible
        # assertion is not.
        return "reject", "independence_reject", f"unrecognized claim {claimed!r}: not interpretable by this verifier"
    parties = {p.lower() for p in inp["parties"]}
    outside = [a for a in inp["attestations"] if a["by"].lower() not in parties]
    if not outside:
        return "reject", "independence_reject", "attested only by parties to the transaction"
    return "valid", None, f"{len(outside)} non-party attestation(s)"


CHECKS = {
    "digest_recompute": check_digest_recompute,
    "canonical_bytes": check_canonical_bytes,
    "chain_link": check_chain_link,
    "chain_set": check_chain_set,
    "anchor_relation": check_anchor_relation,
    "phase_claim": check_phase_claim,
    "independence_claim": check_independence_claim,
}


# ------------------------------------------------------------------------------ runner
# The reason-code closure is PINNED IN CODE, not derived from the manifest — a fork that
# quietly drops a reject class from MANIFEST.json must go red, not stay green.
REQUIRED_REASONS = frozenset({
    "recompute_mismatch", "canonicalization_reject", "continuity_reject",
    "completeness_reject", "existence_reject", "phase_reject", "independence_reject",
})


def _load_strict(path):
    """json load that REJECTS duplicate object names (RFC 7493 / RFC 8785 precondition)."""
    def hook(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            dupes = sorted({k for k in keys if keys.count(k) > 1})
            raise ValueError(f"duplicate object name(s) {dupes} — not valid I-JSON")
        return dict(pairs)
    with open(path) as f:
        return json.load(f, object_pairs_hook=hook)


def main():
    manifest = _load_strict(os.path.join(HERE, "MANIFEST.json"))

    failures, verdicts_seen, reasons_seen, kinds_seen = [], set(), set(), set()
    expected_reasons = {v["reason"] for v in manifest["vectors"] if v["expect"] == "reject"}

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
        if reason:
            reasons_seen.add(reason)
        ok = verdict == entry["expect"] and (verdict == "valid" or reason == entry["reason"])
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
    if kinds_seen != set(CHECKS):
        print(f"NON-CONFORMANT: every vector kind must be exercised; missing {sorted(set(CHECKS) - kinds_seen)}")
        return 1
    print(f"CONFORMANT: {len(manifest['vectors'])} vectors, both verdicts observed, "
          f"all {len(REQUIRED_REASONS)} reject reasons and all {len(CHECKS)} kinds exercised.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
