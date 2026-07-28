#!/usr/bin/env python3
"""Regenerate vectors/ + MANIFEST.json deterministically. Committed for transparency:
anyone can diff a regeneration against the committed bytes (nothing here is random —
regeneration is byte-identical). The two live-provenance vectors embed records from the
live ledger, cross-checkable against the public endpoints named in their `provenance`
blocks (the genesis record body at /v1/genesis; the anchor record at /v1/anchors)."""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from verify import canonical, digest_of, chain_link_digest  # noqa: E402

V = os.path.join(ROOT, "vectors")
os.makedirs(V, exist_ok=True)

GENESIS_ARTIFACT = json.loads(
    '{"format":"eip712","payload":{"issuedAt":1783761710,"network":"eip155:8453",'
    '"payer":"0x36f82906859E5B0bd076069f8cdfAea355358b14",'
    '"resourceUrl":"https://tersign-ledger.kevinn-zhang.workers.dev/v1/receipts/genesis/demo",'
    '"transaction":"","version":1},'
    '"signature":"0x88e3f596dc8e6e5f2aeac45b45eac4484c09e2f58a2b787c73469e5927706b18'
    '341c362491ecdc0df8764831b07f499210523eb11200bacf340869f50a4c46e81b"}'
)
GENESIS_DIGEST = "0xe5874f1ffe87f0a6dd9eb157730f67b86ee4538b125fe30fcc4e165213dd3fc4"
LEDGER_SIGNER = "0x9d38BA84730271eb27Ac9bD4Bd2620c08dB4FDa6"
GENESIS_COUNTERSIG = (
    "0xfccc1add7301c688e03311ff04b9aecac4f0d81a468fc95128b24aa0c8aff2bf"
    "3b148181befffc6dbe739b1991d936cd434a2fa2bcb8ea1f49a06b8f7a3fff1d1c"
)
ANCHOR_SUBJECT = "0xb2c5d2bd28ff65e13c1549a718a4c447916d5277ce046b2061ed63749ff287d9"
ANCHOR_ANCHORED = "0xcf48bed1712f5b7df2a309fb52cb2b3d51ab1a04730e3b115cd3db79c96c9b1a"

assert digest_of(GENESIS_ARTIFACT) == GENESIS_DIGEST, "live genesis digest drifted"

# synthetic 3-record chain for the continuity/completeness vectors
demo = [{"demo": i, "note": "synthetic chain-set record"} for i in (1, 2, 3)]
d = [digest_of(x) for x in demo]

vectors = [
    # ---------------------------------------------------------------- positives
    {
        "id": "p1-live-genesis-receipt",
        "kind": "digest_recompute",
        "expect": "valid",
        "description": "Live ledger record: the tersign ledger's genesis (demo) receipt. The keccak256 content address recomputes from the committed canonical bytes, and the same bytes are served by the ledger's public genesis endpoint. The payload's embedded resourceUrl is the historical demo resource the genesis record was issued against (on the ledger's legacy workers.dev alias, which still serves as an origin) — the record's validity derives from digest, counter-signature and anchor, never from URL liveness.",
        "input": {"payload": GENESIS_ARTIFACT, "expected_digest": GENESIS_DIGEST},
        "provenance": {
            "ledger": "https://tersign.ai",
            "record": "curl https://tersign.ai/v1/genesis",
            "verify": f"curl https://tersign.ai/v1/receipts/{GENESIS_DIGEST}/verify",
            "countersignature": GENESIS_COUNTERSIG,
            "ledger_signer": LEDGER_SIGNER,
            "note": "countersignature is secp256k1 personal_sign over the chain-link digest (crypto-profile check, outside the stdlib core)",
        },
    },
    {
        "id": "p2-canonical-key-order",
        "kind": "canonical_bytes",
        "expect": "valid",
        "description": "Frozen cross-implementation pin: canonical form of {b:'x',a:1}.",
        "input": {"payload": {"b": "x", "a": 1}, "claimed_canonical": '{"a":1,"b":"x"}'},
    },
    {
        "id": "p3-integer-key-utf16-order",
        "kind": "digest_recompute",
        "expect": "valid",
        "description": "Frozen pin for the integer-like-key class: RFC 8785 orders '1' < '10' < '2' by UTF-16 code units. JS engines hoist such keys into numeric order on object rebuild; a suite without this vector cannot catch that class.",
        "input": {
            "payload": {"10": "a", "2": "b", "1": "c"},
            "expected_digest": "0x426b770f81b8ad5e307bcfb767deb02f8d32cd340d81a946be88bb184857e81b",
        },
    },
    {
        "id": "p4-chain-link-genesis",
        "kind": "chain_link",
        "expect": "valid",
        "description": "Chain-link digest binds artifact + prev (genesis = 32 zero bytes) + big-endian 8-byte sequence number. Pinned cross-implementation (Python here, TypeScript reference).",
        "input": {
            "artifact_digest": GENESIS_DIGEST,
            "prev_digest": None,
            "seq": 1,
            "expected_link": chain_link_digest(GENESIS_DIGEST, None, 1),
        },
    },
    {
        "id": "p5-live-bitcoin-anchor",
        "kind": "anchor_relation",
        "expect": "valid",
        "description": "Live production anchor: anchoredDigest = SHA-256(subjectDigest bytes). The subject is a counter-signed ledger chain head; the .ots proof for the anchoredDigest is confirmed in Bitcoin block 958163 and verifies with stock OpenTimestamps tooling.",
        "input": {"subject_digest": ANCHOR_SUBJECT, "anchored_digest": ANCHOR_ANCHORED},
        "provenance": {
            "anchors": "curl https://tersign.ai/v1/anchors",
            "proof": f"curl -O https://tersign.ai/v1/anchors/ledger:{ANCHOR_SUBJECT}/proof.ots",
            "verify": f"ots verify -d {ANCHOR_ANCHORED[2:]} proof.ots",
            "bitcoin_block": 958163,
        },
    },
    {
        "id": "p6-chain-set-complete",
        "kind": "chain_set",
        "expect": "valid",
        "description": "A complete per-seller set: every sequence number 1..head present, prev pointers continuous, head digest matches the final record.",
        "input": {
            "head": {"seq": 3, "digest": d[2]},
            "records": [
                {"seq": 1, "artifact_digest": d[0], "prev_digest": None},
                {"seq": 2, "artifact_digest": d[1], "prev_digest": d[0]},
                {"seq": 3, "artifact_digest": d[2], "prev_digest": d[1]},
            ],
        },
    },
    {
        "id": "p7-phase-consistent",
        "kind": "phase_claim",
        "expect": "valid",
        "description": "Acceptance twin of n6: a delivery-phase record presented as delivery evidence is consistent. Both verdicts are exercised for the phase criterion — an unconditional rejector must fail this vector.",
        "input": {
            "record": {"economic_phase": "delivery", "deliverable_digest": d[0]},
            "presented_as": "delivery",
        },
    },
    {
        "id": "p8-non-party-attestation",
        "kind": "independence_claim",
        "expect": "valid",
        "description": "Acceptance twin of n7: the independence claim holds when at least one attestation comes from outside the transaction's parties — here, a counter-signing ledger that is neither payer nor payee. An unconditional rejector must fail this vector.",
        "input": {
            "claimed": "independent",
            "parties": ["0x2222222222222222222222222222222222222222", "0x3333333333333333333333333333333333333333"],
            "attestations": [
                {"by": "0x2222222222222222222222222222222222222222", "role": "payer"},
                {"by": LEDGER_SIGNER, "role": "counter-signing ledger"},
            ],
        },
    },
    {
        "id": "p9-no-independence-claim",
        "kind": "independence_claim",
        "expect": "valid",
        "description": "A record that claims nothing about independence, attested only by parties. Silence is a valid state: the criterion disqualifies unsupported CLAIMS, so a verifier that rejects every party-attested record regardless of what it claims fails this vector.",
        "input": {
            "claimed": "none",
            "parties": ["0x2222222222222222222222222222222222222222", "0x3333333333333333333333333333333333333333"],
            "attestations": [
                {"by": "0x2222222222222222222222222222222222222222", "role": "payer"},
                {"by": "0x3333333333333333333333333333333333333333", "role": "payee"},
            ],
        },
    },
    # ---------------------------------------------------------------- negatives
    {
        "id": "n1-value-drift",
        "kind": "digest_recompute",
        "expect": "reject",
        "reason": "recompute_mismatch",
        "description": "One field of the genesis artifact altered (issuedAt + 1); the committed digest must not verify.",
        "input": {
            "payload": {**GENESIS_ARTIFACT, "payload": {**GENESIS_ARTIFACT["payload"], "issuedAt": 1783761711}},
            "expected_digest": GENESIS_DIGEST,
        },
    },
    {
        "id": "n2-hoisted-integer-keys",
        "kind": "canonical_bytes",
        "expect": "reject",
        "reason": "canonicalization_reject",
        "description": "The adversarial twin of p3: canonical bytes claimed in NUMERIC key order ('1','2','10') — the exact output of a sort-then-stringify implementation whose engine hoists integer-like keys. Must reject.",
        "input": {
            "payload": {"10": "a", "2": "b", "1": "c"},
            "claimed_canonical": '{"1":"c","2":"b","10":"a"}',
        },
    },
    {
        "id": "n3-chain-link-wrong-prev",
        "kind": "chain_link",
        "expect": "reject",
        "reason": "continuity_reject",
        "description": "Link claimed against the wrong predecessor (self-referential prev). Must reject: the link digest binds the true prev.",
        "input": {
            "artifact_digest": GENESIS_DIGEST,
            "prev_digest": GENESIS_DIGEST,
            "seq": 1,
            "expected_link": chain_link_digest(GENESIS_DIGEST, None, 1),
        },
    },
    {
        "id": "n4-omitted-record",
        "kind": "chain_set",
        "expect": "reject",
        "reason": "completeness_reject",
        "description": "Head commits seq 3; presented set silently omits seq 2. THE completeness class: an issuer-attested sequence alone cannot prove no-omission — the committed head makes the gap arithmetically visible.",
        "input": {
            "head": {"seq": 3, "digest": d[2]},
            "records": [
                {"seq": 1, "artifact_digest": d[0], "prev_digest": None},
                {"seq": 3, "artifact_digest": d[2], "prev_digest": d[1]},
            ],
        },
    },
    {
        "id": "n5-truncated-anchor",
        "kind": "anchor_relation",
        "expect": "reject",
        "reason": "existence_reject",
        "description": "Anchored digest does not bind the presented subject (truncated/substituted head). The existence bound must fail closed.",
        "input": {"subject_digest": d[0], "anchored_digest": ANCHOR_ANCHORED},
    },
    {
        "id": "n6-phase-confusion",
        "kind": "phase_claim",
        "expect": "reject",
        "reason": "phase_reject",
        "description": "A funding-phase record presented as delivery evidence. Economic phases must not collapse: a receipt for one phase MUST NOT verify as evidence of a later one.",
        "input": {
            "record": {"economic_phase": "funding", "amount": "10", "asset": "USDC"},
            "presented_as": "delivery",
        },
    },
    {
        "id": "n7-issuer-only-independence",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "A record attested only by parties to the transaction, claiming independent status. Evidences structure, not independence — an evaluator MUST NOT treat issuer-attested composition as a neutral finding.",
        "input": {
            "claimed": "independent",
            "parties": ["0x2222222222222222222222222222222222222222", "0x3333333333333333333333333333333333333333"],
            "attestations": [
                {"by": "0x2222222222222222222222222222222222222222", "role": "payer"},
                {"by": "0x3333333333333333333333333333333333333333", "role": "payee"},
            ],
        },
    },
    {
        "id": "p10-claim-set-independent",
        "kind": "independence_claim",
        "expect": "valid",
        "description": "The claim expressed as a SET rather than a single string, with an attestation from outside the transaction's parties. A single-valued claim field cannot carry two orthogonal criteria without one silencing the other; the set form is where that field lands. Membership must not depend on the value being hashable — a list claim previously raised TypeError, producing no verdict at all. Reported by @Rul1an (issue #1).",
        "input": {
            "claimed": ["independent"],
            "parties": ["0x2222222222222222222222222222222222222222", "0x3333333333333333333333333333333333333333"],
            "attestations": [
                {"by": "0x2222222222222222222222222222222222222222", "role": "payer"},
                {"by": LEDGER_SIGNER, "role": "counter-signing ledger"},
            ],
        },
    },
    {
        "id": "p11-claim-set-silence-only",
        "kind": "independence_claim",
        "expect": "valid",
        "description": "Accepting twin of n9: a claim SET whose only member asserts nothing about independence, attested only by parties. Silence in set form is a valid state, exactly as p9 pins it for the scalar form. A list branch that drops the silence filter rejects this record and still passes every other vector.",
        "input": {
            "claimed": ["issuer_attested"],
            "parties": ["0x2222222222222222222222222222222222222222", "0x3333333333333333333333333333333333333333"],
            "attestations": [
                {"by": "0x2222222222222222222222222222222222222222", "role": "payer"},
                {"by": "0x3333333333333333333333333333333333333333", "role": "payee"},
            ],
        },
    },
    {
        "id": "n8-unrecognized-independence-claim",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "A record asserting a STRONGER property than independence ('effect_corroborated') while attested only by parties. An exact-equality trigger reads the unfamiliar string, concludes no independence was claimed, and returns valid — the check switches off exactly where more was asserted. A conformant verifier fails closed on a claim it cannot interpret. Reported against this suite by @Rul1an (issue #1).",
        "input": {
            "claimed": "effect_corroborated",
            "parties": ["0x2222222222222222222222222222222222222222", "0x3333333333333333333333333333333333333333"],
            "attestations": [
                {"by": "0x2222222222222222222222222222222222222222", "role": "payer"},
                {"by": "0x3333333333333333333333333333333333333333", "role": "payee"},
            ],
        },
    },
    {
        "id": "n9-unrecognized-member-in-claim-set",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "Rejecting twin of p11: a claim SET carrying one silence token and one member the verifier cannot read, with an attestation from outside the parties. The outside attestor is what makes this discriminating rather than over-determined: p8 and p10 already pin that this attestation shape is valid, so the only thing that can produce a reject here is the unread member. Ignoring an unknown member is only safe where ignoring it can never turn a reject into a valid, which is not established for this field.",
        "input": {
            "claimed": ["issuer_attested", "unknown-claim"],
            "parties": ["0x2222222222222222222222222222222222222222", "0x3333333333333333333333333333333333333333"],
            "attestations": [
                {"by": "0x2222222222222222222222222222222222222222", "role": "payer"},
                {"by": LEDGER_SIGNER, "role": "counter-signing ledger"},
            ],
        },
    },
]

manifest = {
    "suite": "evidence-record-conformance",
    "version": "0.1.0",
    "layer": "evidence-record",
    "canonicalization": "RFC 8785 (JCS); vector domain is I-JSON with integer numerics (|n| <= 2^53-1); duplicate object names rejected",
    "content_address": "keccak256(utf8(canonical(payload)))",
    "chain_link": "keccak256(artifact_digest || prev_digest || seq_uint64_be) — wire form of a genesis predecessor is null; 32 zero bytes is the hashing-time substitution for null",
    "chain_set": "records chain raw artifact digests via prev pointers (genesis prev = null); head.digest equals the final record's artifact digest; completeness = every seq 1..head.seq present",
    "anchor_relation": "anchored_digest = sha256(subject_digest_bytes)",
    "vectors": [
        {"file": f"{v['id']}.json", "kind": v["kind"], "expect": v["expect"],
         **({"reason": v["reason"]} if v["expect"] == "reject" else {})}
        for v in vectors
    ],
}

for v in vectors:
    with open(os.path.join(V, f"{v['id']}.json"), "w") as f:
        json.dump(v, f, indent=2, sort_keys=False)
        f.write("\n")
with open(os.path.join(ROOT, "MANIFEST.json"), "w") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")

print(f"wrote {len(vectors)} vectors + MANIFEST.json")
