#!/usr/bin/env python3
"""Regenerate vectors/ + MANIFEST.json deterministically. Committed for transparency:
anyone can diff a regeneration against the committed bytes (nothing here is random —
regeneration is byte-identical). The two live-provenance vectors embed records from the
live ledger, cross-checkable against the public endpoints named in their `provenance`
blocks (the genesis record body at /v1/genesis; the anchor record at /v1/anchors)."""

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from verify import canonical, digest_of, chain_link_digest  # noqa: E402
from keccak import keccak256  # noqa: E402  (vendored, self-checked at import)

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

# Delivery-commitment pair (p22/n32): a deliverable digest recomputed from the record's
# own bytes, per tersignhq/evidence-record-conformance#3 (2026-08-19, @wowlegend). Real
# v2-sig provenance-tier values from a live PayPerByte receipt (0rkz/foreseal-x402-
# conformance, Apache-2.0): keccak256(answer slice) == payloadHash, signer distinct from
# payTo. Recomputed independently against this suite's own vendored keccak256 below, not
# merely copied from the source repo.
DELIVERY_ANSWER_SLICE = '{"v":"address-reputation/v1","ts":1784840974,"query":{"domain":"payperbyte.io","address":"0xffff4b8da8c165b556326453446f6940c8afe0db","amount":0,"chain":"base"},"verdict":"ALLOW","score":100,"reasons":["domain registration age unknown","valid HTTPS certificate","domain has mail (MX) records","archived web history spans ~4y","receiving address has on-chain history on Base mainnet (tx_count=1)","receiving address is a deployed contract"],"signals":{"domain":{"rdap":{"creation_date":null,"age_days":null,"registrar":null,"source":"https://rdap.org/domain/payperbyte.io","error":"ReadTimeout: HTTPSConnectionPool(host=\'rdap.org\', port=443): Read timed out. (read timeout=10)"},"tls":{"has_https":true,"cert_valid":true,"issuer":"Let\'s Encrypt","not_before":"Jun 26 22:35:07 2026 GMT","not_after":"Sep 24 22:35:06 2026 GMT","cert_age_days":26,"error":null},"dns":{"a_record":true,"mx_record":true,"source":"https://dns.google/resolve","error":null},"wayback":{"first_seen":"2021-12-18T20:00:46Z","age_days":1678,"source":"http://web.archive.org/cdx/search/cdx?url=payperbyte.io&output=json&limit=1&sort=ascending&fl=timestamp","error":null}},"onchain":{"chain":"base","chain_label":"Base mainnet","chain_id":8453,"is_testnet":false,"address":"0xffff4b8da8c165b556326453446f6940c8afe0db","tx_count":1,"balance_wei":0,"balance_eth":0.0,"is_contract":true,"is_delegated_eoa":false,"zero_history":false,"code_size":171,"latest_block":49025813,"source":"https://mainnet.base.org","error":null},"blocklist":{"address_hit":false,"domain_hit":false,"source":null,"reason":null,"hits":[],"feed_status":{"seed_addresses":1,"seed_domains":1,"bulk_feeds":"off","urlhaus_api":"off"}}},"retrieved_at":"2026-07-23T21:09:34Z","methodology":"ar-v1","input_hashes":{"domain":"0xd363468c364bf3c1a2cc62617cbd3be3b87a7a2f1f982dd2963f0cd82a30192f","onchain":"0x0b87e8d317b09148979633293124170f877ba8faf18bbec623d0baf33de732ef","blocklist":"0x7efbc0b52602dbe7c126366ea7543df21275d2d56f321836378bfd143b189552"},"source":"rdap.org + live TLS + dns.google + web.archive.org + public RPC + curated blocklist","error":null}'
DELIVERY_DIGEST = "0x38ed25ba153654d842f76ea24a3c5e5197c99ae788d50d39c065f7063efdd60f"
DELIVERY_SIGNER = "0x670444bE8515C63c50166EbcD0E5b23c578BbE04"  # data-provider signer (provenance tier)
DELIVERY_PAY_TO = "0xffFf4B8Da8C165B556326453446F6940C8AFE0DB"  # settlement payTo — distinct address
DELIVERY_PAYER = "0xE87c9E192dF8dEdcC2389260B15427C38A4A0bA6"   # paying agent, same live receipt

assert keccak256(DELIVERY_ANSWER_SLICE.encode("utf-8")).hex() == DELIVERY_DIGEST[2:],     "delivery answer-slice digest drifted"
# n33's substitution: the delivered verdict flipped, digest left as issued. One field of
# meaning, not a random nibble — the tamper a reader of this record would care about.
DELIVERY_ANSWER_SLICE_SUBSTITUTED = DELIVERY_ANSWER_SLICE.replace('"verdict":"ALLOW"', '"verdict":"DENY"', 1)
assert DELIVERY_ANSWER_SLICE_SUBSTITUTED != DELIVERY_ANSWER_SLICE, "substitution did not apply"
assert keccak256(DELIVERY_ANSWER_SLICE_SUBSTITUTED.encode("utf-8")).hex() != DELIVERY_DIGEST[2:], "substituted bytes must not recompute"

assert digest_of(GENESIS_ARTIFACT) == GENESIS_DIGEST, "live genesis digest drifted"

# synthetic 3-record chain for the continuity/completeness vectors
demo = [{"demo": i, "note": "synthetic chain-set record"} for i in (1, 2, 3)]
d = [digest_of(x) for x in demo]

# Per-record chain links for the set vectors — prev is the previous record's ARTIFACT
# digest, exactly as the production ledger computes (and counter-signs) them.
links = []
_prev = None
for _i, _art in enumerate(d, 1):
    links.append(chain_link_digest(_art, _prev, _i))
    _prev = _art

# Pinned in lockstep with the compliance-fields spec (x402-foundation/x402#2853): the
# number-boundary vector. Recomputed here so a drift in canonical() breaks generation.
DECIMAL_STRING_VECTOR = {"tax": {"amount": "1.10"}, "issuedAt": 1735689600}
DECIMAL_STRING_DIGEST = "0x81086b5801b1bfd992e4d1e929f54907e0d3be0e8ede94f1da1a954b4e78b250"
assert digest_of(DECIMAL_STRING_VECTOR) == DECIMAL_STRING_DIGEST, "spec-lockstep vector drifted"

# Supplementary-plane key-ordering pair: U+FF61 (halfwidth ideographic full stop) is a
# BMP code point ABOVE the surrogate range; U+10000 encodes as a surrogate pair whose
# first unit (0xD800) sorts BELOW 0xFF61. UTF-16 code-unit order therefore puts the
# supplementary character FIRST, while code-point order puts it LAST.
SUPP_PAYLOAD = {"｡": 1, "\U00010000": 2}

# Offer-binding pair — the substitution class from x402-foundation/x402#3006: two offers
# sharing resourceUrl/network/payer, different payment terms. A receipt committing to
# offer A's canonical digest must reject offer B; changing ANY term changes the bytes.
OFFER_A = {
    "resourceUrl": "https://api.example/premium", "network": "eip155:8453",
    "scheme": "exact", "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "payTo": "0x2222222222222222222222222222222222222222", "amount": "1",
}
OFFER_B = {**OFFER_A, "amount": "100", "payTo": "0x3333333333333333333333333333333333333333"}
OFFER_A_DIGEST = digest_of(OFFER_A)

# Authority-decision pair: the same request is reduced under two different host-policy
# limits. The protected record can distinguish the reductions only when it commits to the
# exact canonical decision-evidence object. This is structural binding only: it does not
# authenticate the producer or validate that the reduction itself is truthful.
DECISION_EVIDENCE_A = {
    "requested": {"capabilities": ["read"], "budgets": {"nodes": "10"}},
    "hostAllowed": {"capabilities": ["read"], "budgets": {"nodes": "10"}},
    "effective": {"capabilities": ["read"], "budgets": {"nodes": "10"}},
    "delta": {"removed": {}, "reducedBudgets": {}},
    "policy": {"id": "host-default", "version": "1"},
}
DECISION_EVIDENCE_B = {
    "requested": {"capabilities": ["read"], "budgets": {"nodes": "10"}},
    "hostAllowed": {"capabilities": ["read"], "budgets": {"nodes": "5"}},
    "effective": {"capabilities": ["read"], "budgets": {"nodes": "5"}},
    "delta": {
        "removed": {},
        "reducedBudgets": {"nodes": {"requested": "10", "effective": "5"}},
    },
    "policy": {"id": "host-default", "version": "2"},
}
DECISION_EVIDENCE_A_DIGEST = digest_of(DECISION_EVIDENCE_A)
DECISION_EVIDENCE_B_DIGEST = digest_of(DECISION_EVIDENCE_B)
assert DECISION_EVIDENCE_A_DIGEST == "0x68b2b24ff10af252ca43df157efcf23d05098d8deafa0bb22126bee8c6c2f097"
assert DECISION_EVIDENCE_B_DIGEST == "0x6f1e5578989368eebfa56b16bea09352aecc4f2f17ec7831301121c72100a909"

# Boundary-binding prefix: the three records a boundary event extends. Its digest is computed
# here, so a drift in canonical() breaks generation rather than silently re-pinning the vector.
BOUNDARY_PREFIX = [
    {"event": "record", "seq": 1},
    {"event": "record", "seq": 2},
    {"event": "record", "seq": 3},
]
BOUNDARY_PREFIX_DIGEST = digest_of(BOUNDARY_PREFIX)

# Suite-transition pair: the digest the SAME canonical bytes take under the successor
# suite (sha3-256). Computed live so it is exactly the value a verifier arrives at if it
# re-digests history under the new algorithm at a transition — the failure mode n29 pins.
SUCCESSOR_SUITE_PREFIX_DIGEST = "0x" + hashlib.sha3_256(
    canonical(BOUNDARY_PREFIX).encode("utf-8")).hexdigest()

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
        "description": "A complete per-seller set: every sequence number 1..head present, prev pointers continuous, per-record links recompute (link = keccak256(artifact || prev || seq_be8), prev = previous artifact digest — the production form each counter-signature covers), head digest matches the final record.",
        "input": {
            "head": {"seq": 3, "digest": d[2]},
            "records": [
                {"seq": 1, "artifact_digest": d[0], "prev_digest": None, "link": links[0]},
                {"seq": 2, "artifact_digest": d[1], "prev_digest": d[0], "link": links[1]},
                {"seq": 3, "artifact_digest": d[2], "prev_digest": d[1], "link": links[2]},
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
    # ------------------------------------------------- number-domain boundary (2-sided)
    {
        "id": "p12-ijson-integer-boundary",
        "kind": "digest_recompute",
        "expect": "valid",
        "description": "The largest I-JSON-interoperable integer, 2^53-1: inside the domain, digested identically by every RFC 8785 implementation. The accepting twin of n11 — a verifier that refuses the boundary value itself fails this vector.",
        "input": {"payload": {"n": 9007199254740991}, "expected_digest": digest_of({"n": 9007199254740991})},
    },
    {
        "id": "p13-decimal-string-beside-integer",
        "kind": "digest_recompute",
        "expect": "valid",
        "description": "Pinned in lockstep with the compliance-fields extension (x402-foundation/x402#2853, Numbers): a fractional amount as a decimal STRING with a trailing zero, beside an exact integer — the only two value forms the record domain admits. A pipeline that coerces the numeric-looking string through a number type re-emits 1.1 (dropping the trailing zero) and fails the digest; the exact integer serializes identically everywhere. Digest cross-checked on two unrelated stacks before pinning.",
        "input": {"payload": DECIMAL_STRING_VECTOR, "expected_digest": DECIMAL_STRING_DIGEST},
    },
    {
        "id": "n10-float-in-digest-domain",
        "kind": "canonical_bytes",
        "expect": "reject",
        "reason": "number_domain_reject",
        "description": "A non-integer JSON number in the digest domain. RFC 8785 §3.2.2.3 serializes numbers via ECMAScript Number::toString over IEEE 754 doubles, so a fractional value's bytes depend on the producer's number pipeline — and the digest binds the nearest double, not the decimal the source system held. The domain refuses the class rather than reproducing its damage deterministically.",
        "input": {"payload": {"amount": 1.1}, "claimed_canonical": '{"amount":1.1}'},
    },
    {
        "id": "n11-integer-beyond-ijson-range",
        "kind": "digest_recompute",
        "expect": "reject",
        "reason": "number_domain_reject",
        "description": "2^53 — one past the I-JSON interoperable bound. Beyond 2^53-1, distinct integers share a double representation, so implementations disagree on the serialized form. The rejecting twin of p12.",
        "input": {"payload": {"n": 9007199254740992}, "expected_digest": "0x" + "00" * 32},
    },
    # -------------------------------------- supplementary-plane key ordering (2-sided)
    {
        "id": "p14-supplementary-plane-key-order",
        "kind": "digest_recompute",
        "expect": "valid",
        "description": "Keys where UTF-16 code-unit order diverges from code-point order: U+10000 encodes as a surrogate pair whose first unit (0xD800) sorts BELOW U+FF61, so RFC 8785 puts the supplementary-plane key FIRST while a code-point sort puts it LAST. The suite's README asserted this property; until this vector, no vector exercised it.",
        "input": {"payload": SUPP_PAYLOAD, "expected_digest": digest_of(SUPP_PAYLOAD)},
    },
    {
        "id": "n12-codepoint-key-order",
        "kind": "canonical_bytes",
        "expect": "reject",
        "reason": "canonicalization_reject",
        "description": "The adversarial twin of p14: canonical bytes claimed in CODE-POINT key order — the exact output of an implementation sorting by code point (e.g. Python sorted() over str). Must reject: RFC 8785 orders by UTF-16 code units.",
        "input": {"payload": SUPP_PAYLOAD, "claimed_canonical": '{"｡":1,"\U00010000":2}'},
    },
    # ------------------------------------------- independence: alias + shape fail-closed
    {
        "id": "n13-party-alias-whitespace",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "A party re-attesting as its own 'outside' witness by appending trailing whitespace to its address. Identity comparison runs after normalization (strip + lowercase), so the alias resolves back to the party and the record is attested only by parties. Without normalization this fails OPEN — the alias counts as a non-party attestor and an issuer-only record verifies as independent.",
        "input": {
            "claimed": "independent",
            "parties": ["0x2222222222222222222222222222222222222222", "0x3333333333333333333333333333333333333333"],
            "attestations": [
                {"by": "0x2222222222222222222222222222222222222222", "role": "payer"},
                {"by": "0x3333333333333333333333333333333333333333 ", "role": "auditor"},
            ],
        },
    },
    {
        "id": "n14-unparseable-attestor",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "An attestor identifier carrying an invisible format character (U+200B zero-width space) inside the hex. Not parseable as an address, therefore not evaluable as an identity — and an independence claim whose attestor cannot be evaluated fails closed rather than counting the mangled string as 'outside the parties'.",
        "input": {
            "claimed": "independent",
            "parties": ["0x2222222222222222222222222222222222222222", "0x3333333333333333333333333333333333333333"],
            "attestations": [
                {"by": "0x2222222222222222222222222222222222222222", "role": "payer"},
                {"by": "0x9d38BA84730271eb27Ac9bD4\u200bBd2620c08dB4FDa6", "role": "counter-signing ledger"},
            ],
        },
    },
    {
        "id": "n15-claim-without-attestations",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "Independence claimed, no attestations present at all. A claim that cannot be evaluated must not pass by absence of evidence — failing closed also means returning a verdict where the previous implementation raised KeyError and produced none.",
        "input": {
            "claimed": "independent",
            "parties": ["0x2222222222222222222222222222222222222222", "0x3333333333333333333333333333333333333333"],
        },
    },
    {
        "id": "n16-attestation-not-an-object",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "An attestation presented as a bare string rather than an object naming its attestor. Not an evaluable attestation shape — the previous implementation raised TypeError on it, producing no verdict; a conformant verifier returns a reject.",
        "input": {
            "claimed": "independent",
            "parties": ["0x2222222222222222222222222222222222222222", "0x3333333333333333333333333333333333333333"],
            "attestations": ["0x9d38BA84730271eb27Ac9bD4Bd2620c08dB4FDa6"],
        },
    },
    # --------------------------------------------------- chain-set: renumbered omission
    {
        "id": "n17-renumbered-omission",
        "kind": "chain_set",
        "expect": "reject",
        "reason": "continuity_reject",
        "description": "Omission hidden by renumbering: record 2 dropped, record 3 relabeled seq 2 with its prev pointer rewritten — the sequence closure LOOKS complete. The relabeled record still carries the link computed for its ORIGINAL position (artifact || old-prev || old-seq), and the per-record link recomputation diverges. In production each link is counter-signed at transaction time, so a forger cannot recompute them to match; the stale link is exactly the artifact of that constraint.",
        "input": {
            "head": {"seq": 2, "digest": d[2]},
            "records": [
                {"seq": 1, "artifact_digest": d[0], "prev_digest": None, "link": links[0]},
                {"seq": 2, "artifact_digest": d[2], "prev_digest": d[0], "link": links[2]},
            ],
        },
    },
    # ------------------------------------------------------- phase: closed vocabulary
    {
        "id": "n18-unrecognized-phase",
        "kind": "phase_claim",
        "expect": "reject",
        "reason": "phase_reject",
        "description": "A phase token outside the declared vocabulary ('settled_and_delivered'), presented as delivery evidence. An uninterpretable phase must not verify as ANY phase — the same fail-closed rule the independence criterion applies to claims it cannot read.",
        "input": {
            "record": {"economic_phase": "settled_and_delivered", "amount": "10", "asset": "USDC"},
            "presented_as": "delivery",
        },
    },
    # ------------------------------ independence: commitment scope (2-sided, 4th MUST NOT)
    {
        "id": "p16-independence-scope-committed",
        "kind": "independence_claim",
        "expect": "valid",
        "description": "Accepting twin of n20: independence claimed over both facts the record commits to — the commitments DERIVED from a settlement result whose success carries a resolvable transaction reference ('settlement') and a non-empty network ('network'). The commitment-scope rule (proposed in x402-foundation/x402#2887, 2026-07-27; normative in the compliance-fields extension): an independence claim reaches exactly as far as the record's commitments. Rebuilt on a settlement result rather than a declared list when the declared path was removed — a declared list was the very assertion the rule exists to bound (@Rul1an, issue #4, second report).",
        "input": {
            "claimed": "independent",
            "covers": ["settlement", "network"],
            "settlement_result": {
                "success": True,
                "transaction": "0x4b8a1d6e2f9c0a7b5d3e8f1a6c4b2d0e9f7a5c3b1d8e6f4a2c0b9d7e5f3a1c8b",
                "network": "eip155:8453",
            },
            "parties": ["0x2222222222222222222222222222222222222222", "0x3333333333333333333333333333333333333333"],
            "attestations": [
                {"by": "0x2222222222222222222222222222222222222222", "role": "payer"},
                {"by": LEDGER_SIGNER, "role": "counter-signing ledger"},
            ],
        },
    },
    {
        "id": "n20-independence-scope-uncommitted",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "Rejecting twin of p16: independence claimed as covering 'delivery' while the record's derived commitments are 'settlement' and 'network' — a resolvable settlement, and nothing about delivered bytes. However independent the attestor, the attestation covered the committed facts and nothing else — an evaluator MUST NOT read the claim past the commitment. The genuinely non-party attestation is what makes this vector discriminating: only the scope overreach can produce the reject. Rebuilt on a settlement result rather than a declared list (@Rul1an, issue #4, second report) so the reject stays an overreach reject, not an unevaluable-input one.",
        "input": {
            "claimed": "independent",
            "covers": ["delivery"],
            "settlement_result": {
                "success": True,
                "transaction": "0x4b8a1d6e2f9c0a7b5d3e8f1a6c4b2d0e9f7a5c3b1d8e6f4a2c0b9d7e5f3a1c8b",
                "network": "eip155:8453",
            },
            "parties": ["0x2222222222222222222222222222222222222222", "0x3333333333333333333333333333333333333333"],
            "attestations": [
                {"by": "0x2222222222222222222222222222222222222222", "role": "payer"},
                {"by": LEDGER_SIGNER, "role": "counter-signing ledger"},
            ],
        },
    },
    {
        "id": "p17-independence-scope-derived-settlement",
        "kind": "independence_claim",
        "expect": "valid",
        "description": "Accepting twin of n21: independence claimed over 'settlement', where the commitments are DERIVED from the settlement result rather than declared by it. The result claims success and carries a resolvable transaction reference, so settlement is genuinely among the record's commitments and a non-party attestation may reach it.",
        "input": {
            "claimed": "independent",
            "covers": ["settlement"],
            "settlement_result": {
                "success": True,
                "transaction": "0x9e1f4c2a8b7d6e5f0a3c1b8d7e6f5a4c3b2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f",
                "network": "eip155:8453",
            },
            "parties": ["0x2222222222222222222222222222222222222222", "0x3333333333333333333333333333333333333333"],
            "attestations": [
                {"by": "0x2222222222222222222222222222222222222222", "role": "payer"},
                {"by": LEDGER_SIGNER, "role": "counter-signing ledger"},
            ],
        },
    },
    {
        "id": "n21-independence-scope-empty-settlement",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "Rejecting twin of p17, and the reason commitments must be DERIVED rather than declared. x402 v2 \u00a75.3.2 defines the empty string as what `transaction` carries when settlement failed, while the type only requires a string \u2014 so `success: true` with `transaction: \"\"` is well formed and commits to no settlement anyone can resolve. A declared commitment list would let such a record assert the very scope the commitment-scope rule exists to bound, making the rule vacuous exactly where it matters. Deriving the commitments off the result rejects it without resolving anything on-chain. Reported by @Rul1an (issue #4).",
        "input": {
            "claimed": "independent",
            "covers": ["settlement"],
            "settlement_result": {"success": True, "transaction": "", "network": "eip155:8453"},
            "parties": ["0x2222222222222222222222222222222222222222", "0x3333333333333333333333333333333333333333"],
            "attestations": [
                {"by": "0x2222222222222222222222222222222222222222", "role": "payer"},
                {"by": LEDGER_SIGNER, "role": "counter-signing ledger"},
            ],
        },
    },
    {
        "id": "n22-independence-scope-declared-override",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "The override attack, pinned: n21's unresolvable settlement PLUS a declared `record_commits` list asserting the very scope the derivation denies. When the derivation was first shipped as a fallback behind the declared read, this input scored valid — the declared list overrode the derived commitments, making the derived-not-declared property decorative. The declared field's PRESENCE is now the reject, whatever it holds: a commitment scope a record asserts about itself is not evidence of that scope. Reported with this exact reproduction by @Rul1an (issue #4, second report).",
        "input": {
            "claimed": "independent",
            "covers": ["settlement"],
            "settlement_result": {"success": True, "transaction": "", "network": "eip155:8453"},
            "record_commits": ["settlement"],
            "parties": ["0x2222222222222222222222222222222222222222", "0x3333333333333333333333333333333333333333"],
            "attestations": [
                {"by": "0x2222222222222222222222222222222222222222", "role": "payer"},
                {"by": LEDGER_SIGNER, "role": "counter-signing ledger"},
            ],
        },
    },
    {
        "id": "n23-independence-scope-null-declared",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "The engine-fork input, pinned: a resolvable settlement result with `record_commits` present as an explicit JSON null. Python's `is None` read the null as absence and derived (valid); the TS cross-check's `=== undefined` read it as a declaration and rejected — two implementations of one criterion, two verdicts, invisible to a manifest-oracle cross-check because no vector carried a null. An explicit null is a declaration that evaluates to nothing, which fails closed for the same reason an unrecognized claim string does (design rule 3, issue #1). Both engines now guard on key PRESENCE — `in`, identical semantics in both languages — so this fork is unrepresentable rather than merely untested. Reported by @Rul1an (issue #4, second report).",
        "input": {
            "claimed": "independent",
            "covers": ["settlement"],
            "settlement_result": {
                "success": True,
                "transaction": "0x9e1f4c2a8b7d6e5f0a3c1b8d7e6f5a4c3b2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f",
                "network": "eip155:8453",
            },
            "record_commits": None,
            "parties": ["0x2222222222222222222222222222222222222222", "0x3333333333333333333333333333333333333333"],
            "attestations": [
                {"by": "0x2222222222222222222222222222222222222222", "role": "payer"},
                {"by": LEDGER_SIGNER, "role": "counter-signing ledger"},
            ],
        },
    },
    {
        "id": "n24-independence-scope-declared-no-scope",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "The second half of the presence rule, which n22 and n23 do not reach: `record_commits` present with NO scope asserted at all. Both of those carry `covers`, so a verifier that puts the presence check INSIDE its commitment-scope branch passes the whole corpus while accepting this — a misreading available from this suite's own README, where the rule is introduced under the commitment-scope property and both illustrating vectors assert a scope. The differential harness generates this shape but cannot pin it: its oracle is divergence between engines, and two engines making the same misreading move together. Reported, with a patched stand-in engine and the result table, by @Rul1an (issue #4).",
        "input": {
            "claimed": "independent",
            "record_commits": ["settlement"],
            "parties": ["0x2222222222222222222222222222222222222222", "0x3333333333333333333333333333333333333333"],
            "attestations": [
                {"by": "0x2222222222222222222222222222222222222222", "role": "payer"},
                {"by": LEDGER_SIGNER, "role": "counter-signing ledger"},
            ],
        },
    },
    # ------------------ independence: delivery commitment (2-sided, new commitment class)
    # tersignhq/evidence-record-conformance#3 (2026-08-19): until p23/n33, no derivation
    # could emit "delivery" — n20/n21 above rejected covers=["delivery"] because the
    # vocabulary had no delivery derivation at all, a vocabulary gap rather than a scope
    # decision. derive_delivery_commits now reads it off the record's own bytes. This pair
    # is deliberately independent of that engine change, which is what makes it a control:
    # p22 never reaches the derivation (claimed is silent, independence is not evaluated
    # at all — the record commits to delivery and asserts nothing about who delivered
    # it); n32 rejects on the independence check itself (deliverer's own signature is the
    # only attestation, and the deliverer is a party), before the commitment-scope branch
    # runs, so its verdict and reason do not change once delivery becomes derivable. Real
    # v2-sig provenance-tier values (0rkz/foreseal-x402-conformance, Apache-2.0):
    # keccak256(DELIVERY_ANSWER_SLICE) == DELIVERY_DIGEST, re-checked above against this
    # suite's own vendored keccak256, not merely copied from the source repo. That
    # DELIVERY_SIGNER is who it claims to be is asserted OUT-OF-BAND, not by this vector
    # or the verifier — same disclaimer as the rest of this suite's live vectors.
    {
        "id": "p22-delivery-commitment-recomputed",
        "kind": "independence_claim",
        "expect": "valid",
        "description": "A record carries a deliverable digest that recomputes from the record's own presented bytes (keccak256(DELIVERY_ANSWER_SLICE) == DELIVERY_DIGEST), signed by an address distinct from the settlement payTo. Identity binding — that the signing address is who it claims to be — is stated out-of-band, as it is for this suite's other live vectors; the vector commits to the digest, not to the signer's real-world identity. No independence is claimed — the record commits to delivery and asserts nothing about who delivered it, or about the signer being non-party. Silence is a valid state (p9); this is that same rule on a delivery commitment instead of a settlement one. Reported by @0rkz against tersignhq/evidence-record-conformance#3 (2026-08-19, @wowlegend).",
        "input": {
            "claimed": "none",
            "deliverable_bytes": DELIVERY_ANSWER_SLICE,
            "deliverable_digest": DELIVERY_DIGEST,
            "deliverable_signer": DELIVERY_SIGNER,
            "payTo": DELIVERY_PAY_TO,
            "parties": [DELIVERY_PAYER, DELIVERY_SIGNER],
            "attestations": [
                {"by": DELIVERY_SIGNER, "role": "deliverer"},
            ],
        },
    },
    {
        "id": "n32-delivery-self-attested",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "Same record as p22, with independence claimed over the new commitment: `claimed: \"independent\"`, `covers: [\"delivery\"]`. The record's only attestation for the deliverable is the deliverer's own signature, and the deliverer is a party to the transaction (a different address from payTo, but not thereby independent — the position/faculty distinction @Rul1an drew for p17/n21 applies here unchanged). `outside` stays 0 on the parties/attestations check, so this rejects there, before the commitment-scope branch is reached — the same reason it rejected before delivery was derivable and the same reason it rejects now that it is (p23/n33 drive the derivation; this vector does not move under it), per @wowlegend on tersignhq/evidence-record-conformance#3 (2026-08-19): commitment scope doing its job on the new commitment, not a vocabulary gap.",
        "input": {
            "claimed": "independent",
            "covers": ["delivery"],
            "deliverable_bytes": DELIVERY_ANSWER_SLICE,
            "deliverable_digest": DELIVERY_DIGEST,
            "deliverable_signer": DELIVERY_SIGNER,
            "payTo": DELIVERY_PAY_TO,
            "parties": [DELIVERY_PAYER, DELIVERY_SIGNER],
            "attestations": [
                {"by": DELIVERY_SIGNER, "role": "deliverer"},
            ],
        },
    },
    # The derivation itself, DRIVEN (p23/n33). p22/n32 never reach it — p22's claim is silent
    # and n32 rejects upstream on the independence count — so a suite green on those two alone
    # is green with the delivery derivation absent: the n29 shape, a correct verdict reached by
    # an early exit. p23 is the falsifying input for the pre-derivation engine (which read
    # covers=["delivery"] as unevaluable and rejected it); n33 is its substitution twin — the
    # presented bytes are not the bytes that were digested, so the record commits to no
    # delivery and the claim overreaches. Same live PayPerByte fixture as p22 (@0rkz, PR #7);
    # the non-party attestor is the counter-signing ledger, exactly as in p16.
    {
        "id": "p23-delivery-independence-within-commitment",
        "kind": "independence_claim",
        "expect": "valid",
        "description": "Accepting twin of n33, and the vector that drives the delivery derivation p22/n32 anticipated. The record commits to delivery — keccak256(deliverable_bytes) recomputes to deliverable_digest — and a non-party (the counter-signing ledger) attests alongside the deliverer, so `claimed: \"independent\"`, `covers: [\"delivery\"]` is a claim within the record's own DERIVED commitments. No settlement result is present: a record can commit to delivery without committing to settlement, which is the shape acceptance evidence takes downstream of a settlement record rather than inside it. Built on @0rkz's PayPerByte fixture (PR #7, issue #3); the pre-derivation engine rejected this exact input as unevaluable, which is what made it the falsifying case (repo rule 1).",
        "input": {
            "claimed": "independent",
            "covers": ["delivery"],
            "deliverable_bytes": DELIVERY_ANSWER_SLICE,
            "deliverable_digest": DELIVERY_DIGEST,
            "deliverable_signer": DELIVERY_SIGNER,
            "payTo": DELIVERY_PAY_TO,
            "parties": [DELIVERY_PAYER, DELIVERY_SIGNER],
            "attestations": [
                {"by": DELIVERY_SIGNER, "role": "deliverer"},
                {"by": LEDGER_SIGNER, "role": "counter-signing ledger"},
            ],
        },
    },
    {
        "id": "n33-delivery-substitution-scope-overreach",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "Rejecting twin of p23: same claim, same non-party attestation, same digest — but the presented deliverable bytes are not the bytes that were digested (`\"verdict\":\"ALLOW\"` substituted with `\"verdict\":\"DENY\"` — the delivered verdict flipped, the tamper a reader would care about). The digest no longer recomputes, so the record commits to no delivery, and an independence claim covering `delivery` reaches past the record's commitments — n20's overreach on a delivery commitment instead of a settlement one. It rejects on the scope branch (commitments evaluated and found empty), not the unevaluable one: a record that presents bytes and a digest HAS presented a commitment for evaluation; it simply fails it. This suite pins verdict and reason; the branch is visible in the stdlib verifier's detail line (`claim covers ['delivery'] — fact(s) the record does not commit to`, not `commitments are not evaluable`). The genuinely non-party attestation keeps this discriminating — an engine that trusts a declared digest without recomputing it accepts this vector.",
        "input": {
            "claimed": "independent",
            "covers": ["delivery"],
            "deliverable_bytes": DELIVERY_ANSWER_SLICE_SUBSTITUTED,
            "deliverable_digest": DELIVERY_DIGEST,
            "deliverable_signer": DELIVERY_SIGNER,
            "payTo": DELIVERY_PAY_TO,
            "parties": [DELIVERY_PAYER, DELIVERY_SIGNER],
            "attestations": [
                {"by": DELIVERY_SIGNER, "role": "deliverer"},
                {"by": LEDGER_SIGNER, "role": "counter-signing ledger"},
            ],
        },
    },
    # -------------------------------------- boundary binding (2-sided, 3 known failure classes)
    {
        "id": "p18-boundary-binds-prefix-and-position",
        "kind": "boundary_binding",
        "expect": "valid",
        "description": "Accepting twin: a boundary event that changes a stream's verification parameters binds BOTH the canonical digest of the prefix it extends and its own position in that prefix's continuation, and the coverage it claims is within the prefix its attestation actually reaches. A verifier holding only the stream can check every one of those.",
        "input": {
            "prefix": [
                {"event": "record", "seq": 1},
                {"event": "record", "seq": 2},
                {"event": "record", "seq": 3},
            ],
            "boundary_event": {
                "event": "witness_ref_introduced",
                "ruleVersion": "witness-ref-v1",
                "prefixDigest": BOUNDARY_PREFIX_DIGEST,
                "position": 3,
                "attestedPrefixLength": 3,
            },
            "covered_through": 3,
        },
    },
    {
        "id": "n25-boundary-prefix-only-no-position",
        "kind": "boundary_binding",
        "expect": "reject",
        "reason": "boundary_reject",
        "description": "The fabricated-boundary class. The event names the prefix it extends TRUTHFULLY — the digest recomputes — but binds nothing about its own position in that prefix's continuation. Two conflicting continuations of the same prefix can therefore both name it truthfully, and a verifier accepts either without being able to say which the deployment committed to; an event appended later claiming an earlier effective point is indistinguishable from one that was always there. Demonstrated against a live implementation and reproduced four independent ways in modelcontextprotocol/modelcontextprotocol#3004 (2026-08-08/09), where @Tetsurohhori then made the binding retrospective and @navigatorbuilds restated the rule normatively.",
        "input": {
            "prefix": [
                {"event": "record", "seq": 1},
                {"event": "record", "seq": 2},
                {"event": "record", "seq": 3},
            ],
            "boundary_event": {
                "event": "witness_ref_introduced",
                "ruleVersion": "witness-ref-v1",
                "prefixDigest": BOUNDARY_PREFIX_DIGEST,
            },
        },
    },
    {
        "id": "n26-coverage-claimed-over-empty-attestation",
        "kind": "boundary_binding",
        "expect": "reject",
        "reason": "boundary_reject",
        "description": "The downgrade class. Everything binds correctly, and the stream claims coverage through position 3 while the attestation reaches an empty prefix. A verifier that falls back to digest and link arithmetic when it cannot find the attestation reports success having checked nothing — and says so in the same breath, which is how @Tetsurohhori found it in his own tool (2026-08-09): VERIFY OK printed beside attested_prefix_lines=0. An offline snapshot is then indistinguishable from a verified stream, so unattested must be its own outcome rather than a pass.",
        "input": {
            "prefix": [
                {"event": "record", "seq": 1},
                {"event": "record", "seq": 2},
                {"event": "record", "seq": 3},
            ],
            "boundary_event": {
                "event": "witness_ref_introduced",
                "ruleVersion": "witness-ref-v1",
                "prefixDigest": BOUNDARY_PREFIX_DIGEST,
                "position": 3,
                "attestedPrefixLength": 0,
            },
            "covered_through": 3,
        },
    },
    # ------------------------------- decision-evidence binding (2-sided, 2 failures)
    {
        "id": "p19-authority-reduction-bound",
        "kind": "decision_evidence_binding",
        "expect": "valid",
        "description": "Accepting twin: the protected record commits to the exact canonical decision-evidence object, so the presented requested-to-effective authority reduction is structurally distinguishable from another reduction.",
        "input": {
            "record": {
                "outcome": "allowed",
                "decisionEvidenceDigest": DECISION_EVIDENCE_A_DIGEST,
            },
            "decision_evidence": DECISION_EVIDENCE_A,
        },
    },
    {
        "id": "n27-authority-reduction-unbound",
        "kind": "decision_evidence_binding",
        "expect": "reject",
        "reason": "binding_reject",
        "description": "CG-DELTA-LOSS-01, unbound case: the protected record carries no decision-evidence digest, so the presented authority reduction is not structurally bound to it and must reject. This vector tests only the missing-commitment branch; p19/n28 execute the distinct A/B substitution contrast.",
        "input": {
            "record": {"outcome": "allowed"},
            "decision_evidence": DECISION_EVIDENCE_B,
        },
    },
    {
        "id": "n28-authority-reduction-substitution",
        "kind": "decision_evidence_binding",
        "expect": "reject",
        "reason": "binding_reject",
        "description": "Substitution case: the record commits to authority reduction A while reduction B, carrying a different host limit, delta and policy version, is presented.",
        "input": {
            "record": {
                "outcome": "allowed",
                "decisionEvidenceDigest": DECISION_EVIDENCE_A_DIGEST,
            },
            "decision_evidence": DECISION_EVIDENCE_B,
        },
    },
    {
        "id": "p20-suite-transition-preserves-prefix",
        "kind": "boundary_binding",
        "expect": "valid",
        "description": "The algorithm-transition accepting twin, requested by Songbo Bu on the IETF web-bot-auth list (2026-08-09): an algorithm-transition vector that preserves the prior prefix without rewriting it. A transition event that moves the stream's digest suite forward (here keccak256 \u2192 sha3-256, for the continuation) binds the prefix under the suite IN FORCE WHEN THE PREFIX WAS WRITTEN: the prior records stay byte-for-byte as committed, their original digest remains the binding, and the event binds its own position exactly as p18 requires. The successor suite governs records after the boundary \u2014 never the history the boundary extends.",
        "input": {
            "prefix": [
                {"event": "record", "seq": 1},
                {"event": "record", "seq": 2},
                {"event": "record", "seq": 3},
            ],
            "boundary_event": {
                "event": "digest_suite_transition",
                "ruleVersion": "suite-transition-v1",
                "fromSuite": "keccak256-jcs",
                "toSuite": "sha3-256-jcs",
                "prefixDigest": BOUNDARY_PREFIX_DIGEST,
                "position": 3,
                "attestedPrefixLength": 3,
            },
            "covered_through": 3,
        },
    },
    {
        "id": "n29-suite-transition-redigests-prefix",
        "kind": "boundary_binding",
        "expect": "reject",
        "reason": "boundary_reject",
        "description": "The retroactive-re-digest class. The same transition event names the same three records \u2014 but the digest it binds is computed under the SUCCESSOR suite (sha3-256 over the identical canonical bytes). That is precisely the value a verifier arrives at if it helpfully re-hashes history under the new algorithm at a transition, which is what makes this vector discriminating rather than trivially wrong: an engine with that bug AGREES with the claimed digest and accepts. The binding to the bytes as originally committed is broken \u2014 any re-forged prefix that digests correctly under the new suite could stand in for the history \u2014 so prefix preservation across a transition means the prior suite's digest remains the binding, and this rejects.",
        "input": {
            "prefix": [
                {"event": "record", "seq": 1},
                {"event": "record", "seq": 2},
                {"event": "record", "seq": 3},
            ],
            "boundary_event": {
                "event": "digest_suite_transition",
                "ruleVersion": "suite-transition-v1",
                "fromSuite": "keccak256-jcs",
                "toSuite": "sha3-256-jcs",
                "prefixDigest": SUCCESSOR_SUITE_PREFIX_DIGEST,
                "position": 3,
                "attestedPrefixLength": 3,
            },
            "covered_through": 3,
        },
    },
    # ------------------------------- identity-syntax portability (2-sided, URN identities)
    # The independence criterion compares attestor identity. Until 2026-08-19 its normaliser
    # parsed 0x-addresses only, so under any other identity syntax it rejected on the
    # identifier before reaching the question — it could not return valid for that syntax at
    # all. Found against a foreign corpus (AXES Golden Trace v2 custody twins, axes#6): we
    # rejected the twin the corpus accepts. @Rul1an (issue #1) traced the regression to
    # d50545a — the aliasing fail-closed fix, 4 days after a published control — and proposed
    # the gate: for every syntax identifier_normalization says it evaluates, one accepting
    # vector of each kind. These two are that gate for URN identities; the per-kind
    # two-sidedness check in verify.py now makes their disappearance go red.
    {
        "id": "p21-independence-urn-identities",
        "kind": "independence_claim",
        "expect": "valid",
        "description": "Identity-syntax portability, accepting twin. The same independence predicate as p8, under scheme-qualified identities (org:/agent:) instead of 0x-addresses: the attestor is a party outside the transaction, so the claim holds. Shaped on the accepting custody twin of a foreign corpus, which this criterion rejected on the identifier alone until 2026-08-19. An engine bound to one identity syntax must fail this vector.",
        "input": {
            "claimed": "independent",
            "parties": ["org:caldera-robotics", "agent:caldera/ap-pilot"],
            "attestations": [{"by": "org:trustline-custody/eu-west"}],
        },
    },
    {
        "id": "n30-independence-urn-self-attested",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "Identity-syntax portability, rejecting twin. Same identities, but the sole attestor IS the deployer — attested only by parties to the transaction. Must reject for the independence reason, not for an unparseable identifier: a normaliser that rejected p21 and this vector on the same identifier branch would agree with the expected verdict here for the wrong reason, which is exactly what the accepting twin exists to separate.",
        "input": {
            "claimed": "independent",
            "parties": ["org:caldera-robotics", "agent:caldera/ap-pilot"],
            "attestations": [{"by": "org:caldera-robotics"}],
        },
    },
    {
        "id": "n31-independence-urn-alias-trailing-slash",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "Alias bypass under URN identities — n13's attack one syntax over. The deployer signs as `org:caldera-robotics/` (trailing slash) while the parties list carries `org:caldera-robotics`; a byte-exact comparison reads it as an outside attestor. The verifier does not own any scheme's equivalence rules, so it folds toward SAME PARTY (case, trailing `/` `.` `#`) and rejects. Found by the adversarial self-review that shipped p21 — the first URN normaliser was case-significant and accepted this. Known open sibling, deliberately NOT pinned as passing: percent-encoding (`org:caldera%2Drobotics`) still reads as distinct; decoding is scheme-specific and an open-ended normaliser is its own attack surface, so that boundary is stated here rather than hidden.",
        "input": {
            "claimed": "independent",
            "parties": ["org:caldera-robotics", "agent:caldera/ap-pilot"],
            "attestations": [{"by": "org:caldera-robotics/"}],
        },
    },
    # ------------------------------------------------------ offer binding (2-sided)
    {
        "id": "p15-offer-binding",
        "kind": "offer_binding",
        "expect": "valid",
        "description": "A receipt committing to the accepted offer's canonical digest, presented with that exact offer: the binding recomputes. This is the accepting twin of n19 — the mechanism that makes a receipt proof of TERMS, not merely proof of signature.",
        "input": {"offer": OFFER_A, "receipt": {"offerDigest": OFFER_A_DIGEST}},
    },
    {
        "id": "n19-offer-substitution",
        "kind": "offer_binding",
        "expect": "reject",
        "reason": "binding_reject",
        "description": "The offer-substitution class (reported upstream as x402-foundation/x402#3006): a second offer sharing resourceUrl/network with the accepted one but carrying different amount and payTo, presented against a receipt bound to the first offer's digest. Changing any term changes the canonical bytes, so the digest diverges and the substitution rejects — the regression criterion 'changing any one of amount, asset, payTo, scheme breaks verification', executable.",
        "input": {"offer": OFFER_B, "receipt": {"offerDigest": OFFER_A_DIGEST}},
    },
    # ------------------------------------ independence: unread member in a claim SET
    # Contributed by @Rul1an (PR #2): the rejecting twin of p11. n13-n16 above pin the
    # scalar/shape fail-closed cases; this pins the SET case — an unread member inside a
    # claim set, with a genuine outside attestor, so the only thing that can produce a
    # reject is the member the verifier cannot interpret.
    {
        "id": "n9-unrecognized-member-in-claim-set",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "Rejecting twin of p11: a claim SET carrying one silence token and one member the verifier cannot read, with an attestation from outside the parties. The outside attestor is what makes this discriminating rather than over-determined: p8 and p10 already pin that this attestation shape is valid, so the only thing that can produce a reject here is the unread member. Ignoring an unknown member is only safe where ignoring it can never turn a reject into a valid, which is not established for this field. Contributed by @Rul1an (issue #1 / PR #2).",
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
    "version": "0.4.0",
    "layer": "evidence-record",
    "profile": "structural (stdlib): digests, canonical bytes, chain arithmetic, sequence closure, declared-claim evaluation. Counter-signature recovery over the links (secp256k1 personal_sign) is the crypto profile, outside the stdlib core — a structurally complete set recomputed wholesale by one forging party passes the structural predicate; the counter-signatures are what prevent that in production.",
    "canonicalization": "RFC 8785 (JCS); vector domain is I-JSON with integer numerics (|n| <= 2^53-1); non-integer JSON numbers rejected (number_domain_reject); duplicate object names rejected",
    "content_address": "keccak256(utf8(canonical(payload)))",
    "chain_link": "keccak256(artifact_digest || prev_digest || seq_uint64_be) — wire form of a genesis predecessor is null; 32 zero bytes is the hashing-time substitution for null",
    "chain_set": "records chain raw artifact digests via prev pointers (genesis prev = null); head.digest equals the final record's artifact digest; completeness = every seq 1..head.seq present; where a record presents a link, it must recompute as keccak256(artifact || prev || seq_be8)",
    "anchor_relation": "anchored_digest = sha256(subject_digest_bytes)",
    "offer_binding": "receipt.offerDigest = keccak256(utf8(canonical(offer))); a receipt that commits to no offer digest cannot bind terms and fails closed",
    "decision_evidence_binding": "within this suite, record.decisionEvidenceDigest = keccak256(utf8(canonical(decision_evidence))); a record presented as authority-decision evidence must bind the exact object. This instantiates the general match/missing/mismatch binding property and does not prescribe a digest, canonicalization, or field location for AUEC, MCP, or another protocol; producer truth and decision semantics remain out of scope",
    "identifier_normalization": "two identity syntaxes, both evaluated by every criterion that compares identity (pinned by one accepting vector each under the per-kind two-sided gate): 0x-addresses compare after strip + lowercase; scheme-qualified identifiers (lowercase alnum scheme, one colon, printable non-space ASCII path) compare after strip, case-significant; digests compare after strip + lowercase; identifiers that do not parse after normalization fail closed",
    "commitment_derivation": "an independence claim reaches exactly as far as the record's DERIVED commitments, never a declared list (n22-n24): `settlement` when settlement_result.success is true and transaction is a non-empty string; `network` when settlement_result.network is a non-empty string; `delivery` when keccak256(utf8(deliverable_bytes)) == deliverable_digest. A record presenting none of these fields has no evaluable commitments (a scoped claim rejects as unevaluable); a record presenting them and committing to none has an EMPTY commitment set (a scoped claim rejects as overreach). Who delivered is not read by the derivation — position is the independence axis, decided before scope is",
    "field_naming": "harness-level input keys are snake_case (settlement_result, deliverable_bytes, decision_evidence, boundary_event); a key that quotes a protocol's own field keeps that protocol's wire spelling wherever it sits (payTo, resourceUrl, offerDigest, decisionEvidenceDigest). Contributed vectors follow the same two rules; the suite does not rename a protocol's fields to match its own, and does not camelCase its own",
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
