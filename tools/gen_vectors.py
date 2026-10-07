#!/usr/bin/env python3
"""Regenerate vectors/ + MANIFEST.json deterministically. Committed for transparency:
anyone can diff a regeneration against the committed bytes (nothing here is random —
regeneration is byte-identical). The three live-provenance vectors embed records from the
live ledger, cross-checkable against the public endpoints named in their `provenance`
blocks (the genesis record body at /v1/genesis; the anchor records at /v1/anchors/{id};
the genesis chain walked backwards through /v1/receipts/{digest}/verify)."""

import hashlib
import json
import os
import re
import sys
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from verify import canonical, digest_of, chain_link_digest, chain_acc_step, ACC_GENESIS, check_chain_set  # noqa: E402
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
# A synthetic party address with hex letters in both cases, for the cross-namespace alias
# vectors (n63-n66, n69, p37): the forms differ in case as well as in namespace.
CA1DE_ADDR = "0xCa1De7A500000000000000000000000000000Bb0"
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

# Chain-commitment accumulator over those links (v0.5.0): acc_0 = keccak256(utf8(schema)),
# acc_n = keccak256(acc_{n-1} || link_n). Pinned against the production ledger's own test
# suite (ledger/test/commitment.test.ts DEMO_ACCS) so a drift in either implementation
# breaks generation rather than silently re-pinning p26.
assert ACC_GENESIS == "0x79dde68558318c3f4b7d1af20992f140584708a1001befee3e4ec19c217acfe3", "commitment seed drifted"
accs = []
_acc = ACC_GENESIS
for _link in links:
    _acc = chain_acc_step(_acc, _link)
    accs.append(_acc)
assert accs == [
    "0xe720e2ed33d43c61b5dba81994d46200a51c1b28207c555c034fadc8877217f1",
    "0x067d811a57c765d912c1096b279c2bf19fd904830ab8d0c3f56c7ff2653a8e16",
    "0xae28e0e8b22b15cd27de2390efbe4e3c206decbfe5cede4751b85410f6648f4f",
], "demo accumulators drifted from the production pins"

# n36: record 1 substituted, prevs and links recomputed so the STRUCTURAL predicate (chain_set)
# still walks and the head digest is unchanged — only the accumulator tells the two prefixes
# apart. The true accumulator of the substituted chain is pinned so the vector cannot drift
# into carrying it by accident.
SUBSTITUTED_RECORD_1 = {"demo": 1, "note": "synthetic chain-set record (substituted)"}
d_sub = [digest_of(SUBSTITUTED_RECORD_1), d[1], d[2]]
assert d_sub[0] == "0x9473ed5e265517974b7a073afd50605372f918a60177ca3655da2117520ef53c"
links_sub = []
_prev = None
for _i, _art in enumerate(d_sub, 1):
    links_sub.append(chain_link_digest(_art, _prev, _i))
    _prev = _art
_acc = ACC_GENESIS
for _link in links_sub:
    _acc = chain_acc_step(_acc, _link)
SUBSTITUTED_TRUE_ACC = _acc
assert SUBSTITUTED_TRUE_ACC == "0x5479a41d713938384141892656be4e7e8e0ffbdf621b65b6f2194ccd2688e3ba"
assert SUBSTITUTED_TRUE_ACC != accs[2]

# n37: an accumulator folded over the LAST link only — the "anchor commits to the last record"
# shape the commitment exists to close.
LAST_LINK_ONLY_ACC = chain_acc_step(ACC_GENESIS, links[2])
assert LAST_LINK_ONLY_ACC == "0x4062010194c5605f41afc27e0094266c1cee5063703f5614901893c7fb67ec64"
assert LAST_LINK_ONLY_ACC != accs[2]

# v0.5.2 — duplicate sequence numbers (equivocation). Synthetic issuer records whose content
# quotes the extension's `seq` / `correctionSeq` (protocol spelling, per field_naming).
# ISSUER_R2A and ISSUER_R2B carry the SAME (seq, correctionSeq) and differ in content: two
# different records under one number. The suite fixes no convention for the correctionSeq an
# uncorrected record carries; equality of the pair is what defines the class.
ISSUER = "0x3333333333333333333333333333333333333333"  # the synthetic payee of p8/n7


def _issuer_record(seq, amount):
    return {"seq": seq, "correctionSeq": 0, "amount": amount, "note": "synthetic issuer record"}


def _row(seq, artifact, prev):
    return {"seq": seq, "artifact_digest": artifact, "prev_digest": prev, "link": chain_link_digest(artifact, prev, seq)}


ISSUER_R1 = digest_of(_issuer_record(1, "10.00"))
ISSUER_R2A = digest_of(_issuer_record(2, "20.00"))
ISSUER_R2B = digest_of(_issuer_record(2, "25.00"))  # same seq AND correctionSeq as R2A
ISSUER_R3 = digest_of(_issuer_record(3, "30.00"))
ISSUER_R3B = digest_of(_issuer_record(3, "25.00"))  # R2B renumbered to the next free number (p28)
ISSUER_R4 = digest_of(_issuer_record(4, "30.00"))   # R3 renumbered after it (p28)
assert len({ISSUER_R1, ISSUER_R2A, ISSUER_R2B, ISSUER_R3, ISSUER_R3B, ISSUER_R4}) == 6

# n39: the issuer's sequence forked after seq 1 — R2A and R2B both chain off R1 at position 2,
# each with the correct link for that position; R3 continues from R2A. p28: the same records,
# each at its own number.
DUP_SEQ_RECORDS = [
    _row(1, ISSUER_R1, None),
    _row(2, ISSUER_R2A, ISSUER_R1),
    _row(2, ISSUER_R2B, ISSUER_R1),
    _row(3, ISSUER_R3, ISSUER_R2A),
]
DISTINCT_SEQ_RECORDS = [
    _row(1, ISSUER_R1, None),
    _row(2, ISSUER_R2A, ISSUER_R1),
    _row(3, ISSUER_R3B, ISSUER_R2A),
    _row(4, ISSUER_R4, ISSUER_R3B),
]

# p29 / n40: the committed prefix (R1, R2A, R3) and the equivocating presentation (R1, R2B, R3),
# prevs and links recomputed. Both pass the structural chain_set predicate under ONE head
# digest — asserted here, so the claim that an issuer-only sequence cannot tell them apart is
# executed on every regeneration — and only the accumulator over every link differs.
COMMITTED_PREFIX = [_row(1, ISSUER_R1, None), _row(2, ISSUER_R2A, ISSUER_R1), _row(3, ISSUER_R3, ISSUER_R2A)]
EQUIVOCATING_PREFIX = [_row(1, ISSUER_R1, None), _row(2, ISSUER_R2B, ISSUER_R1), _row(3, ISSUER_R3, ISSUER_R2B)]
_acc = ACC_GENESIS
for _r in COMMITTED_PREFIX:
    _acc = chain_acc_step(_acc, _r["link"])
COMMITTED_PREFIX_ACC = _acc
_acc = ACC_GENESIS
for _r in EQUIVOCATING_PREFIX:
    _acc = chain_acc_step(_acc, _r["link"])
assert _acc != COMMITTED_PREFIX_ACC, "the two presentations must differ under the accumulator"
_head = {"seq": 3, "digest": ISSUER_R3}
assert check_chain_set({"head": _head, "records": COMMITTED_PREFIX})[0] == "valid"
assert check_chain_set({"head": _head, "records": EQUIVOCATING_PREFIX})[0] == "valid", \
    "the equivocating presentation must pass the issuer-only structural predicate under the same head"

# p27: the live ledger's genesis chain — 13 counter-signed records, walked backwards from the
# head through the public /verify endpoint on 2026-08-28 (13 GETs, prevDigest at each step),
# artifact digests and prevs in seq order. The commitment over this prefix is the subject of
# the confirmed anchor SELLER_COMMITMENT_ANCHOR; the fold below must reproduce its acc.
GENESIS_CHAIN_HEAD = "0x339800528596c7d53d32571ad999695aef6dfc8fc86dcc4fb827bb6080493961"
GENESIS_CHAIN_ACC = "0xfc831c0f98c8ea5df6417cd26afa278ed4ab82a1e682d170e47aa4a4173c5511"
GENESIS_CHAIN_COMMITMENT_DIGEST = "0xcbbef04598368ed02ae67fc0c8ffade6753628d0b8faf4e9211c9dd49a2dbe7b"
GENESIS_CHAIN_ANCHORED_DIGEST = "0x" + hashlib.sha256(bytes.fromhex(GENESIS_CHAIN_COMMITMENT_DIGEST[2:])).hexdigest()
assert GENESIS_CHAIN_ANCHORED_DIGEST == "0x7c00ab806c6a9cc3fd654c0cbb107224ccff80642ea289f3c8f226b592647675", "anchoredDigest of the live commitment drifted"
SELLER_COMMITMENT_ANCHOR = f"seller:{GENESIS_CHAIN_COMMITMENT_DIGEST}"
GENESIS_CHAIN_DIGESTS = [
    "0xe5874f1ffe87f0a6dd9eb157730f67b86ee4538b125fe30fcc4e165213dd3fc4",
    "0x89dbfc8c52bd5fa4ed5e879915518f9729cfbd74d9ab020e569eeffd881a4f1c",
    "0xdee12c6dd1f0a263811d26123224b493ddc3ee089a82aec2d149b87a09e10189",
    "0xddc12b814c54daa839b1e9e66820d7d28c5bbf254eec0004de2f9d8ba98331ae",
    "0x3cf272fb879bbe676992167cf2c7d46804f835972204e4b183b96281ebeed632",
    "0x2f1e9eaea561a71d386145886a2b432997d7d91aee95a0d83e3a1cdae1d2da0a",
    "0x236779752d6a336da2dbc965b00031408b2927975a8fe209710afa40ae696ae5",
    "0xb94bbc4fb7d7097039b2afaf244e30f56820cfe89dd7a2201a9a2a63a8ec4e38",
    "0x2c35d95f7c7f87678dd76d902e4c4809219f0952589ea5116af94997524fecf8",
    "0xe1cfd0af616a04a041bba95901c4b673cb61d8663e447943c2be1497393dc4fa",
    "0x7f1570bfb6949fc8fe4d87357e859ba7b901df501b88078a7dca0f4ddb4909b0",
    "0x45c5a3f282896f2899b6d2ae85b9c37d098c8deb6e6e2f49d531be270d757f2a",
    GENESIS_CHAIN_HEAD,
]
assert GENESIS_CHAIN_DIGESTS[0] == GENESIS_DIGEST, "the genesis chain starts at the genesis receipt (p1)"
GENESIS_CHAIN_RECORDS = [
    {"seq": _i, "artifact_digest": _art, "prev_digest": (None if _i == 1 else GENESIS_CHAIN_DIGESTS[_i - 2])}
    for _i, _art in enumerate(GENESIS_CHAIN_DIGESTS, 1)
]
_acc = ACC_GENESIS
_prev = None
for _r in GENESIS_CHAIN_RECORDS:
    _acc = chain_acc_step(_acc, chain_link_digest(_r["artifact_digest"], _prev, _r["seq"]))
    _prev = _r["artifact_digest"]
assert _acc == GENESIS_CHAIN_ACC, "live genesis-chain accumulator drifted"
assert digest_of({"acc": GENESIS_CHAIN_ACC, "head": GENESIS_CHAIN_HEAD, "schema": "tersign-chain-commitment-v1", "seq": 13}) == GENESIS_CHAIN_COMMITMENT_DIGEST, "live commitment digest drifted"

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

# v0.5.5 (issue #1, 2026-09-30) — non-ASCII string VALUES in the digest domain. Until v0.5.5
# the corpus carried non-ASCII only in keys (p14, n12), so an engine that escaped VALUES to ASCII
# before hashing passed every vector. Each accepting payload hashes keccak256 over the UTF-8
# bytes of its canonical form, code points as is (RFC 8785 §3.2.2.2, §3.2.4, no normalization
# §3.1); each rejecting twin carries the SAME payload with the digest one plausible wrong
# encoding produces. Every alternative encoding is computed here from the canonical text, so a
# drift in canonical() breaks generation rather than re-pinning a vector.
NON_ASCII_LATIN1 = {"a": "\u00e9"}          # e-acute, one code point U+00E9 (NFC); @Rul1an's input
NON_ASCII_CJK = {"a": "\u4e2d\u6587"}  # two BMP code points (zhong wen), three UTF-8 bytes each
NON_ASCII_ASTRAL = {"a": "\U00020bb7"}       # U+20BB7: surrogate pair D842 DFB7 in UTF-16
NON_ASCII_DECOMPOSED = {"a": "e\u0301"}      # e-acute as e + U+0301 COMBINING ACUTE ACCENT (NFD)


def _keccak_hex(b):
    return "0x" + keccak256(b).hex()


def _utf16_units(text):
    u = text.encode("utf-16-be", "surrogatepass")
    return [int.from_bytes(u[i:i + 2], "big") for i in range(0, len(u), 2)]


# n71: the text Python's json.dumps emits with its default ensure_ascii=True and the compact
# separators below — every non-ASCII code point as a \u escape, an astral one as an escaped
# surrogate pair. (With the default separators it writes a space after the colon.)
ESCAPED_LATIN1_TEXT = json.dumps(NON_ASCII_LATIN1, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
assert ESCAPED_LATIN1_TEXT == '{"a":"' + chr(92) + 'u00e9"}' and ESCAPED_LATIN1_TEXT.isascii()
# n72: one byte per UTF-16 code unit, its low eight bits — Node's Buffer.from(text, "latin1")
# (alias "binary"), measured 2026-10-01: U+4E2D -> 0x2d, U+6587 -> 0x87.
LATIN1_CJK_BYTES = bytes(u & 0xFF for u in _utf16_units(canonical(NON_ASCII_CJK)))
assert LATIN1_CJK_BYTES == b'{"a":"\x2d\x87"}'
# n73: CESU-8 (Unicode TR #26) — each UTF-16 code unit UTF-8-encoded on its own, so each half
# of the pair becomes three bytes. Identical to UTF-8 on the BMP; only an astral code point can
# tell the two apart.
CESU8_ASTRAL_BYTES = "".join(chr(u) for u in _utf16_units(canonical(NON_ASCII_ASTRAL))).encode("utf-8", "surrogatepass")
assert canonical(NON_ASCII_ASTRAL).encode("utf-8") == b'{"a":"\xf0\xa0\xae\xb7"}'
assert CESU8_ASTRAL_BYTES == b'{"a":"\xed\xa1\x82\xed\xbe\xb7"}'
# n74: the decomposed value's canonical text normalized to NFC before hashing — p39's digest.
NFC_OF_DECOMPOSED_TEXT = unicodedata.normalize("NFC", canonical(NON_ASCII_DECOMPOSED))
assert NFC_OF_DECOMPOSED_TEXT == canonical(NON_ASCII_LATIN1) != canonical(NON_ASCII_DECOMPOSED)
assert canonical(NON_ASCII_DECOMPOSED).encode("utf-8") == b'{"a":"e\xcc\x81"}'

# v0.5.5 — the chain_link sequence domain, an integer token in [1, 2^53-1]. The upper boundary
# pair carries a non-genesis link (p6's second record over its predecessor), so the only thing
# that differs from p43 to n76 is seq.
SEQ_MAX = 2**53 - 1
assert chain_link_digest(d[1], d[0], SEQ_MAX) != chain_link_digest(d[1], d[0], SEQ_MAX + 1)

# v0.5.5 — a lone surrogate. A surrogate-pair ESCAPE is one code point (U+20BB7 here, the
# astral value of p41) and is legal I-JSON; an unpaired one is not (RFC 7493 §2.1: "\uDEAD" is
# invalid, "\uD800\uDEAD" legal), and RFC 8785 §3.2.2.2 requires a canonicalizer to terminate on
# it. Each rejecting vector claims the text a plausible implementation emits for the lone code
# unit: Python's json.dumps(..., ensure_ascii=False) writes it as is (n81), JSON.stringify since
# ES2019 writes it as a lowercase \u escape (n82, n83, n84; measured on Node 24, 2026-10-01).
BS = chr(92)
PAIR_ESC = BS + "ud842" + BS + "udfb7"       # the escape text of U+20BB7
HIGH_ESC, LOW_ESC = BS + "ud842", BS + "udfb7"
LONE_HIGH, LONE_LOW = chr(0xD842), chr(0xDFB7)
ASTRAL = "\U00020bb7"
assert json.loads('"' + PAIR_ESC + '"') == ASTRAL and json.loads('"' + HIGH_ESC + '"') == LONE_HIGH
# n83: the digest a JSON.stringify-based canonicalizer computes for {"a": <lone D842>}.
LONE_SURROGATE_JS_TEXT = '{"a":"' + HIGH_ESC + '"}'
# n84: p14's payload with U+10000's low half dropped, so the second NAME is a lone D800. The
# escaped name sorts first by UTF-16 code unit (0xD800 < 0xFF61), as JSON.stringify-based
# canonicalizers sort it.
LONE_NAME_PAYLOAD = {chr(0xFF61): 1, chr(0xD800): 2}
LONE_NAME_JS_TEXT = '{"' + BS + 'ud800":2,"' + chr(0xFF61) + '":1}'
assert list(SUPP_PAYLOAD) == [chr(0xFF61), chr(0x10000)]

# v0.5.5, review round — each clause of the new MANIFEST text pinned by a vector. _js_text is the
# text a JSON.stringify-based canonicalizer emits when it does not check for unpaired surrogates:
# canonical() as written, except that an unpaired surrogate becomes a lowercase \u escape (ES2019
# JSON.stringify) instead of failing. Integer numbers only, as in the corpus.
def _js_text(v):
    if isinstance(v, str):
        units, out, i = _utf16_units(v), [], 0
        while i < len(units):
            u = units[i]
            if 0xD800 <= u <= 0xDBFF and i + 1 < len(units) and 0xDC00 <= units[i + 1] <= 0xDFFF:
                out.append(chr(0x10000 + ((u - 0xD800) << 10) + (units[i + 1] - 0xDC00)))
                i += 2
                continue
            out.append(BS + "u%04x" % u if 0xD800 <= u <= 0xDFFF else json.dumps(chr(u), ensure_ascii=False)[1:-1])
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


# On well-formed input the helper is canonical() itself, and it reproduces n83's and n84's texts.
for _x in (OFFER_A, DECISION_EVIDENCE_A, BOUNDARY_PREFIX, SUPP_PAYLOAD, NON_ASCII_ASTRAL, NON_ASCII_DECOMPOSED):
    assert _js_text(_x) == canonical(_x)
assert LONE_SURROGATE_JS_TEXT == _js_text({"a": LONE_HIGH}) and LONE_NAME_JS_TEXT == _js_text(LONE_NAME_PAYLOAD)

# p45/n85: U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR are outside the range RFC 8785
# section 3.2.2.2 escapes, so the canonical text carries them as is. n85's digest is over the
# text with both written as \u escapes, which is what Go's encoding/json emits for this payload,
# with or without SetEscapeHTML(false) (measured, go1.27.1, 2026-10-01).
LINE_SEPARATORS = {"a": "\u2028\u2029"}
ESCAPED_SEPARATORS_TEXT = '{"a":"' + BS + 'u2028' + BS + 'u2029"}'
assert canonical(LINE_SEPARATORS).encode("utf-8") == b'{"a":"\xe2\x80\xa8\xe2\x80\xa9"}'
# p46/n86: a decomposed NAME, as p42/n74 pin a decomposed value. n86's digest is the canonical
# text normalized to NFC, {"\u00e9":1}.
DECOMPOSED_NAME = {"e\u0301": 1}
NFC_OF_DECOMPOSED_NAME_TEXT = unicodedata.normalize("NFC", canonical(DECOMPOSED_NAME))
assert NFC_OF_DECOMPOSED_NAME_TEXT == '{"\u00e9":1}' != canonical(DECOMPOSED_NAME)
# n92: an unpaired surrogate and an integer-valued float token in one payload_text, the number
# first. The text's shape, the surrogate included, is decided before its number tokens, so the
# reason is canonicalization_reject. claimed_canonical is what an engine that checks neither
# emits: JSON.parse collapses 2.0 to 2, and JSON.stringify escapes the code unit.
SURROGATE_AFTER_NUMBER_TEXT = '{"a":2.0,"b":"' + BS + 'ud800"}'
SURROGATE_AFTER_NUMBER_JS_TEXT = '{"a":2,"b":"' + BS + 'ud800"}'
# n93: one name written twice, first with the high half of U+20BB7's pair as a raw code unit and
# the low half escaped, then as two escapes. Both decode to the same two UTF-16 code units, D842
# DFB7. Python's json joins only an ESCAPED pair, so the first decodes to two code points and the
# second to one: compared as code points the names differ, and compared as UTF-16 code units, as
# JSON.parse holds them, they are one name. claimed_canonical is what an engine that misses the
# duplicate emits.
HALF_ESCAPED_PAIR = LONE_HIGH + LOW_ESC
HALF_ESCAPED_DUP_TEXT = '{"' + HALF_ESCAPED_PAIR + '":1,"' + PAIR_ESC + '":2}'
HALF_ESCAPED_DUP_CLAIM = '{"' + ASTRAL + '":1,"' + ASTRAL + '":2}'
assert json.loads('"' + HALF_ESCAPED_PAIR + '"') != json.loads('"' + PAIR_ESC + '"')
assert json.loads('"' + HALF_ESCAPED_PAIR + '"').encode("utf-16-be", "surrogatepass") \
    == json.loads('"' + PAIR_ESC + '"').encode("utf-16-be", "surrogatepass")
# n94-n96: an unpaired surrogate inside each object a binding or boundary criterion digests,
# committed to by the digest a JSON.stringify-based canonicalizer computes for it, so an engine
# that skips the check there recomputes the committed digest and accepts.
LONE_OFFER = {"resourceUrl": "https://api.example/x", "a": chr(0xD800)}
assert _js_text(LONE_OFFER) == '{"a":"' + BS + 'ud800","resourceUrl":"https://api.example/x"}'
LONE_DECISION_EVIDENCE = {**DECISION_EVIDENCE_A, "policy": {"id": "host-default" + chr(0xD800), "version": "1"}}
LONE_BOUNDARY_PREFIX = [
    {"event": "record", "seq": 1},
    {"event": "record" + chr(0xDC00), "seq": 2},
    {"event": "record", "seq": 3},
]

# v0.5.5, second review round — clauses a mutant could still break without failing a vector.
# A number token json.dump cannot write (an exponent form: Python writes the float 1.0 as 1.0)
# is carried in the vector as RAW_TOKEN + the token, a string, and the writer below replaces
# that quoted string with the bare token, then checks that the file parses and that no
# placeholder remains.
RAW_TOKEN = "\u0000raw-json-number-token:"
RAW_TOKEN_RE = re.compile(re.escape(json.dumps(RAW_TOKEN)[:-1])
                          + r'(-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)"')


def _raw_number(token):
    if not RAW_TOKEN_RE.fullmatch(json.dumps(RAW_TOKEN + token)):
        sys.exit(f"raw number token {token!r} is not a JSON number token")
    return RAW_TOKEN + token


assert json.loads("1e0") == 1 and isinstance(json.loads("1e0"), float)
# p51/n98: "<", ">" and "&" are outside the range RFC 8785 section 3.2.2.2 escapes, so the
# canonical text carries them as is. n98's digest is over the text with the three written as
# <, > and &, which Go's json.Marshal emits by default (HTML-safe output); an
# Encoder with SetEscapeHTML(false) writes them as is (measured, go1.27.1, 2026-10-01).
HTML_SIGNIFICANT = {"a": "<b>&"}
HTML_ESCAPED_TEXT = '{"a":"' + BS + 'u003cb' + BS + 'u003e' + BS + 'u0026"}'
assert canonical(HTML_SIGNIFICANT) == '{"a":"<b>&"}'
# p52/n102: DEL (U+007F) and the C1 controls U+0080 and U+009F are control characters (Unicode
# general category Cc) outside the range RFC 8785 section 3.2.2.2 escapes, so the canonical text
# carries them as is. n102's digest is over the text with the three written as \u escapes, which
# is what Python's json.dumps emits with its default ensure_ascii=True (which escapes DEL as well
# as every non-ASCII code point) and separators=(",", ":"), and what an encoder that escapes
# every Cc character emits.
CC_OUTSIDE_JCS = {"a": "\u007f\u0080\u009f"}
CC_ESCAPED_TEXT = '{"a":"' + BS + 'u007f' + BS + 'u0080' + BS + 'u009f"}'
assert canonical(CC_OUTSIDE_JCS).encode("utf-8") == b'{"a":"\x7f\xc2\x80\xc2\x9f"}'
assert json.dumps(CC_OUTSIDE_JCS, separators=(",", ":")) == CC_ESCAPED_TEXT
# p53: U+00E9 and e + U+0301 as two names in one object. As UTF-16 code units they differ
# (00E9 against 0065 0301), and no normalization applies (RFC 8785 section 3.1), so the text
# repeats no name; the decomposed name sorts first (0x0065 < 0x00E9).
NFC_AND_NFD_NAMES_TEXT = '{"é":1,"é":2}'
NFC_AND_NFD_NAMES_CANONICAL = '{"é":2,"é":1}'
assert canonical(json.loads(NFC_AND_NFD_NAMES_TEXT)) == NFC_AND_NFD_NAMES_CANONICAL
assert unicodedata.normalize("NFC", "é") == "é"

# v0.5.6: settlement scope, and the letter case of a 0x-address. n104/p54 and n105/p55 reuse the
# synthetic parties of n7/p8 with an auditor outside them; n106/p56 use addresses that carry hex
# letters, so a letter-case variant differs from the address as written.
SCOPE_PARTIES = ["0x2222222222222222222222222222222222222222", "0x3333333333333333333333333333333333333333"]
SCOPE_AUDITOR = [{"by": "0x4444444444444444444444444444444444444444", "role": "auditor"}]
SCOPE_TX = "0x9e1f4c2a8b7d6e5f0a3c1b8d7e6f5a4c3b2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f"
SCOPE_DELIVERABLE = '{"answer":"synthetic deliverable"}'
SCOPE_DELIVERABLE_DIGEST = _keccak_hex(SCOPE_DELIVERABLE.encode("utf-8"))


def _eip55(addr):
    """EIP-55 checksum form of a 0x-address: a hex letter is upper case where the matching
    nibble of keccak256(the lowercase hex digits, as ASCII) is 8 or more."""
    low = addr.lower()[2:]
    h = keccak256(low.encode("ascii")).hex()
    return "0x" + "".join(c.upper() if c.isalpha() and int(h[i], 16) >= 8 else c for i, c in enumerate(low))


# Two of EIP-55's own example addresses: the helper must reproduce them. Not `assert`, so the
# check holds under `python3 -O` too.
for _kat in ("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"):
    if _eip55(_kat) != _kat:
        sys.exit(f"_eip55 does not reproduce {_kat}")
CASE_PARTY_A = "0xabcdef0123456789abcdef0123456789abcdef01"
CASE_PARTY_B = "0xfedcba9876543210fedcba9876543210fedcba98"
CASE_OUTSIDE = "0x0123456789abcdef0123456789abcdef01234567"
CASE_PARTIES = [_eip55(CASE_PARTY_A), CASE_PARTY_B]
if CASE_PARTIES[0] == CASE_PARTY_A:
    sys.exit("the checksum form of CASE_PARTY_A must differ from its lowercase form")

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
    # ------------------ completeness: witnessed inclusion is not completeness (2-sided pin)
    # A public log, however many parties cosign its checkpoint, evidences that what was included
    # existed and that the log is consistent; it cannot evidence that the issuer's sequence has
    # no gap, because the issuer chose what to include. The pair pins that this evaluator reads
    # `witness` material as non-load-bearing for completeness: p24 carries a cosigned checkpoint
    # and per-record inclusion proofs beside a complete set and is valid on the set alone; n34
    # carries the same witness block beside a set with seq 2 missing and rejects on the gap — an
    # engine that let inclusion proofs stand in for the missing record would accept it. Spec:
    # compliance_fields.md §Sequential numbering (amended 2026-08-22). Log names are generic.
    {
        "id": "p24-witnessed-complete-set",
        "kind": "chain_set",
        "expect": "valid",
        "description": "Accepting twin of n34: a complete set (seq 1..3 under the committed head) that ALSO carries witness material — a cosigned checkpoint of a public log and one inclusion-proof reference per record. The verdict rests on the set: every seq present, links continuous, head matches. The witness block is permitted and ignored by the completeness predicate; it is evidence of existence and of the log's consistency, never of no-omission. Pins the rule added to the extension's §Sequential numbering on 2026-08-22: inclusion proofs and checkpoint cosignatures, however many signers, are not a completeness attestation.",
        "input": {
            "head": {"seq": 3, "digest": d[2]},
            "records": [
                {"seq": 1, "artifact_digest": d[0], "prev_digest": None, "link": links[0]},
                {"seq": 2, "artifact_digest": d[1], "prev_digest": d[0], "link": links[1]},
                {"seq": 3, "artifact_digest": d[2], "prev_digest": d[1], "link": links[2]},
            ],
            "witness": {
                "checkpoint": {"origin": "example.org/log", "tree_size": 7574, "cosignatures": 7, "quorum": 4},
                "inclusion": [{"seq": 1, "leaf_index": 7011}, {"seq": 2, "leaf_index": 7012}, {"seq": 3, "leaf_index": 7013}],
            },
        },
    },
    {
        "id": "n34-witnessed-inclusion-not-completeness",
        "kind": "chain_set",
        "expect": "reject",
        "reason": "completeness_reject",
        "description": "Rejecting twin of p24: seq 2 is absent from the presented set while the witness block carries a seven-cosignature checkpoint and inclusion proofs for seq 1, 2 AND 3 — a leaf index offered in place of the record that is not presented. A leaf index is a claim that something was included; it is not the record, and the evaluator cannot recompute a link over a leaf index. The log proves what it holds existed and that its own history is consistent; it cannot make a record the issuer did not present part of the set. An evaluator MUST reject on the gap (`missing seq [2] under committed head`) exactly as it would without the witness block — an engine that counted witnessed inclusions as presence, or read a cosigned checkpoint as a completeness attestation, accepts this vector and is wrong. No-omission requires a non-party attestation over the sequence itself, made when the records were issued; cosigners of a log the issuer writes to are not that party.",
        "input": {
            "head": {"seq": 3, "digest": d[2]},
            "records": [
                {"seq": 1, "artifact_digest": d[0], "prev_digest": None, "link": links[0]},
                {"seq": 3, "artifact_digest": d[2], "prev_digest": d[1], "link": links[2]},
            ],
            "witness": {
                "checkpoint": {"origin": "example.org/log", "tree_size": 7574, "cosignatures": 7, "quorum": 4},
                "inclusion": [{"seq": 1, "leaf_index": 7011}, {"seq": 2, "leaf_index": 7012}, {"seq": 3, "leaf_index": 7013}],
            },
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
    # ---------------------------------------- identifier aliases (v0.5.4, issues #8 and #9)
    # One rule, stated in the manifest's identifier_normalization and implemented step for step
    # by both engines: strip the White_Space set; a 0x-address lowercases; otherwise the ASCII
    # grammar (either case), percent-encoded UNRESERVED characters decoded once (RFC 3986
    # §6.2.2.2, §2.4), any `%` or `?` left fails closed, a dot-segment fails closed, case folded,
    # every trailing `/` `.` `#` removed, a `#` left fails closed, and the result must still
    # parse; two identifiers naming one 0x-address are one party. Each alias class has a
    # rejecting vector (a party's alias as attestor, or a form that is not evaluable). Where the
    # class admits an accepting input, an accepting twin carries the form on a party OUTSIDE the
    # transaction, so an engine that defends the class by refusing the form fails as hard as one
    # that misses it. A class whose forms are never evaluable has no accepting twin; where a form
    # close to the class is evaluable, a NEAR-MISS accepting vector carries it instead (p36 beside
    # the dot-segments, p31's trailing `#` beside a fragment with content), and the rest have
    # none (n50, n51, n55, n56, n61).
    # n31's description predates v0.5.4 and its file stays byte-identical; its closing sentence
    # on percent-encoding is superseded by n48-n50.
    {
        "id": "p31-independence-urn-case-and-trailing-punctuation-outside-party",
        "kind": "independence_claim",
        "expect": "valid",
        "description": "Accepting twin of n31, n45-n47 and n58: letter case (the scheme's included) and a trailing `#`, `/` and `.`, on one attestor OUTSIDE the parties written three ways. Normalization folds each to org:trustline-custody/eu-west, which is not a party, so the claim holds. An engine that defends the alias classes by refusing the forms, failing closed on an upper-case letter or on any one of a trailing `/` `.` `#`, rejects here.",
        "input": {
            "claimed": "independent",
            "parties": ["org:caldera-robotics", "agent:caldera/ap-pilot"],
            "attestations": [
                {"by": "Org:Trustline-Custody/EU-West#"},
                {"by": "org:trustline-custody/eu-west/"},
                {"by": "org:trustline-custody/eu-west."},
            ],
        },
    },
    {
        "id": "p32-independence-urn-percent-encoded-outside-party",
        "kind": "independence_claim",
        "expect": "valid",
        "description": "Accepting twin of n48/n49: percent-encoded unreserved characters on an attestor outside the parties, one triplet in each hex case. They decode (RFC 3986 §6.2.2.2) to org:trustline-custody/eu-west, which is not a party, so the claim holds. An engine that fails closed on any `%`, or decodes only one hex case, rejects here.",
        "input": {
            "claimed": "independent",
            "parties": ["org:caldera-robotics", "agent:caldera/ap-pilot"],
            "attestations": [{"by": "org:trustline%2dcustody/eu%2Dwest"}],
        },
    },
    {
        "id": "p33-independence-identifier-whitespace-set",
        "kind": "independence_claim",
        "expect": "valid",
        "description": "Accepting twin for the whitespace set, whose rejecting side is n13 (a party padded with a space is that party). The set is the Unicode White_Space property, enumerated in identifier_normalization. Here an attestor outside the parties is padded with U+0085 and U+3000, and a party with U+00A0, all White_Space, so both identifiers parse and the claim holds. JavaScript's trim() does not remove U+0085, so an engine that strips with it rejects this input.",
        "input": {
            "claimed": "independent",
            "parties": [chr(0xA0) + "org:caldera-robotics", "agent:caldera/ap-pilot"],
            "attestations": [{"by": chr(0x85) + "org:trustline-custody/eu-west" + chr(0x3000)}],
        },
    },
    {
        "id": "n45-independence-urn-alias-case",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "Alias bypass by letter case: the deployer attests as org:Caldera-robotics while the parties list carries org:caldera-robotics. Letter case folds toward the same party, so the record is attested only by parties. An engine that compares scheme-qualified identifiers case-significantly counts the alias as an outside attestor and accepts.",
        "input": {
            "claimed": "independent",
            "parties": ["org:caldera-robotics", "agent:caldera/ap-pilot"],
            "attestations": [{"by": "org:Caldera-robotics"}],
        },
    },
    {
        "id": "n46-independence-urn-alias-trailing-dot",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "Alias bypass by a trailing `.`. Every trailing `/` `.` `#` is removed before comparison, so org:caldera-robotics. is the party org:caldera-robotics. n31 pins the trailing `/`; an engine that strips only `/` accepts here.",
        "input": {
            "claimed": "independent",
            "parties": ["org:caldera-robotics", "agent:caldera/ap-pilot"],
            "attestations": [{"by": "org:caldera-robotics."}],
        },
    },
    {
        "id": "n47-independence-urn-alias-trailing-hash",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "Alias bypass by a trailing `#` (an empty fragment). Every trailing `/` `.` `#` is removed before comparison, so org:caldera-robotics# is the party org:caldera-robotics. An engine that strips only `/` accepts here.",
        "input": {
            "claimed": "independent",
            "parties": ["org:caldera-robotics", "agent:caldera/ap-pilot"],
            "attestations": [{"by": "org:caldera-robotics#"}],
        },
    },
    {
        "id": "n48-independence-urn-alias-percent-encoded",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "Alias bypass by percent-encoding. %2D encodes `-`, an unreserved character, and percent-encoded unreserved characters are decoded before comparison (RFC 3986 §6.2.2.2), so the attestor org:caldera%2Drobotics is the party org:caldera-robotics. Without decoding, the alias counts as an outside attestor and the record verifies as independent. The attestor is @stillmarcus24's probe from issue #8, on n31's parties.",
        "input": {
            "claimed": "independent",
            "parties": ["org:caldera-robotics", "agent:caldera/ap-pilot"],
            "attestations": [{"by": "org:caldera%2Drobotics"}],
        },
    },
    {
        "id": "n49-independence-urn-alias-party-side-encoded-dot",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "The folds apply to the parties list as well as the attestors, and in order: decode, then fold case, then strip trailing punctuation. The party is written org:Caldera-Robotics%2e (an encoded trailing `.`), the attestor org:caldera-robotics. An engine that normalizes attestors only, or strips trailing punctuation before decoding, keeps the two distinct and accepts.",
        "input": {
            "claimed": "independent",
            "parties": ["org:Caldera-Robotics%2e", "agent:caldera/ap-pilot"],
            "attestations": [{"by": "org:caldera-robotics"}],
        },
    },
    {
        "id": "n50-independence-urn-percent-encoded-reserved",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "A percent-encoding of a character that is not unreserved. RFC 3986 does not make %2F equivalent to `/`, and some schemes decode it anyway, so a verifier that owns no scheme's rules cannot decide which party the identifier names: it is not evaluable, and the claim fails closed as n14's does. This attestor is outside the parties under either reading, so the reject comes from the identifier rule alone; an engine that leaves the triplet in place, or decodes it, accepts. The same rule stops org:caldera-robotics%2F from counting as an attestor outside the transaction.",
        "input": {
            "claimed": "independent",
            "parties": ["org:caldera-robotics", "agent:caldera/ap-pilot"],
            "attestations": [{"by": "org:trustline-custody%2Feu-west"}],
        },
    },
    {
        "id": "n51-independence-urn-empty-after-normalization",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "An identifier that is empty after normalization: org:/ loses its trailing `/` and leaves no path. It names no party, so it cannot count as one outside the transaction; an identifier that does not parse after normalization fails closed. An engine that checks the grammar only before normalizing accepts here.",
        "input": {
            "claimed": "independent",
            "parties": ["org:caldera-robotics", "agent:caldera/ap-pilot"],
            "attestations": [{"by": "org:/"}],
        },
    },
    {
        "id": "n52-independence-identifier-format-character-padding",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "U+FEFF at the edge of an attestor identifier. It is a format character, not White_Space, so it is not stripped and the identifier does not parse, as U+200B inside one does not (n14): the claim fails closed. JavaScript's trim() removes U+FEFF, so an engine that strips with it counts this attestor, a party outside the transaction, as evaluable and accepts.",
        "input": {
            "claimed": "independent",
            "parties": ["org:caldera-robotics", "agent:caldera/ap-pilot"],
            "attestations": [{"by": chr(0xFEFF) + "org:trustline-custody/eu-west"}],
        },
    },
    {
        "id": "n53-independence-identifier-control-character-padding",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "U+001C at the edge of an attestor identifier. It is a control character, not White_Space, so it is not stripped and the identifier does not parse: the claim fails closed. Python's str.strip() removes U+001C-U+001F, so an engine that strips with it counts this attestor, a party outside the transaction, as evaluable and accepts.",
        "input": {
            "claimed": "independent",
            "parties": ["org:caldera-robotics", "agent:caldera/ap-pilot"],
            "attestations": [{"by": "org:trustline-custody/eu-west" + chr(0x1C)}],
        },
    },
    {
        "id": "n58-independence-urn-alias-scheme-case",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "Alias bypass by the case of the scheme alone: the deployer attests as ORG:caldera-robotics while the parties list carries org:caldera-robotics. Schemes are case-insensitive (RFC 3986 section 3.1) and letter case folds in the scheme as in the path, so the record is attested only by parties. An engine that folds the path but keeps the scheme's case counts the alias as an outside attestor and accepts. p31 is the accepting side (an upper-case scheme on a party outside the transaction).",
        "input": {
            "claimed": "independent",
            "parties": ["org:caldera-robotics", "agent:caldera/ap-pilot"],
            "attestations": [{"by": "ORG:caldera-robotics"}],
        },
    },
    {
        "id": "p34-independence-urn-percent-encoded-unreserved-set-outside-party",
        "kind": "independence_claim",
        "expect": "valid",
        "description": "The rest of the unreserved set (RFC 3986 section 2.3), percent-encoded on an attestor outside the parties: `_` (%5f), `~` (%7E), `-` (%2D), a digit (%32) and a letter (%41). Each triplet decodes, so the attestor is org:trustline_custody/eu~west-2a, which is not a party, and the claim holds. An engine whose unreserved set omits `_`, `~`, the digits or the letters leaves that triplet encoded, reads the identifier as not evaluable, and rejects here.",
        "input": {
            "claimed": "independent",
            "parties": ["org:caldera-robotics", "agent:caldera/ap-pilot"],
            "attestations": [{"by": "org:trustline%5fcustody/eu%7Ewest%2D%32%41"}],
        },
    },
    {
        "id": "n54-independence-urn-alias-percent-encoded-unreserved-set",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "Rejecting side of p34: the party is org:caldera_robotics~2 and the attestor writes it org:caldera%5Frobotics%7e%32. The triplets decode to `_`, `~` and `2`, so the attestor is the party and the record is attested only by parties. An engine that checks the decoded form for a leftover `%` but compares the identifier as written counts the alias as an outside attestor and accepts.",
        "input": {
            "claimed": "independent",
            "parties": ["org:caldera_robotics~2", "agent:caldera/ap-pilot"],
            "attestations": [{"by": "org:caldera%5Frobotics%7e%32"}],
        },
    },
    {
        "id": "n55-independence-urn-percent-encoded-percent-sign",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "Decoding runs once. The attestor ends in %2574: %25 encodes `%` itself, which is not unreserved, so it stays encoded, a `%` remains, and the identifier is not evaluable. RFC 3986 section 2.4: implementations must not decode the same string more than once. An engine that decodes %25 and then decodes again reads %74 as `t`, gets org:trustline-custody/eu-west, a party outside the transaction, and accepts.",
        "input": {
            "claimed": "independent",
            "parties": ["org:caldera-robotics", "agent:caldera/ap-pilot"],
            "attestations": [{"by": "org:trustline-custody/eu-wes%2574"}],
        },
    },
    {
        "id": "n56-independence-urn-triplet-assembled-by-decoding",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "Decoding runs once, in one left-to-right pass. The attestor ends in %%37%34: the first `%` begins no triplet, and %37 %34 decode to `7` and `4`, so one pass leaves %74 and the identifier is not evaluable. An engine that repeats the unreserved decode until nothing changes decodes the %74 it assembled into `t`, gets org:trustline-custody/eu-west, a party outside the transaction, and accepts.",
        "input": {
            "claimed": "independent",
            "parties": ["org:caldera-robotics", "agent:caldera/ap-pilot"],
            "attestations": [{"by": "org:trustline-custody/eu-wes%%37%34"}],
        },
    },
    {
        "id": "n59-independence-urn-alias-dot-segment",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "Alias bypass by a dot-segment. agent:caldera/./ap-pilot resolves, by RFC 3986's remove_dot_segments (sections 5.2.4 and 6.2.2.3), to the party agent:caldera/ap-pilot. This verifier does not own a scheme's resolution rules, so a path with a `.` or `..` segment is not evaluable and the claim fails closed. An engine that compares the form as written counts it as an outside attestor and accepts.",
        "input": {
            "claimed": "independent",
            "parties": ["org:caldera-robotics", "agent:caldera/ap-pilot"],
            "attestations": [{"by": "agent:caldera/./ap-pilot"}],
        },
    },
    {
        "id": "n60-independence-urn-encoded-trailing-dot-segment",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "A `..` segment written as %2E%2E at the end of an attestor outside the parties. It decodes to `..`, a dot-segment, so the identifier is not evaluable, and the reject comes from the identifier rule alone. The check runs after decoding and before the trailing strip. An engine that looks for dot-segments before decoding, that looks only for `.`, or that strips the trailing `/..` first reads org:trustline-custody/eu-west/witness and accepts; so does one that resolves the segments. Under the same rule, agent:caldera/ap-pilot/witness/.. never counts as an attestor outside the transaction.",
        "input": {
            "claimed": "independent",
            "parties": ["org:caldera-robotics", "agent:caldera/ap-pilot"],
            "attestations": [{"by": "org:trustline-custody/eu-west/witness/%2E%2E"}],
        },
    },
    {
        "id": "n67-independence-urn-alias-leading-dot-segment",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "Alias bypass by a dot-segment at the start of the path. The path of org:./caldera-robotics runs from the scheme's colon, so its first segment is `.`, and RFC 3986's remove_dot_segments (section 5.2.4, step A) reads the identifier as the party org:caldera-robotics. A path with a `.` or `..` segment is not evaluable, the first segment included, and the claim fails closed. An engine that splits segments from the start of the whole identifier reads the first segment as `org:.`, finds no dot-segment, and accepts; so does one that skips the first segment.",
        "input": {
            "claimed": "independent",
            "parties": ["org:caldera-robotics", "agent:caldera/ap-pilot"],
            "attestations": [{"by": "org:./caldera-robotics"}],
        },
    },
    {
        "id": "n70-independence-urn-alias-leading-dot-dot-segment",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "n67 with `..`: the path of org:../caldera-robotics starts with the segment `..`, and remove_dot_segments strips a leading `../` as it strips a leading `./` (RFC 3986 section 5.2.4, step A), reading the identifier as the party org:caldera-robotics. A path with a `.` or `..` segment is not evaluable, the first segment included, and the claim fails closed. An engine that catches a leading `./` but finds `..` only after a `/` accepts here.",
        "input": {
            "claimed": "independent",
            "parties": ["org:caldera-robotics", "agent:caldera/ap-pilot"],
            "attestations": [{"by": "org:../caldera-robotics"}],
        },
    },
    {
        "id": "p36-independence-urn-dots-within-segments-outside-party",
        "kind": "independence_claim",
        "expect": "valid",
        "description": "Near-miss accepting vector for n59/n60/n67/n70: a dot-segment is never evaluable, so the class has no accepting twin; this vector carries an evaluable form beside it instead, dots that are not dot-segments, on an attestor outside the parties. The segments .well-known, ... and ..v2 are ordinary segments (only a complete `.` or `..` is a dot-segment, RFC 3986 section 3.3), so the identifier is evaluable, is not a party, and the claim holds. An engine that rejects any segment starting with a dot, or any run of dots, rejects here.",
        "input": {
            "claimed": "independent",
            "parties": ["org:caldera-robotics", "agent:caldera/ap-pilot"],
            "attestations": [{"by": "org:trustline-custody/.well-known/.../..v2"}],
        },
    },
    {
        "id": "n61-independence-urn-query-component",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "A `?` in an identifier. It begins a query component (RFC 3986 section 3.4), and whether a query changes which party an identifier names is the scheme's rule, which this verifier does not own: the identifier is not evaluable and the claim fails closed. This attestor is outside the parties with or without its query, so the reject comes from the identifier rule alone; an engine that compares the form as written, or drops the query, accepts. Under the same rule org:caldera-robotics? never counts as an attestor outside the transaction. The class has no accepting side: no identifier containing `?` is evaluable.",
        "input": {
            "claimed": "independent",
            "parties": ["org:caldera-robotics", "agent:caldera/ap-pilot"],
            "attestations": [{"by": "org:trustline-custody/eu-west?role=witness"}],
        },
    },
    {
        "id": "n62-independence-urn-fragment-component",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "A non-empty fragment. After the trailing `/` `.` `#` are removed, a `#` that remains begins a fragment with content (RFC 3986 section 3.5), which may or may not name another party; the identifier is not evaluable and the claim fails closed. This attestor is outside the parties with or without its fragment, so the reject comes from the identifier rule alone; an engine that compares the form as written, or drops the fragment, accepts. Under the same rule org:caldera-robotics#witness never counts as an attestor outside the transaction. The class has no accepting twin; p31 is the near-miss that accepts, since a trailing `#` alone is removed.",
        "input": {
            "claimed": "independent",
            "parties": ["org:caldera-robotics", "agent:caldera/ap-pilot"],
            "attestations": [{"by": "org:trustline-custody/eu-west#witness"}],
        },
    },
    {
        "id": "n63-independence-address-alias-caip10-and-did-pkh",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "Alias bypass across namespaces. The party is a bare 0x-address; the attestors write the same address as a CAIP-10 account on chain 8453 and as a did:pkh on chain 1, in mixed case. An identifier whose final colon-separated component is a 0x-address names that address, so both attestors are the party and the record is attested only by parties. An engine that compares the forms as distinct identifiers, or recognizes only one of the two forms, counts an outside attestor and accepts.",
        "input": {
            "claimed": "independent",
            "parties": [CA1DE_ADDR.lower(), "0x3333333333333333333333333333333333333333"],
            "attestations": [
                {"by": "eip155:8453:" + CA1DE_ADDR},
                {"by": "did:pkh:eip155:1:" + CA1DE_ADDR.lower()},
            ],
        },
    },
    {
        "id": "n64-independence-address-alias-party-in-caip10",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "n63 with the forms swapped: the party is listed as the CAIP-10 account eip155:8453:<address>, and the attestors are the bare address and a did:pkh on another chain. Addresses compare by the address they name, whichever side carries which form and whatever the chain reference, so both attestors are the party. An engine that applies the rule only when the parties list carries the bare address accepts here.",
        "input": {
            "claimed": "independent",
            "parties": ["eip155:8453:" + CA1DE_ADDR, "0x3333333333333333333333333333333333333333"],
            "attestations": [
                {"by": CA1DE_ADDR.lower()},
                {"by": "did:pkh:eip155:1:" + CA1DE_ADDR},
            ],
        },
    },
    {
        "id": "p37-independence-address-caip10-outside-party",
        "kind": "independence_claim",
        "expect": "valid",
        "description": "Accepting side of n63/n64: an attestor written as a CAIP-10 account and one written as a did:pkh, both naming 0x4444...4444, an address that is not a party's. They are evaluable, outside the transaction, and the claim holds. An engine that refuses the CAIP-10 or did:pkh forms rejects here.",
        "input": {
            "claimed": "independent",
            "parties": [CA1DE_ADDR.lower(), "0x3333333333333333333333333333333333333333"],
            "attestations": [
                {"by": "eip155:8453:0x4444444444444444444444444444444444444444"},
                {"by": "did:pkh:eip155:1:0x4444444444444444444444444444444444444444"},
            ],
        },
    },
    {
        "id": "n65-independence-address-alias-did-ethr",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "Alias bypass in a namespace outside CAIP-10 and did:pkh. The party is a bare 0x-address and the attestor writes it as did:ethr:<address>, in mixed case. The rule keys every scheme-qualified identifier whose final colon-separated component is a 0x-address to that address, not a list of known namespaces, so the attestor is the party and the record is attested only by parties. An engine that derives the address only for the CAIP-10 and did:pkh forms counts an outside attestor and accepts.",
        "input": {
            "claimed": "independent",
            "parties": [CA1DE_ADDR.lower(), "0x3333333333333333333333333333333333333333"],
            "attestations": [{"by": "did:ethr:" + CA1DE_ADDR}],
        },
    },
    {
        "id": "n66-independence-address-alias-party-in-ethereum-namespace",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "n65 from the party side: the party is listed as ethereum:<address> and the attestor as did:ethr:<address>, so neither side carries the bare address, a CAIP-10 account or a did:pkh. Both identifiers end in the same 0x-address, so the attestor is the party. An engine that derives the address from any namespace on the attestor side but only from the bare, CAIP-10 or did:pkh forms on the party side accepts here.",
        "input": {
            "claimed": "independent",
            "parties": ["ethereum:" + CA1DE_ADDR, "0x3333333333333333333333333333333333333333"],
            "attestations": [{"by": "did:ethr:" + CA1DE_ADDR.lower()}],
        },
    },
    {
        "id": "n69-independence-address-alias-any-scheme",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "The address rule does not depend on the scheme. The party is a bare 0x-address and the attestor writes it as acct:<address>, in mixed case, under a scheme outside the CAIP-10, did:pkh, did:ethr and ethereum: forms that n63-n66 pin. Its final colon-separated component is the party's 0x-address, so the attestor is the party and the record is attested only by parties. An engine that derives the address only for a list of schemes (CAIP-10, did:pkh, did:ethr, ethereum: or any other finite list without acct:) counts an outside attestor and accepts.",
        "input": {
            "claimed": "independent",
            "parties": [CA1DE_ADDR.lower(), "0x3333333333333333333333333333333333333333"],
            "attestations": [{"by": "acct:" + CA1DE_ADDR}],
        },
    },
    {
        "id": "p38-independence-address-other-namespaces-outside-party",
        "kind": "independence_claim",
        "expect": "valid",
        "description": "Accepting side of n65/n66/n69: attestors written as did:ethr:<address>, ethereum:<address> and acct:<address>, all naming 0x4444...4444, an address that is not a party's. They are evaluable, outside the transaction, and the claim holds. An engine that defends the address rule by refusing identifiers that end in a 0x-address outside a list of schemes (CAIP-10 and did:pkh, or those plus did:ethr and ethereum:) rejects here.",
        "input": {
            "claimed": "independent",
            "parties": [CA1DE_ADDR.lower(), "0x3333333333333333333333333333333333333333"],
            "attestations": [
                {"by": "did:ethr:0x4444444444444444444444444444444444444444"},
                {"by": "ethereum:0x4444444444444444444444444444444444444444"},
                {"by": "acct:0x4444444444444444444444444444444444444444"},
            ],
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
    # Integer-valued float token pair (p25/n35): found by @Rul1an's mutation-adequacy run
    # against this corpus (issue #1, 2026-08-23) — the corpus's only fractional number token
    # (n10) carries 1.1, so an engine weakened to accept integer-valued floats survives the
    # whole suite. Underneath the corpus gap sat a live cross-engine divergence: the
    # TypeScript loader (JSON.parse) erased the token, reading the wire bytes 2.0 as the
    # integer 2, and the TS engine accepted; Python's json keeps 2.0 a float, and
    # canonical() rejects it. The pair therefore puts the payload in RAW TEXT:
    # `payload_text` carries the distinction to both engines, and the pair pins the
    # boundary at the TOKEN class.
    {
        "id": "p25-integer-token-in-text",
        "kind": "canonical_bytes",
        "expect": "valid",
        "description": "Accepting twin of n35, and the accepting pin of the payload_text pathway itself: the same wire bytes with a plain integer token. {\"amount\": 2} parses to an integer in every language, canonicalizes to {\"amount\":2}, and is valid. An engine that unconditionally rejects the raw-text pathway fails here, per the two-sided gate.",
        "input": {"payload_text": '{"amount": 2}', "claimed_canonical": '{"amount":2}'},
    },
    {
        "id": "n35-integer-valued-float-token",
        "kind": "canonical_bytes",
        "expect": "reject",
        "reason": "number_domain_reject",
        "description": "A number token with a fraction part whose VALUE is an integer: {\"amount\": 2.0}. The digest-domain boundary is the token class, not the value — JSON.parse collapses 2.0 to 2, so an engine reading parsed values sees a valid integer while an engine preserving float-ness rejects, and the two sign different verdicts over identical wire bytes. Rejecting the token class is the only deterministic cross-language rule. Kills the mutant that accepts integer-valued floats (survivor of the pre-p25 corpus, @Rul1an issue #4); the shipped Python engine already rejected, the shipped TS engine accepted until this pin.",
        "input": {"payload_text": '{"amount": 2.0}', "claimed_canonical": '{"amount":2}'},
    },
    # ------------------------------ raw-text pathway carries the loader's rules (v0.5.4)
    # `payload_text` is the one place JSON text is parsed after load, and it was parsed with no
    # duplicate-name check in either engine: {"a":1,"a":2} read valid against {"a":2} in both.
    # Reported by @Rul1an (issue #10) against the Python engine; the TS engine read the same.
    # Three siblings on the same pathway forked the engines: NaN (Python number_domain_reject,
    # TS no verdict), a payload_text that is not a string (Python no verdict, TS valid), and
    # text that does not parse. Text with no canonical form -> canonicalization_reject; the
    # reject-reason closure stays at 10.
    {
        "id": "p30-canonical-bytes-name-repeated-across-objects",
        "kind": "canonical_bytes",
        "expect": "valid",
        "description": "Accepting twin of n41/n42: one name repeated across DISTINCT objects is not a duplicate. In {\"a\":{\"a\":1},\"b\":[{\"a\":2},{\"a\":3}]} every object's own names are unique, so the text is I-JSON and its canonical form compares. A duplicate-name check whose key set spans more than one object rejects this and fails here, per the two-sided gate.",
        "input": {"payload_text": '{"a":{"a":1},"b":[{"a":2},{"a":3}]}', "claimed_canonical": '{"a":{"a":1},"b":[{"a":2},{"a":3}]}'},
    },
    {
        "id": "n41-canonical-bytes-duplicate-name",
        "kind": "canonical_bytes",
        "expect": "reject",
        "reason": "canonicalization_reject",
        "description": "Duplicate object names inside payload_text: {\"a\":1,\"a\":2}, claimed canonical {\"a\":2}, the form a last-wins parser produces. RFC 8785 §3.1 requires input without duplicate property names (RFC 7493 §2.3 forbids them), so the text has no canonical form to compare against. The duplicate-name rule applies to payload_text as it does to the vector file at load. Input from @Rul1an's report (issue #10).",
        "input": {"payload_text": '{"a":1,"a":2}', "claimed_canonical": '{"a":2}'},
    },
    {
        "id": "n42-canonical-bytes-escaped-duplicate-name",
        "kind": "canonical_bytes",
        "expect": "reject",
        "reason": "canonicalization_reject",
        "description": "n41's duplicate with the second name written as a JSON escape (backslash-u0061 is \"a\"). Names compare after decoding, the form RFC 8785 sorts them in; a detector that compares raw key tokens misses the duplicate and fails here.",
        "input": {"payload_text": '{"a":1,"' + chr(92) + 'u0061":2}', "claimed_canonical": '{"a":2}'},
    },
    {
        "id": "n43-canonical-bytes-non-json-constant",
        "kind": "canonical_bytes",
        "expect": "reject",
        "reason": "canonicalization_reject",
        "description": "A NaN token inside payload_text. RFC 8259 has no such token: Python's json accepts it by default and JSON.parse refuses it, so an engine that inherits either default returns number_domain_reject or no verdict at all. Text that is not JSON has no canonical form, in both engines.",
        "input": {"payload_text": '{"amount":NaN}', "claimed_canonical": '{"amount":0}'},
    },
    {
        "id": "n44-canonical-bytes-text-not-a-string",
        "kind": "canonical_bytes",
        "expect": "reject",
        "reason": "canonicalization_reject",
        "description": "payload_text that is not a string. JSON.parse coerces the number 2 to the text \"2\", so an engine that passes the value straight to it reads a valid canonical form; Python's json raises on a non-string and returns no verdict. The raw-text pathway carries JSON TEXT, and any other value rejects.",
        "input": {"payload_text": 2, "claimed_canonical": "2"},
    },
    {
        "id": "n57-canonical-bytes-duplicate-name-after-array",
        "kind": "canonical_bytes",
        "expect": "reject",
        "reason": "canonicalization_reject",
        "description": "A duplicate name that follows an array value: in {\"a\":[1,2],\"a\":3} the second `a` repeats a name of the same object. The comma inside the array separates elements, not names, and the object's names stay in scope across the array. A duplicate-name scanner that does not track arrays reads that comma as the object's and loses the object at the array's close, misses the duplicate, and accepts the last-wins form {\"a\":3}.",
        "input": {"payload_text": '{"a":[1,2],"a":3}', "claimed_canonical": '{"a":3}'},
    },
    {
        "id": "p35-canonical-bytes-string-value-equal-to-a-name",
        "kind": "canonical_bytes",
        "expect": "valid",
        "description": "Accepting side of the duplicate-name rule: in {\"k\":\"v\",\"v\":1} the string value \"v\" equals the next name, and a value is not a name. Every object's names are unique, so the text is I-JSON and its canonical form compares. A scanner that reads a string value as a name finds a duplicate that is not there and rejects here.",
        "input": {"payload_text": '{"k":"v","v":1}', "claimed_canonical": '{"k":"v","v":1}'},
    },
    {
        "id": "n68-canonical-bytes-duplicate-name-in-nested-object",
        "kind": "canonical_bytes",
        "expect": "reject",
        "reason": "canonicalization_reject",
        "description": "A duplicate name in an object nested inside an array inside an object: in {\"x\":[{\"a\":1,\"a\":2}]} the inner object repeats `a`. The names of every object must be unique, at any depth, so the text is not I-JSON and has no canonical form. A duplicate-name check that reads the outermost object only, or that opens no name scope for an object inside an array or inside another object, misses the duplicate and accepts the last-wins form {\"x\":[{\"a\":2}]}.",
        "input": {"payload_text": '{"x":[{"a":1,"a":2}]}', "claimed_canonical": '{"x":[{"a":2}]}'},
    },
    # ----------------------------------- chain commitment (2-sided, v0.5.0, ADDITIVE kind)
    # A head digest binds the LAST record only: two prefixes ending in the same record — the
    # real one, and one whose earlier rows were substituted with prevs and links recomputed —
    # both pass chain_set and both sit under the same anchored head. The commitment closes
    # that: an accumulator folded over every recomputed link, seeded by a tagged digest, so
    # one anchored value commits the whole prefix. Every pre-0.5.0 vector is byte-identical;
    # p6's records are reused so the two predicates are compared over the SAME bytes. n37 was
    # written before the check existed (repo rule 1): the pre-0.5.0 engine has no such kind
    # (KeyError → 'malformed'), and the same input under chain_set is 'valid' — the
    # structural predicate cannot see the defect the accumulator names.
    {
        "id": "p26-chain-commitment-complete",
        "kind": "chain_commitment",
        "expect": "valid",
        "description": "Accepting twin of n36/n37: p6's complete set with a head accumulator folded over every recomputed link — acc_0 = keccak256(utf8('tersign-chain-commitment-v1')), acc_n = keccak256(acc_{n-1} || link_n), link_n = keccak256(artifact || prev || seq_be8) with prev = the previous artifact digest. head.acc equals acc_3, so the presented prefix is the one the commitment was built over. Structural profile only: the counter-signatures over the links and the anchor over the commitment are the crypto and existence profiles.",
        "input": {
            "head": {"seq": 3, "digest": d[2], "acc": accs[2]},
            "records": [
                {"seq": 1, "artifact_digest": d[0], "prev_digest": None, "link": links[0]},
                {"seq": 2, "artifact_digest": d[1], "prev_digest": d[0], "link": links[1]},
                {"seq": 3, "artifact_digest": d[2], "prev_digest": d[1], "link": links[2]},
            ],
        },
    },
    {
        "id": "p27-live-chain-commitment-genesis-chain",
        "kind": "chain_commitment",
        "expect": "valid",
        "description": "Live ledger chain: the 13 counter-signed records of the tersign ledger's genesis chain (seq 1 is the genesis receipt, p1), walked backwards from the head through the public /verify endpoint on 2026-08-28 — artifact digest and prevDigest at each of 13 steps. The accumulator over the 13 recomputed links equals the `acc` inside the confirmed anchor's subject: production anchors keccak256(utf8(canonical({acc, head, schema: 'tersign-chain-commitment-v1', seq}))) rather than the head digest, so the single anchored value commits every record with seq <= 13. Re-walk the chain and re-fold the accumulator yourself; the anchor row carries the subject object, its merkle path to the batch root, and the OpenTimestamps proof.",
        "input": {
            "head": {"seq": 13, "digest": GENESIS_CHAIN_HEAD, "acc": GENESIS_CHAIN_ACC},
            "records": GENESIS_CHAIN_RECORDS,
        },
        "provenance": {
            "ledger": "https://tersign.ai",
            "walk": f"curl https://tersign.ai/v1/receipts/{GENESIS_CHAIN_HEAD}/verify  # then follow prevDigest 12 more times to seq 1 (null prevDigest)",
            "commitment": {"acc": GENESIS_CHAIN_ACC, "head": GENESIS_CHAIN_HEAD, "schema": "tersign-chain-commitment-v1", "seq": 13},
            "commitment_digest": GENESIS_CHAIN_COMMITMENT_DIGEST,
            "anchored_digest": GENESIS_CHAIN_ANCHORED_DIGEST,
            "anchor": f"curl https://tersign.ai/v1/anchors/{SELLER_COMMITMENT_ANCHOR}",
            "proof": f"curl -O https://tersign.ai/v1/anchors/{SELLER_COMMITMENT_ANCHOR}/proof.ots",
            "ledger_signer": LEDGER_SIGNER,
            "note": "commitment_digest = keccak256(utf8(canonical(commitment))); the anchor's anchoredDigest = sha256(commitment_digest bytes) (anchor_relation); counter-signatures over each link are secp256k1 personal_sign material (crypto profile, outside the stdlib core)",
        },
    },
    {
        "id": "n36-chain-commitment-prefix-substituted",
        "kind": "chain_commitment",
        "expect": "reject",
        "reason": "continuity_reject",
        "description": "The substituted-prefix class. Record 1 replaced by a different record; prevs and links recomputed so the structural predicate still walks — seq 1..3 dense, every prev the previous artifact digest, every link recomputes, head digest unchanged (record 3 is untouched). chain_set accepts this set; under the SAME anchored head it is indistinguishable from the real one. Presented with the real chain's accumulator (acc_3 of p26), it rejects: the true accumulator of the substituted chain is a different value, and the anchor over the commitment was not built over this prefix. In production the recomputed links would also fail counter-signature recovery; this vector pins that the accumulator alone already separates the two prefixes.",
        "input": {
            "head": {"seq": 3, "digest": d_sub[2], "acc": accs[2]},
            "records": [
                {"seq": 1, "artifact_digest": d_sub[0], "prev_digest": None, "link": links_sub[0]},
                {"seq": 2, "artifact_digest": d_sub[1], "prev_digest": d_sub[0], "link": links_sub[1]},
                {"seq": 3, "artifact_digest": d_sub[2], "prev_digest": d_sub[1], "link": links_sub[2]},
            ],
        },
    },
    {
        "id": "n37-chain-commitment-last-link-only",
        "kind": "chain_commitment",
        "expect": "reject",
        "reason": "continuity_reject",
        "description": "The last-link-only class, and the falsifying input this kind was written against (repo rule 1: authored before the check existed; the pre-0.5.0 engine has no such kind, and the same input passes chain_set). p6's complete set with head.acc = keccak256(acc_0 || link_3) — an accumulator that folds the LAST link only, which is exactly what an anchor over the head digest commits to: the final record, not the prefix beneath it. A verifier that checks the head and the last link and calls the prefix committed accepts this vector and is wrong; the commitment is the fold over EVERY link from the tagged seed, and this value is not it.",
        "input": {
            "head": {"seq": 3, "digest": d[2], "acc": LAST_LINK_ONLY_ACC},
            "records": [
                {"seq": 1, "artifact_digest": d[0], "prev_digest": None, "link": links[0]},
                {"seq": 2, "artifact_digest": d[1], "prev_digest": d[0], "link": links[1]},
                {"seq": 3, "artifact_digest": d[2], "prev_digest": d[1], "link": links[2]},
            ],
        },
    },
    # ----------------------------------- v0.5.1: number-TOKEN class on integer fields (B25)
    # p6's complete set with head.seq written as the wire token `3.0`. JSON.parse collapses it
    # to 3 and a TS engine would call the set complete; Python's json keeps a float and the
    # integer predicate rejects. The suite's number-domain boundary is the TOKEN class (p25/n35
    # pinned it for canonical bytes); this vector pins the same boundary for sequence numbers,
    # and the TS engine reads integer fields at the token level so both engines agree.
    {
        "id": "n38-chain-set-float-seq-token",
        "kind": "chain_set",
        "expect": "reject",
        "reason": "completeness_reject",
        "description": "Number-token class on an integer field. p6's complete, continuous set with head.seq written as the JSON token 3.0 (integer-valued, non-integer token). A JSON.parse-based engine collapses 3.0 to 3 and calls the set complete; a json-module engine keeps a float and the integer predicate rejects. The suite's boundary is the token class, not the value (p25/n35 pin it for canonical bytes): a sequence number is an integer TOKEN, so this set rejects in both engines. Falsifying input authored against the pre-0.5.1 TS engine, which returned valid on these bytes.",
        "input": {
            "head": {"seq": 3.0, "digest": d[2]},
            "records": [
                {"seq": 1, "artifact_digest": d[0], "prev_digest": None, "link": links[0]},
                {"seq": 2, "artifact_digest": d[1], "prev_digest": d[0], "link": links[1]},
                {"seq": 3, "artifact_digest": d[2], "prev_digest": d[1], "link": links[2]},
            ],
        },
    },
    # ------------------------------------ v0.5.2: duplicate sequence numbers (equivocation)
    # chain_set has always rejected a second record at an occupied seq, but no vector reached
    # that branch: a verifier that deduplicated records by seq before the completeness check
    # passed every pre-0.5.2 vector. p28/n39 pin the branch; p29/n40 pin what a single
    # presentation cannot show — the other record, presented alone at a committed position.
    {
        "id": "p28-issuer-sequence-distinct-seq",
        "kind": "chain_set",
        "expect": "valid",
        "description": "Accepting twin of n39: the same issuer records renumbered so each has its own sequence number — n39's second seq-2 record becomes 3 and its successor 4 (content and digests change with the number), prevs and links recomputed. The only attestation over the sequence is the issuer's own (`attestations`, not read by the predicate). Valid is the structural predicate over the PRESENTED records: every seq 1..4 present exactly once, links continuous, head matches. It is not evidence that no other record carries any of these numbers: a record the issuer never presented is not in these bytes (n40 is that case, checked against a committed prefix).",
        "input": {
            "head": {"seq": 4, "digest": ISSUER_R4},
            "records": DISTINCT_SEQ_RECORDS,
            "attestations": [{"by": ISSUER, "role": "issuer"}],
        },
    },
    {
        "id": "n39-issuer-sequence-duplicate-seq",
        "kind": "chain_set",
        "expect": "reject",
        "reason": "completeness_reject",
        "description": "Rejecting twin of p28: two different issuer records carrying the same `seq` and `correctionSeq`, both presented at seq 2 of an issuer-held sequence, each with the correct prev and link for that position (the sequence forked after seq 1). The only attestation over the sequence is the issuer's own. An evaluator MUST reject on the duplicate (`duplicate seq [2] under committed head`). An engine that omits the duplicate check (for instance because the issuer attests its numbers are unique) rejects only for the wrong reason (continuity: the second seq-2 record does not chain from the first); one that deduplicates by seq before the completeness check accepts when it keeps the first record and rejects for the wrong reason when it keeps the last. All three fail this vector. The duplicate is visible here only because both records were presented together: a sequence attested only by its issuer does not evidence that no other record carries the same number (n40).",
        "input": {
            "head": {"seq": 3, "digest": ISSUER_R3},
            "records": DUP_SEQ_RECORDS,
            "attestations": [{"by": ISSUER, "role": "issuer"}],
        },
    },
    {
        "id": "p29-committed-prefix-one-record-per-position",
        "kind": "chain_commitment",
        "expect": "valid",
        "description": "Accepting twin of n40: the committed prefix — three issuer records (n39's seq 1, first seq 2 and seq 3), head.acc folded over every recomputed link. Valid: the presented prefix is the one the commitment was built over, so the record at each position is the one committed there. In production the links are counter-signed at issuance by a party outside the transaction and the commitment is anchored; this structural profile checks the fold only.",
        "input": {
            "head": {"seq": 3, "digest": ISSUER_R3, "acc": COMMITTED_PREFIX_ACC},
            "records": COMMITTED_PREFIX,
        },
    },
    {
        "id": "n40-equivocating-record-at-committed-position",
        "kind": "chain_commitment",
        "expect": "reject",
        "reason": "continuity_reject",
        "description": "Equivocation against a committed prefix. The issuer's other record carrying seq 2 and the same correctionSeq (n39's second seq 2) is presented alone at position 2, in place of the committed record, with prevs and links recomputed. This presentation passes the structural chain_set predicate under the same head digest as p29 (asserted at generation): an issuer-only sequence cannot tell the two apart. Only head.acc, the commitment over every link, does, and it rejects (`accumulator mismatch`): two records cannot occupy one committed position. The arithmetic is n36's substitution at an interior position; what differs is the substituted record, a second record under an existing number rather than a forgery.",
        "input": {
            "head": {"seq": 3, "digest": ISSUER_R3, "acc": COMMITTED_PREFIX_ACC},
            "records": EQUIVOCATING_PREFIX,
        },
    },
    # ------------------------- v0.5.5: non-ASCII string VALUES in the digest domain (2-sided)
    # Reported by @Rul1an (issue #1, 2026-09-30): n12/p14 cover non-ASCII keys and nothing
    # covered values. Four accepting payloads (Latin-1 range, BMP CJK, astral, decomposed), each
    # beside a rejecting twin whose digest is the one a plausible wrong encoding produces.
    {
        "id": "p39-digest-non-ascii-latin1-value",
        "kind": "digest_recompute",
        "expect": "valid",
        "description": "A non-ASCII string VALUE in the digest domain: {\"a\":\"\u00e9\"}, with \u00e9 the single code point U+00E9. RFC 8785 serializes every code point outside the ASCII control range as is (section 3.2.2.2) and encodes the result in UTF-8 (section 3.2.4), so the digest is keccak256 over the bytes 7b 22 61 22 3a 22 c3 a9 22 7d. Until v0.5.5 the corpus carried non-ASCII in the digest domain only in keys (p14, n12), so an engine that escaped string values to ASCII before hashing passed every vector. Accepting twin of n71. Input from @Rul1an's report (issue #1).",
        "input": {"payload": NON_ASCII_LATIN1, "expected_digest": _keccak_hex(canonical(NON_ASCII_LATIN1).encode("utf-8"))},
    },
    {
        "id": "n71-digest-non-ascii-escaped-before-hashing",
        "kind": "digest_recompute",
        "expect": "reject",
        "reason": "recompute_mismatch",
        "description": "Rejecting twin of p39: the same payload, with expected_digest computed over {\"a\":\"\\u00e9\"}, \u00e9 written as a \\u escape. That is the text Python's json.dumps emits with its default ensure_ascii=True and separators=(\",\", \":\"), so it is the digest a canonicalizer built on json.dumps(value, sort_keys=True, separators=(\",\", \":\")) computes. RFC 8785 section 3.2.2.2 escapes only the control range, the quotation mark and the backslash, and serializes every other code point as is: the escaped text is not the canonical form, and its digest does not commit to this payload. An engine that escapes non-ASCII values rejects p39 to p42 and accepts this vector; one that accepts either form accepts this vector only.",
        "input": {"payload": NON_ASCII_LATIN1, "expected_digest": _keccak_hex(ESCAPED_LATIN1_TEXT.encode("utf-8"))},
    },
    {
        "id": "p40-digest-non-ascii-cjk-value",
        "kind": "digest_recompute",
        "expect": "valid",
        "description": "A non-ASCII string value from the Basic Multilingual Plane above Latin-1: {\"a\":\"\u4e2d\u6587\"} (U+4E2D U+6587), each a three-byte UTF-8 sequence. The digest is keccak256 over the UTF-8 bytes of the canonical form, code points as is (RFC 8785 sections 3.2.2.2 and 3.2.4). Accepting twin of n72.",
        "input": {"payload": NON_ASCII_CJK, "expected_digest": _keccak_hex(canonical(NON_ASCII_CJK).encode("utf-8"))},
    },
    {
        "id": "n72-digest-non-ascii-latin1-bytes",
        "kind": "digest_recompute",
        "expect": "reject",
        "reason": "recompute_mismatch",
        "description": "Rejecting twin of p40: the same payload, with expected_digest computed over the canonical text encoded one byte per UTF-16 code unit, each truncated to its low eight bits. Those are the bytes Node's Buffer.from(text, \"latin1\") (alias \"binary\") produces, so this is the digest of a pipeline that hashes the canonical string through that encoding: \u4e2d (U+4E2D) becomes 0x2d and \u6587 (U+6587) 0x87, and the value is lost. RFC 8785 section 3.2.4 requires UTF-8. An engine that hashes Latin-1 bytes rejects p39 to p42 and p14 and accepts this vector; one that accepts either encoding accepts this vector only.",
        "input": {"payload": NON_ASCII_CJK, "expected_digest": _keccak_hex(LATIN1_CJK_BYTES)},
    },
    {
        "id": "p41-digest-non-ascii-astral-value",
        "kind": "digest_recompute",
        "expect": "valid",
        "description": "A supplementary-plane string value: {\"a\":\"\U00020bb7\"}, U+20BB7 (a CJK Extension B ideograph), one code point that UTF-16 holds as the surrogate pair D842 DFB7 and UTF-8 encodes in four bytes, f0 a0 ae b7. The digest is keccak256 over the UTF-8 bytes of the canonical form. Accepting twin of n73, and of n83, which drops the pair's second half.",
        "input": {"payload": NON_ASCII_ASTRAL, "expected_digest": _keccak_hex(canonical(NON_ASCII_ASTRAL).encode("utf-8"))},
    },
    {
        "id": "n73-digest-non-ascii-cesu8-bytes",
        "kind": "digest_recompute",
        "expect": "reject",
        "reason": "recompute_mismatch",
        "description": "Rejecting twin of p41: the same payload, with expected_digest computed over CESU-8 (Unicode Technical Report #26), where each half of the surrogate pair is encoded on its own in three bytes, ed a1 82 ed be b7 in place of f0 a0 ae b7. That is the output of a UTF-8 encoder that walks UTF-16 code units without combining pairs. CESU-8 equals UTF-8 on every BMP character, so p39, p40 and p42 cannot tell the two apart; only an astral code point can. RFC 8785 section 3.2.4 requires UTF-8. An engine that hashes CESU-8 rejects p41 and p14 and accepts this vector; one that accepts either encoding accepts this vector only.",
        "input": {"payload": NON_ASCII_ASTRAL, "expected_digest": _keccak_hex(CESU8_ASTRAL_BYTES)},
    },
    {
        "id": "p42-digest-non-ascii-decomposed-value",
        "kind": "digest_recompute",
        "expect": "valid",
        "description": "p39's value in decomposed form: e followed by U+0301 COMBINING ACUTE ACCENT (Unicode NFD), which renders as p39's \u00e9 and is a different code-point sequence. RFC 8785 applies no Unicode normalization: every component of a JCS scheme MUST preserve string data as is (section 3.1). The digest is therefore keccak256 over the UTF-8 bytes of these code points (65 cc 81 for the value), and it differs from p39's. Accepting twin of n74: an engine that normalizes strings to NFC before hashing computes p39's digest here and rejects.",
        "input": {"payload": NON_ASCII_DECOMPOSED, "expected_digest": _keccak_hex(canonical(NON_ASCII_DECOMPOSED).encode("utf-8"))},
    },
    {
        "id": "n74-digest-non-ascii-normalized-before-hashing",
        "kind": "digest_recompute",
        "expect": "reject",
        "reason": "recompute_mismatch",
        "description": "Rejecting twin of p42: the same decomposed payload, with expected_digest computed over the canonical text normalized to NFC. That is p39's digest (asserted at generation), the value an engine that normalizes strings before hashing arrives at. Normalization changes the bytes a digest binds, and RFC 8785 section 3.1 requires string data to be preserved as is, so this digest does not commit to the presented payload. An engine that normalizes to NFC accepts this vector and rejects p42; one that accepts either form accepts this vector only.",
        "input": {"payload": NON_ASCII_DECOMPOSED, "expected_digest": _keccak_hex(NFC_OF_DECOMPOSED_TEXT.encode("utf-8"))},
    },
    # ------------------------------ v0.5.5: chain_link sequence domain [1, 2^53-1] (2-sided)
    # Reported by @Rul1an (issue #1, 2026-09-30): no vector reached the seq < 1 branch, and the
    # manifest's chain_link line did not state the domain. The crypto profile (crypto/, PR #11,
    # field_domain) states the same domain: seq 1 is the genesis link. p4 is the accepting twin
    # at the lower bound, p43 at the upper.
    {
        "id": "n75-chain-link-seq-zero",
        "kind": "chain_link",
        "expect": "reject",
        "reason": "continuity_reject",
        "description": "p4's genesis link with seq 0, expected_link recomputed for seq 0, so the arithmetic holds and only the sequence domain can reject. A sequence number is an integer token in [1, 2^53-1]: seq 1 is the genesis link, as chain_set numbers its records 1..head.seq, so 0 is outside the domain. It is the link a zero-based numbering produces. p4 is the accepting twin at the lower bound. Without the lower bound this vector verifies; p4 with only seq changed rejects with or without it, because its link no longer matches. Input from @Rul1an's report (issue #1).",
        "input": {
            "artifact_digest": GENESIS_DIGEST,
            "prev_digest": None,
            "seq": 0,
            "expected_link": chain_link_digest(GENESIS_DIGEST, None, 0),
        },
    },
    {
        "id": "n76-chain-link-seq-past-ijson-range",
        "kind": "chain_link",
        "expect": "reject",
        "reason": "continuity_reject",
        "description": "seq = 2^53, one past the sequence domain [1, 2^53-1], on p6's second record over its predecessor, expected_link recomputed for that seq. Past 2^53-1 a JSON number token no longer names one integer in every engine: a parser that reads numbers as doubles reads 9007199254740993 as 2^53 and recomputes a different link than an exact-integer parser does (measured on v0.5.4's engines with seq 2^53+1 and its exact link: Python valid, TypeScript continuity_reject). The domain stops where the I-JSON integer domain does (p12/n11). Rejecting twin of p43; v0.5.4's engines both accepted this vector.",
        "input": {
            "artifact_digest": d[1],
            "prev_digest": d[0],
            "seq": SEQ_MAX + 1,
            "expected_link": chain_link_digest(d[1], d[0], SEQ_MAX + 1),
        },
    },
    {
        "id": "p43-chain-link-seq-ijson-boundary",
        "kind": "chain_link",
        "expect": "valid",
        "description": "The top of the sequence domain: seq = 2^53-1, the largest integer every JSON engine carries exactly, on p6's second record over its predecessor, link recomputed. Valid. Accepting twin of n76: an engine that defends the bound by stopping short of it rejects here.",
        "input": {
            "artifact_digest": d[1],
            "prev_digest": d[0],
            "seq": SEQ_MAX,
            "expected_link": chain_link_digest(d[1], d[0], SEQ_MAX),
        },
    },
    {
        "id": "n77-chain-link-float-seq-token",
        "kind": "chain_link",
        "expect": "reject",
        "reason": "continuity_reject",
        "description": "p4 with seq written as the JSON token 1.0 and p4's link. JSON.parse collapses the token to 1, and the link recomputes; Python's json keeps a float. A sequence number is an integer TOKEN (n38 pins the same rule for chain_set), so this rejects in both engines. p4 is the accepting twin.",
        "input": {
            "artifact_digest": GENESIS_DIGEST,
            "prev_digest": None,
            "seq": 1.0,
            "expected_link": chain_link_digest(GENESIS_DIGEST, None, 1),
        },
    },
    # ----------------------------------------- v0.5.5: phase_claim, every clause reached
    # Reported by @Rul1an (issue #1, 2026-09-30): no vector reached the no-economic_phase branch.
    # n79 reaches the record-not-an-object half of the same branch; n80 isolates the vocabulary
    # clause, which n18 does not (its presented_as differs from its phase, so equality alone
    # rejects it; listed as unisolated in issue #9). p7 is the accepting twin of all three.
    {
        "id": "n78-phase-claim-no-economic-phase",
        "kind": "phase_claim",
        "expect": "reject",
        "reason": "phase_reject",
        "description": "p7's record with economic_phase removed, presented as delivery. A record that carries no economic_phase is evidence of no phase and rejects. Until v0.5.5 no vector reached this branch: with it removed, the Python engine raises on this input and returns no verdict, while the TypeScript engine rejects through the vocabulary check, so there this vector pins the verdict rather than the branch. p7 is the accepting twin. Input from @Rul1an's report (issue #1).",
        "input": {
            "record": {"deliverable_digest": d[0]},
            "presented_as": "delivery",
        },
    },
    {
        "id": "n79-phase-claim-record-not-an-object",
        "kind": "phase_claim",
        "expect": "reject",
        "reason": "phase_reject",
        "description": "The record presented as an explicit JSON null, as delivery evidence. A record that is not an object carries no phase and rejects; without the object check, both engines raise on the key test and return no verdict. p7 is the accepting twin.",
        "input": {
            "record": None,
            "presented_as": "delivery",
        },
    },
    {
        "id": "n80-phase-claim-unrecognized-phase-presented-as-itself",
        "kind": "phase_claim",
        "expect": "reject",
        "reason": "phase_reject",
        "description": "n18's unrecognized phase token, presented as that same token. The phase vocabulary is closed (funding, delivery, settlement, refund, reversal): a record's phase must be one of them, and an uninterpretable phase does not verify as any phase, its own spelling included. n18 presents the token as delivery, so phase equality alone rejects it and the vocabulary clause stays unisolated; here only the vocabulary clause can reject. p7 is the accepting twin.",
        "input": {
            "record": {"economic_phase": "settled_and_delivered", "amount": "10", "asset": "USDC"},
            "presented_as": "settled_and_delivered",
        },
    },
    # --------------------------------- v0.5.5: lone surrogates have no canonical form (2-sided)
    # RFC 7493 section 2.1 forbids unpaired surrogates in names and values; RFC 8785 section
    # 3.2.2.2 requires a canonicalizer to terminate on them. v0.5.4's engines forked on every
    # one of n81-n84 (measured). p44 is the paired form; n81/n82 each drop one half of one of
    # its two pairs; n83 drops p41's second half, and n84 the second half of p14's astral name.
    {
        "id": "p44-canonical-bytes-surrogate-pair",
        "kind": "canonical_bytes",
        "expect": "valid",
        "description": "Accepting twin of n81 and n82: payload_text {\"\\ud842\\udfb7\":\"\\ud842\\udfb7\"}, U+20BB7 written as a surrogate-pair escape, as a name and as a value. A paired escape is one code point (RFC 7493 section 2.1: \"\\uD800\\uDEAD\" is legal), and the canonical form writes it as is: {\"\U00020bb7\":\"\U00020bb7\"}. An engine that rejects every surrogate escape, rather than an unpaired one, fails here.",
        "input": {"payload_text": '{"' + PAIR_ESC + '":"' + PAIR_ESC + '"}', "claimed_canonical": '{"' + ASTRAL + '":"' + ASTRAL + '"}'},
    },
    {
        "id": "n81-canonical-bytes-lone-high-surrogate-in-value",
        "kind": "canonical_bytes",
        "expect": "reject",
        "reason": "canonicalization_reject",
        "description": "p44 with the value's second half dropped: payload_text {\"\\ud842\\udfb7\":\"\\ud842\"}, a lone high surrogate in a value. RFC 7493 section 2.1 forbids an unpaired surrogate (\"\\uDEAD\" is invalid), and RFC 8785 section 3.2.2.2 requires a canonicalizer to terminate on one, so the text has no canonical form. claimed_canonical carries the code unit as is, the text Python's json.dumps(value, ensure_ascii=False) emits for it, so an engine that skips the check compares equal and accepts. Measured on v0.5.4's engines: Python valid, TypeScript canonicalization_reject (JSON.stringify escapes the code unit, so the comparison failed).",
        "input": {"payload_text": '{"' + PAIR_ESC + '":"' + HIGH_ESC + '"}', "claimed_canonical": '{"' + ASTRAL + '":"' + LONE_HIGH + '"}'},
    },
    {
        "id": "n82-canonical-bytes-lone-low-surrogate-in-name",
        "kind": "canonical_bytes",
        "expect": "reject",
        "reason": "canonicalization_reject",
        "description": "p44 with the name's first half dropped: payload_text {\"\\udfb7\":\"\\ud842\\udfb7\"}, a lone LOW surrogate in a NAME. The rule covers names as well as values (RFC 7493 section 2.1), and a low half without its high half as well as the reverse, so a check that reads only values, or only looks for a high surrogate missing its low half, misses it. claimed_canonical carries the escape, {\"\\udfb7\":\"\U00020bb7\"}, the text JSON.stringify emits since ES2019, so an engine built on it that skips the check compares equal and accepts. Measured on v0.5.4's engines: TypeScript valid, Python number_domain_reject (its key sort raised a UnicodeEncodeError, which it read as a number-domain error).",
        "input": {"payload_text": '{"' + LOW_ESC + '":"' + PAIR_ESC + '"}', "claimed_canonical": '{"' + LOW_ESC + '":"' + ASTRAL + '"}'},
    },
    {
        "id": "n83-digest-lone-surrogate-in-value",
        "kind": "digest_recompute",
        "expect": "reject",
        "reason": "canonicalization_reject",
        "description": "p41's payload with the pair's second half dropped: {\"a\":\"\\ud842\"}, a lone high surrogate in the digest domain, with expected_digest computed over the text {\"a\":\"\\ud842\"} with the code unit escaped, which is what a canonicalizer built on JSON.stringify hashes. The payload has no canonical form (RFC 8785 section 3.2.2.2; RFC 7493 section 2.1) and no UTF-8 encoding, so it rejects with canonicalization_reject whatever digest is claimed. Measured on v0.5.4's engines: TypeScript valid, Python number_domain_reject.",
        "input": {"payload": {"a": LONE_HIGH}, "expected_digest": _keccak_hex(LONE_SURROGATE_JS_TEXT.encode("utf-8"))},
    },
    {
        "id": "n84-digest-lone-surrogate-in-name",
        "kind": "digest_recompute",
        "expect": "reject",
        "reason": "canonicalization_reject",
        "description": "p14's payload with the second name's low half dropped: the name U+10000 (D800 DC00) becomes a lone high surrogate, D800, in the digest domain. expected_digest is computed over the text JSON.stringify emits for it, with that name escaped and sorted first by UTF-16 code unit. A name holding an unpaired surrogate has no canonical form (RFC 7493 section 2.1 covers member names; RFC 8785 section 3.2.2.2), so it rejects with canonicalization_reject, as n83 does for a value; p14 is the accepting twin. An engine that checks values and not names reads this vector valid when it is built on JSON.stringify, and rejects it with number_domain_reject when, as v0.5.4's Python engine did, its UTF-16 sort key raises on the name.",
        "input": {"payload": LONE_NAME_PAYLOAD, "expected_digest": _keccak_hex(LONE_NAME_JS_TEXT.encode("utf-8"))},
    },
    # ------------- v0.5.5, review round: every clause the new MANIFEST text states, pinned
    # Line and paragraph separators, and a decomposed NAME, in the digest domain (2-sided).
    {
        "id": "p45-digest-line-separators-value",
        "kind": "digest_recompute",
        "expect": "valid",
        "description": 'U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR as a string value. RFC 8785 section 3.2.2.2 escapes only the control range U+0000-U+001F, the quotation mark and the backslash, and writes every other code point as is, these two included, so the digest is keccak256 over the UTF-8 bytes of the canonical text, with the value as e2 80 a8 e2 80 a9. Accepting twin of n85: an engine that escapes the two separators rejects here.',
        "input": {"payload": LINE_SEPARATORS, "expected_digest": _keccak_hex(canonical(LINE_SEPARATORS).encode("utf-8"))},
    },
    {
        "id": "n85-digest-line-separators-escaped",
        "kind": "digest_recompute",
        "expect": "reject",
        "reason": "recompute_mismatch",
        "description": 'Rejecting twin of p45: the same payload, with expected_digest computed over {"a":"' + BS + 'u2028' + BS + 'u2029"}, both separators written as escapes. Go encoding/json emits that text for this payload, with or without SetEscapeHTML(false) (measured, go1.27.1), so it is the digest a canonicalizer built on it computes. RFC 8785 section 3.2.2.2 does not escape them: the escaped text is not the canonical form, and its digest does not commit to this payload. An engine that escapes them rejects p45 and accepts this vector; one that accepts either form accepts this vector only.',
        "input": {"payload": LINE_SEPARATORS, "expected_digest": _keccak_hex(ESCAPED_SEPARATORS_TEXT.encode("utf-8"))},
    },
    {
        "id": "p46-digest-decomposed-name",
        "kind": "digest_recompute",
        "expect": "valid",
        "description": 'A decomposed NAME in the digest domain: e followed by U+0301 COMBINING ACUTE ACCENT (Unicode NFD), as a member name with the value 1. p42 and n74 pin the rule for a value; a name is a string too, and RFC 8785 section 3.1 requires string data to be preserved as is, so the name is serialized and hashed as written, 65 cc 81. Accepting twin of n86: an engine that normalizes names to NFC rejects here.',
        "input": {"payload": DECOMPOSED_NAME, "expected_digest": _keccak_hex(canonical(DECOMPOSED_NAME).encode("utf-8"))},
    },
    {
        "id": "n86-digest-decomposed-name-normalized",
        "kind": "digest_recompute",
        "expect": "reject",
        "reason": "recompute_mismatch",
        "description": 'Rejecting twin of p46: the same payload, with expected_digest computed over the canonical text normalized to NFC, where the name is the single code point U+00E9 (c3 a9). An engine that normalizes names, and not values, before serializing passes p42 and n74, rejects p46 and accepts this vector; one that accepts either form accepts this vector only. RFC 8785 section 3.1 applies no normalization to names or values.',
        "input": {"payload": DECOMPOSED_NAME, "expected_digest": _keccak_hex(NFC_OF_DECOMPOSED_NAME_TEXT.encode("utf-8"))},
    },
    # A chain_link seq that is not an integer token at all: a string, a boolean, null. Each carries
    # p4's link for seq 1, so an engine that coerces the value to 1 recomputes the link and accepts.
    {
        "id": "n87-chain-link-seq-string",
        "kind": "chain_link",
        "expect": "reject",
        "reason": "continuity_reject",
        "description": 'p4 with seq written as the JSON string "1" and p4 link for seq 1. A sequence number is an integer token, and a string is not one, whatever it spells, so this rejects. An engine that coerces seq (Number() in JavaScript, int() in Python) reads 1, recomputes the link and accepts. p4 is the accepting twin.',
        "input": {
            "artifact_digest": GENESIS_DIGEST,
            "prev_digest": None,
            "seq": "1",
            "expected_link": chain_link_digest(GENESIS_DIGEST, None, 1),
        },
    },
    {
        "id": "n88-chain-link-seq-boolean",
        "kind": "chain_link",
        "expect": "reject",
        "reason": "continuity_reject",
        "description": 'p4 with seq written as the JSON literal true and p4 link for seq 1. A boolean is not an integer token, so this rejects. In Python bool is a subclass of int and True == 1, so an engine that checks isinstance(seq, int) alone accepts; so does one that coerces seq with Number(). p4 is the accepting twin.',
        "input": {
            "artifact_digest": GENESIS_DIGEST,
            "prev_digest": None,
            "seq": True,
            "expected_link": chain_link_digest(GENESIS_DIGEST, None, 1),
        },
    },
    {
        "id": "n89-chain-link-seq-null",
        "kind": "chain_link",
        "expect": "reject",
        "reason": "continuity_reject",
        "description": 'p4 with seq written as null and p4 link for seq 1. null is not an integer token, so this rejects. An engine that defaults a missing or null seq to the genesis sequence number 1 recomputes the link and accepts. p4 is the accepting twin.',
        "input": {
            "artifact_digest": GENESIS_DIGEST,
            "prev_digest": None,
            "seq": None,
            "expected_link": chain_link_digest(GENESIS_DIGEST, None, 1),
        },
    },
    # phase_claim: an EARLIER phase presented, and a phase token in another letter case.
    {
        "id": "n90-phase-claim-delivery-presented-as-funding",
        "kind": "phase_claim",
        "expect": "reject",
        "reason": "phase_reject",
        "description": 'p7 presented as funding: a delivery-phase record offered as evidence of funding, an earlier phase. n6 pins the other direction, a funding record presented as delivery. A record verifies as evidence of the phase it carries and of no other, so an engine that rejects only a record presented as a LATER phase passes n6 and accepts this vector. p7 is the accepting twin. Issue #9 listed an earlier phase presented among its coverage gaps.',
        "input": {
            "record": {"economic_phase": "delivery", "deliverable_digest": d[0]},
            "presented_as": "funding",
        },
    },
    {
        "id": "n91-phase-claim-phase-letter-case",
        "kind": "phase_claim",
        "expect": "reject",
        "reason": "phase_reject",
        "description": 'A record whose economic_phase is "Delivery", presented as delivery. The vocabulary is closed and its tokens compare as exact strings: "Delivery" is not "delivery", so the record carries no phase this verifier can interpret, and it rejects. An engine that case-folds phase tokens accepts. p7 is the accepting twin.',
        "input": {
            "record": {"economic_phase": "Delivery"},
            "presented_as": "delivery",
        },
    },
    {
        "id": "p47-phase-claim-funding-as-itself",
        "kind": "phase_claim",
        "expect": "valid",
        "description": 'A record whose economic_phase is funding, presented as funding: valid. The vocabulary is closed at five words; p7 accepts delivery, and p47 to p50 accept the other four, one each, so an engine whose vocabulary leaves one out rejects here.',
        "input": {
            "record": {"economic_phase": "funding"},
            "presented_as": "funding",
        },
    },
    {
        "id": "p48-phase-claim-settlement-as-itself",
        "kind": "phase_claim",
        "expect": "valid",
        "description": 'A record whose economic_phase is settlement, presented as settlement: valid. The vocabulary is closed at five words; p7 accepts delivery, and p47 to p50 accept the other four, one each, so an engine whose vocabulary leaves one out rejects here.',
        "input": {
            "record": {"economic_phase": "settlement"},
            "presented_as": "settlement",
        },
    },
    {
        "id": "p49-phase-claim-refund-as-itself",
        "kind": "phase_claim",
        "expect": "valid",
        "description": 'A record whose economic_phase is refund, presented as refund: valid. The vocabulary is closed at five words; p7 accepts delivery, and p47 to p50 accept the other four, one each, so an engine whose vocabulary leaves one out rejects here.',
        "input": {
            "record": {"economic_phase": "refund"},
            "presented_as": "refund",
        },
    },
    {
        "id": "p50-phase-claim-reversal-as-itself",
        "kind": "phase_claim",
        "expect": "valid",
        "description": 'A record whose economic_phase is reversal, presented as reversal: valid. The vocabulary is closed at five words; p7 accepts delivery, and p47 to p50 accept the other four, one each, so an engine whose vocabulary leaves one out rejects here.',
        "input": {
            "record": {"economic_phase": "reversal"},
            "presented_as": "reversal",
        },
    },
    # payload_text: the surrogate-before-number order, and a duplicate name that only a
    # comparison by UTF-16 code units finds.
    {
        "id": "n92-canonical-bytes-lone-surrogate-after-number",
        "kind": "canonical_bytes",
        "expect": "reject",
        "reason": "canonicalization_reject",
        "description": 'payload_text {"a":2.0,"b":"' + BS + 'ud800"}: an integer-valued float token, which n35 rejects with number_domain_reject, and after it a lone high surrogate, which n81 rejects with canonicalization_reject. With both faults in one text, the rule decides which reason it names: the shape of the text, an unpaired surrogate included, is decided before its number tokens, so this rejects with canonicalization_reject. An engine that finds the surrogate only while serializing meets the number first and names number_domain_reject. claimed_canonical is the text an engine that checks neither emits (JSON.parse collapses 2.0 to 2, and JSON.stringify escapes the code unit), so such an engine accepts.',
        "input": {"payload_text": SURROGATE_AFTER_NUMBER_TEXT, "claimed_canonical": SURROGATE_AFTER_NUMBER_JS_TEXT},
    },
    {
        "id": "n93-canonical-bytes-duplicate-name-half-escaped-pair",
        "kind": "canonical_bytes",
        "expect": "reject",
        "reason": "canonicalization_reject",
        "description": 'payload_text names U+20BB7 twice: first with the high half of its surrogate pair, D842, as a raw code unit and the low half written ' + BS + 'udfb7, then as the two escapes ' + BS + 'ud842' + BS + 'udfb7. Both decode to the same UTF-16 code units, D842 DFB7, so the text repeats a name and rejects with canonicalization_reject (RFC 7493 section 2.3). Python json joins only an escaped pair, so there the first name decodes to two code points and the second to one; an engine that compares decoded names as code points sees two names, and accepts. Names compare as UTF-16 code units, as JSON.parse holds them. claimed_canonical is the text such an engine emits. An engine that rejects the raw code unit in the text itself also rejects with canonicalization_reject. The vector file carries the raw code unit as the escape ' + BS + 'ud842 inside payload_text, so a loader has to keep it, as for n81.',
        "input": {"payload_text": HALF_ESCAPED_DUP_TEXT, "claimed_canonical": HALF_ESCAPED_DUP_CLAIM},
    },
    # An unpaired surrogate inside the objects the binding and boundary criteria digest.
    {
        "id": "n94-offer-binding-lone-surrogate",
        "kind": "offer_binding",
        "expect": "reject",
        "reason": "binding_reject",
        "description": 'An offer holding a lone high surrogate, D800, in a string value, and a receipt committing to the digest of {"a":"' + BS + 'ud800","resourceUrl":"https://api.example/x"}, the text JSON.stringify emits for it. The offer has no canonical form (RFC 7493 section 2.1; RFC 8785 section 3.2.2.2), so no digest of it exists to bind, and the criterion rejects with its own reason, binding_reject. An engine that skips the well-formedness check when it digests the offer recomputes the committed digest and accepts. p15 is the accepting twin of the criterion.',
        "input": {"offer": LONE_OFFER, "receipt": {"offerDigest": _keccak_hex(_js_text(LONE_OFFER).encode("utf-8"))}},
    },
    {
        "id": "n95-decision-evidence-binding-lone-surrogate",
        "kind": "decision_evidence_binding",
        "expect": "reject",
        "reason": "binding_reject",
        "description": 'p19 decision evidence with a lone high surrogate, D800, appended to policy.id, and a record committing to the digest a JSON.stringify-based canonicalizer computes for it, with the code unit escaped. The object has no canonical form, so the binding rejects with binding_reject. An engine that skips the well-formedness check when it digests decision evidence recomputes the committed digest and accepts. p19 is the accepting twin.',
        "input": {
            "record": {
                "outcome": "allowed",
                "decisionEvidenceDigest": _keccak_hex(_js_text(LONE_DECISION_EVIDENCE).encode("utf-8")),
            },
            "decision_evidence": LONE_DECISION_EVIDENCE,
        },
    },
    {
        "id": "n96-boundary-binding-lone-surrogate-in-prefix",
        "kind": "boundary_binding",
        "expect": "reject",
        "reason": "boundary_reject",
        "description": 'p18 with a lone low surrogate, DC00, appended to the second prefix record event, and prefixDigest the digest a JSON.stringify-based canonicalizer computes for that prefix, with the code unit escaped; position, attested length and coverage as in p18. The prefix has no canonical form, so the boundary event cannot bind it, and the criterion rejects with boundary_reject. An engine that skips the well-formedness check when it digests the prefix recomputes the claimed digest and accepts. p18 is the accepting twin.',
        "input": {
            "prefix": LONE_BOUNDARY_PREFIX,
            "boundary_event": {
                "event": "witness_ref_introduced",
                "ruleVersion": "witness-ref-v1",
                "prefixDigest": _keccak_hex(_js_text(LONE_BOUNDARY_PREFIX).encode("utf-8")),
                "position": 3,
                "attestedPrefixLength": 3,
            },
            "covered_through": 3,
        },
    },
    # v0.5.5, second review round: a clause each, which a mutant broke without failing a vector.
    # The exponent form of a number token, in chain_link's seq and in the digest domain.
    {
        "id": "n97-chain-link-exponent-seq-token",
        "kind": "chain_link",
        "expect": "reject",
        "reason": "continuity_reject",
        "description": "p4 with seq written as the JSON token 1e0, the exponent form, and p4's link. JSON.parse reads the token as the number 1, and the link recomputes; Python's json reads a float. A sequence number is an integer TOKEN, and a token with an exponent part is not one whatever its value, so this rejects in both engines. n77 pins the fraction form, 1.0; an engine, or a vector loader, that looks only for a decimal point passes n77 and accepts this vector. p4 is the accepting twin.",
        "input": {
            "artifact_digest": GENESIS_DIGEST,
            "prev_digest": None,
            "seq": _raw_number("1e0"),
            "expected_link": chain_link_digest(GENESIS_DIGEST, None, 1),
        },
    },
    {
        "id": "n103-canonical-bytes-exponent-token",
        "kind": "canonical_bytes",
        "expect": "reject",
        "reason": "number_domain_reject",
        "description": "payload_text {\"amount\": 1e2}: a number token with an exponent part whose value is an integer. The digest-domain boundary is the token class, so the exponent form rejects as the fraction form does (n35, {\"amount\": 2.0}). JSON.parse reads 1e2 as 100, and claimed_canonical is {\"amount\":100}, the text JSON.stringify then emits, so an engine that looks only for a decimal point in number tokens passes n35 and accepts this vector. p25 is the accepting twin.",
        "input": {"payload_text": '{"amount": 1e2}', "claimed_canonical": '{"amount":100}'},
    },
    # Code points RFC 8785 section 3.2.2.2 writes as is that an encoder may escape.
    {
        "id": "p51-digest-html-significant-value",
        "kind": "digest_recompute",
        "expect": "valid",
        "description": 'A string value holding "<", ">" and "&": {"a":"<b>&"}. RFC 8785 section 3.2.2.2 escapes only the control range, the quotation mark and the backslash, so the canonical text carries the three as is, and the digest is keccak256 over its UTF-8 bytes. Accepting twin of n98: an engine that escapes them for HTML safety rejects here.',
        "input": {"payload": HTML_SIGNIFICANT, "expected_digest": _keccak_hex(canonical(HTML_SIGNIFICANT).encode("utf-8"))},
    },
    {
        "id": "n98-digest-html-significant-escaped",
        "kind": "digest_recompute",
        "expect": "reject",
        "reason": "recompute_mismatch",
        "description": 'Rejecting twin of p51: the same payload, with expected_digest computed over {"a":"' + BS + 'u003cb' + BS + 'u003e' + BS + 'u0026"}, the three written as escapes. Go encoding/json emits that text by default (json.Marshal escapes "<", ">" and "&" for HTML safety; an Encoder with SetEscapeHTML(false) does not; measured, go1.27.1), so it is the digest a canonicalizer built on json.Marshal computes. The escaped text is not the canonical form, and its digest does not commit to this payload. An engine that escapes them rejects p51 and accepts this vector; one that accepts either form accepts this vector only.',
        "input": {"payload": HTML_SIGNIFICANT, "expected_digest": _keccak_hex(HTML_ESCAPED_TEXT.encode("utf-8"))},
    },
    {
        "id": "p52-digest-del-and-c1-controls-value",
        "kind": "digest_recompute",
        "expect": "valid",
        "description": "A string value holding DEL (U+007F) and the C1 controls U+0080 and U+009F. They are control characters in Unicode's general category Cc, but outside the range RFC 8785 section 3.2.2.2 escapes (U+0000-U+001F), so the canonical text carries them as is, and the digest is keccak256 over its UTF-8 bytes, 7f c2 80 c2 9f for the three. Accepting twin of n102: an engine that escapes every control character, not only that range, rejects here.",
        "input": {"payload": CC_OUTSIDE_JCS, "expected_digest": _keccak_hex(canonical(CC_OUTSIDE_JCS).encode("utf-8"))},
    },
    {
        "id": "n102-digest-del-and-c1-controls-escaped",
        "kind": "digest_recompute",
        "expect": "reject",
        "reason": "recompute_mismatch",
        "description": 'Rejecting twin of p52: the same payload, with expected_digest computed over {"a":"' + BS + 'u007f' + BS + 'u0080' + BS + 'u009f"}, the three written as escapes. That is the text Python\'s json.dumps emits with its default ensure_ascii=True, which escapes DEL as well as every non-ASCII code point, and separators=(",", ":"), so it is the digest a canonicalizer built on json.dumps(value, sort_keys=True, separators=(",", ":")) computes; an encoder that escapes every control character emits the same text. It is not the canonical form, and its digest does not commit to this payload. An engine that escapes them rejects p52 and accepts this vector; one that accepts either form accepts this vector only.',
        "input": {"payload": CC_OUTSIDE_JCS, "expected_digest": _keccak_hex(CC_ESCAPED_TEXT.encode("utf-8"))},
    },
    # Duplicate names compare as UTF-16 code units, never after normalization.
    {
        "id": "p53-canonical-bytes-names-differ-only-in-normalization",
        "kind": "canonical_bytes",
        "expect": "valid",
        "description": 'payload_text {"' + "é" + '":1,"e' + "́" + '":2}: the name U+00E9, and the name e + U+0301, which is U+00E9 decomposed (NFD). Names compare as UTF-16 code units, 00E9 against 0065 0301, and no normalization applies (RFC 8785 section 3.1), so the text repeats no name and has a canonical form; the decomposed name sorts first. An engine that normalizes names before its duplicate check reads one name twice and rejects here. n93 is the duplicate that a comparison by code units does find.',
        "input": {"payload_text": NFC_AND_NFD_NAMES_TEXT, "claimed_canonical": NFC_AND_NFD_NAMES_CANONICAL},
    },
    # phase_claim: presented_as in another letter case, absent, and the neighbouring phase.
    {
        "id": "n99-phase-claim-presented-as-letter-case",
        "kind": "phase_claim",
        "expect": "reject",
        "reason": "phase_reject",
        "description": 'p7 presented as "Delivery". n91 pins letter case in the record\'s economic_phase; this pins it in presented_as. The vocabulary\'s words compare as exact strings wherever they stand, so "Delivery" is no phase, and the claim rejects. An engine that case-folds presented_as alone passes n91 and accepts this vector. p7 is the accepting twin.',
        "input": {
            "record": {"economic_phase": "delivery", "deliverable_digest": d[0]},
            "presented_as": "Delivery",
        },
    },
    {
        "id": "n100-phase-claim-presented-as-absent",
        "kind": "phase_claim",
        "expect": "reject",
        "reason": "phase_reject",
        "description": "p7 with presented_as absent. presented_as must equal the record's phase, and an absent value equals no phase, so this rejects. An engine that defaults presented_as to the record's own phase accepts every record presented as nothing. p7 is the accepting twin.",
        "input": {
            "record": {"economic_phase": "delivery", "deliverable_digest": d[0]},
        },
    },
    {
        "id": "n101-phase-claim-refund-presented-as-reversal",
        "kind": "phase_claim",
        "expect": "reject",
        "reason": "phase_reject",
        "description": "A refund-phase record presented as reversal. The vocabulary's five words are five phases, refund and reversal among them, so a record of one is not evidence of the other. An engine that reads the two as one phase accepts. p49 is the accepting twin, and p50 accepts reversal presented as itself.",
        "input": {
            "record": {"economic_phase": "refund"},
            "presented_as": "reversal",
        },
    },
    # ------------------------------ v0.5.6: settlement scope, and a 0x-address in another letter case
    {
        "id": "n104-independence-scope-settlement-no-transaction",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "A settlement-scoped independence claim over a record whose settlement result carries no `transaction` member at all. n21 pins the empty string; this pins the absent member. A result that names no transaction commits to no settlement, however independent its attestor, so `settlement` is not among the record's derived commitments and the claim overreaches. An engine that reads only an empty `transaction` as no settlement accepts this vector. p54 is the accepting twin.",
        "input": {
            "claimed": "independent",
            "covers": ["settlement"],
            "settlement_result": {"success": True, "network": "eip155:8453"},
            "parties": SCOPE_PARTIES,
            "attestations": SCOPE_AUDITOR,
        },
    },
    {
        "id": "p54-independence-scope-settlement-with-transaction",
        "kind": "independence_claim",
        "expect": "valid",
        "description": "Accepting twin of n104: the same record with a `transaction` member. The result claims success and names a transaction, so settlement is among the derived commitments, and an attestation by a non-party reaches it. p17 accepts the same scope with another attestor; this pair differs in the `transaction` member alone.",
        "input": {
            "claimed": "independent",
            "covers": ["settlement"],
            "settlement_result": {"success": True, "network": "eip155:8453", "transaction": SCOPE_TX},
            "parties": SCOPE_PARTIES,
            "attestations": SCOPE_AUDITOR,
        },
    },
    {
        "id": "n105-independence-scope-settlement-over-delivery-only",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "The record binds delivered bytes (keccak256 of deliverable_bytes recomputes to deliverable_digest) and carries no settlement result. A claim covering settlement as well as delivery overreaches: the record commits to delivery only. An engine that checks scope only over the fact classes whose fields a record presents accepts this vector. p55 is the accepting twin.",
        "input": {
            "claimed": "independent",
            "covers": ["delivery", "settlement"],
            "deliverable_bytes": SCOPE_DELIVERABLE,
            "deliverable_digest": SCOPE_DELIVERABLE_DIGEST,
            "deliverable_signer": SCOPE_PARTIES[1],
            "parties": SCOPE_PARTIES,
            "attestations": SCOPE_AUDITOR,
        },
    },
    {
        "id": "p55-independence-scope-delivery-only",
        "kind": "independence_claim",
        "expect": "valid",
        "description": "Accepting twin of n105: the same record, with the claim scoped to delivery, which the record commits to. p23 accepts the same scope over another deliverable; this pair differs in `covers` alone.",
        "input": {
            "claimed": "independent",
            "covers": ["delivery"],
            "deliverable_bytes": SCOPE_DELIVERABLE,
            "deliverable_digest": SCOPE_DELIVERABLE_DIGEST,
            "deliverable_signer": SCOPE_PARTIES[1],
            "parties": SCOPE_PARTIES,
            "attestations": SCOPE_AUDITOR,
        },
    },
    {
        "id": "n106-independence-address-alias-letter-case",
        "kind": "independence_claim",
        "expect": "reject",
        "reason": "independence_reject",
        "description": "Both attestations are by parties to the transaction, each written in another letter case. The first party is listed in its EIP-55 checksum form and attests in lowercase; the second is listed in lowercase and attests as 0X followed by upper-case hex digits. A 0x-address compares lowercased, its prefix included (identifier_normalization, rule 2), so neither attestor is outside the parties and the claim rejects. An engine that compares a 0x-address as written, or lowercases the digits but not the prefix, counts an attestor as outside and accepts this vector. p56 is the accepting twin.",
        "input": {
            "claimed": "independent",
            "parties": CASE_PARTIES,
            "attestations": [
                {"by": CASE_PARTY_A, "role": "auditor"},
                {"by": CASE_PARTY_B.upper(), "role": "auditor"},
            ],
        },
    },
    {
        "id": "p56-independence-address-letter-case-outside-party",
        "kind": "independence_claim",
        "expect": "valid",
        "description": "Accepting twin of n106: the second attestation is by an address outside the parties, written the same way, 0X followed by upper-case hex digits, so one attestor is outside the parties and the claim accepts. The first attestation is still a party's own, in another letter case. An engine that does not parse the upper-case prefix rejects here; n106 cannot show that, since an attestor that does not parse rejects the claim as well.",
        "input": {
            "claimed": "independent",
            "parties": CASE_PARTIES,
            "attestations": [
                {"by": CASE_PARTY_A, "role": "auditor"},
                {"by": CASE_OUTSIDE.upper(), "role": "auditor"},
            ],
        },
    },
]

# ------------------------------------------------------------------ per-vector provenance
# v0.5.3. MANIFEST-only metadata: every vector file stays byte-identical. Each manifest entry
# names its `author` and its `origin`.
#   author        the GitHub account that authored the commit adding the vector
#                 (`git log --diff-filter=A -- vectors/<file>`); the maintainer's is Tersign's.
#   origin.class  where the vector's MATERIAL came from, one of ORIGIN_CLASSES (closed).
#   origin.source names that source: the PR / commit / fixture / published reproduction, or
#                 the live record.
# Credit for REPORTING a failure class a vector pins lives in CONTRIBUTORS.md, not here: a
# report is not material, while a published reproduction (an input its author ran and posted)
# is. Every vector must have an entry (no default: a missing entry would
# otherwise read as Tersign-authored synthetic material, the wrong-credit failure this exists
# to prevent). Where the bytes can decide it, a declared class is cross-checked against the
# vector's own bytes below; authorship is not decidable from the bytes and stays checkable
# against git history with the command above.
TERSIGN = "Tersign (@wowlegend)"
ORIGIN_CLASSES = ("synthetic", "live-ledger", "live-ledger-derived", "contributed")
_SYN = (TERSIGN, "synthetic", "inputs constructed in tools/gen_vectors.py")
_LIVE_ENDPOINTS = "unaltered; the vector's provenance block names the public endpoints"
_PR2 = ("@Rul1an", "contributed", "PR #2, commit d672d5c (cherry-picked from 0dee263)")
_PR5 = ("@mohammedmessaoudene-cmd", "contributed", "PR #5, commit c23a985")
_PR6 = ("@navigatorbuilds", "contributed",
        "PR #6, commit 2f4e967; first delivered inline on the IETF web-bot-auth list, 2026-08-09")
_PR7 = "PR #7, commit adb6bab (issue #3): PayPerByte fixture, values from a live receipt in 0rkz/foreseal-x402-conformance (Apache-2.0)"
_ON_0RKZ = "built on @0rkz's PayPerByte fixture (PR #7, issue #3); written here, commit a2b906d"
_R4 = "@Rul1an's reproduction in issue #4 (2026-08-08), written here"
_R1 = "@Rul1an's report in issue #1 (2026-09-30), issuecomment-5908429130"

PROVENANCE = {
    "p1-live-genesis-receipt": (TERSIGN, "live-ledger", f"the ledger's genesis receipt and its counter-signature, {_LIVE_ENDPOINTS}"),
    "p2-canonical-key-order": _SYN,
    "p3-integer-key-utf16-order": _SYN,
    "p4-chain-link-genesis": (TERSIGN, "live-ledger-derived", "the genesis receipt digest (p1) as a genesis link's artifact; the link is computed here"),
    "p5-live-bitcoin-anchor": (TERSIGN, "live-ledger", f"a counter-signed chain head and its Bitcoin anchor (block 958163), {_LIVE_ENDPOINTS}"),
    "p6-chain-set-complete": _SYN,
    "p7-phase-consistent": _SYN,
    "p8-non-party-attestation": _SYN,
    "p9-no-independence-claim": _SYN,
    "n1-value-drift": (TERSIGN, "live-ledger-derived", "p1's genesis receipt with one field altered (issuedAt + 1)"),
    "n2-hoisted-integer-keys": _SYN,
    "n3-chain-link-wrong-prev": (TERSIGN, "live-ledger-derived", "the genesis receipt digest (p1) as both the artifact and the claimed predecessor of a link"),
    "n4-omitted-record": _SYN,
    "n5-truncated-anchor": (TERSIGN, "live-ledger-derived", "p5's anchored digest paired with a synthetic subject it does not bind"),
    "n6-phase-confusion": _SYN,
    "n7-issuer-only-independence": _SYN,
    "p10-claim-set-independent": _SYN,
    "p11-claim-set-silence-only": _PR2,
    "n8-unrecognized-independence-claim": _SYN,
    "p12-ijson-integer-boundary": _SYN,
    "p13-decimal-string-beside-integer": _SYN,
    "n10-float-in-digest-domain": _SYN,
    "n11-integer-beyond-ijson-range": _SYN,
    "p14-supplementary-plane-key-order": _SYN,
    "n12-codepoint-key-order": _SYN,
    "n13-party-alias-whitespace": _SYN,
    "n14-unparseable-attestor": _SYN,
    "n15-claim-without-attestations": _SYN,
    "n16-attestation-not-an-object": _SYN,
    "n17-renumbered-omission": _SYN,
    "n18-unrecognized-phase": _SYN,
    "p16-independence-scope-committed": _SYN,
    "n20-independence-scope-uncommitted": _SYN,
    "p17-independence-scope-derived-settlement": _SYN,
    "n21-independence-scope-empty-settlement": _SYN,
    "n22-independence-scope-declared-override": (TERSIGN, "contributed", f"{_R4}: n21's input plus a declared record_commits, issuecomment-5225737040"),
    "n23-independence-scope-null-declared": (TERSIGN, "contributed", f"{_R4}: his z1-null-commits input, issuecomment-5225737040"),
    "n24-independence-scope-declared-no-scope": (TERSIGN, "contributed", f"{_R4}: n22's input with covers removed (settlement_result also dropped here), issuecomment-5228448679"),
    "p22-delivery-commitment-recomputed": ("@0rkz", "contributed", _PR7),
    "n32-delivery-self-attested": ("@0rkz", "contributed", f"{_PR7}; description later edited here, commit a2b906d"),
    "p23-delivery-independence-within-commitment": (TERSIGN, "contributed", _ON_0RKZ),
    "n33-delivery-substitution-scope-overreach": (TERSIGN, "contributed", f"p23 with the fixture's delivered verdict substituted (ALLOW to DENY); {_ON_0RKZ}"),
    "p24-witnessed-complete-set": _SYN,
    "n34-witnessed-inclusion-not-completeness": _SYN,
    "p18-boundary-binds-prefix-and-position": _SYN,
    "n25-boundary-prefix-only-no-position": _SYN,
    "n26-coverage-claimed-over-empty-attestation": _SYN,
    "p19-authority-reduction-bound": _PR5,
    "n27-authority-reduction-unbound": (_PR5[0], _PR5[1], "PR #5, commits c23a985 and 2f6bef0"),
    "n28-authority-reduction-substitution": _PR5,
    "p20-suite-transition-preserves-prefix": _PR6,
    "n29-suite-transition-redigests-prefix": _PR6,
    "p21-independence-urn-identities": _SYN,
    "n30-independence-urn-self-attested": _SYN,
    "n31-independence-urn-alias-trailing-slash": _SYN,
    "p31-independence-urn-case-and-trailing-punctuation-outside-party": _SYN,
    "p32-independence-urn-percent-encoded-outside-party": _SYN,
    "p33-independence-identifier-whitespace-set": _SYN,
    "n45-independence-urn-alias-case": _SYN,
    "n46-independence-urn-alias-trailing-dot": _SYN,
    "n47-independence-urn-alias-trailing-hash": _SYN,
    "n48-independence-urn-alias-percent-encoded": (TERSIGN, "contributed", "@stillmarcus24's probe in issue #8 (2026-09-29), his attestor verbatim on n31's parties, written here"),
    "n49-independence-urn-alias-party-side-encoded-dot": _SYN,
    "n50-independence-urn-percent-encoded-reserved": _SYN,
    "n51-independence-urn-empty-after-normalization": _SYN,
    "n52-independence-identifier-format-character-padding": _SYN,
    "n53-independence-identifier-control-character-padding": _SYN,
    "n58-independence-urn-alias-scheme-case": _SYN,
    "p34-independence-urn-percent-encoded-unreserved-set-outside-party": _SYN,
    "n54-independence-urn-alias-percent-encoded-unreserved-set": _SYN,
    "n55-independence-urn-percent-encoded-percent-sign": _SYN,
    "n56-independence-urn-triplet-assembled-by-decoding": _SYN,
    "n59-independence-urn-alias-dot-segment": _SYN,
    "n60-independence-urn-encoded-trailing-dot-segment": _SYN,
    "n67-independence-urn-alias-leading-dot-segment": _SYN,
    "n70-independence-urn-alias-leading-dot-dot-segment": _SYN,
    "p36-independence-urn-dots-within-segments-outside-party": _SYN,
    "n61-independence-urn-query-component": _SYN,
    "n62-independence-urn-fragment-component": _SYN,
    "n63-independence-address-alias-caip10-and-did-pkh": _SYN,
    "n64-independence-address-alias-party-in-caip10": _SYN,
    "p37-independence-address-caip10-outside-party": _SYN,
    "n65-independence-address-alias-did-ethr": _SYN,
    "n66-independence-address-alias-party-in-ethereum-namespace": _SYN,
    "n69-independence-address-alias-any-scheme": _SYN,
    "p38-independence-address-other-namespaces-outside-party": _SYN,
    "p15-offer-binding": _SYN,
    "n19-offer-substitution": _SYN,
    "n9-unrecognized-member-in-claim-set": _PR2,
    "p25-integer-token-in-text": _SYN,
    "n35-integer-valued-float-token": _SYN,
    "p30-canonical-bytes-name-repeated-across-objects": _SYN,
    "n41-canonical-bytes-duplicate-name": (TERSIGN, "contributed", "@Rul1an's reproduction in issue #10 (2026-09-29), his input verbatim, written here"),
    "n42-canonical-bytes-escaped-duplicate-name": _SYN,
    "n43-canonical-bytes-non-json-constant": _SYN,
    "n44-canonical-bytes-text-not-a-string": _SYN,
    "n57-canonical-bytes-duplicate-name-after-array": _SYN,
    "p35-canonical-bytes-string-value-equal-to-a-name": _SYN,
    "n68-canonical-bytes-duplicate-name-in-nested-object": _SYN,
    "p26-chain-commitment-complete": _SYN,
    "p27-live-chain-commitment-genesis-chain": (TERSIGN, "live-ledger", f"the ledger's genesis chain (13 counter-signed records) and its commitment anchored in Bitcoin block 964428, {_LIVE_ENDPOINTS}"),
    "n36-chain-commitment-prefix-substituted": _SYN,
    "n37-chain-commitment-last-link-only": _SYN,
    "n38-chain-set-float-seq-token": _SYN,
    "p28-issuer-sequence-distinct-seq": _SYN,
    "n39-issuer-sequence-duplicate-seq": _SYN,
    "p29-committed-prefix-one-record-per-position": _SYN,
    "n40-equivocating-record-at-committed-position": _SYN,
    # v0.5.5. Three inputs are @Rul1an's, posted in issue #1 after he ran each against verify.py
    # at ab7704d: p39 and n78 verbatim (contributed), and n75, which carries p4's live-ledger
    # genesis digest and is therefore classed live-ledger-derived, its source naming him. n71,
    # p39's twin, is synthetic: the value that distinguishes it, the escaped digest, is the
    # suite's construction (vector_provenance in the manifest states the convention).
    "p39-digest-non-ascii-latin1-value": (TERSIGN, "contributed", f"{_R1}: his input verbatim ({{\"a\":\"\u00e9\"}} with its correct digest), written here"),
    "n71-digest-non-ascii-escaped-before-hashing": _SYN,
    "p40-digest-non-ascii-cjk-value": _SYN,
    "n72-digest-non-ascii-latin1-bytes": _SYN,
    "p41-digest-non-ascii-astral-value": _SYN,
    "n73-digest-non-ascii-cesu8-bytes": _SYN,
    "p42-digest-non-ascii-decomposed-value": _SYN,
    "n74-digest-non-ascii-normalized-before-hashing": _SYN,
    "n75-chain-link-seq-zero": (TERSIGN, "live-ledger-derived", f"{_R1}: his input, p4's genesis link at seq 0 with the link recomputed for seq 0, written here"),
    "n76-chain-link-seq-past-ijson-range": _SYN,
    "p43-chain-link-seq-ijson-boundary": _SYN,
    "n77-chain-link-float-seq-token": (TERSIGN, "live-ledger-derived", "p4's genesis link with seq written as the token 1.0"),
    "n78-phase-claim-no-economic-phase": (TERSIGN, "contributed", f"{_R1}: his input verbatim, p7 without economic_phase, written here"),
    "n79-phase-claim-record-not-an-object": _SYN,
    "n80-phase-claim-unrecognized-phase-presented-as-itself": _SYN,
    "p44-canonical-bytes-surrogate-pair": _SYN,
    "n81-canonical-bytes-lone-high-surrogate-in-value": _SYN,
    "n82-canonical-bytes-lone-low-surrogate-in-name": _SYN,
    "n83-digest-lone-surrogate-in-value": _SYN,
    "n84-digest-lone-surrogate-in-name": _SYN,
    # v0.5.5, review round. n87-n89 carry p4's live-ledger genesis digest.
    "p45-digest-line-separators-value": _SYN,
    "n85-digest-line-separators-escaped": _SYN,
    "p46-digest-decomposed-name": _SYN,
    "n86-digest-decomposed-name-normalized": _SYN,
    "n87-chain-link-seq-string": (TERSIGN, "live-ledger-derived", "p4's genesis link with seq written as the string \"1\""),
    "n88-chain-link-seq-boolean": (TERSIGN, "live-ledger-derived", "p4's genesis link with seq written as true"),
    "n89-chain-link-seq-null": (TERSIGN, "live-ledger-derived", "p4's genesis link with seq written as null"),
    "n90-phase-claim-delivery-presented-as-funding": _SYN,
    "n91-phase-claim-phase-letter-case": _SYN,
    "p47-phase-claim-funding-as-itself": _SYN,
    "p48-phase-claim-settlement-as-itself": _SYN,
    "p49-phase-claim-refund-as-itself": _SYN,
    "p50-phase-claim-reversal-as-itself": _SYN,
    "n92-canonical-bytes-lone-surrogate-after-number": _SYN,
    "n93-canonical-bytes-duplicate-name-half-escaped-pair": _SYN,
    "n94-offer-binding-lone-surrogate": _SYN,
    "n95-decision-evidence-binding-lone-surrogate": (TERSIGN, "contributed", "p19's decision-evidence object from @mohammedmessaoudene-cmd's PR #5 (commit c23a985), with a lone surrogate appended to policy.id; written here"),
    "n96-boundary-binding-lone-surrogate-in-prefix": _SYN,
    # v0.5.5, second review round. n97 carries p4's live-ledger genesis digest.
    "n97-chain-link-exponent-seq-token": (TERSIGN, "live-ledger-derived", "p4's genesis link with seq written as the token 1e0"),
    "n103-canonical-bytes-exponent-token": _SYN,
    "p51-digest-html-significant-value": _SYN,
    "n98-digest-html-significant-escaped": _SYN,
    "p52-digest-del-and-c1-controls-value": _SYN,
    "n102-digest-del-and-c1-controls-escaped": _SYN,
    "p53-canonical-bytes-names-differ-only-in-normalization": _SYN,
    "n99-phase-claim-presented-as-letter-case": _SYN,
    "n100-phase-claim-presented-as-absent": _SYN,
    "n101-phase-claim-refund-presented-as-reversal": _SYN,
    # v0.5.6
    "n104-independence-scope-settlement-no-transaction": _SYN,
    "p54-independence-scope-settlement-with-transaction": _SYN,
    "n105-independence-scope-settlement-over-delivery-only": _SYN,
    "p55-independence-scope-delivery-only": _SYN,
    "n106-independence-address-alias-letter-case": _SYN,
    "p56-independence-address-letter-case-outside-party": _SYN,
}

# Values from the live ledger, and from the contributed fixtures Tersign-written vectors reuse
# or could reuse: @0rkz's PayPerByte delivery digest (PR #7), the `hostAllowed` member that
# every decision-evidence object of PR #5 carries, and PR #6's suite-transition rule version.
# Declared classes are checked against these in the vectors' own bytes, so a class cannot drift
# from the material it describes. A contributed input with no value of its own (a reproduction
# or probe written here, such as n41 or n48) has no marker; its class is declared.
LIVE_LEDGER_MARKERS = tuple(x.lower() for x in (
    GENESIS_DIGEST, GENESIS_ARTIFACT["signature"], ANCHOR_SUBJECT, ANCHOR_ANCHORED,
    GENESIS_CHAIN_HEAD, GENESIS_CHAIN_COMMITMENT_DIGEST,
))
CONTRIBUTED_MARKERS = {
    DELIVERY_DIGEST.lower(): "@0rkz",
    '"hostallowed":': "@mohammedmessaoudene-cmd",
    '"suite-transition-v1"': "@navigatorbuilds",
}
SIGNER_NOTE = "the live ledger's signer address appears as sample data"


def _provenance_fail(msg):
    # Not `assert`: this gate must hold under `python3 -O` too.
    sys.exit(f"provenance: {msg}")


def provenance_of(v):
    entry = PROVENANCE.get(v["id"])
    if entry is None:
        _provenance_fail(f"{v['id']} has no entry; every vector names its author and origin")
    author, cls, source = entry
    if not (isinstance(author, str) and author.strip() and isinstance(source, str) and source.strip()):
        _provenance_fail(f"{v['id']}: author and origin.source must be non-empty strings")
    if cls not in ORIGIN_CLASSES:
        _provenance_fail(f"{v['id']}: origin class {cls!r} not in {ORIGIN_CLASSES}")
    raw = json.dumps(v).lower()
    if (cls == "live-ledger") != ("provenance" in v):
        _provenance_fail(f"{v['id']}: class 'live-ledger' iff the vector carries a provenance block")
    if any(m in raw for m in LIVE_LEDGER_MARKERS) != cls.startswith("live-ledger"):
        _provenance_fail(f"{v['id']}: class {cls!r} disagrees with the live-ledger values in its bytes")
    for marker, contributor in CONTRIBUTED_MARKERS.items():
        if marker in raw and (cls != "contributed" or contributor not in author + source):
            _provenance_fail(f"{v['id']}: carries {contributor}'s fixture but does not credit it")
    if cls != "live-ledger" and LEDGER_SIGNER.lower() in json.dumps(v["input"]).lower():
        source = f"{source}; {SIGNER_NOTE}"
    return {"author": author, "origin": {"class": cls, "source": source}}


_ids = [v["id"] for v in vectors]
if len(_ids) != len(set(_ids)):
    _provenance_fail("duplicate vector id")
if set(PROVENANCE) != set(_ids):
    _provenance_fail(f"vectors without an entry: {sorted(set(_ids) - set(PROVENANCE))}; "
                     f"entries without a vector: {sorted(set(PROVENANCE) - set(_ids))}")

manifest = {
    "suite": "evidence-record-conformance",
    "version": "0.5.6",
    "layer": "evidence-record",
    "profile": "structural (stdlib): digests, canonical bytes, chain arithmetic, sequence closure, declared-claim evaluation. Counter-signature recovery over the links (secp256k1 personal_sign) is the crypto profile, outside the stdlib core — a structurally complete set recomputed wholesale by one forging party passes the structural predicate; the counter-signatures are what prevent that in production.",
    "canonicalization": "RFC 8785 (JCS); vector domain is I-JSON with integer numerics (|n| <= 2^53-1); non-integer JSON number TOKENS rejected (number_domain_reject) — the boundary is the token class, so a fraction or exponent form rejects even when integer-valued (2.0, 1e2; p25/n35/n103); duplicate object names rejected, at load and inside `payload_text`, where names compare after decoding, as UTF-16 code units, and only within one object, so a surrogate pair written with one half raw and the other escaped repeats the same pair written as two escapes (canonicalization_reject; p30/n41/n42/n93), while names that differ only in Unicode normalization are two names (p53); no vector pins whether a pair written half raw accepts where it repeats no name; a `payload_text` that is not a string holding JSON text (a non-JSON constant such as NaN, text that does not parse) rejects the same way (n43/n44), and its shape, an unpaired surrogate included, is decided before its number tokens (n92); strings, names included, are serialized as RFC 8785 section 3.2.2.2 specifies: U+0000-U+001F, the quotation mark and the backslash are escaped (no vector pins these escapes), and every other code point is written as is, U+2028 and U+2029 (p45/n85), `<`, `>` and `&` (p51/n98), and DEL and the C1 controls (p52/n102) included; the canonical text is hashed as UTF-8 (section 3.2.4), so a digest over the text with non-ASCII written as \\u escapes, over Latin-1 bytes or over CESU-8 rejects (recompute_mismatch; p39-p41 accept, n71-n73 reject); no Unicode normalization is applied (section 3.1), so a decomposed value or name digests as written (p42/n74 for a value, p46/n86 for a name); a name or string value containing a surrogate that is not half of a pair is outside I-JSON (RFC 7493 section 2.1) and has no canonical form (RFC 8785 section 3.2.2.2): canonical_bytes and digest_recompute reject it with canonicalization_reject (n81-n84; a paired escape accepts, p44, as does p14's pair in a name), and a criterion that digests an object rejects it with its own reason (binding_reject for an offer, n94, and for decision evidence, n95; boundary_reject for a boundary prefix, n96). n81, n83, n84 and n93-n96 carry an unpaired surrogate as a \\u escape in the vector file itself, the only way a vector can carry one, so a vector loader must keep it as the code unit it names: a loader that replaces it (with U+FFFD, say) or refuses it does not run those vectors as written. A noncharacter, which RFC 7493 section 2.1 also excludes, is serialized as is; no vector pins it",
    "content_address": "keccak256(utf8(canonical(payload)))",
    "chain_link": "keccak256(artifact_digest || prev_digest || seq_uint64_be) — wire form of a genesis predecessor is null; 32 zero bytes is the hashing-time substitution for null. seq is an integer TOKEN in [1, 2^53-1], and seq_uint64_be is that integer as 8 big-endian bytes. The lower bound is the first number chain_set gives a record (it numbers records 1..head.seq); chain_link does not relate a null prev_digest to seq, and no vector pins that relation. 2^53-1 is the I-JSON integer bound (p12/n11), past which two JSON engines can read one token as different integers. A seq of 0 (n75), a seq past 2^53-1 (n76), or a seq that is not an integer token (a fraction form, n77; an exponent form, n97; a string, n87; a boolean, n88; null, n89) rejects with continuity_reject; p4 accepts the lower bound and p43 the upper",
    "chain_set": "records chain raw artifact digests via prev pointers (genesis prev = null); head.digest equals the final record's artifact digest; completeness = every seq 1..head.seq present exactly once (a second record at an occupied seq rejects: n39); where a record presents a link, it must recompute as keccak256(artifact || prev || seq_be8)",
    "chain_commitment": "acc_0 = keccak256(utf8('tersign-chain-commitment-v1')); acc_n = keccak256(acc_{n-1} || link_n) over the recomputed links of a chain_set-valid set; head.acc must equal acc_{head.seq}. Production stamps keccak256(utf8(canonical({acc, head, schema:'tersign-chain-commitment-v1', seq}))); a prefix that passes the structural chain_set predicate but was not the one the commitment was built over rejects here",
    "anchor_relation": "anchored_digest = sha256(subject_digest_bytes)",
    "phase_claim": "the economic-phase vocabulary is closed: funding, delivery, settlement, refund, reversal, each compared as an exact string (each accepts presented as itself: p47, p7, p48, p49, p50). A record verifies as evidence of the phase it carries and of no other phase, later or earlier: `record` must be an object (n79) carrying `economic_phase` (n78); that phase must be in the vocabulary, since a token outside it is not interpretable and verifies as no phase, its own spelling included (n80, n18), and so does a vocabulary word in another letter case (n91); `presented_as` is read against the same vocabulary, so a word in another letter case there is no phase either (n99), and no vector pins any other near-spelling on either side, such as a word padded with whitespace; and `presented_as` must be present (n100) and equal the record's phase. A vector pins three of the twenty ordered pairs of distinct words: a funding record presented as delivery (n6), a delivery record presented as funding (n90), and a refund record presented as reversal (n101), so refund and reversal are two phases; no vector pins the other seventeen, settlement's included. Every reject is phase_reject; p7 accepts",
    "offer_binding": "receipt.offerDigest = keccak256(utf8(canonical(offer))); a receipt that commits to no offer digest cannot bind terms and fails closed",
    "decision_evidence_binding": "within this suite, record.decisionEvidenceDigest = keccak256(utf8(canonical(decision_evidence))); a record presented as authority-decision evidence must bind the exact object. This instantiates the general match/missing/mismatch binding property and does not prescribe a digest, canonicalization, or field location for AUEC, MCP, or another protocol; producer truth and decision semantics remain out of scope",
    "identifier_normalization": "two identity syntaxes, both evaluated by every criterion that compares identity (pinned by one accepting vector each under the per-kind two-sided gate). Every identifier, whether in `parties` or an attestation's `by`, is normalized by one rule and compared only after it; the rule folds toward SAME PARTY, and an identifier it cannot decide does not parse. (1) Strip leading and trailing characters with the Unicode White_Space property, U+0009-U+000D, U+0020, U+0085, U+00A0, U+1680, U+2000-U+200A, U+2028, U+2029, U+202F, U+205F and U+3000, and no others (n13/p33); a character without the property is not stripped, so an identifier padded with U+FEFF (a format character) or U+001C (a control character without the property) does not parse (n52/n53). (2) A 0x-address (the prefix 0x or 0X, then 40 hex digits in either case) compares lowercased, its prefix included, so an EIP-55 checksum variant, the all-lowercase form and 0X with upper-case digits are one address (n106; p56 accepts an outside attestor written 0X with upper-case digits). (3) Otherwise the identifier must be a scheme-qualified identifier in ASCII: a letter, then letters, digits, `+`, `.` or `-`, then one colon, then one or more printable non-space ASCII characters, letters in either case. Every percent-encoded triplet (either hex case) that encodes an unreserved character (A-Z a-z 0-9 `-` `.` `_` `~`) is decoded, in one left-to-right pass that is never repeated (RFC 3986 sections 6.2.2.2 and 2.4; n48/n49/n54/p32/p34); if any `%` remains, the identifier does not parse (n50/n55/n56). If it contains `?` (a query component), or its path, from the colon to the first `?` or `#`, has a segment that is exactly `.` or `..` (a dot-segment, RFC 3986 section 3.3), it does not parse (n59/n60/n61/n67/n70; neither class has an accepting twin, and p36, dots within segments, is the near-miss that accepts beside the dot-segments). The result is lowercased, the scheme included (n45/n58/p31), and every trailing `/`, `.` and `#` is removed (n31/n46/n47/p31); if a `#` remains (a fragment with content), it does not parse (n62; p31's trailing `#` alone is the near-miss that accepts); and it must still match the grammar with a lowercase scheme and a non-empty path (n51). (4) Anything else does not parse (n14). (5) Two identifiers name the same party when they are equal after normalization, or when both name the same 0x-address: a 0x-address names itself, and a scheme-qualified identifier whose final colon-separated component is a 0x-address (a CAIP-10 account such as eip155:8453:0x..., a did:pkh such as did:pkh:eip155:1:0x...) names that address, whatever the scheme (did:ethr:0x..., ethereum:0x..., acct:0x... as well), on either side and whatever the chain reference (n63/n64/p37 for CAIP-10 and did:pkh; n65/n66/n69/p38 for other schemes, acct: included). An identifier that does not parse after normalization fails the claim closed: it is never counted outside the parties. Not folded, and pinned by no vector: scheme-specific equivalences beyond these (RFC 3986 section 6.2.3, such as a default port) and names that resolve to an address (an ENS name, a did:web); two such identifiers compare as distinct. Digests compare after the same whitespace strip, lowercased",
    "witnessed_inclusion": "witness material (a cosigned checkpoint, inclusion proofs) presented beside a chain set is permitted and NOT load-bearing for completeness: it evidences existence and the log's consistency, never no-omission; a set with a gap rejects on the gap regardless of how many parties cosigned the log (p24/n34). Completeness requires a non-party attestation over the sequence itself, made at issuance",
    "duplicate_sequence": "a sequence attested only by its issuer evidences ordering, not that no other record carries the same `seq` and `correctionSeq`. Two records at one seq in a presented set reject on the duplicate, whatever the issuer attests (p28/n39; the issuer's `attestations` are permitted and not read). A record the issuer did not present is not in the bytes: the other record presented alone passes the structural chain_set predicate under the same head, and only a commitment over every link rejects it (p29/n40)",
    "commitment_derivation": "an independence claim reaches exactly as far as the record's DERIVED commitments, never a declared list (n22-n24): `settlement` when settlement_result.success is true and transaction is a string that is not empty after the whitespace strip of identifier_normalization (a result with no transaction member commits to no settlement: n104/p54; a record with no settlement result commits to no settlement: n105/p55); `network` when settlement_result.network is such a string; `delivery` when keccak256(utf8(deliverable_bytes)) == deliverable_digest. A record presenting none of these fields has no evaluable commitments (a scoped claim rejects as unevaluable); a record presenting them and committing to none has an EMPTY commitment set (a scoped claim rejects as overreach). Who delivered is not read by the derivation — position is the independence axis, decided before scope is",
    "field_naming": "harness-level input keys are snake_case (settlement_result, deliverable_bytes, decision_evidence, boundary_event); a key that quotes a protocol's own field keeps that protocol's wire spelling wherever it sits (payTo, resourceUrl, offerDigest, decisionEvidenceDigest). Contributed vectors follow the same two rules; the suite does not rename a protocol's fields to match its own, and does not camelCase its own",
    "vector_provenance": "every entry names `author`, the GitHub account that authored the commit adding the vector (git log --diff-filter=A -- vectors/<file>), and `origin` = {class, source}. origin.class is closed: synthetic (inputs constructed in tools/gen_vectors.py); live-ledger (a record from the live ledger, unaltered, with a provenance block in the vector); live-ledger-derived (a live-ledger value reused or altered); contributed (an outside contributor's PR, commit, fixture or published reproduction, named in origin.source, including vectors written here on such material). Among vectors written here, the class follows the value that distinguishes the vector: contributed where it is the contributor's (p39 and n78, @Rul1an's inputs; n24, his reproduction; n48, @stillmarcus24's attestor) and synthetic where the suite constructed it, beside a contributed vector or not (n42, n41's input with its second name escaped; n71, p39's payload under an escaping encoder's digest; n74, whose NFC digest equals p39's); a vector that carries a contributed fixture with a value of its own is contributed whoever altered it (n33, n95). Generation fails if a vector has no entry, if its live-ledger class (or its lack of one) disagrees with the live-ledger values and provenance block in its own bytes, or if it carries one of the contributed fixtures the generator recognizes in a vector's bytes (@0rkz's PayPerByte delivery digest, PR #5's decision-evidence objects, PR #6's suite-transition rule version) without crediting the contributor; a contributed input with no value of its own (a reproduction or probe written here) is declared, not derived; authorship is not decided at generation: it is checkable against git history with the command above. Credit for reporting a failure class is recorded in CONTRIBUTORS.md. Metadata only: neither engine reads it",
    "vectors": [
        {"file": f"{v['id']}.json", "kind": v["kind"], "expect": v["expect"],
         **({"reason": v["reason"]} if v["expect"] == "reject" else {}),
         **provenance_of(v)}
        for v in vectors
    ],
}

# ------------------------------------------------------------ README provenance table
# The README restates the per-class counts and the total in prose, where a reader checks them
# against this manifest. They drifted once (a `synthetic` row of 78 beside 83 entries, a table
# summing to 101 beside "Of the 106 vectors"), so generation fails unless the README has exactly
# one row per origin class, each row's count (and its listed ids, where the row lists them)
# equals the manifest's, and the one stated total equals the number of vectors. Checked before
# any file is written; a table this gate cannot find fails it too.
def _readme_fail(msg):
    sys.exit(f"README: {msg}")


def check_readme_provenance(text, entries):
    want = {c: [] for c in ORIGIN_CLASSES}
    for e in entries:
        want[e["origin"]["class"]].append(e["file"].split("-", 1)[0])
    row_re = re.compile(r"^\| `(" + "|".join(re.escape(c) for c in ORIGIN_CLASSES)
                        + r")` \| (\d+)(?: \(([^)]*)\))? \|", re.M)
    rows = {}
    for m in row_re.finditer(text):
        if m.group(1) in rows:
            _readme_fail(f"provenance table has two `{m.group(1)}` rows")
        rows[m.group(1)] = (int(m.group(2)), m.group(3))
    if set(rows) != set(ORIGIN_CLASSES):
        _readme_fail(f"provenance table rows {sorted(rows)} != origin classes {sorted(ORIGIN_CLASSES)}")
    for cls, (n, ids) in rows.items():
        if n != len(want[cls]):
            _readme_fail(f"`{cls}` row says {n}, the manifest has {len(want[cls])}")
        if ids is not None and sorted(i.strip() for i in ids.split(",")) != sorted(want[cls]):
            _readme_fail(f"`{cls}` row lists {ids}, the manifest has {', '.join(want[cls])}")
    totals = re.findall(r"Of the (\d+) vectors", text)
    if totals != [str(len(entries))]:
        _readme_fail(f"stated total(s) {totals} != [{len(entries)}] vectors")


with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
    check_readme_provenance(f.read(), manifest["vectors"])

for v in vectors:
    text = RAW_TOKEN_RE.sub(r"\1", json.dumps(v, indent=2, sort_keys=False))
    json.loads(text)  # the substituted file still parses
    if "raw-json-number-token" in text:
        sys.exit(f"{v['id']}: a raw number token placeholder survived the writer")
    with open(os.path.join(V, f"{v['id']}.json"), "w") as f:
        f.write(text)
        f.write("\n")
with open(os.path.join(ROOT, "MANIFEST.json"), "w") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")

print(f"wrote {len(vectors)} vectors + MANIFEST.json")
