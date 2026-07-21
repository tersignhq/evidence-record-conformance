# evidence-record-conformance

Conformance vectors for the **evidence-record layer** of agent commerce — the layer whose
properties must survive the record being held by an interested party.

Action identifiers and signed action receipts (maturing elsewhere) answer *"what did this
agent do, and is this record intact?"* The evidence-record layer sits above them and answers
three questions no record shape or signature supplies by structure alone:

- **Independence** — a record attested only by parties to the transaction evidences
  *structure*, not *independence*. An evaluator **MUST NOT** treat issuer-attested
  composition as a neutral finding. (`independence_reject`)
- **Completeness** — an issuer-attested sequence evidences *ordering*, not *no-omission*.
  Without a committed head, a truncated sequence is invisible; without an independently
  verifiable existence bound, the head itself is just another claim. (`completeness_reject`,
  `existence_reject`)
- **Phase separation** — a receipt for one economic phase (funding) **MUST NOT** verify as
  evidence of a later one (delivery, settlement). (`phase_reject`)

These are stated normatively in the x402 compliance-fields extension (PR
[x402-foundation/x402#2853](https://github.com/x402-foundation/x402/pull/2853)); this suite
makes them executable.

## Run

```
python3 verify.py
```

stdlib-only, no dependencies, no network. Exit 0 only if every vector produces its expected
verdict **and** the run observed both verdicts **and** every reject reason was exercised — a
green run demonstrates the verifier discriminates, not merely accepts.

## Vector classes

| class | positive | adversarial twin | reason code |
|---|---|---|---|
| content address (keccak256 over RFC 8785) | p1 (live), p3 | n1 value drift | `recompute_mismatch` |
| canonical bytes | p2 | n2 **hoisted integer keys** | `canonicalization_reject` |
| chain link (artifact ∥ prev ∥ seq) | p4 | n3 wrong predecessor | `continuity_reject` |
| per-seller set continuity + completeness | p6 | n4 **silently omitted record** | `completeness_reject` |
| anchored existence bound | p5 (live) | n5 truncated/substituted head | `existence_reject` |
| economic-phase separation | — | n6 funding-as-delivery | `phase_reject` |
| independence criterion | — | n7 issuer-only attestation | `independence_reject` |

Design rule: **at least one adversarial vector per known failure class** — an all-happy-path
suite proves nothing about the class it never exercises. n2 encodes a failure observed in a
real implementation (JS engines hoist integer-like keys into numeric order on object rebuild,
silently defeating sort-then-stringify; RFC 8785 orders `"1" < "10" < "2"` by UTF-16 code
units). n4 is the completeness class this layer exists for.

## Live provenance — two vectors are production bytes, not fixtures

**p1** is the genesis receipt of the tersign ledger. Recompute and cross-check it yourself:

```
python3 verify.py                    # recomputes the digest from committed bytes
curl https://tersign.ai/v1/receipts/0xe5874f1ffe87f0a6dd9eb157730f67b86ee4538b125fe30fcc4e165213dd3fc4/verify
```

**p5** is a counter-signed chain head anchored to Bitcoin (block 958163). Verify the
existence bound with stock OpenTimestamps tooling — no account, no trust in the operator:

```
curl https://tersign.ai/v1/anchors           # the anchor record
# fetch proof.ots from the record's proofUrl, then:
ots verify -d cf48bed1712f5b7df2a309fb52cb2b3d51ab1a04730e3b115cd3db79c96c9b1a proof.ots
```

Counter-signatures in the live vectors are secp256k1 `personal_sign` material (signer
published at `https://tersign.ai/v1/ledger`); recovering them requires an EVM crypto
library and sits outside the stdlib core by design — every check above needs hashing only.

## Canonicalization contract

RFC 8785 (JCS) over the I-JSON, integer-numeric vector domain. Keys sort by **UTF-16 code
units** (the verifier encodes to UTF-16BE and compares bytes — explicit, not delegated to
the host language's default). Content addresses are keccak256 (pre-NIST padding, as used by
Ethereum) — `hashlib.sha3_256` is a different function; a compact Keccak implementation is
vendored in `keccak.py`, self-checked at import against measured known-answer values and
cross-checked byte-for-byte against the TypeScript reference (`tools/cross_check_ts.mjs`).

Regeneration is deterministic and diffable: `python3 tools/gen_vectors.py` rewrites
`vectors/` + `MANIFEST.json` byte-identically.

## License

Apache-2.0. Maintained by [Tersign](https://tersign.ai) — the evidence layer for the agent
economy. Cross-runs, counter-vectors, and adversarial additions welcome.
