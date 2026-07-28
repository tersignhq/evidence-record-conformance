# evidence-record-conformance

[![verify](https://github.com/tersignhq/evidence-record-conformance/actions/workflows/verify.yml/badge.svg)](https://github.com/tersignhq/evidence-record-conformance/actions/workflows/verify.yml)

Conformance vectors for the **evidence-record layer** of agent commerce — the layer whose
properties must survive the record being held by an interested party.

Record shapes and signatures (maturing in several parallel efforts) answer *"is this record
intact, and what does it name?"* The evidence-record layer sits above them and answers three
questions no record shape or signature supplies by structure alone:

- **Independence** — a record attested only by parties to the transaction evidences
  *structure*, not *independence*. An evaluator **MUST NOT** treat issuer-attested
  composition as a neutral finding. (`independence_reject`)
- **Completeness** — an issuer-attested sequence evidences *ordering*, not *no-omission*.
  Without a committed head, a truncated sequence is invisible; without an independently
  verifiable existence bound, the head itself is just another claim. (`completeness_reject`,
  `existence_reject`)
- **Phase separation** — a record evidencing one economic phase (funding) **MUST NOT** verify
  as evidence of a later one (delivery, settlement). (`phase_reject`)

All three are proposed normatively in the open compliance-fields extension PR
([x402-foundation/x402#2853](https://github.com/x402-foundation/x402/pull/2853), under
review); this suite makes them executable.

## Run

```
python3 verify.py
```

stdlib-only, no dependencies, no network. Exit 0 only if every vector produces its expected
verdict **and** the run observed both verdicts **and** the pinned closure of 7 reject reasons
and 7 vector kinds was fully exercised — the closure is pinned in the verifier, not derived
from the manifest, so a fork that quietly drops a class goes red. A green run demonstrates
the verifier discriminates, not merely accepts.

## Vector classes

| class | accepts | rejects | reason code |
|---|---|---|---|
| content address (keccak256 over RFC 8785) | p1 (live), p3 | n1 value drift | `recompute_mismatch` |
| canonical bytes | p2 | n2 **hoisted integer keys** | `canonicalization_reject` |
| chain link (artifact ∥ prev ∥ seq) | p4 | n3 wrong predecessor | `continuity_reject` |
| per-seller set continuity + completeness | p6 | n4 **silently omitted record** | `completeness_reject` |
| anchored existence bound | p5 (live) | n5 truncated/substituted head | `existence_reject` |
| economic-phase separation | p7 | n6 funding-as-delivery | `phase_reject` |
| independence criterion | p8, p9 (no claim), p10 (claim **set**), p11 (set, silence only) | n7 issuer-only attestation, n8 **unrecognized claim**, n9 **unread member in a set** | `independence_reject` |

Two design rules, both enforced by the run itself:

1. **At least one adversarial vector per known failure class** — an all-happy-path suite
   proves nothing about the class it never exercises. n2 encodes a failure observed in a real
   implementation (JS engines hoist integer-like keys into numeric order on object rebuild,
   silently defeating sort-then-stringify; RFC 8785 orders `"1" < "10" < "2"` by UTF-16 code
   units). n4 is the completeness class this layer exists for.
2. **Every criterion is two-sided** — each class has an accepting twin, so an implementation
   that unconditionally rejects a class fails the suite just as one that unconditionally
   accepts it does (p7/p8 exist for exactly this).

A third rule, added after this suite failed it: **a criterion's trigger must fail closed.**
An exact-equality trigger (`if claimed != "independent": valid`) reads any unfamiliar claim
string — including a *stronger* one — as no claim at all, switching the check off precisely
where more was asserted. Silence is a valid state (p9); an assertion the verifier cannot
interpret is not (n8). Failing closed also means *returning a verdict*: membership tests that
raise on an unhashable value produce no verdict at all, so the criterion must evaluate the
shapes a claim actually takes — including the set form (p10), which is where a field carrying
two orthogonal criteria has to land. Reported against this suite by [@Rul1an](https://github.com/tersignhq/evidence-record-conformance/issues/1).

## Live provenance — two vectors are records from the live ledger

**p1** is the tersign ledger's genesis (demo) receipt — the one receipt whose full body is
public by design. Re-fetch the bytes and recompute the digest yourself:

```
curl https://tersign.ai/v1/genesis        # the record body — same bytes as the vector
python3 verify.py                         # recomputes the digest from the committed bytes
curl https://tersign.ai/v1/receipts/0xe5874f1ffe87f0a6dd9eb157730f67b86ee4538b125fe30fcc4e165213dd3fc4/verify
```

(The payload's embedded `resourceUrl` is the historical demo resource the genesis record was
issued against, on the ledger's legacy workers.dev alias — the record's validity derives from
digest, counter-signature and anchor, never from URL liveness.)

**p5** is a counter-signed chain head anchored in Bitcoin block 958163. The existence bound
is checkable without trusting the operator:

```
curl https://tersign.ai/v1/anchors        # the anchor record; fetch proof.ots from its proofUrl
ots verify -d cf48bed1712f5b7df2a309fb52cb2b3d51ab1a04730e3b115cd3db79c96c9b1a proof.ots
```

`ots verify` needs a local Bitcoin node to confirm the block header. Without one, the
no-node path is stronger anyway — it shows the trust chain explicitly:
`ots info proof.ots` prints the Bitcoin attestation (height 958163, merkle root
`d23b2da439b5…f85df18c`); compare that root against block 958163 in any block explorer.

Counter-signatures in the live vectors are secp256k1 `personal_sign` material (signer
published at `https://tersign.ai/v1/ledger`); recovering them requires an EVM crypto library
and sits outside the stdlib core by design — every check above needs hashing only.

## Canonicalization contract

RFC 8785 (JCS) over the I-JSON vector domain: integer numerics within `|n| ≤ 2^53−1`
(enforced — out-of-range integers are refused rather than silently serialized into digests
other JCS implementations cannot reproduce), duplicate object names rejected at load. Keys
sort by **UTF-16 code units** (the verifier encodes to UTF-16BE and compares bytes —
explicit, not delegated to the host language's default). Content addresses are keccak256
(pre-NIST padding, as used by Ethereum) — `hashlib.sha3_256` is a different function; a
compact Keccak implementation is vendored in `keccak.py`, self-checked at import against
measured known-answer values and cross-checked byte-for-byte against the TypeScript
reference (`npm i viem` in the repo root, then `node tools/cross_check_ts.mjs`).

Regeneration is deterministic and diffable: `python3 tools/gen_vectors.py` rewrites
`vectors/` + `MANIFEST.json` byte-identically (CI asserts this on every push).

## License

Apache-2.0. Maintained by [Tersign](https://tersign.ai). Cross-runs, counter-vectors, and
adversarial additions welcome.
