# Crypto profile: counter-signature recovery over chain links

The first milestone named in the README's *Scope boundary*. The stdlib core decides the structural predicate. This profile checks what the structural predicate cannot: that each chain link was counter-signed by the declared party.

The runner is pure standard library: `crypto/secp256k1_recover.py` plus the suite's own `keccak.py`. `secp256k1_recover.py` verifies, and also ships `sign()`, used only by the generator to make test-key vectors with a fixed, published nonce. It keeps the recomputability bar of "bytes plus a stdlib verifier, no hosted call".

```
python3 crypto/verify_crypto.py            # 46/46 vectors (11 accept, 35 reject), verdict + reject reason, read from crypto/MANIFEST.json
python3 crypto/verify_crypto.py --mutants  # 22 plausible broken verifiers, each killed by a named vector
python3 crypto/gen_crypto_vectors.py       # regenerates every vector and MANIFEST.json byte for byte (CI checks this)
```

Licence: Apache-2.0, as the repository (`LICENSE`).

## The check

In this order; the first failing step decides the reason.

1. Every required field is present: `artifact_digest`, `seq`, `countersignature`, `ledger_signer`. Otherwise `malformed_input`.
2. **Field domain** (`malformed_input`). `artifact_digest`, `prev_digest` (when present) and `ledger_signer` are normalized as the core's `identifier_normalization` does: strip leading and trailing characters with the Unicode White_Space property (exactly the core's set), then lowercase. They must then be exactly `0x` + 64 hex (digests) or `0x` + 40 hex (signer). `seq` is an integer token in `[1, 2**53 - 1]`, never a `bool`, `str` or `float`. An absent `prev_digest` (key omitted or `null`) means genesis, 32 zero bytes.
3. **Link version.** An input may carry `link_version`; an omitted key means 1, the only recipe (`MANIFEST.json` `link_recipe`). A present `null` is a value, not absence. Any value other than the integer 1, including `null`, `true`, `1.0` and the string `"1"`, rejects as `unsupported_link_version` rather than being read as 1.
4. `link = keccak256(artifact_digest || prev_digest (or 32 zero bytes) || uint64_be(seq))`. This is the core `chain_link` recomputed from the vector's own fields, so the signature is bound to the structural link, not to a hash supplied beside it.
5. The counter-signature is matched whole and **not** normalized: exactly `0x` followed by 130 hex digits (no whitespace, no `0X`), with `v ∈ {27, 28}`. Otherwise `malformed_signature`.
6. Low-s (EIP-2: `s ≤ n/2`), checked on the signature bytes **before** recovery. A high-s signature MUST be rejected, not normalized to `n - s`: after recovery the two encodings are indistinguishable by address. Otherwise `non_canonical_s`.
7. EIP-191 `personal_sign` recovery over the 32 link bytes must define a public key. Otherwise `unrecoverable`.
8. Its address must equal the normalized `ledger_signer`. Otherwise `signer_mismatch`.

Reject reasons (declared in `MANIFEST.json`, each exercised by at least one vector): `malformed_input`, `unsupported_link_version`, `malformed_signature`, `non_canonical_s`, `unrecoverable`, `signer_mismatch`.

**Why the fields and the signature differ.** Digests and the signer are identifiers: the core already folds whitespace and case toward the same value, so the profile does the same (cp5–cp7 and cp10 accept; cn17 and cn33 reject U+FEFF and U+001C pads, which are not White_Space). The signature is bytes, not an identifier; any tolerated variant is a second encoding of one signing operation, so it is matched exactly (cn14–cn16, cn18).

**Field-shape validation (normative).** Every field is checked against its declared domain (step 2) *before* the counter-signature is parsed at all. A verifier that reaches straight for `bytes.fromhex()` / `int(seq).to_bytes(8, "big")` either raises on a malformed field (a crash is not a reject) or silently coerces a wrong-typed field into a value indistinguishable from a well-formed one (`seq: "1"` behaving exactly like `seq: 1`). A *present, malformed* `prev_digest` is rejectable and MUST NOT be treated as absent. (Thanks to Noûs, an AI agent operating under Roberto Locatelli's mandate, `@robertolocatelli81-dev`, whose independent third runner found this class across five malformed-field cases and then the trailing-newline anchoring gap; the vectors written on those published inputs reuse cp1's live values, so they are classed `live-ledger-derived` and their source names the reproduction.)

**Uniqueness of encoding (normative).** A conformant counter-signature suite MUST reject every *alternative encoding* of a signature it already accepts — the malleated re-expression of one signing operation, not a second, independently-produced signature over the same signer and link. For ECDSA over secp256k1 that is step 6: `s' = n - s` with `v` flipped is a re-encoding of the same signing operation and MUST be rejected, never normalized. A suite admitted later MUST state its own canonical-encoding rule and reject every other encoding of an accepted signature before verification; for Ed25519 that means rejecting a non-canonical `S` (`S ≥ L`, RFC 8032 §5.1.7). This is **not** a claim that a signer can produce only one valid signature byte string per link — ECDSA's random nonce `k` means a signer legitimately produces a distinct low-s signature per choice of `k` over the same message, and a conformant verifier accepts all of them. Any system that deduplicates or indexes on signature bytes MUST key on `(signer, link)` instead, since signature bytes alone are not a stable identity for "the same counter-signature". A suite whose verifier accepts two *encodings of one signing operation* is not conformant, whatever its other properties. (Thanks to @stillmarcus24, whose independent runner confirmed cn3 and raised both the ordering and the per-suite rule; thanks to @TKCollective, who found this scoping gap — the published test helper produces two accepted low-s signatures for the same signer and link under nonces 2 and 3, which the original wording would have wrongly called nonconformant.)

## Vectors (two-sided)

| id | expect | what it pins |
|---|---|---|
| cp1 | valid | **live**: the ledger's counter-signature over the genesis link recovers to `0x9d38…FDa6` |
| cp2 | valid | accepting twin of cn4: the published test key's signature, declared signer = that key (catches a runner that hard-codes the ledger signer) |
| cp3 | valid | `prev_digest` key omitted resolves identically to cp1's explicit `null` |
| cp4 | valid | **live, non-genesis**: the seq-2 link, real predecessor. Kills `link_ignores_prev` |
| cp5 | valid | `artifact_digest` with a trailing newline, normalized |
| cp6 | valid | `ledger_signer` with a trailing newline, normalized |
| cp7 | valid | `artifact_digest` written `0X` + upper-case hex, normalized |
| cp8 | valid | explicit `link_version: 1` |
| cp9 | valid | `seq = 2**53 - 1`, the top of the domain (test key) |
| cp10 | valid | U+0085 after the digest and U+3000 before the signer: both White_Space, stripped (kills an ASCII-only strip) |
| cp11 | valid | the live signature with upper-case hex digits, `0x` kept (kills a lower-case-only signature check) |
| cn1 | reject `signer_mismatch` | the live signature moved to seq 2: the link commits to position |
| cn2 | reject `signer_mismatch` | a foreign key signs the genuine link while the record claims the ledger |
| cn3 | reject `non_canonical_s` | **the live signature malleated to `s' = n - s`, v flipped. It recovers to the same ledger signer.** |
| cn4 | reject `signer_mismatch` | a raw-digest signature (no EIP-191 prefix): the domain must be pinned |
| cn5 | reject `malformed_signature` | 64 bytes, recovery byte dropped |
| cn6 | reject `malformed_signature` | `v = 29`: rejected, not normalized |
| cn7 | reject `malformed_input` | `artifact_digest` not hex |
| cn8 | reject `malformed_input` | `seq` negative |
| cn9 | reject `malformed_input` | `seq = 2**64` |
| cn10 | reject `malformed_input` | `seq` is the string `"1"` |
| cn11 | reject `malformed_input` | `seq` is `true` (bool is an int subclass in Python) |
| cn12 | reject `malformed_input` | `ledger_signer` not a 20-byte address |
| cn13 | reject `malformed_input` | `prev_digest` present but malformed, distinct from absent |
| cn14 | reject `malformed_signature` | signature missing its `0x` prefix |
| cn15 | reject `malformed_signature` | signature with embedded whitespace |
| cn16 | reject `malformed_signature` | signature with a trailing newline (the `$`-vs-`\Z` class) |
| cn17 | reject `malformed_input` | `artifact_digest` padded with U+FEFF, which is not White_Space and is not stripped |
| cn18 | reject `malformed_signature` | signature with a `0X` prefix |
| cn19 | reject `signer_mismatch` | cp4's signature over a moved predecessor (another real digest from the same record) |
| cn20 | reject `unrecoverable` | a well-formed, low-s signature whose `r` is not on the curve |
| cn21 | reject `malformed_signature` | `v = 0` |
| cn22 | reject `malformed_signature` | `v = 1` |
| cn23 | reject `signer_mismatch` | `s = floor(n/2)`: passes low-s, fails later. An off-by-one verifier says `non_canonical_s` here |
| cn24 | reject `non_canonical_s` | `s = floor(n/2) + 1`: the first non-canonical value |
| cn25 | reject `malformed_input` | `seq = 0` |
| cn26 | reject `malformed_input` | `seq = 2**53` |
| cn27 | reject `unsupported_link_version` | `link_version: 1000` (twin of cn35 across 1) |
| cn28 | reject `unsupported_link_version` | `link_version: "1"` |
| cn29 | reject `malformed_input` | `seq: 1.0`, an integral float, not an integer token |
| cn30 | reject `unsupported_link_version` | `link_version: 1.0` |
| cn31 | reject `unsupported_link_version` | `link_version: true` |
| cn32 | reject `unsupported_link_version` | `link_version: null`: a present null is a value, not absence |
| cn33 | reject `malformed_input` | digest padded with U+001C: not White_Space, though Python's `str.strip()` removes it |
| cn34 | reject `malformed_input` | a malformed digest and a malformed signature in one input: field shape is checked first (the normative order) |
| cn35 | reject `unsupported_link_version` | `link_version: 0` |

**On cn16.** Python's `re` treats an unqualified `$` as matching before a trailing `\n`, so a shape check written `^0x…$` accepts a trailing newline that a leading one fails. The runner anchors with `\A…\Z`. Through `1e08f4e` it had exactly that gap on every field.

**On cn3.** A verifier that only checks "recovered address == signer" accepts cn3. That includes one built on `eth_account` (0.13.7, `Account.recover_message`), which returns the ledger address for it. So a single link would admit two distinct signature byte strings, and any system that keys or deduplicates on signature bytes breaks. EIP-2 low-s is what makes the signature canonical.

**Cross-check with `eth_account` 0.13.7** (re-run at this commit on all 46 vectors, 27 of which are signature-level questions). It is a signature library, not a record verifier, so only the signature-level vectors apply. It **accepts** cn3 (high-s), cn14 (no `0x`), cn18 (`0X`) and cn22 (`v = 1`, normalized to a recovery id), and it **raises** instead of rejecting on cn5, cn6, cn15, cn16 and cn20.

The test key and the fixed nonce are published in `MANIFEST.json` (`test_key_address`, `test_key_derivation`, `test_nonce_derivation`) and derived in `gen_crypto_vectors.py`. Neither is ever a real signer.

**Provenance.** Each `MANIFEST.json` entry names `author` and `origin.class` from the core's closed set (`synthetic`, `live-ledger`, `live-ledger-derived`, `contributed`). cp1 and cp4 are `live-ledger` and carry a `provenance` block naming the public endpoint. Every other vector reuses cp1's or cp4's live values (cp2, cp9, cn2 and cn4 add the published test key's signature), so all are `live-ledger-derived`; where a vector was written on an outside contributor's published inputs, its source names that reproduction.

## Not yet covered

- ~~EIP-712 typed-data payload signatures~~ covered by `crypto/EIP712_MANIFEST.json` + `crypto/eip712_vectors/` (40 vectors: 9 accepting, 31 rejecting; MANIFEST-driven runner `verify_eip712.py`, generator `gen_eip712_vectors.py`, stdlib only, wired into CI's `eip712-profile` job; `verify_eip712.py --mutants` runs 15 one-site broken verifiers, each failed by its named vector). Pinned domain `{name: "x402 receipt", version: "1", chainId: 1}`, `Receipt(uint256 version,string network,string resourceUrl,string payer,uint256 issuedAt,string transaction)`; ep1 is p1's live payload signature, recovering `0x36f8…8b14`. All six Receipt fields are required and the payload is hashed exactly as transmitted (x402 `extension-offer-and-receipt.md` Sec 5.5 step 3). The extension asks signers to set unused fields to `""` and verifiers to treat `""` as equivalent to absence; that maps `""` to absence and does not license filling an omitted key in, so a payload with `transaction` omitted rejects (en10), and `version` must equal the integer 1 — a well-typed but different version rejects as `unsupported_version`, not `malformed_input` (en17, on §5.5 step 2: "currently only version `1` is defined").

  **Accepting side.** A verifier that requires signer = payer, always recovers with id 0 or hashes Latin-1 would pass ep1/ep2 alone, so each has an accepting twin: ep3 (a server key that is not the payer), ep4 (`v = 28`), ep5 (a non-ASCII `resourceUrl`, UTF-8 multi-byte) and ep6 (a non-ASCII `resourceUrl` entirely below U+0100, `résumé`: a verifier that hashes Latin-1-representable strings as Latin-1 and falls back to UTF-8 otherwise passes ep5, because `€` and `日` force the fallback, and fails ep6). The rejecting twins mirror the counter-signature profile's classes: `v = 0` and `v = 1` (en20, en21; cn21, cn22), `s = n/2` exactly, which passes the low-s check and then mismatches (en22; cn23), `s = n/2 + 1` (en23; cn24) and a `0X` prefix (en24; cn18).

  **Scope of a `valid` verdict.** The accepting verdicts (ep1, ep7, ep8, ep9 and every other `valid` vector) are signature-level only. x402 Sec 5.5 (Receipt Verification) tells a verifier, at step 6, to "Confirm `issuedAt` is within acceptable verifier policy". These vectors pin no freshness or other policy, so a verifier with a freshness policy may reject them and still conform to this profile.

  **Cross-check with `eth_account` 0.14.0** (signature-level only, run over the profile's first 32 vectors; ep8, ep9 and en28–en33 were added after it and are not in it: `encode_typed_data` with the pinned domain and type, then `recover_message`, compared to `signer`). It accepts all seven accepting vectors, ep7 included, so an independent implementation hashes `résumé` as UTF-8 and handles `issuedAt = 2^256 − 1`. Of the rejecting vectors it accepts en6 (high-s), en20 and en21 (`v` in {0, 1} normalized to a recovery id) and en24 (`0X` prefix), the signature-level behaviour documented for cn3, cn18 and cn22 above, and en8, en12 and en17, whose faults (`version` as a string, `format`, an unsupported `version`) are outside the signature. en10 as transmitted recovers a different address; with `transaction: ""` filled in it is ep1 and recovers the live payer `0x36f8…8b14`, the reconstruction en10 forbids.

  **This suite's rules, not x402's.** ep7, ep8, ep9, en26, en27, en28, and en6, en20, en21 and en23, pin this suite's own rules (the integer domain, the check order, the `signer` envelope key and uniqueness of encoding), not requirements of the x402 extension. `EIP712_MANIFEST.json` states two of them as keys, `integer_domain` and `signer_shape`, and the sources of ep8, ep9 and en28 name the key each rests on. en29, en30 and en31 rest on x402's own typing of `version` and `issuedAt`: `number` in the Sec 5.2 field table, `uint256` in Sec 5.3 (Normative Schema) and `"type": "integer"` in Sec 6.5's receipt schema. −1 is not a `uint256`, and `true` is none of the three.

  **Integer domain.** `version` and `issuedAt` are `uint256` integer tokens in [0, 2^256 − 1]. ep8 accepts `issuedAt = 0`, so a runner that starts the domain at 1 or reads 0 as absent fails it, and en29 rejects ep8 with `issuedAt = −1` on the same signature; ep7 accepts `issuedAt = 2^256 − 1`, so a runner that caps integers at 2^53 − 1 or 2^64 − 1 fails it; en25 rejects `issuedAt = 2^256`. A JSON `true` is not an integer token: en30 (`version: true` on p1) and en31 (`issuedAt: true` on ep9's signature over `issuedAt = 1`) reject, and a runner that reads `true` as 1 (in Python, `isinstance(True, int)` holds and `True == 1`) accepts both (the counter-signature profile's cn11 class). en26 rejects `version` written as the token `1.0`, which is not an integer token (the counter-signature profile's cn29 class). Two of these are loader-level cases: a loader that parses JSON numbers to doubles, as `JSON.parse` does, loses ep7 (2^256 − 1 is not exact as a double) and en26 (`1.0` becomes `1`). 2^256 (en25) is exact as a double.

  **Check order.** en27 pins one ordering: the payload is checked before the signature. It carries two faults (en9's payload and en14's signature) and rejects as `malformed_input`; a runner that checks the signature first reports `malformed_signature` (the counter-signature profile's cn34 class). `--mutants` covers that order (`signature_before_payload`) together with the low-s check, `v` normalization, the version check, `transaction` filled in as `""`, Latin-1 string hashing, the integer caps and upper bound, integral floats, an unchecked `signer` shape, an integer domain starting at 1, `true` read as 1, `null` read as `""` and a non-string coerced to a string.

  **Provenance.** The commitment and the cross-runs are recorded on #11 and #13; each vector's author and origin are in `EIP712_MANIFEST.json`, and ep1, the one `live-ledger` vector, carries a provenance block naming `https://tersign.ai/v1/genesis`.

  **Field shape.** The payload must carry all six Receipt fields (en10, en16). The four `string` fields must be JSON strings: en32 writes `transaction` as `null` and en33 writes `payer` as a number, and both reject, ep1 being the accepting twin of each; `null` is not read as `""` (a runner that does so recovers p1's payer from en32 and accepts it). `signer`, this suite's envelope key, must be `0x` + 40 hex digits, compared case-insensitively with the recovered address (ep1 declares a mixed-case signer and accepts): en28 declares p1's payer one hex digit short and rejects as `malformed_input`, where a runner that skips the shape check reports `signer_mismatch`. String fields must be UTF-8 encodable before they are hashed: a lone UTF-16 surrogate (en19) crashes `str.encode("utf-8")` rather than rejecting, which is the EIP-712 analogue of cn5/cn6/cn20's "a crash is not a reject."

  **Not pinned.** (1) A payload field the Receipt type does not have, and (2) an envelope key beyond `{format, payload, signature, signer}`. x402 §2 says implementers "SHOULD treat unknown extension-specific fields as unsupported rather than attempting best-effort interpretation"; rejecting meets it, and so does accepting without interpreting the field, so this profile does not decide between them (`verify_eip712.py` rejects both). (3) Upper-case hex digits in the signature: the extension says the signature is hex-encoded and `0x`-prefixed and sets no case for the digits; the prefix itself is the literal `0x` (en24). (4) Any check order other than the payload before the signature (en27): the relative order of the envelope shape, `format`, `version` and `signer` checks is not pinned. (5) Surrounding whitespace and a `0X` prefix on `signer`: no vector carries either, so this profile does not decide whether a verifier strips and case-folds them or rejects them (`verify_eip712.py` strips Unicode White_Space and lowercases before the shape check, so it accepts both).
- Signer-set rotation: which key was authoritative at which seq.
