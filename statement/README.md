# Chain-statement profile: `tersign-chain-statement-v1`

A chain statement is an object a ledger signs over one range of one record chain. What a valid statement establishes,
and what it does not, is in the top-level README (*Chain statements*); this file is the check and the vectors.

The runner is pure standard library: the suite's `keccak.py`, the core's canonical form (`verify.py` `canonical`, the
form `digest_recompute` pins) and the counter-signature profile's recovery (`crypto/secp256k1_recover.py`). The second
implementation is `tools/cross_check_statement.mjs` (TypeScript stack, viem; same authors, so a second implementation,
not independent reproduction).

```
python3 statement/verify_statement.py            # 164/164 vectors (34 accept, 130 reject), verdict + reason, read from statement/MANIFEST.json
python3 statement/verify_statement.py --mutants  # 56 plausible broken verifiers, each failed by a named vector
python3 statement/gen_statement_vectors.py       # regenerates every vector and statement/MANIFEST.json byte for byte (CI checks this)
node tools/cross_check_statement.mjs             # the TypeScript engine over the same 164 vectors
python3 tools/differential_statement.py          # both engines, the corpus plus an off-corpus battery, no manifest oracle
```

Licence: Apache-2.0, as the repository (`LICENSE`).

## Input

```
{"body_text": "<the served body, as text>", "expected_signer": "0x...", "records": ["0x...", ...]}
```

`body_text` is the response body as served, as text, because two of the parse rules (a member name written twice, a
number token such as `1.0`) are invisible once a JSON reader has turned the text into values. `expected_signer` is the
ledger's key obtained from elsewhere; `records` is the range's artifact digests in ledger order. Both are optional and
read by key presence (`rules.input`, a suite rule).

## The check

In this order; the first rule broken decides the reason (`rules.check_order`, a suite rule).

1. **parse** — the body is one JSON object; no object carries a member name twice; every number token is an integer in
   [-(2^53 - 1), 2^53 - 1]; every string, member names included, is well-formed Unicode.
2. **shape** — the body is exactly `{statement, statementDigest, signature, signer}`.
3. **Statement rules** — the closed sets and consistency rules over `statement`, in the order of `statement_refusal` in
   `verify_statement.py`, each with its own reason: `shape` (members, fixed values, types), `scope`, `chain_key`,
   `range`, `attachments_version`, `attachment_entry`, `consistency` and `anchor`. The rules are stated in
   `statement/MANIFEST.json` `rules`, and the constants they use (the schema strings, the fixed `limits` text, the
   closed sets, the caps 5,000 records, 256 list entries and 1,000 bridge links, the member lists) in `format`, which
   both engines compare with their own pinned copies.
4. **shape** — `signer` equals `statement.ledger`, byte for byte.
5. **digest** — `statementDigest` is keccak256 over the UTF-8 bytes of `canonical(statement)`, compared exactly.
6. **signature** — `"0x"` then 130 hex digits of either case, `v` 27 or 28, `s` at most n/2, `1 <= r < n`, `s >= 1`,
   decided on the bytes before recovery (the counter-signature profile's steps 5 to 7); then personal_sign recovery
   over the UTF-8 string `"tersign-chain-statement-v1:" + statementDigest` must yield `statement.ledger`, compared
   case-insensitively.
7. **signer** — with `expected_signer`: it equals `statement.ledger`, case-insensitively.
8. **records** — with `records`: one `0x` + 64 lower-case hex digest per record of the range, folding from `before` to
   `through` (link = keccak256(digest || prev, or 32 zero bytes at seq 1 || uint64_be(seq)); acc = keccak256(acc ||
   link), the core's `chain_link` and `chain_commitment` steps).

Reject reasons (the closure is pinned in both engines and compared with `reject_reasons` in the manifest; each is
exercised by at least one vector): `parse`, `shape`, `scope`, `attachments_version`, `attachment_entry`, `range`,
`chain_key`, `consistency`, `anchor`, `digest`, `signature`, `signer`, `records`.

## Vectors (two-sided)

Every rejecting vector names its accepting twin (`twin`, in the vector and in its manifest entry): the accepting vector
it was built from by one change. Where the change is to the statement, the test key signs the changed statement again,
so the digest and signature checks cannot be what rejects it. The runner fails a set in which a twin is missing or not
valid, a reason is never exercised, or the manifest's `format` differs from the runner's constants.

| class | accepts | rejects | reason |
|---|---|---|---|
| served shape | sp1 (anchor and a one-link bridge), sp2 (sp1 with its records), sp3 (from seq 1, no anchor), sp4 (anchor at `range.to`, bridge null), sp5 (no expected signer) | | |
| scope | sp1 | sn1 value outside the set, sn2 letter case, sn3 null, sn4 empty | `scope` |
| | | sn5 member missing | `shape` |
| attachments | sp6–sp8 (declared entries, before and inside the range) | sn9–sn14 version 2, `"1"`, `true`, 0, null container, an undefined member | `attachments_version` |
| entries | sp6, sp7, sp12 (position = `range.to`) | sn15 entries an object, sn16–sn18 **binding outside the closed set**, letter case, null; sn19–sn21 undefined member, its value null, binding missing; sn22–sn27 position 0, after `range.to`, repeated, inverted, a string, `true` | `attachment_entry` |
| entry type | sp13–sp19 (2 and 64 characters, a final digit, 31 hex digits, 31 split by hyphens, `x` + 32 hex digits, 32 hex digits + `x`) | sn28–sn37 letter case, empty, final hyphen, underscore, leading digit, 1 and 65 characters, 32 and 64 hex digits, 32 split by hyphens | `attachment_entry` |
| sealed binding | sp9 (all-v2 range), sp10 (at the first v2 link of a mixed range), sp11 (before `range.from` when v1 is 0) | sn6 no v2 link, sn7 a v1 link of a mixed range, sn8 before `range.from` on a mixed range | `attachment_entry` |
| range | sp20 (5,000 records) | sn38–sn41 5,001 records, from 0, from > to, from a string | `range` |
| | | sn42 an undefined member | `shape` |
| chain | sp21 (key present) | sn43–sn48 key empty, null, upper case, 31 and 33 bytes, zero bytes | `chain_key` |
| | | sn49–sn52 an undefined member, id empty, a number, missing | `shape` |
| ledger and fixed members | sp22 (ledger in lower case) | sn53–sn56 ledger of 39 and 41 digits, without `0x`, a non-hex character; sn57 limits altered; sn58, sn59 **an undefined member** (value 1, value null); sn60 **schema v2**; sn61 commitmentSchema v2; sn62, sn63, sn129 upper-case hex; sn64 linkVersions `v3` | `shape` |
| consistency | sp1, sp3 | sn65 before.seq; sn66 **linkVersions miscount**; sn67 **issuer counts miscount**; sn68 the seed; sn69 head null after seq 0; sn70 through.seq | `consistency` |
| issuer numbering | sp23 (two series, a gap, a duplicate), sp24–sp26 (256 series, missing numbers, duplicates) | sn71–sn77, sn79, sn81, sn82, sn84–sn86 (series without a bound record, ranges, order, caps, 255 and 257) | `consistency` |
| | | sn78 correctionSeq −1, sn80 an undefined member, sn83 truncated a string | `shape` |
| anchor and bridge | sp27 (pending, batch root), sp28 (1,001 past, no bridge), sp29 (1,000 past, 1,000 links) | sn87 **a bridge link replaced**; sn88, sn89 subject and anchored digests; sn90 status; sn91 no bridge within the cap; sn92 a bridge without an anchor; sn93 **an anchor before `range.to`**; sn94, sn95 id and proof URL; sn96 an anchor at `range.to` with another head; sn97 an empty bridge object; sn98, sn130 height −1 and `true`; sn99 batch root upper case; sn100, sn101 the cap; sn102 an undefined member; sn103, sn104 subjectSchema v2; sn105, sn106 upper-case hex | `anchor` |
| digest | sp1 | sn107 a changed head with the original digest; sn127 the digest in upper case | `digest` |
| signature | sp1, sp34 (upper-case hex digits) | sn108 the original signature over a changed statement; sn109 **another key while naming the ledger**; sn110 **the high-s twin**; sn111 **the raw recovery id**; sn125 a `0X` prefix; sn126 a trailing newline | `signature` |
| signer | sp30, sp31 (another key, without and as the expected signer), sp32 (expected signer in lower case) | sn112 **a self-consistent statement by another key** | `signer` |
| envelope | sp1 | sn113 signer names another key; sn114 an undefined member; sn128 signer in another letter case | `shape` |
| parse | sp33 (a surrogate pair written as escapes) | sn115 **a member written twice**; sn116 **the token `1.0`**; sn117 an integer beyond 2^53 − 1; sn118, sn119 lone surrogates | `parse` |
| records | sp2 | sn120–sn124 **swapped, left out, of another chain, one appended, upper case** | `records` |

**Mutants.** `--mutants` runs 56 one-site broken verifiers, among them: the last of two equal member names kept,
`1.0` read as 1, no integer bound, undefined members ignored, the limits text not compared, `scope` and `binding`
letter case folded or not checked, the hex rule on entry types counting characters or refusing any 32-digit run, the
sealed rule read only from `range.from` on or only without v2 links, five consistency rules removed (`before.seq`, the
seed, the link-version count, the issuer counts, `listCap`) and two bounds lifted, the range, list and bridge caps one off, the bridge not folded, the digest not compared or compared case-insensitively, high-s accepted, the raw
recovery id normalized, the expected signer ignored or compared case-sensitively, records not checked or extra records
ignored. Each is failed by the vector it names.

**Not pinned.** (1) The rule that `anchor.seq` is at least `range.to` has no vector of its own: an anchor before
`range.to` also breaks the bridge rule, which rejects with the same reason, so a verifier without the seq rule passes
every vector (sn93 carries both faults). (2) The order among rules that share a reason, and among the parse rules. (3)
Anything about the time-stamp proof `anchor.proofUrl` names; this profile never fetches or opens it.

**Provenance.** Every vector is `synthetic`, generated by `gen_statement_vectors.py` from two chains whose record
digests are keccak256 of fixed labels, and signed by two published test keys (`test_key_address`,
`second_test_key_address` and their derivations in the manifest; the first is the counter-signature profile's test key).
The signing nonce is derived per signature (`test_nonce_derivation`). `proofUrl` values use the reserved host
`ledger.example`. No vector carries a record, a key or an anchor of a live ledger.
