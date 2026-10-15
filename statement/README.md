# Chain-statement profile: `tersign-chain-statement-v1`

A chain statement is an object a ledger signs over one range of one record chain. What a valid statement establishes,
and what it does not, is in the top-level README (*Chain statements*); this file is the check and the vectors.

The runner is pure standard library: the suite's `keccak.py`, the core's canonical form (`verify.py` `canonical`, the
form `digest_recompute` pins) and the counter-signature profile's recovery (`crypto/secp256k1_recover.py`). The second
implementation is `tools/cross_check_statement.mjs` (TypeScript stack, viem; same authors, so a second implementation,
not independent reproduction).

```
python3 statement/verify_statement.py            # 263/263 vectors (40 accept, 223 reject), verdict + reason, read from statement/MANIFEST.json
python3 statement/verify_statement.py --mutants  # 56 plausible broken verifiers switched inside the Python engine, each failed by a named vector
python3 statement/gen_statement_vectors.py       # regenerates every vector and statement/MANIFEST.json byte for byte (CI checks this)
node tools/cross_check_statement.mjs             # the TypeScript engine over the same 263 vectors
python3 tools/differential_statement.py          # both engines, the corpus plus an off-corpus battery, no manifest oracle
python3 tools/mutate_statement.py                # 105 source mutants in the two engines, each failed by its named vectors
```

Licence: Apache-2.0, as the repository (`LICENSE`).

## Input

```
{"body_text": "<the served body, as text>", "expected_signer": "0x...", "records": ["0x...", ...]}
```

`body_text` is the response body as served, as text, because several parse rules (a member name written twice, a
number token such as `1.0`, how deep the body nests, a surrogate code point written raw) are invisible once a JSON reader has
turned the text into values. `expected_signer` is the ledger's key obtained from elsewhere; `records` is the range's
artifact digests in ledger order. Both are optional and read by key presence (`rules.input`, a suite rule).

## The check

In this order; the first rule broken decides the reason (`rules.check_order`, a suite rule).

1. **parse**: the body is JSON text that nests objects and arrays at most 64 deep, the body counting 1 (`rules.depth`,
   a suite rule, counted on the text); no object carries a member name twice; every number token is an integer in
   [-(2^53 - 1), 2^53 - 1]; every string, member names included, is well-formed Unicode (`rules.parse`); and no
   surrogate code point is written raw in the text, even where an escape next to it would complete a pair
   (`rules.raw_surrogate`, a suite rule). A character outside the Basic Multilingual Plane written raw is one code
   point, not a surrogate, and is accepted (sp39).
2. **shape**: the body is an object with exactly the members `{statement, statementDigest, signature, signer}`. A body
   that is JSON text but not an object, an array for example, is refused here, not by the parse rules (sn189).
3. **Statement rules**: the closed sets and consistency rules over `statement`, in the order of `statement_refusal` in
   `verify_statement.py`, each with its own reason: `shape` (members, fixed values, types), `scope`, `chain_key`,
   `range`, `attachments_version`, `attachment_entry`, `consistency` and `anchor`. The rules are stated in
   `statement/MANIFEST.json` `rules`, and the constants they use (the schema strings, the fixed `limits` text, the
   closed sets, the caps 5,000 records, 256 list entries and 1,000 bridge links, the nesting bound 64, the member
   lists) in `format`, which both engines compare with their own pinned copies.
4. **shape**: `signer` equals `statement.ledger`, byte for byte.
5. **digest**: `statementDigest` is keccak256 over the UTF-8 bytes of `canonical(statement)`, compared exactly.
6. **signature**: `"0x"` then 130 hex digits of either case, `v` 27 or 28, `s` at most n/2, `1 <= r < n`, `s >= 1`,
   decided on the bytes before recovery (the counter-signature profile's steps 5 to 7); then personal_sign recovery
   over the UTF-8 string `"tersign-chain-statement-v1:" + statementDigest` must yield `statement.ledger`, compared
   case-insensitively.
7. **signer**: with `expected_signer`: it equals `statement.ledger`, case-insensitively.
8. **records**: with `records`: one `0x` + 64 lower-case hex digest per record of the range, folding from `before` to
   `through` (link = keccak256(digest || prev, or 32 zero bytes at seq 1 || uint64_be(seq)); acc = keccak256(acc ||
   link), the core's `chain_link` and `chain_commitment` steps).

Reject reasons (the closure is pinned in both engines and compared with `reject_reasons` in the manifest; each is
exercised by at least one vector): `parse`, `shape`, `scope`, `attachments_version`, `attachment_entry`, `range`,
`chain_key`, `consistency`, `anchor`, `digest`, `signature`, `signer`, `records`.

**The nesting bound is this suite's rule, not the format's.** The format sets no bound, and a reader without one decides
deep nesting by wherever its parser stops, which differs between parsers and interpreters; the suite fixes 64 so that
its two engines agree on every input. The bound changes a reason, never a verdict, since a statement nests 8 deep at
most. The two depth vectors sit at the bound (64 levels, read and refused as `scope`) and at 3,000 levels (`parse`).

**The raw-surrogate rule is this suite's rule, not the format's.** A body served as UTF-8 cannot carry a raw surrogate,
so the rule changes no verdict on a served body; it decides text a verifier is handed. A reader of code points sees a
pair written half raw (sn146, sn147) as two lone surrogates, while a reader that decodes escapes into UTF-16 code units
first, as JavaScript's `JSON.parse` does, joins the halves into a pair. The format's parse rule is written over
decoded strings and does not say which of these readings applies. The suite reads code points and refuses such a text,
so that its two engines agree.

## Vectors (two-sided)

Every rejecting vector names its accepting twin (`twin`, in the vector and in its manifest entry), and its description
names what changed: one value; one logical change that moves values bound to each other (an anchor's derived members
recomputed, a count with the count that must match it, a statement signed by another key); or, for the order vectors,
two faults. Where the change is to the statement, the test key signs the changed statement again, so the digest and
signature checks cannot be what rejects it, except in sn107 and sn108, which keep the original digest or signature
because those checks are what they test. The vectors that change the served text or the envelope instead (sn113–sn117, sn128, sn146–sn149,
sn188, sn189, sn218, sn220) keep the twin's digest and signature, and the rule that rejects each is decided before the
digest is checked. The runner fails a set in which a twin is missing or not valid, a reason is never exercised, or the
manifest's `format` differs from the runner's constants.

| class | accepts | rejects | reason |
|---|---|---|---|
| served shape | sp1 (anchor and a one-link bridge), sp2 (sp1 with its records), sp3 (from seq 1, no anchor), sp4 (anchor at `range.to`, bridge null), sp5 (no expected signer) | | |
| scope | sp1 | sn1 value outside the set, sn2 letter case, sn3 null, sn4 empty | `scope` |
| | | sn5 member missing | `shape` |
| attachments | sp6–sp8 (declared entries, before and inside the range) | sn9–sn14 version 2, `"1"`, `true`, 0, null container, an undefined member | `attachments_version` |
| entries | sp6, sp7, sp12 (position = `range.to`) | sn15 entries an object, sn16–sn18 **binding outside the closed set**, letter case, null; sn19–sn21 undefined member, its value null, binding missing; sn22–sn27 position 0, after `range.to`, repeated, inverted, a string, `true` | `attachment_entry` |
| entry type | sp13–sp19 (2 and 64 characters, a final digit, 31 hex digits, 31 split by hyphens, `x` + 32 hex digits, 32 hex digits + `x`) | sn28–sn37 letter case, empty, final hyphen, underscore, leading digit, 1 and 65 characters, 32 and 64 hex digits, 32 split by hyphens; sn221 the type an array | `attachment_entry` |
| sealed binding | sp9 (all-v2 range), sp10 (at the first v2 link of a mixed range), sp11 (before `range.from` when v1 is 0) | sn6 no v2 link, sn7 a v1 link of a mixed range, sn8 before `range.from` on a mixed range | `attachment_entry` |
| range | sp20 (5,000 records) | sn38–sn41 5,001 records, from 0, from > to, from a string; sn210 to a string | `range` |
| | | sn42 an undefined member | `shape` |
| chain | sp21 (key present) | sn43–sn48 key empty, null, upper case, 31 and 33 bytes, zero bytes | `chain_key` |
| | | sn49–sn52 an undefined member, id empty, a number, missing; sn192 chain null | `shape` |
| ledger and fixed members | sp22 (ledger in lower case) | sn53–sn56 ledger of 39 and 41 digits, without `0x`, a non-hex character; sn191 ledger a number; sn57 limits altered; sn58, sn59 **an undefined member** (value 1, value null); sn185, sn186 **`anchor` and `bridge` absent where they are null** (twins sp3, sp4); sn60 **schema v2**; sn61 commitmentSchema v2; sn62, sn63, sn129 upper-case hex; sn64 linkVersions `v3` | `shape` |
| consistency | sp1, sp3 | sn65 before.seq; sn66 **linkVersions miscount**; sn67 **issuer counts miscount**; sn68 the seed; sn69 head null after seq 0; sn131 **a head at seq 0**; sn70 through.seq | `consistency` |
| before, through | sp1, sp3 | sn137, sn138 an undefined member; sn142 **`before.head` absent where it is null**; sn193, sn194 `before.seq` and `through.seq` strings; sn195 **`through.acc` in upper case** | `shape` |
| link versions | sp1 | sn196, sn197 `v1` and `v2` strings; sn198, sn199 `v1` and `v2` −1 | `shape` |
| issuer numbering | sp23 (two series, a gap, a duplicate), sp24–sp26 (256 series, missing numbers, duplicates), sp35 (corrections: `correctionSeq` 0 and 1, the min and the max missing), sp40 (a series at number 0) | sn71–sn77, sn79, sn81, sn82, sn84–sn86 (series without a bound record, ranges, order, caps, 255 and 257); sn177 **min −1**; sn178 **a missing number below min**; sn179–sn181 **ledger seqs from 0, descending, repeated**; sn183, sn184 **series ids and missing numbers descending**; sn205 a missing number a string; sn216 a ledger seq a string | `consistency` |
| | | sn78 correctionSeq −1, sn80 and sn139, sn140 an undefined member in a series, `issuerSeq` and a duplicate, sn83 truncated a string, sn145 **`correctionSeq` absent where it is null**; sn176 **a negative count, the sums still equal**; sn182 **a series id in upper case**; sn200 `series` an object; sn201, sn202 min and max strings; sn203, sn204 `missing` and `duplicates` objects; sn206 a duplicate's seq a string; sn207 its `ledgerSeqs` an object; sn211–sn214 `boundRecords`, `unboundRecords`, `absentRecords` and `listCap` strings; sn215 a duplicate's `correctionSeq` a string | `shape` |
| anchor and bridge | sp27 (pending, batch root), sp28 (1,001 past, no bridge), sp29 (1,000 past, 1,000 links), sp36, sp37 (height 0 and 2^53 − 1), sp38 (an anchor at `range.to` of a one-record range) | sn87 **a bridge link replaced**; sn88, sn89 subject and anchored digests; sn90 status; sn91 no bridge within the cap; sn92 a bridge without an anchor; sn93, sn136 **an anchor before `range.to`**, with a bridge and without; sn94, sn95 id and proof URL; sn208 the proof URL a number; sn96, sn132 an anchor at `range.to` with another head, another acc; sn97 an empty bridge object; sn98, sn130 height −1 and `true`; sn187 height −(2^53 − 1), read and refused here; sn99 batch root upper case; sn175 anchor.seq `true` at a `range.to` of 1; sn100, sn101 the cap; sn102, sn141 an undefined member in the anchor and the bridge; sn103, sn104 subjectSchema v2; sn105, sn106 upper-case hex; sn133 **no bridge link, the anchor's acc set to `through.acc`**; sn134, sn135 bridge `from` and `to`; sn209 **bridge links an object**; sn143, sn144 **`batchRoot` and `bitcoinBlockHeight` absent where they are null** | `anchor` |
| digest | sp1 | sn107 a changed head with the original digest; sn127 the digest in upper case | `digest` |
| signature | sp1, sp34 (upper-case hex digits) | sn108 the original signature over a changed statement; sn109 **another key while naming the ledger**; sn110 **the high-s twin**; sn111 **the raw recovery id**; sn125 a `0X` prefix; sn126 a trailing newline; sn222 the signature a number | `signature` |
| signer | sp30, sp31 (another key, without and as the expected signer), sp32 (expected signer in lower case) | sn112 **a self-consistent statement by another key** | `signer` |
| envelope | sp1 | sn113 signer names another key; sn114 an undefined member; sn128 signer in another letter case; sn189 **the body an array** | `shape` |
| parse | sp33 (a surrogate pair written as escapes), sp39 (**a character outside the BMP written raw**) | sn115 **a member written twice**; sn116 **the token `1.0`**; sn117 an integer beyond 2^53 − 1; sn188 **an integer below −(2^53 − 1)**; sn118, sn119 lone surrogates; sn146, sn147 **a pair written half raw**, in both orders; sn149 nesting 3,000 deep; sn217 **a lone surrogate in a member name**; sn218 **not JSON text**; sn219 **a lone surrogate in an array element** (a bridge link); sn220 **a lone surrogate in the envelope's signer** | `parse` |
| | | sn148 nesting 64 deep, the bound: read, and refused as `scope` | `scope` |
| records | sp2 | sn120–sn124 **swapped, left out, of another chain, one appended, upper case**; sn223 **the last record not `through.head`** | `records` |
| check order | | sn150–sn174, one per adjacent pair of reason groups, and sn190, one order across two series (below) | the first group's |

**Check order.** Each of sn150–sn174 carries two faults from reason groups that are adjacent in the order above, and
expects the first group's reason; the generator checks that each fault alone rejects with its own reason. The pairs:
parse, envelope shape (sn150) · statement shape, scope (sn151) · scope, chain shape (sn152) · chain shape, chain_key
(sn153) · chain_key, range shape (sn154) · range shape, range (sn155) · range, attachments_version (sn156) ·
attachments_version, attachment_entry (sn157) · attachment_entry, before shape (sn158) · before shape, consistency
(sn159) · before consistency, linkVersions shape (sn160) · linkVersions shape, its count (sn161) · the count, the sealed
rule (sn162) · the sealed rule, issuerSeq shape (sn163) · issuerSeq shape, consistency (sn164) · issuer counts, series
shape (sn165) · series shape, series consistency (sn166) · series consistency, duplicate shape (sn167) · duplicate
shape, duplicate consistency (sn168) · duplicate consistency, anchor (sn169) · anchor, envelope signer (sn170) ·
envelope signer, digest (sn171) · digest, signature (sn172) · signature, signer (sn173) · signer, records (sn174).
Each vector pins the order of the two rules it breaks, at the place in the statement where its faults sit, and no
other. sn166–sn168 put both faults in the first series or in its first duplicate, so they pin the order inside one
series or one duplicate; sn165 pins the issuer counts before the second series' shape, and sn169 the first duplicate's
consistency before the anchor. sn190 pins one order across two series: the first series' `min` above its `max`
(consistency) and a sixth member in the second series (shape) reject as consistency, because the series are checked
one after another, each series' shape, consistency and duplicates before the next series' shape.

**Mutants.** `--mutants` runs 56 broken verifiers switched inside the Python engine, among them: the last of
two equal member names kept, `1.0` read as 1, no integer bound, undefined members ignored, the limits text not compared,
`scope` and `binding` letter case folded or not checked, the hex rule on entry types counting characters or refusing any
32-digit run, the sealed rule read only from `range.from` on or only without v2 links, five consistency rules removed
(`before.seq`, the seed, the link-version count, the issuer counts, `listCap`) and two bounds lifted, the range, list
and bridge caps one off, the bridge not folded, the digest not compared or compared case-insensitively, high-s accepted,
the raw recovery id normalized, the expected signer ignored or compared case-sensitively, records not checked or extra
records ignored. `tools/mutate_statement.py` edits the source of both engines instead, one change per mutant: 50 Python
and 55 TypeScript mutants. Most edit one site; a move of one check past the next swaps two adjacent blocks, deletes
the check at one site and inserts it at another, or (the envelope-signer and every-series-shape moves) inserts a copy of
the check ahead of the other; and the two that read an anchor before `range.to` like one at it edit two lines. Among
them: a head at seq 0 read in one direction only, an anchor at `range.to` compared on its head only, the bridge link
count dropped, a missing number not allowed to equal min or max, `correctionSeq` read as null
only or as positive only, undefined members ignored in `before`, `through`, `range`, `issuerSeq`, a series, a duplicate
and the bridge, absent members read as null (in `before`, the anchor, a duplicate, and `anchor` and `bridge`
themselves), the bridge's `from` or `to` not compared, an anchor before `range.to` read like one at it, `anchor.seq`
read without its type, height 0 refused, the integer bound made exclusive, the parse rule's lower bound made exclusive
or removed, the parse rules made to require an object, every surrogate code unit of the text refused, the halves of a
pair joined, the nesting bound one lower or (TypeScript) removed, negative issuer counts allowed, a negative `min`
allowed or a `min` of 0 refused, a missing number below `min` allowed, ledger seqs from 0, series ids, missing numbers
and ledger seqs checked only for repeats, ledger seqs allowed to repeat, the series id form not checked, and 23 changes of
order, which reach 15 of the 26 order vectors (the other 11 rest on their order vectors alone). Each is failed by
the vectors it names, and one comment-only mutant per engine must survive.

**Not pinned.** (1) The rule that `anchor.seq` is at least `range.to` cannot be isolated: an anchor before `range.to`
always breaks the bridge rule too, with the same reason (`bridge.to` would have to be `anchor.seq` with fewer than
zero links), so removing the seq rule changes no verdict and no reason; sn93 and sn136 carry both. (2) The order among
rules that share a reason and among the parse rules; the order of any pair of rules across a boundary other than the
pair its order vector breaks; and any order across two series or two duplicates other than sn190's (a duplicate's
shape against an earlier duplicate's consistency, for example). (3) The exact nesting bound from above: no vector sits
between 65 and 2,999 levels, where a reader without an explicit bound decides by its parser's limit, so a verifier
whose bound is anywhere from 64 to 2,999 passes both depth vectors. (4) Anything about the time-stamp proof
`anchor.proofUrl` names; this profile never fetches or opens it. (5) Checks that a check beside them already implies,
so that removing one changes no verdict and no reason: the well-formed-Unicode test repeated on the statement after the
parse rules; the range test inside each integer type check, which the parse rule's integer bound already applies to
every number token; the string test on `body_text`, which the input requires; the string test before `scope`,
`binding` and `status` are compared with their closed sets; the integer test on `bridge.from` and `bridge.to`, each of
which must equal an integer of at least 2; `position` at least 1, given that positions ascend strictly from 0;
`1 <= r < n` and `s >= 1` in the signature encoding, which recovery refuses in both engines; the form tests on `anchor.subjectDigest` and `anchor.anchoredDigest`, which their comparisons with the values computed from the anchor already imply, and on `anchor.acc` for an anchor at most 1,000 records past `range.to`, which the comparison with `through.acc` or the bridge fold already implies; and the number of
`records`, which the fold to `through.acc` already fixes. (6) The exact low-s bound: no vector carries a signature whose
`s` is n/2 or n/2 + 1, so a verifier that also refuses s = n/2 passes every vector. (7) Clauses no vector isolates, found after (1)–(6): a number token with an exponent (`1e0`; sn116 writes only a fraction); a member name written twice with an escape in one of the two (sn115 writes both alike); a hex value written as a one-element array, which a JavaScript RegExp tests as its text (sn221 covers that for the entry type only); the form of `anchor.acc` on an anchor more than 1,000 records past `range.to`, which no other check reads; a signature of more than 130 hex digits; the tokens `NaN`, `Infinity` and `-Infinity`; and the non-negativity of `unboundRecords`, `absentRecords` and `listCap` taken one at a time (sn176 makes only `boundRecords` negative). This list is not known to be complete.

**What the accepting vectors test.** The accepting vectors test the format's rules, not what a ledger serves today.
Tersign's ledger code, building statements over the same records (with a stand-in for its database, 2026-10-14),
gives the statement, digest and served text of sp1–sp5, sp27, sp30–sp32 and sp36–sp38, the signature's nonce aside.
It gives the statements of sp33 and sp34 served in another form: it writes sp33's character outside the BMP raw, as
sp39 does, and the hex digits of a signature in lower case. sp39, added after that measurement, is sp33's statement in
the form the ledger writes it. The others carry values Tersign's ledger would not sign today:

- attachment entries (sp6–sp8, sp12–sp19): the ledger signs no statement that lists an attachment entry today;
- v2 links (sp23–sp26, sp35, sp40): the ledger counter-signs every link as v1 today, so no statement it serves carries
  a v2 link, a bound record or a series;
- both (sp9–sp11);
- sp20: `through.head` and `through.acc` are written by hand, not folded over 5,000 records;
- sp21: the ledger sets no `chain.key`;
- sp22: the ledger writes its address in mixed case, never in lower case;
- sp28: the anchor's `head` and `acc` are not values of the chain, and the ledger states no anchor whose commitment
  disagrees with its own fold;
- sp29: the 1,000 bridge links are synthetic.

**Issuer-numbering reports.** Every accepting vector that carries a v2 link has its report computed by
`issuer_report()` in the generator from one link binding per ledger seq, as the format defines the report (counts,
min and max over the range; a number missing when no original binding at or before `range.to` names it; a duplicate
named by two or more bindings, one of them in the range), so each is a report a ledger could sign; each such vector's
description lists its bindings or names the vector that does. The rules this profile checks are looser than that
definition: they do not, for example, require a duplicate's number to lie between min and max, so a report no ledger
would compute can still pass them.

**Provenance.** Every vector is `synthetic`, generated by `gen_statement_vectors.py` from three chains whose record
digests are keccak256 of fixed labels, and signed by two published test keys (`test_key_address`,
`second_test_key_address` and their derivations in the manifest; the first is the counter-signature profile's test key).
The signing nonce is derived per signature (`test_nonce_derivation`). `proofUrl` values use the reserved host
`ledger.example`. No vector carries a record, a key or an anchor of a live ledger.

**Reporting a run.** Publish each vector's verdict and, for a reject, its reason, as the README's *Reproduction*
describes, and compare it with `python3 tools/compare_run.py <output.json> --manifest statement/MANIFEST.json`.
