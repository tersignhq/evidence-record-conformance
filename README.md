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
- **Phase separation** — a record evidencing one economic phase **MUST NOT** verify as
  evidence of any other phase, a later one or an earlier one: a funding record presented as
  delivery (n6), a delivery record presented as funding (n90). (`phase_reject`)

All three are proposed normatively in the open compliance-fields extension PR
([x402-foundation/x402#2853](https://github.com/x402-foundation/x402/pull/2853), under
review); this suite makes them executable.

**Externally exercised.** The corpus has been executed and attacked from outside this
repository, on the record: byte-identical reproduction from the IETF `web-bot-auth` list
([Songbo Bu, 2026-08-10](https://mailarchive.ietf.org/arch/msg/web-bot-auth/8JVz3WDXgmS9W71Az_oALXM5cW4/) —
verifier, TypeScript cross-check, 258-case differential and byte-identical regeneration, against
`46ad663`); a published mutation-adequacy re-grade by
[@Rul1an](https://github.com/tersignhq/evidence-record-conformance/issues/1#issuecomment-5416529673)
(2026-08-25, at `0e560c1`: 11 declared mutants killed, 0 survived, 1 declared equivalent); the
anchor-preimage relation recomputed from a separate implementation
([#3](https://github.com/tersignhq/evidence-record-conformance/issues/3)); and four vector classes
contributed by external authors ([CONTRIBUTORS.md](CONTRIBUTORS.md)).

## Run

```
python3 verify.py
```

stdlib-only, no dependencies, no network. Exit 0 only if every vector produces its expected
verdict **and** the run observed both verdicts **and** the pinned closure of 10 reject reasons
and 11 vector kinds was fully exercised, **and every kind produced both verdicts** — the closure is pinned in the verifier, not derived
from the manifest, so a fork that quietly drops a class goes red. A green run demonstrates
the verifier discriminates, not merely accepts.

A reject counts only with its reason, and reasons compare as exact strings: `independence_reject`
matches itself and nothing else, with no case folding, no whitespace trimming and no prefix match.
`verify.py`, `tools/cross_check_ts.mjs` and `tools/compare_run.py` all compare this way.

## Vector classes

| class | accepts | rejects | reason code |
|---|---|---|---|
| content address (keccak256 over RFC 8785) | p1 (live), p3 | n1 value drift | `recompute_mismatch` |
| canonical bytes | p2 | n2 **hoisted integer keys**, n12 **code-point key order** | `canonicalization_reject` |
| number domain (I-JSON integers) | p12 (2^53−1 boundary), p13 (**decimal string** beside integer — spec-lockstep) | n10 **float**, n11 integer past 2^53−1 | `number_domain_reject` |
| number token in the digest domain | p25 (**integer token** via raw `payload_text`) | n35 **integer-valued float token** (wire bytes `2.0` — `JSON.parse` collapses it to `2`, the cross-engine divergence the pair closes), n103 **integer-valued exponent token** (`1e2`) | `number_domain_reject` |
| raw-text pathway (`payload_text` carries the loader's rules) | p30 (one name **repeated across distinct objects**), p35 (a **string value equal to a name**), p53 (two names that **differ only in normalization**, U+00E9 and `e` + U+0301) | n41 **duplicate name** (#10), n42 **escaped duplicate** (names compare decoded), n43 **`NaN` token**, n44 **`payload_text` not a string**, n57 **duplicate after an array value**, n68 **duplicate in a nested object**, n93 **duplicate written half raw, half escaped** (names compare as UTF-16 code units) | `canonicalization_reject` |
| supplementary-plane key order (UTF-16 vs code point) | p14 | n12 | `canonicalization_reject` |
| strings in the digest domain (UTF-8 of the canonical text, every code point outside RFC 8785's escape set as is, never normalized) | p39 (Latin-1 range), p40 (BMP), p41 (**astral**), p42 (**decomposed**, NFD), p45 (**U+2028 and U+2029**), p46 (**decomposed name**), p51 (**`<`, `>` and `&`**), p52 (**DEL and C1 controls**) | n71 **escaped before hashing**, n72 **Latin-1 bytes**, n73 **CESU-8**, n74 **NFC-normalized**, n85 **separators escaped**, n86 **name NFC-normalized**, n98 **HTML-escaped**, n102 **DEL and C1 escaped** (each the same payload under the digest a wrong encoder computes) | `recompute_mismatch` |
| unpaired surrogates (no canonical form) | p44 (**a surrogate pair**, as a name and a value) | n81 **lone high surrogate in a value**, n82 **lone low surrogate in a name**, n83 / n84 **lone surrogate in the digest domain**, in a value and in a name (p14 is n84's twin; each of the four forked v0.5.4's engines), n92 **lone surrogate after a float token** (the shape is decided before the numbers) | `canonicalization_reject` |
| chain link (artifact ∥ prev ∥ seq; seq an integer token in [1, 2^53−1]) | p4 (seq 1, the lower bound), p43 (2^53−1, the upper bound) | n3 wrong predecessor, n75 **seq 0**, n76 **seq 2^53**, n77 **float `seq` token**, n97 **exponent `seq` token** (`1e0`), n87 / n88 / n89 **`seq` a string, a boolean, null** | `continuity_reject` |
| per-seller set continuity + completeness | p6 (with per-record links) | n4 **silently omitted record**, n17 **renumbered omission** (stale link), n38 **float `seq` token** (p6's set with `head.seq` written `3.0` — `JSON.parse` collapses it to `3`; a sequence number is an integer token) | `completeness_reject`, `continuity_reject` |
| witnessed inclusion vs completeness | p24 (**witnessed complete set**) | n34 **witnessed inclusion is not completeness** | `completeness_reject` |
| chain commitment (accumulator over counter-signed links) | p26, p27 (live) | n36 **substituted prefix**, n37 **last-link-only accumulator** | `continuity_reject` |
| duplicate sequence number (equivocation) | p28 (issuer-only, **distinct seqs**), p29 (**committed prefix**) | n39 **two records at one seq** (issuer-only), n40 **equivocating record at a committed position** | `completeness_reject`, `continuity_reject` |
| anchored existence bound | p5 (live) | n5 truncated/substituted head | `existence_reject` |
| economic-phase separation | p7, p47–p50 (**each vocabulary word as itself**) | n6 funding-as-delivery, n90 **delivery-as-funding** (an earlier phase), n18 **unrecognized phase**, n78 **no `economic_phase`**, n79 **record not an object**, n80 **unrecognized phase presented as itself** (the vocabulary clause on its own), n91 **phase in another letter case**, n99 **`presented_as` in another letter case**, n100 **no `presented_as`**, n101 **refund-as-reversal** (no vector pins another pair of words) | `phase_reject` |
| offer binding (receipt commits to the accepted offer's canonical digest) | p15 | n19 **offer substitution** (same resource/network, different amount/payTo), n94 **lone surrogate in the offer** | `binding_reject` |
| decision-evidence binding (protected record commits to the canonical authority reduction) | p19 | n27 **unbound reduction**, n28 **reduction substitution**, n95 **lone surrogate in the evidence** | `binding_reject` |
| boundary binding | p18 (binds prefix **and** position), p20 (**suite transition** preserves the prefix under the suite in force when written) | n25 **fabricated boundary** (prefix-only binding), n26 **downgrade** (coverage over an empty attestation), n29 **retroactive re-digest** (transition binds the successor-suite digest of the same bytes — the engine that re-hashes history agrees with it, so it discriminates), n96 **lone surrogate in the prefix** | `boundary_reject` |
| independence criterion | p8, p9 (no claim), p10 (claim **set**), p11 (set, silence only), p16 (scope ⊆ **derived** commitments), p17 (**derived** commitments, resolvable settlement), p21 (**URN identities** — the criterion decides under a second identity syntax), p31 (**case and trailing punctuation** on an outside party), p32 / p34 (**percent-encoded unreserved** characters on an outside party), p33 (**whitespace set** — White_Space padding JavaScript's `trim()` misses), p36 (near-miss: **dots within segments**, not dot-segments), p37 (**CAIP-10 / did:pkh** form of a non-party address), p38 (**did:ethr / `ethereum:` / `acct:`** form of a non-party address), p22 (**delivery commitment**, recomputed digest, claim silent), p23 (**delivery independence within commitment** — the vector that drives the delivery derivation; no settlement present), p54 (**settlement result naming a transaction**, n104's twin), p55 (**delivery scope over a record with no settlement result**, n105's twin), p56 (**an outside attestor written `0X` with upper-case digits**, n106's twin) | n7 issuer-only attestation, n8 **unrecognized claim**, n9 **unread member in a set**, n13 **party alias** (whitespace), n14 unparseable attestor, n15 claim w/o attestations, n16 non-object attestation, n20 **scope past commitment**, n21 **empty settlement** (derived commitments), n22 **declared override** (list beside derivable result), n23 **explicit-null declaration** (the engine-fork input), n24 **declared with no scope asserted** (the presence rule's second half), n30 **URN self-attested** (rejects for the independence reason, not the identifier), n31 **URN alias** (trailing slash — n13 one syntax over), n45 **alias by case**, n46 / n47 **alias by trailing `.` / `#`**, n48 **alias by percent-encoding** (#8), n49 **alias on the party side**, decoded before the trailing strip, n50 **residual percent-encoding** (not evaluable), n51 **empty after normalization**, n52 / n53 **format / control character** at the edge (not White_Space; not evaluable), n54 **alias by the rest of the unreserved set**, n55 / n56 **decoded once** (`%25`, an assembled triplet), n58 **alias by scheme case alone**, n59 / n60 / n67 / n70 **dot-segments** (not evaluable; n67 and n70 at the path's first segment), n61 **query component**, n62 **fragment with content**, n63–n66, n69 **a party's address in another namespace** (CAIP-10, did:pkh, did:ethr, `ethereum:`, `acct:`), n32 **delivery self-attested** (same record as p22, independence claimed over it — the deliverer's own signature is the only attestation), n33 **delivery substitution** (p23's bytes tampered, digest as issued — commits to no delivery, the claim overreaches; rejects on the scope branch, not the unevaluable one), n104 **settlement result with no `transaction` member** (n21 pins the empty string), n105 **settlement claimed over a delivery-only record**, n106 **a party's address in another letter case** (an EIP-55 checksum form against lowercase, and `0X` with upper-case digits) | `independence_reject` |

Two design rules, both enforced by the run itself:

1. **At least one adversarial vector per known failure class** — an all-happy-path suite
   proves nothing about the class it never exercises. n2 encodes a failure observed in a real
   implementation (JS engines hoist integer-like keys into numeric order on object rebuild,
   silently defeating sort-then-stringify; RFC 8785 orders `"1" < "10" < "2"` by UTF-16 code
   units); n12 is the same rule where it bites hardest — a supplementary-plane key sorts FIRST
   by UTF-16 code units and LAST by code point. n4 is the completeness class this layer exists
   for, and n17 is its harder sibling: omission hidden by renumbering, visible only because
   the relabeled record carries the link computed for its original position.
2. **Every criterion is two-sided** — each criterion has accepting vectors beside its rejecting
   ones, and each class that admits an accepting input has an accepting twin (a form that is
   never evaluable, such as n50's, has none), so an implementation that unconditionally rejects
   a class fails the suite just as one that unconditionally accepts it does (p7/p8 exist for exactly this). **Enforced per kind since 2026-08-19**,
   not per run: until then the gate checked `{valid, reject}` over the whole run, so a
   criterion whose accepting vectors all disappeared stayed green as long as some other
   criterion contributed a `valid` somewhere — the rule was real in this paragraph and absent
   from the gate. Reported by @Rul1an (#1), who also traced what it had already let through:
   `d50545a` moved the independence criterion from deciding to not-deciding under URN
   identities, and the run said nothing. It is also why p21/n30 exist — one accepting vector
   per identity syntax the manifest says the criterion evaluates, so that trade goes red at
   the commit.

A third rule, added after this suite failed it: **a criterion's trigger must fail closed.**
An exact-equality trigger (`if claimed != "independent": valid`) reads any unfamiliar claim
string — including a *stronger* one — as no claim at all, switching the check off precisely
where more was asserted. Silence is a valid state (p9); an assertion the verifier cannot
interpret is not (n8). Failing closed also means *returning a verdict for every shape*: a
claim with no attestations (n15), an attestation that is not an object (n16), or an attestor
identifier that does not parse as an address (n14) each produce a reject, where earlier
implementations raised and produced no verdict at all — including the set form (p10), which
is where a field carrying two orthogonal criteria has to land. Reported against this suite
by [@Rul1an](https://github.com/tersignhq/evidence-record-conformance/issues/1).

A fourth criterion property, from the extension's commitment-scope rule (first proposed in
[x402-foundation/x402#2887](https://github.com/x402-foundation/x402/issues/2887), 2026-07-27):
**an independence claim reaches exactly as far as the record's commitments.** However
independent the attestor, the attestation covered the committed bytes and nothing else — a
claim covering an uncommitted fact class rejects (n20), and a scoped claim within the
commitments accepts (p16). This is a rule its authors fail-safe on deliberately: a record with
no delivered-bytes commitment carries no delivery independence, whoever counter-signed it.
Three fact classes are derivable (`MANIFEST.json` → `commitment_derivation`): `settlement` and
`network` off a settlement result, and — since v0.4.0 — `delivery` off the record's own bytes,
when `keccak256(utf8(deliverable_bytes))` recomputes to `deliverable_digest` (p23 accepts a
delivery-scoped claim with a non-party attestor; n33 substitutes one byte of the deliverable and
the claim overreaches). Until then no record could commit to `delivery` at all, so n20 rejected
for a structural reason that happened to be correct for the wrong cause — enumerated by
[@0rkz](https://github.com/tersignhq/evidence-record-conformance/issues/3), whose PayPerByte
fixture (p22/n32) anticipated the derivation and does not move under it. Field naming follows
the manifest's `field_naming` rule: harness keys `snake_case`, protocol-quoted keys keep the
protocol's spelling.

A fifth property, and the reason the fourth cannot be satisfied by assertion: **a record's
commitments are DERIVED from the record, never declared alongside it — and a declared
commitment scope is itself a rejectable input, whatever it holds.** A declared commitment
list lets a record assert the very scope the commitment-scope rule exists to bound, which makes
the rule vacuous exactly where it matters. The concrete case: x402 v2 §5.3.2 defines the empty
string as what `transaction` carries when settlement failed, while the type only requires a
string — so `success: true` with `transaction: ""` is well formed and commits to no settlement
anyone can resolve. Deriving commitments off the settlement result rejects an independence claim
over that record (n21) without resolving anything on-chain, and accepts the same claim when the
result carries a transaction reference that resolves (p17). The property is enforced on the
field's *presence*: a record carrying `record_commits` beside a derivable result rejects even
when the list matches the claim (n22 — the override that made the first, fallback-shaped fix
decorative), and an explicit `null` rejects identically in both implementations (n23 — the
input on which a value-sentinel guard forked the two engines; both now guard on key presence,
whose semantics are identical in Python and JS). Reported against this suite — twice, the
second time against the first fix — by
[@Rul1an](https://github.com/tersignhq/evidence-record-conformance/issues/4).

A sixth, added by the same review discipline: **identity comparison runs after
normalization.** EIP-55 mixed case and stray whitespace are the same address; without
normalization, a party relabels itself as its own "outside" witness by appending a space to
its own address (n13) — an alias bypass of the independence criterion, failing open exactly
where the criterion exists to fail closed. An identifier that does not parse *after*
normalization is not evaluable and rejects (n14). The full rule, one sentence per step, is
`identifier_normalization` in `MANIFEST.json`; the alias classes it folds are pinned by vectors,
two-sided where the class admits an accepting input, and the classes it leaves out are named
(v0.5.4, below).

A seventh property applies the same binding arithmetic to a different semantic object:
**a protected record presented as evidence of an authority decision must commit to the exact
decision-evidence object it names.** Without that commitment, the presented reduction is
unbound and rejects (n27). n27 deliberately exercises only this missing-commitment branch;
the distinct-object contrast is load-bearing across p19/n28: a commitment to reduction A
accepts A (p19) and rejects B (n28). This structural criterion does not validate the authority
intersection, authenticate the producer or establish historical position; it only makes a
missing commitment and substitution detectable.

This suite instantiates the relation with its local RFC-8785-compatible canonicalizer and
Keccak-256. The conformance property is the algorithm-parametric relation “matching canonical
object accepts; missing or mismatching commitment rejects”, not a prescription of a digest,
canonicalization, or field location for AUEC, MCP, or another protocol.

## Wrong readings and the vectors that reject them

Each row names a wrong reading and the vectors an engine that reads that way fails, by accepting
them or by rejecting them for another reason.

| wrong reading | vectors | reason |
|---|---|---|
| a party's own attestation read as independent | n7, n30, n32, and every vector in the next row | `independence_reject` |
| identifiers compared as written | n13, n31, n45–n49, n54, n58, n63–n66, n69, n106 | `independence_reject` |
| a settlement claim over a record that names no settlement transaction | n21, n104, n105 | `independence_reject` |
| a number outside the vector domain (I-JSON integers) read as a number | n10, n11, n35, n103 | `number_domain_reject` |
| duplicate member names read as one object | n41, n42, n57, n68, n93 | `canonicalization_reject` |

## Settlement scope and address letter case (v0.5.6)

Six vectors in three two-sided pairs, all `independence_claim`. Neither engine changed: both
already read all six as the vectors expect. Each reject twin pins a reading no earlier vector
decided:

- **A settlement result with no `transaction` member** (n104, twin p54). n21 pins the empty
  string; n104 pins the absent member. An engine that reads only an empty `transaction` as no
  settlement passes every v0.5.5 vector and accepts n104.
- **A settlement claim over a record that carries no settlement result** (n105, twin p55). The
  record binds delivered bytes and nothing else, so a claim covering settlement as well
  overreaches. An engine that reads a record with no settlement result as settled passes every
  v0.5.5 vector and accepts n105.
- **A 0x-address in another letter case** (n106, twin p56). Rule (2) of
  `identifier_normalization` named no vector: the earlier alias vectors compare a 0x-address with
  another syntax (n63–n66, n69), never two bare 0x-addresses that differ only in letter case.
  n106 lists one party in its EIP-55 checksum form and has it attest in lowercase, and has the
  other attest as `0X` followed by upper-case digits. An engine that parses `0X` but compares a
  bare 0x-address as written, or lowercases the digits but not the prefix, passes every v0.5.5
  vector and accepts n106; one that compares as written and parses only `0x` is caught by p56. p56 accepts an outside attestor written the same way, which is what shows that `0X`
  parses: an attestor that does not parse rejects the claim too, so n106 alone cannot tell the
  two readings apart.

p54 and p55 add no killing power over p16/p17 and p23, which accept the same scopes; each differs
from its reject twin in one member, so the pair shows which member decides the verdict. p56 does:
an engine that does not parse `0X` passes every v0.5.5 vector and fails p56.

Additive: every pre-0.5.6 vector is byte-identical, the kinds stay at 11 and the reject-reason
closure at 10. `MANIFEST.json` gains the six entries and two clauses: `commitment_derivation`
names n104/p54 and n105/p55, and rule (2) of `identifier_normalization` names the `0X` prefix and
n106/p56. `tools/compare_run.py` is new (see *Reproduction*).

## Strings, sequence numbers and phases (v0.5.5)

**Three classes reported against `ab7704d` by
[@Rul1an](https://github.com/tersignhq/evidence-record-conformance/issues/1#issuecomment-5908429130)
(#1, 2026-09-30), and a fourth beside the first.** His re-grade at v0.5.4 killed the same 11
mutants as in August; a wider set left three survivors that neither #9 nor v0.5.4 lists, each
checked against `verify.py`. v0.5.5 pins all three, and an unpaired surrogate, on which v0.5.4's
two engines returned different verdicts. Each rule is now written in `MANIFEST.json`, and every
clause v0.5.5 adds there is pinned by a vector or says that no vector pins it.

**Non-ASCII string values.** n12 and p14 put non-ASCII in keys; no vector put it in a value, so an
engine that escaped values to ASCII passed the corpus. Strings, names included, are serialized as
RFC 8785 §3.2.2.2 specifies: U+0000–U+001F, the quotation mark and the backslash are escaped (no
vector pins these escapes), and every other code point is written as is, never normalized (§3.1); the canonical text is hashed as
UTF-8 (§3.2.4). Each accepting payload has a rejecting twin that carries the same payload and the
digest a wrong encoder computes for it:

| accepts | rejects | the twin's digest, and the implementation that produces it |
|---|---|---|
| p39 `{"a":"é"}`, U+00E9 (his input) | n71 | `é` written `\u00e9`: Python's `json.dumps` with its default `ensure_ascii=True` and `separators=(",", ":")` |
| p40 `{"a":"中文"}` | n72 | one byte per UTF-16 code unit, truncated: Node's `Buffer.from(text, "latin1")` |
| p41 `{"a":"𠮷"}`, U+20BB7 | n73 | CESU-8, each surrogate half encoded on its own: a UTF-8 encoder that walks code units |
| p42 `é` as `e` + U+0301 (NFD) | n74 | the text normalized to NFC, which is p39's digest |
| p45, a value of U+2028 and U+2029 (line and paragraph separators) | n85 | both written as `\u` escapes: Go's `encoding/json`, with or without `SetEscapeHTML(false)` (measured, go1.27.1) |
| p46, a member name `e` + U+0301 (NFD) | n86 | the text normalized to NFC: a canonicalizer that normalizes names and not values passes p42 and n74 |
| p51 `{"a":"<b>&"}` | n98 | `<`, `>` and `&` written `\u003c`, `\u003e`, `\u0026`: Go's `json.Marshal` default; an `Encoder` with `SetEscapeHTML(false)` writes them as is (measured, go1.27.1) |
| p52, DEL (U+007F) and the C1 controls U+0080 and U+009F | n102 | all three written as `\u` escapes: Python's `json.dumps` with its default `ensure_ascii=True`, which escapes DEL with the non-ASCII code points, and `separators=(",", ":")`, or any encoder that escapes every control character |

An engine that writes or encodes the text the wrong way rejects the accepting vector; one that
accepts either form, the right one or its own, is caught only by the twin.

**Unpaired surrogates.** RFC 7493 §2.1 forbids a surrogate that is not half of a pair, in a name
or a value, and RFC 8785 §3.2.2.2 requires a canonicalizer to terminate on one. A pair written as
two escapes is one code point and accepts (p44, in a name and in a value; p14 in a digested
name). v0.5.4's engines read an unpaired one differently: Python kept it as is and failed wherever
it had to encode it, and `JSON.stringify` wrote it as a `\u` escape and hashed on. Measured there:
n81 (a lone high surrogate in a value, claimed as is) read `valid` in Python; n82 (a lone low
surrogate in a name, claimed escaped), n83 and n84 (a lone surrogate in the digest domain, in a
value and in a name, each with its escaped digest) read `valid` in TypeScript and
`number_domain_reject` in Python. Both engines now reject all four with `canonicalization_reject`,
and a criterion that digests an object rejects one with its own reason: n94 (an offer, `binding_reject`),
n95 (decision evidence, `binding_reject`) and n96 (a boundary prefix, `boundary_reject`), each
committed to by the digest a `JSON.stringify`-based canonicalizer computes, so an engine that skips
the check there accepts; v0.5.4's TypeScript engine read all three `valid`. In `payload_text` an
unpaired surrogate is part of the text's shape, decided before its number tokens in both engines,
as v0.5.4 decided duplicate names: n92 puts the float token `2.0` before a lone surrogate and
rejects with `canonicalization_reject`, which both v0.5.4 engines read as `number_domain_reject`.
A noncharacter, which RFC 7493 §2.1 also excludes, is still serialized as is in both engines; no
vector pins it.

**Duplicate names compare as UTF-16 code units.** A surrogate pair written with one half raw and
the other escaped is the same name as the pair written as two escapes: `JSON.parse` holds both as
the code units D842 DFB7. Python's `json` joins only an escaped pair into one code point, so the
split form decodes there to two code points, and a comparison of decoded names as code points
sees two names. n93 writes U+20BB7 both ways in one object and rejects with
`canonicalization_reject`; v0.5.4 read it `number_domain_reject` in Python and
`canonicalization_reject` in TypeScript. `verify.py` now compares names by their UTF-16 code units.
Nothing is normalized before the comparison: p53 names U+00E9 and `e` + U+0301 in one object, two
names, and accepts, so an engine that normalizes names before its duplicate check fails it. No
vector pins whether a pair written half raw accepts where it repeats no name: an engine that
rejects the raw code unit wherever it stands still rejects n93, with the same reason.

n81, n83, n84 and n93–n96 carry an unpaired surrogate as a JSON escape in the vector file itself,
the only way a vector can carry one, so a loader has to keep it; `MANIFEST.json` states the
requirement. Go's `encoding/json` (measured, go1.27.1) replaces it with U+FFFD at load, so n81's
claim matches its text's canonical form as Go decodes it and n83 and n84 reject as recompute
mismatches; a decoder that refuses the escape cannot load these seven files.

**The chain-link sequence domain.** `chain_link` in `MANIFEST.json` now states it: `seq` is an
integer token in [1, 2^53−1]. The lower bound is the first number `chain_set` gives a record
(`chain_link` does not relate a null predecessor to `seq`, and no vector pins that relation);
2^53−1 is the I-JSON integer bound. n75 is p4 at seq 0 with
the link recomputed for seq 0 (his input; without the lower bound it verifies), n76 is seq 2^53
with p43 its accepting twin at 2^53−1, and n77 and n97 are p4 with `seq` written `1.0` and `1e0`,
the fraction and the exponent form, so a loader that looks only for a decimal point fails n97.
n103 puts the exponent form in `payload_text` (`1e2`), where the canonicalization line names it
beside the fraction form and no vector carried it before. n87, n88 and n89 are
p4 with `seq` written `"1"`, `true` and `null`, each beside p4's link, so an engine that coerces
the value to 1 accepts; the crypto profile (`crypto/`, PR #11) rejects the first two forms as well (cn10, cn11).
Past the bound the engines had forked: at seq 2^53+1 Python recomputed the exact link and accepted, while `JSON.parse`
read the token as 2^53 and rejected; at 2^64−1 Python accepted while TypeScript, reading 2^64,
raised; from 2^64 both raised and returned no verdict. Both now reject.

**The phase rule, written down.** `MANIFEST.json` had no line for `phase_claim`; it now has one,
and each clause has a vector or says that none pins it: a record that is not an object (n79), a
record with no `economic_phase` (n78, his input), a phase outside the closed vocabulary presented
as itself (n80, which isolates the vocabulary clause that n18 does not, as #9 noted), and a phase
presented as another, in either direction: n6 presents a funding record as delivery, a later phase,
and n90 a delivery record as funding, an earlier one, which #9 listed among its coverage gaps. The
vocabulary's words compare as exact strings, so `Delivery` is outside it, in the record (n91) and
in `presented_as` (n99); no vector pins another near-spelling, such as a word padded with
whitespace. `presented_as` must be present (n100: an engine that defaults it to the record's phase
accepts), and refund and reversal are two phases: n101 presents a refund record as reversal. n6,
n90 and n101 are the only vectors that present one word of the vocabulary as another, so three of
the twenty ordered pairs are pinned; no vector pins the other seventeen, settlement's included, and
`MANIFEST.json` says so. p7 accepts delivery presented as itself, and p47–p50 accept the other four
words, so a vocabulary that leaves one out fails. With the presence check removed, the Python
engine raises on n78; the TypeScript engine rejects it through the vocabulary check, so there n78
pins the verdict and the removal is an equivalent mutant.

Additive: every pre-0.5.5 vector is byte-identical, and the reject-reason closure stays at 10. The
differential battery gained the sequence domain at and past both bounds, the phase rule's
clauses at the shapes the two languages read differently (null against absent, arrays,
non-string phases, letter case), and a fixed string-domain battery: non-ASCII values and names
under UTF-8, every non-ASCII code unit escaped, Latin-1 truncation, CESU-8, NFC and NFD (the
encodings n71–n74, n85 and n86 name; no case carries n98's HTML escapes or n102's escaped DEL,
and no battery payload holds `<`, `>` or `&`), unpaired surrogates in values, names,
arrays and nested objects, through `digest_recompute`, `payload_text` and the binding and boundary
criteria, and duplicate names that differ only in how a surrogate pair is written. Run with
v0.5.4's engines it reports 251 divergences in 7,984 cases; with v0.5.5's, none. v0.5.4's engines
already read p51–p53 and n97–n103 as those vectors expect: the ten pin rules both engines followed
against an engine that reads them differently.

## Identifier aliases and the raw-text pathway (v0.5.4)

**One identifier rule, both engines; the alias classes below are pinned by vectors, and the
ones it leaves out are named.** Parties and attestors are normalized by the same rule before
they are compared. The rule folds toward *same party*, and where it cannot decide which party an
identifier names, the identifier is not evaluable:

1. strip the characters with the Unicode White_Space property (enumerated in the manifest) and
   no others. The property includes some control characters (U+0009–U+000D, U+0085) and no
   format character, so U+FEFF (a format character) or U+001C (a control character without the
   property) at the edge leaves the identifier unparseable, although JavaScript's `trim()`
   removes the first and Python's `strip()` the second;
2. a `0x`-address compares lowercased;
3. otherwise an ASCII scheme-qualified identifier, letters in either case: percent-encoded
   **unreserved** characters are decoded, in one pass that is never repeated (RFC 3986 §6.2.2.2,
   §2.4); any `%` left over, any `?`, or a complete `.` or `..` path segment makes the
   identifier not evaluable; the result is lowercased, the scheme included; every trailing `/`
   `.` `#` is removed; a `#` still present (a fragment with content) makes it not evaluable;
   and what remains must still parse, with a non-empty path;
4. two identifiers are one party when they are equal after this, or when both name the same
   `0x`-address: an identifier whose final colon-separated component is a `0x`-address names
   that address whatever the scheme (a CAIP-10 account such as `eip155:8453:0x…`, a
   `did:pkh:eip155:1:0x…`, a `did:ethr:0x…`, an `ethereum:0x…`, an `acct:0x…`), on either side
   of the comparison and whatever the chain reference.

An identifier that is not evaluable fails the claim closed. Each class has a rejecting vector.
Where the class admits an accepting input, an accepting twin carries the form on a party outside
the transaction, so an engine that defends the class by refusing the form fails as hard as one
that misses it. A class whose forms are never evaluable has no accepting twin; where an
evaluable form sits next to the class, a *near-miss* accepting vector carries that form instead,
and otherwise the cell is —:

| class | accepts (twin, or near-miss) | rejects |
|---|---|---|
| whitespace (Unicode White_Space only) | p33 | n13, n52 (U+FEFF), n53 (U+001C) |
| letter case | p31 | n45 (path), n58 (scheme alone) |
| trailing `/` `.` `#` | p31 (each of the three) | n31, n46, n47 |
| percent-encoded unreserved | p32, p34 (`_` `~` digit, letter) | n48, n49 (party side; decoded before the trailing strip), n54 (`_` `~` digit) |
| other percent-encoding; decoding more than once | — | n50, n55 (`%25`), n56 (a triplet assembled by decoding) |
| dot-segments | near-miss: p36 (dots within segments) | n59, n60 (`%2E%2E`, trailing), n67 (`./` at the path's start), n70 (`../` at the path's start) |
| query component | — | n61 |
| fragment with content | near-miss: p31 (a trailing `#` alone) | n62 |
| empty after normalization | — | n51 |
| a `0x`-address in another namespace | p37 (CAIP-10, did:pkh), p38 (did:ethr, `ethereum:`, `acct:`) | n63 (party bare), n64 (party in CAIP-10), n65 (attestor in did:ethr), n66 (party in `ethereum:`), n69 (attestor in `acct:`, any scheme) |

**Not folded, and not pinned.** The rule folds syntax a verifier can decide without owning a
scheme. It does not apply scheme-specific equivalences (RFC 3986 §6.2.3; a default port in a
URL, for example), and it does not resolve names to addresses (an ENS name, a `did:web`). Two
such identifiers compare as distinct, so a party written in one of those forms counts as outside
the transaction. No vector pins those classes.

n31's description predates this version and its file stays byte-identical; its last sentence,
on percent-encoding, is superseded by n48–n50. What a verifier that ran v0.5.3 may see move:
percent-encoded identifiers (decoded, or not evaluable), upper-case schemes (now folded), an
identifier with an empty path, a `?`, a fragment with content or a dot-segment (now not
evaluable), a party's `0x`-address written in another namespace (now the same party), and
padding with U+001C–U+001F, U+0085 or U+FEFF.

**The raw-text pathway carries the loader's rules.** `payload_text` is the one place JSON text is
parsed after load. Both engines now reject, with `canonicalization_reject`, a `payload_text`
with a duplicate name inside one object (n41, reported in
[#10](https://github.com/tersignhq/evidence-record-conformance/issues/10); n42 is the same name
written as an escape), a non-JSON constant such as `NaN` (n43), text that does not parse, and a
value that is not a string (n44). A name repeated across distinct objects is not a duplicate
(p30). The scan tracks nesting: a name after an array value is compared with its object's other
names (n57), a string value is not a name (p35), and every object has its own names at any
depth, an object inside an array included (n68). The text's shape is decided before its number tokens, in both engines, so a duplicate
beside an integer too long to parse reads the same everywhere.

Additive: every pre-0.5.4 vector is byte-identical, and the reject-reason closure stays at 10.
The differential battery gained the raw-text cases, a fixed list of alias forms for each class
above on a party and on an attestor (a form not on the list is not compared), and whitespace
padding at identifiers, digests and settlement fields. Measured on
v0.5.3's engines: n41, n42, n48–n51, n54–n57 and n59–n70 read `valid` in both; n43, n44, p33,
n52 and n53 split the two engines; p31 rejects in both. p30, p32, p34–p38, n45–n47 and n58
already passed there (n58 because v0.5.3 could not parse an upper-case scheme at all), and pin
the same rule against an engine that reads it differently.

## Per-vector provenance (v0.5.3)

Every `MANIFEST.json` entry names its `author` and its `origin`. `author` is the GitHub account
that authored the commit adding the vector; check any entry with
`git log --diff-filter=A -- vectors/<file>`. `origin.class` says where the vector's material came
from, from a closed set, and `origin.source` names the PR, commit, fixture, published reproduction
or live record.

| `origin.class` | vectors | material |
|---|---|---|
| `synthetic` | 130 | inputs constructed in `tools/gen_vectors.py` |
| `live-ledger` | 3 (p1, p5, p27) | a record from the live ledger, unaltered, with a `provenance` block in the vector |
| `live-ledger-derived` | 10 (p4, n1, n3, n5, n75, n77, n87, n88, n89, n97) | a value from those records, reused or altered |
| `contributed` | 19 | an outside contributor's PR, commit, fixture or published reproduction |

Of the 162 vectors, nine were authored by four outside contributors (@Rul1an p11/n9,
@mohammedmessaoudene-cmd p19/n27/n28, @navigatorbuilds p20/n29, @0rkz p22/n32). Ten more, also
`contributed`, were written here on outside material, and their origin names its author: p23/n33 on
@0rkz's PayPerByte fixture, n95 on p19's decision-evidence object from PR #5, n22/n23/n24 from
@Rul1an's published reproductions in issue #4, n41 from @Rul1an's input in issue #10, p39 and n78
from his inputs in issue #1, and n48 from @stillmarcus24's probe in issue #8. n75, his third input
in issue #1, carries p4's live-ledger digest, so it is classed `live-ledger-derived` and its source
names him. Among vectors written here, the class follows the value that distinguishes the vector:
where the suite constructed it, the vector is `synthetic`, beside a contributed vector or not: n42
(n41's input with its second name escaped), n71 (p39's payload under an escaping encoder's digest)
and n74 (whose NFC digest equals p39's). A vector that carries a contributed fixture with a value
of its own is `contributed` whoever altered it (n33, n95). Thirteen vectors carry the live ledger's
signer address as sample data, and their `origin.source` says so. Both engines read it only as an
attestor outside the parties, so any other well-formed address outside a vector's parties gives the
same verdicts.

Generation fails if a vector has no entry, if its class disagrees with the live-ledger values or
`provenance` block in its own bytes, or if it carries a contributed fixture it recognizes in the
bytes (@0rkz's delivery digest, PR #5's decision-evidence objects, PR #6's suite-transition rule
version) without crediting its contributor. It
also fails if the table above disagrees with the manifest, in a row's count, in the vectors a row
lists, or in the total that follows the table. The class of every other `contributed` entry is declared rather than derived from the bytes; each
names the PR, commit or issue comment it rests on, which is where to check it. Authorship is not
decidable from the bytes either; the git command above checks it.
Credit for *reporting* a failure class a vector pins is not material and stays in
[CONTRIBUTORS.md](CONTRIBUTORS.md).

Metadata only: every vector file is byte-identical to v0.5.2, and neither engine reads the new
fields, so verdicts, kinds and the reject-reason closure are unchanged.

## Duplicate sequence numbers (v0.5.2)

A sequence attested only by its issuer evidences ordering. It does not evidence that no other
record carries the same `seq` and `correctionSeq`: an issuer holding two records under one
number can present each to a different relying party, and each presentation is complete on its
own terms. `chain_set` has always rejected a second record at an occupied seq, but no vector
reached that branch — a verifier that deduplicated records by seq before the completeness check
passed all 65 pre-0.5.2 vectors (measured 2026-09-28, in both engines). n39 pins it: two
different records carrying the same `seq` and `correctionSeq`, presented together beside the
issuer's own attestation, reject on the duplicate; p28 is the same records at distinct numbers.

What one presentation cannot show is the record it does not contain. n40 is the issuer's other
record presented alone at position 2 of p29's prefix, prevs and links recomputed: it passes the
structural `chain_set` predicate under p29's head digest (asserted in `tools/gen_vectors.py` on
every regeneration), and only the accumulator over every link rejects it. Arithmetically n40 is
n36's substitution at an interior position, and the mutants it kills are ones n36 and n37
already kill; what it adds is the class — a second record under an existing number, not a
forgery.

Additive: every pre-0.5.2 vector is byte-identical. The differential battery gained a
duplicated-record mutation for both chain kinds; against a TypeScript engine that deduplicates
by seq it goes red where the previous battery stayed green.

## Number-token class on integer fields (v0.5.1)

`JSON.parse` collapses the wire token `3.0` to the integer `3`; Python's `json` keeps a float, and
every integer predicate in `verify.py` rejects it. Until v0.5.1 the two engines therefore diverged on
the same bytes for a fractional or exponent `seq` token — a real parity fork, found by an adversarial
review of v0.5.0. The suite's number-domain boundary has always been the TOKEN class (p25/n35 pin it
for canonical bytes); n38 pins the same boundary for sequence numbers, and the TypeScript engine now
loads every vector and differential case through a reviver that reads integer fields at the token
level (Node ≥ 21 source access), so both engines reject `3.0` / `3e0` wherever an integer is
required. Additive: every pre-0.5.1 vector is byte-identical; the differential battery gained
float-token mutations on `head.seq` and `records[].seq` for both chain kinds.

## Commitment accumulator (v0.5.0)

A committed head binds the **last** record only. Two prefixes that end in the same record —
the real one, and one whose earlier rows were substituted with prevs and links recomputed —
both pass the `chain_set` predicate and both sit under the same anchored head digest; the
head cannot tell them apart, and an anchor over the head therefore commits to the final
record, not to the prefix beneath it. The `chain_commitment` kind pins the construction that
closes this: an accumulator folded over **every** recomputed link,

```
acc_0 = keccak256(utf8("tersign-chain-commitment-v1"))
acc_n = keccak256(acc_{n-1} || link_n)        link_n = keccak256(artifact_n || prev_n || seq_be8)
```

with `prev_n` the previous record's artifact digest (32 zero bytes at `seq` 1). `head.acc`
must equal `acc_{head.seq}`; any omission, insertion, reordering or rewrite below the head
changes it. The seed is a tagged digest, never the 32-zero-byte link-genesis sentinel — link
preimages are 72 raw bytes, accumulator preimages 64, every canonical-object digest is UTF-8
text starting `{`, so the three domains cannot collide by construction. Production anchors
`keccak256(utf8(canonical({acc, head, schema: "tersign-chain-commitment-v1", seq})))` rather
than the head digest, so one anchored value commits the whole prefix (p27 is that live chain;
its anchor row carries the subject object). n36 is the substituted prefix presented with the
real chain's accumulator; n37 is an accumulator folded over the last link only — the exact
value an anchor over the head commits to, and the shape this kind exists to reject.

The kind is **additive**: every pre-0.5.0 vector is byte-identical, `chain_set`'s semantics
are unchanged (`chain_commitment` runs it first and propagates any non-valid verdict as-is),
and the external reproductions at `46ad663` (Songbo Bu) and `0e560c1` (@Rul1an) stand as
published. Verification is O(N) in the number of records — one link and one accumulator step
per record, hashing only — which is the cost of a completeness check that does not delegate
to anyone's word; the anchor over the commitment is what turns the fold into an existence
bound (`anchor_relation` over the commitment digest).

## Scope boundary — structural profile vs crypto profile

This stdlib core decides the **structural predicate**: digests, canonical bytes, sequence
closure, link arithmetic, declared-claim evaluation. It does **not** recover
counter-signatures. A structurally complete set whose head and links were all recomputed
wholesale by a single forging party passes the structural predicate — what prevents that in
production is that every chain link is counter-signed at transaction time by a party outside
the transaction, and the chain's commitment is anchored (p5, p27). Signature recovery over the links (secp256k1
`personal_sign`; signer published at `https://tersign.ai/v1/ledger`) is the **crypto
profile** (`crypto/`, PR #11), deliberately outside the stdlib core so that every check above
needs hashing only.

## Live provenance — three vectors are records from the live ledger

Ten more (p4, n1, n3, n5, n75, n77, n87, n88, n89, n97) reuse or alter a value from these records; their manifest
`origin.class` is `live-ledger-derived`.

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
curl https://tersign.ai/v1/anchors/ledger:0xb2c5d2bd28ff65e13c1549a718a4c447916d5277ce046b2061ed63749ff287d9
                                          # the anchor record BY ID; fetch proof.ots from its proofUrl
ots verify -d cf48bed1712f5b7df2a309fb52cb2b3d51ab1a04730e3b115cd3db79c96c9b1a proof.ots
```

(Fetch it by id: the unqualified `/v1/anchors` listing returns the newest rows and will
eventually not include this one.) `ots verify` needs a local Bitcoin node to confirm the block
header. Without one, the no-node path is stronger anyway — it shows the trust chain
explicitly: `ots info proof.ots` prints the Bitcoin attestation (height 958163, merkle root
`d23b2da439b5…f85df18c`); compare that root against block 958163 in any block explorer.

**p27** is the ledger's genesis chain — 13 counter-signed records, seq 1 being the genesis
receipt p1 — with the accumulator over all 13 links, and the commitment over it is anchored
in Bitcoin block 964428. Re-walk and re-fold it yourself, then check the anchor:

```
curl https://tersign.ai/v1/receipts/0x339800528596c7d53d32571ad999695aef6dfc8fc86dcc4fb827bb6080493961/verify
                                          # the head; follow prevDigest 12 more times to seq 1 (prevDigest null)
python3 verify.py                         # folds the accumulator over the 13 committed records
curl https://tersign.ai/v1/anchors/seller:0xcbbef04598368ed02ae67fc0c8ffade6753628d0b8faf4e9211c9dd49a2dbe7b
                                          # subjectArtifact = {acc, head, schema, seq}; merklePath to batchRoot; proofUrl
```

The anchor's `subjectDigest` is `keccak256(utf8(canonical(subjectArtifact)))` and its
`anchoredDigest` is `sha256` of those bytes (the same `anchor_relation` p5 pins); the vector's
`provenance` block carries both values.

Counter-signatures in the live vectors are secp256k1 `personal_sign` material; recovering them
requires an EVM crypto library and sits outside the stdlib core by design — every check above
needs hashing only.

**Pin the signer, do not fetch it.** The ledger signer at genesis is
`0x9d38BA84730271eb27Ac9bD4Bd2620c08dB4FDa6`, committed in this repository since
`p1-live-genesis-receipt.json` (field `ledger_signer`) and reproduced byte-identically by
`tools/gen_vectors.py` on every CI run. `https://tersign.ai/v1/ledger` serves the same value,
but a key fetched at verification time only proves what the server says *now* — "verify
offline" has to mean against a key committed at a fixed point in time, which is what the
vector gives you. The genesis receipt digest is likewise fixed
(`0xe5874f1ffe87f0a6dd9eb157730f67b86ee4538b125fe30fcc4e165213dd3fc4`) and its chain head is
Bitcoin-anchored, so the pinned pair is recoverable from an anchored record rather than from
an endpoint. Any future signer rotation must be published as a new pinned vector, never as a
silent change at that URL.

## Canonicalization contract

RFC 8785 (JCS) over the I-JSON vector domain: integer numerics within `|n| ≤ 2^53−1`
(enforced two-sidedly — p12 accepts the boundary value, n11 rejects one past it), **no
non-integer JSON numbers** (n10 — RFC 8785 §3.2.2.3 routes numbers through ECMAScript
`Number::toString` over IEEE 754 doubles, so a fractional value's bytes depend on the
producer's number pipeline, and the digest binds the nearest double rather than the decimal
the source system held; fractional values are decimal **strings**, pinned in lockstep with
the compliance-fields extension's number rule by p13), duplicate object names rejected at
load and inside `payload_text`, names compared as UTF-16 code units (p30, p53/n41/n42/n93). Keys sort by **UTF-16 code units** (the verifier encodes to UTF-16BE and compares
bytes — explicit, not delegated to the host language's default; p14/n12 pin the
supplementary-plane case where code-unit and code-point order genuinely diverge). Strings, names
included, are written as RFC 8785 §3.2.2.2 specifies, U+0000–U+001F, the quotation mark and the
backslash escaped (no vector pins these escapes) and every other code point as is, never normalized, and the canonical text is
hashed as UTF-8 (p39–p42, p45, p46, p51, p52/n71–n74, n85, n86, n98, n102); a name or value holding an unpaired
surrogate has no canonical form (p44/n81–n84, n92, n94–n96). Content
addresses are keccak256 (pre-NIST padding, as used by Ethereum) — `hashlib.sha3_256` is a
different function; a compact Keccak implementation is vendored in `keccak.py`, self-checked
at import against measured known-answer values.

## Reproduction

Independent reproduction means a run by an implementation that shares no code and no authors with this suite's engines. At `0eda303`, two such implementations have each run the full set and published the output: a Node verifier ([#8](https://github.com/tersignhq/evidence-record-conformance/issues/8)) and a clean-room Python verifier ([#9](https://github.com/tersignhq/evidence-record-conformance/issues/9)). Both match all 69 verdicts and every named reject reason. That reproduces the 69 vectors; a reading no vector pins is not reproduced by it. v0.5.4 adds 39 vectors and changes how identifiers normalize, and v0.5.5 adds 48 more and changes how unpaired surrogates, duplicate names that differ only in how a surrogate pair is written, and out-of-range `chain_link` sequence numbers read; both runs predate them. Agreement makes no verifier a reference, ours included. Earlier outside runs re-ran *our* verifier (byte-identical at `46ad663`; mutation-tested at `0e560c1`), and an outside verifier ran `p18`, `n25` and `n26` (CONTRIBUTORS.md, @Tetsurohhori).

v0.5.6 adds six vectors; at this release no outside implementation has run them. To report a run,
publish each vector's verdict and, for a reject, its reason, as a JSON array with one object per
vector in `MANIFEST.json`:

```
[
  {"file": "n1-value-drift.json", "verdict": "reject", "reason": "recompute_mismatch"},
  {"file": "p2-canonical-key-order.json", "verdict": "valid"}
]
```

`file` is the vector's file name as `MANIFEST.json` lists it, `verdict` is `valid` or `reject`, a
reject carries `reason`, and a valid carries none (`null` counts as none). An entry with any other
key, two entries for one file, and text that is not such an array are refused.
`python3 tools/compare_run.py <output.json>` compares that output with `MANIFEST.json`, verdict
and reason as exact strings, lists each disagreement, and ends with the line

```
agrees on N/M verdicts and reasons at v<version> (MANIFEST.json sha256 <digest>)
```

where M is the number of vectors in the manifest. A vector the output leaves out counts as a
disagreement, and an entry for a file the manifest does not list is named on its own line, counted on
that line, and fails the comparison. It exits 0 only
when every vector agrees, 1 on any disagreement, and 2 on output it refuses, an empty one
included. It compares outputs and nothing else: whether a runner is independent is for readers
to judge from its repository.

Cross-implementation measurement: `tools/cross_check_ts.mjs` is a second implementation of
**every check** on a TypeScript stack, written by the same authors as `verify.py`. Agreement
between the two is therefore not independent reproduction (see *Reproduction* above); it is
run over the **full committed corpus**
(`npm i viem` in the repo root, then `node tools/cross_check_ts.mjs`) — two implementations,
one vector set, byte-level agreement required on every verdict and reason. CI runs both on
every push.

That corpus runner scores each engine against `MANIFEST.json`, so engine-to-engine agreement
there is *transitive through the shared expectations* — both implementations can hold the same
wrong assumption and stay green, and an input the corpus does not carry is never compared at
all. `tools/differential.py` is the non-transitive control: every vector **plus** an
off-corpus mutation battery at fork-prone keys (explicit nulls, declared/derivable conflicts,
containers of the wrong shape), run through **both engines directly**, verdict and reason
compared with no manifest in between. Replayed against the pre-fix engines it reports exactly
the null-guard fork it was built after; on current code it must report zero divergences. CI
runs it beside the corpus pass. The limit it closes was identified by
[@Rul1an](https://github.com/tersignhq/evidence-record-conformance/issues/4): parity through a
shared oracle confirms a shared assumption instead of catching it.

Regeneration is deterministic and diffable: `python3 tools/gen_vectors.py` rewrites
`vectors/` + `MANIFEST.json` byte-identically (CI asserts this on every push).

## Contributors

Who sharpened which criterion, and how each contribution landed, is recorded in
[CONTRIBUTORS.md](CONTRIBUTORS.md) — credited by commit authorship rather than by a merge
badge, since some contributions were cherry-picked onto a hardened `main` and their PRs
therefore read as closed.

## License

Apache-2.0. Maintained by [Tersign](https://tersign.ai). Cross-runs, counter-vectors, and
adversarial additions welcome.
