# Contributors

This suite exists to be checked by people who did not write it, so who sharpened which
criterion is part of the record rather than a courtesy. Everything below is verifiable from
this repository: `git log` for authorship, the linked issue or PR for the argument, and
`python3 verify.py` for the vector that resulted.

A note on how contributions land here, because the git history is easy to misread.
Contributions are credited by **commit authorship**, not by a pull request's merge badge — and
not every contribution arrives as a pull request at all; several of the criteria below came
from issues.

One case needs saying explicitly. [PR #2](https://github.com/tersignhq/evidence-record-conformance/pull/2)
shows as **closed rather than merged**, and it was neither rejected nor abandoned: a hardening
pass landed on `main` between the PR opening and closing, touching three of the same files, so
the branch could not be fast-forwarded. The commit was applied with `git cherry-pick -x` — its
author preserved, and the provenance line
`(cherry picked from commit 0dee263…)` still visible in
[`d672d5c`](https://github.com/tersignhq/evidence-record-conformance/commit/d672d5c) — and the
PR closed with that explanation. That work is in `main` under its author's name.

Since then, every merged pull request has landed through GitHub and shows as merged with its
link: #5, #6 and #7 by merge commit, #11 and #15 by squash.

---

## [@Rul1an](https://github.com/Rul1an) — Roel Schuurkes

**The fail-closed rule.** Reported in
[#1](https://github.com/tersignhq/evidence-record-conformance/issues/1) that the independence
criterion failed **open**: an exact-equality trigger (`if claimed != "independent"`) read any
unfamiliar claim string — including a *stronger* one — as no claim at all, switching the check
off precisely where more had been asserted. That became the suite's third design rule, "a
criterion's trigger must fail closed," and the requirement that the verifier return a verdict
for *every* shape rather than raising and producing none.

**Vectors `p11` / `n9`** — commit
[`d672d5c`](https://github.com/tersignhq/evidence-record-conformance/commit/d672d5c), authored
by him, from PR [#2](https://github.com/tersignhq/evidence-record-conformance/pull/2). Made the
claim-*set* branch two-sided: a set carrying only silence accepts, a set carrying a member the
verifier cannot interpret rejects. (This is the cherry-picked case described above — the PR
reads "closed", the work is in `main`.)

**The survivor behind the integer-valued-float token pair** — vectors `p25` / `n35`, from his
published mutation-adequacy measurement of this corpus
([#1](https://github.com/tersignhq/evidence-record-conformance/issues/1), 2026-08-23). His
run showed the corpus's only fractional number token (n10, value 1.1) lets an engine weakened
to accept integer-valued floats survive the whole suite — verified against current `main`,
not just his pin. The vectors themselves were written here, and the division of credit is his
own: *"The token-class boundary and the `JSON.parse` erasure beneath it are your findings, not
ours. We surfaced a survivor; you identified what it was hiding."* Underneath the corpus gap sat
a live cross-engine divergence this suite's own differential harness had never exercised: Python
preserves `2.0` as a float and rejected; `JSON.parse` collapses the same wire bytes to `2` and
the TS engine accepted. The pair
carries its payload as raw text (`payload_text`) so the distinction reaches both engines,
and pins the digest-domain boundary at the number-TOKEN class. He also withdrew his own
earlier `boundary_binding` survivor finding after re-deriving it — the guard subsumes it —
which is the review posture this suite exists to reward.

**Commitments must be derived, not declared** — vectors `p17` / `n21`, from his review on
[#4](https://github.com/tersignhq/evidence-record-conformance/issues/4#issuecomment-5163808204) (2026-08-03). He observed that the
commitment-scope rule is only load-bearing once a record's commitments are *derived from the
record*: a declared list lets a record assert the very scope the rule exists to bound. The
concrete case he identified is that x402 v2 §5.3.2 defines the empty string as what
`transaction` carries when settlement failed, so `success: true` with `transaction: ""` is well
formed and commits to no settlement anyone can resolve — now rejected without resolving
anything on-chain.

In the same review he made the sharper form of an argument this suite rests on: *position was
doing the work of faculty*. A party that merely occupies a different position — a distinct
address, a declared label — is not thereby independent, and a declared field grounds nothing.
That distinction is why the proposed `settledBy` producer field was **not** adopted: a
criterion satisfiable by declaration reproduces the defect it was meant to catch.

**The derivation has to replace the declaration, not sit behind it** — vectors `n22` / `n23`,
from his second report on
[#4](https://github.com/tersignhq/evidence-record-conformance/issues/4#issuecomment-5225737040) (2026-08-08, against
`2b13f48`). He showed that the derivation shipped for p17/n21 was a fallback: the declared
`record_commits` was read first, so n21's input with `record_commits: ["settlement"]` added
scored valid. In the same report he built an input with an explicit `record_commits: null` and
ran it through both engines: Python read the null as absence and accepted, the TS cross-check
read it as a declaration and rejected, and the cross-check stayed green because no vector
carried a null. `n22` and `n23` are those two inputs, written here from his reproductions, and
the manifest classes them `contributed`. Both engines now reject on the declared field's
presence. He also worked out that deleting the declared read would turn `p16` red and leave
`n20` rejecting for the wrong reason; `p16` / `n20` were rebuilt on a settlement result, the
first of the two repairs he laid out.

**The presence rule's second half** — vector `n24`, from his third report on
[#4](https://github.com/tersignhq/evidence-record-conformance/issues/4#issuecomment-5228448679) (2026-08-08). `n22` and
`n23` both assert a scope, so an engine that checks the declared field's presence only inside
its scope branch passed the whole corpus. He stood such an engine up in a throwaway copy,
published the result table, and specified the missing vector: n22's input with `covers`
removed, expected reject. `n24` is that input, with the settlement result also dropped, written
here and classed `contributed`.

**Two-sidedness per kind** —
[#1](https://github.com/tersignhq/evidence-record-conformance/issues/1#issuecomment-5265724838) (2026-08-12). He showed that
the suite's second design rule, that every criterion is two-sided, was gated run-wide rather than
per kind, so a criterion whose accepting vectors all vanished still passed. He traced the lost
accepting path for URN identities to `d50545a`, the aliasing fix, four days after a published
control, and proposed the gate: for every identifier syntax `identifier_normalization` says it
evaluates, one accepting vector of each kind. That gate landed in `2f80fb2` with `p21` / `n30` /
`n31`.

**Duplicate names reach past load** — vector `n41`, from
[#10](https://github.com/tersignhq/evidence-record-conformance/issues/10) (2026-09-29). He showed
that the manifest's duplicate-name rule held at load only: `payload_text`, the one place JSON text
is parsed after load, went through a plain `json.loads`, and `{"a":1,"a":2}` read valid against
`{"a":2}`. He checked the Python engine; the TypeScript engine read the same. `n41` is his input,
written here and classed `contributed`; `p30` and `n42`–`n44`, siblings on the same pathway, were
written here (v0.5.4).

**Strings, sequence numbers and the phase rule** — vectors `p39`, `n75` and `n78`, from his
wider mutation run at `ab7704d`
([#1](https://github.com/tersignhq/evidence-record-conformance/issues/1#issuecomment-5908429130),
2026-09-30). He re-ran August's 11 mutants and 2 controls against v0.5.4, all killed, then a wider
set, and reported three survivors that neither #9 nor v0.5.4 lists, each checked against
`verify.py`: no vector put non-ASCII in a string value, so an engine that escaped values to ASCII
passed; no vector reached `chain_link`'s seq-below-1 branch, and the manifest did not state the
domain (p4 with only `seq` set to 0 rejects either way, so the vector needs the link recomputed for
seq 0); and no vector reached `phase_claim`'s missing-`economic_phase` branch, which in the
TypeScript engine the vocabulary check covers. `p39` and `n78` are his inputs, classed
`contributed`; `n75` is his input on p4's genesis digest, classed `live-ledger-derived` with his
name in its source; their twins and the other vectors of v0.5.5 were written here.

## [@mohammedmessaoudene-cmd](https://github.com/mohammedmessaoudene-cmd) — Mohammed Messaoudene

**Authority-decision evidence binding** — vectors `p19` / `n27` / `n28`, merged from
[PR #5](https://github.com/tersignhq/evidence-record-conformance/pull/5). Reported
`CG-DELTA-LOSS-01` from an AUEC-controlled experiment in the
[SEP-3004 discussion](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/3004#issuecomment-5228991875):
two allowed decisions can have different host limits, policy versions and
requested-to-effective reductions while producing the same protected record. In the corpus,
n27 exercises the missing-commitment branch with one presented reduction; p19/n28 execute the
distinct-object A/B contrast. The criterion is structural only and does not assert producer
truth, independent validation, MCP adoption, or a normative digest, canonicalization, or field
location. v0.5.5's `n95` is built on p19's decision-evidence object, with a lone surrogate appended
to `policy.id`; it was written here and is classed `contributed`.

OpenAI ChatGPT and Codex assisted with implementation, testing, analysis and drafting;
Mohammed Messaoudene reviewed the executed evidence and remains responsible for the
contribution.

## [@navigatorbuilds](https://github.com/navigatorbuilds) — Elara (AI agent)

**Suite-transition pair** — vectors `p20` / `n29`, merged from
[PR #6](https://github.com/tersignhq/evidence-record-conformance/pull/6). Requested by
**Songbo Bu** on the IETF `web-bot-auth` list (2026-08-09), delivered there inline the same day,
and independently reproduced by Songbo against `46ad663` on 2026-08-10 before arriving here —
the first vector class whose provenance runs through a venue outside GitHub entirely. Pins the
digest-suite transition contract: records written under a predecessor suite stay bound by
their original digest (p20); a transition event carrying the successor-suite digest of the
identical bytes rejects (n29). n29 is discriminating by construction — an engine that
"helpfully" re-hashes history under the new suite *agrees* with the forged digest and accepts,
which is exactly the engine the pair exists to separate.

Submitted under its receipted on-chain mandate, per the same disclosure convention used on
the list.

**The boundary-binding rule, stated normatively** — in the SEP-3004 thread
([issuecomment-5227496013](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/3004#issuecomment-5227496013),
2026-08-08), after building the fork on its own machine: a boundary event binds the digest of the
prefix it extends *and* its own position in that prefix's continuation. That is the rule `p18`
accepts and `n25` rejects.

## [@0rkz](https://github.com/0rkz)

**Delivery-commitment pair** — vectors `p22` / `n32`, merged from
[PR #7](https://github.com/tersignhq/evidence-record-conformance/pull/7). He found the hole by
enumeration rather than by argument: across every accepting `independence_claim` vector, none
carried `delivery` in `covers` or in its derived commitments — because `derive_settlement_commits`
cannot emit `delivery` at all, so the commitment-scope rule treated it as a candidate scope no
record could commit to. The pair closes it with a live PayPerByte fixture: `p22` accepts a record
whose deliverable digest recomputes byte-exact from the record's own bytes while claiming nothing
about who delivered it; `n32` rejects the same record claiming independence over that commitment,
and rejects **on the independence question** — the deliverer signed, and a distinct address is not
thereby an outside one — rather than on the vocabulary gap, so the verdict survives the derivation
change it anticipates without re-pinning. That derivation landed in v0.4.0 (`derive_delivery_commits`,
both engines), driven by `p23` / `n33` — built on his fixture, with the counter-signing ledger as
the non-party attestor — and p22/n32 did not move, which was the test. His field names
(`deliverable_bytes` / `deliverable_digest` / `deliverable_signer`) were kept as contributed: they
already followed the suite's harness-key convention, now written down in the manifest
(`field_naming`) so the next contributor does not have to infer it.

**Bilateral anchor cross-check** —
[#3](https://github.com/tersignhq/evidence-record-conformance/issues/3). Independently
recomputed the anchor-preimage relation from a separate implementation, and had his own v2-sig
commitments recomputed byte-for-byte from fresh stdlib code on this side. Two implementations
reaching the same bytes from opposite directions is the only evidence of interoperability worth
the name; assertion is not.

**The number rule.** His review of the upstream compliance-fields extension caught that a
decimal amount emitted as a JSON *number* is re-interpreted as the nearest IEEE 754 double
before canonicalization runs — so the digest binds a value the issuing system never held, even
when two implementations agree on the bytes. That became the extension's normative Numbers
section and vectors `p13` (decimal string beside integer) and `n10`/`n11` (float and
out-of-range integer) here.

## [@Tetsurohhori](https://github.com/Tetsurohhori) — Tetsuroh Hori

**Fabricated boundary and downgrade-to-unattested** — vectors `n25` / `n26`, accepting twin
`p18`, from the
[SEP-3004](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/3004) thread. The
fork `n25` pins, two continuations of one prefix that both name it truthfully and both verify,
was demonstrated against the verifier of his live anchor stream, and he reproduced it himself,
the fourth independent reproduction
([issuecomment-5229108806](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/3004#issuecomment-5229108806),
2026-08-09). In the same comment he made the position binding retrospective, then attacked his
own fix and found the downgrade `n26` pins: with the attestation stripped, his tool fell back to
the weaker path and printed `VERIFY OK` beside `attested_prefix_lines=0`. He made unattested a
third outcome with its own exit code. The vectors were written here. He then ran `p18` / `n25` /
`n26` at `46ad663` against his own verifier through an adapter he wrote, with expected and
observed agreeing on all three, and declined to score himself on the vectors his verifier has no
path to
([issuecomment-5234222504](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/3004#issuecomment-5234222504)).

**Regeneration outside CI** — [#14](https://github.com/tersignhq/evidence-record-conformance/issues/14)
(2026-10-03 to 2026-10-06). At `521c180` he regenerated the structural set (156 vectors and
`MANIFEST.json`) and the crypto set (46 vectors and its manifest) from empty directories with no
network: byte-identical across a changed hash seed and Python 3.11 and 3.12 (structural), on glibc
and musl and on s390x under emulation (both sets), with a syscall record for one x86_64 glibc
run of each set. He re-ran both sets at `73865e2` on Python 3.10 as a control on CI. Regeneration shows that the
generators are deterministic, not that the vectors are correct.

## [@stillmarcus24](https://github.com/stillmarcus24)

**The percent-encoded alias** — vector `n48`, from his full-set run in
[#8](https://github.com/tersignhq/evidence-record-conformance/issues/8) (2026-09-29, against
`0eda303`). He made percent-decoding switchable, ran the corpus under both readings, and
published the probe that separates them: party `org:caldera-robotics`, attestor
`org:caldera%2Drobotics`, valid under one reading and rejected under the other, with no vector to
decide between them. `n48` is his attestor on n31's parties, written here and classed
`contributed`; the other identifier vectors of v0.5.4 were written here.

## @robertolocatelli81-dev (Noûs)

**Unpinned classes, listed** — from the clean-room run in
[#9](https://github.com/tersignhq/evidence-record-conformance/issues/9) (2026-09-29, against
`0eda303`). Its per-vector reading listed the case fold of scheme identifiers, percent-encoding
and duplicate object names among the classes no vector pinned. v0.5.4 adds vectors for all
three: scheme case (`n58`, with `p31` on the accepting side), percent-encoding (`n48`–`n50`,
`n54`–`n56`, `p32`, `p34`) and duplicate names (`n41`, `n42`, `n57`, `n68`, `p30`, `p35`); the vectors
were written here.
The same reading noted that `n18` does not isolate the phase vocabulary rule, because its
`presented_as` differs from its phase and equality alone rejects it. v0.5.5's `n80` presents an
unrecognized phase as itself, which only the vocabulary rule rejects; it was written here. Its
coverage gaps also listed an *earlier* phase presented: v0.5.5's `n90` presents a delivery record
as funding, the reverse of `n6`; it was written here.

## Reported upstream

**Offer substitution** — `p15` / `n19` pin the class @johnakeke reported against the x402
offer-and-receipt extension in
[x402-foundation/x402#3006](https://github.com/x402-foundation/x402/issues/3006) (2026-07-31):
a privacy-minimal receipt does not bind the payment terms of the accepted offer, so a second
offer sharing the resource, network and payer cannot be told apart from the one paid.

---

## How to contribute

Counter-vectors and adversarial additions are the most useful thing you can send. A vector that
makes this suite go red is worth more to us than one that makes it green — the whole point is
that the criteria discriminate rather than merely accept.

Two conventions, both enforced by the run itself: every criterion carries **both** an accepting
and a rejecting twin, so an implementation that unconditionally rejects a class fails just as
one that unconditionally accepts it does; and the reject-reason closure is pinned in the
verifier rather than derived from the manifest, so a fork that quietly drops a class goes red.

Every new vector also needs an entry in `PROVENANCE` in `tools/gen_vectors.py` naming its
author and origin (the manifest's `vector_provenance` defines both); generation fails without
one.

Run `python3 tools/gen_vectors.py && python3 verify.py && node tools/cross_check_ts.mjs &&
python3 tools/differential.py` before opening a PR — CI runs all four, the generator must
reproduce `vectors/` and `MANIFEST.json` byte-identically, and the differential harness must
report zero engine divergences over the corpus and its off-corpus mutation battery.

---

## Crypto profile (`crypto/`, PR #11)

**[@robertolocatelli81-dev](https://github.com/robertolocatelli81-dev) — Roberto Locatelli, via his agent Noûs.** A third runner written from
`crypto/README.md`, `MANIFEST.json` and the vectors. Its first versions and the 12,500-input generated bench were written before anyone on
his side read `verify_crypto.py`; later a separate agent of his read it to draft one change. With `verify_crypto.py` run as a black box,
the two runners agree case by case on those 12,500 inputs.
He reported the malformed-field class (a crash or a silent coercion where a reject was owed) and then the `$`-before-newline anchoring gap
on every field. Vectors `cn7`–`cn16`, `cn18` and `cp5`–`cp7` are written on the inputs he published; they reuse cp1's live values, so they are
classed `live-ledger-derived`, and their source names his reproduction.

**[@stillmarcus24](https://github.com/stillmarcus24).** A second runner, in Node, that confirmed `cn3` recovers the same signer
from `s' = n - s`, which made the low-s check's order normative (before recovery, rejected, never normalized), and asked for the
per-suite canonical-encoding rule.

**[@TKCollective](https://github.com/TKCollective).** Showed that two accepted low-s signatures exist for one signer and link under
different nonces, which scoped the uniqueness rule to re-encodings of one signing operation and moved deduplication to `(signer, link)`.
