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

It is the only pull request this repository has received to date, and handling it that way was
a mistake worth recording: it optimised for landing the code over the signal the repository
emits, and a closed PR reads as a rejection to anyone who does not dig. The preference going
forward is to rebase a contributor's branch onto `main` and merge it, so the badge, the link
and the authorship stay together.

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

**Commitments must be derived, not declared** — vectors `p17` / `n21`, from his review on
[#4](https://github.com/tersignhq/evidence-record-conformance/issues/4). He observed that the
commitment-scope rule is only load-bearing once a record's commitments are *derived from the
record*: a declared list lets a record assert the very scope the rule exists to bound. The
concrete case he identified is that x402 v2 §5.3.2 defines the empty string as what
`transaction` carries when settlement failed, so `success: true` with `transaction: ""` is well
formed and commits to no settlement anyone can resolve — now rejected without resolving
anything on-chain.

In the same review he made the sharper form of an argument this suite rests on: *position was
doing the work of faculty*. A party that merely occupies a different position — a distinct
address, a declared label — is not thereby independent, and a declared field grounds nothing.
That distinction is why the `settledBy` producer field he raised was **not** adopted: a
criterion satisfiable by declaration reproduces the defect it was meant to catch.

## [@mohammedmessaoudene-cmd](https://github.com/mohammedmessaoudene-cmd) — Mohammed Messaoudene

**Authority-decision evidence binding** — vectors `p19` / `n27` / `n28`. Reported
`CG-DELTA-LOSS-01` from an AUEC-controlled experiment in the
[SEP-3004 discussion](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/3004#issuecomment-5228991875):
two allowed decisions can have different host limits, policy versions and
requested-to-effective reductions while producing the same protected record. In the corpus,
n27 exercises the missing-commitment branch with one presented reduction; p19/n28 execute the
distinct-object A/B contrast. The criterion is structural only and does not assert producer
truth, independent validation, MCP adoption, or a normative digest, canonicalization, or field
location.

OpenAI ChatGPT and Codex assisted with implementation, testing, analysis and drafting;
Mohammed Messaoudene reviewed the executed evidence and remains responsible for the
contribution.

## [@navigatorbuilds](https://github.com/navigatorbuilds) — Elara (AI maintainer, elara-mesh)

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

## [@0rkz](https://github.com/0rkz) — PayPerByte

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
change it anticipates without re-pinning.

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

---

## How to contribute

Counter-vectors and adversarial additions are the most useful thing you can send. A vector that
makes this suite go red is worth more to us than one that makes it green — the whole point is
that the criteria discriminate rather than merely accept.

Two conventions, both enforced by the run itself: every criterion carries **both** an accepting
and a rejecting twin, so an implementation that unconditionally rejects a class fails just as
one that unconditionally accepts it does; and the reject-reason closure is pinned in the
verifier rather than derived from the manifest, so a fork that quietly drops a class goes red.

Run `python3 tools/gen_vectors.py && python3 verify.py && node tools/cross_check_ts.mjs &&
python3 tools/differential.py` before opening a PR — CI runs all four, the generator must
reproduce `vectors/` and `MANIFEST.json` byte-identically, and the differential harness must
report zero engine divergences over the corpus and its off-corpus mutation battery.
