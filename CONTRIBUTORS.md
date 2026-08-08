# Contributors

This suite exists to be checked by people who did not write it, so who sharpened which
criterion is part of the record rather than a courtesy. Everything below is verifiable from
this repository: `git log` for authorship, the linked issue or PR for the argument, and
`python3 verify.py` for the vector that resulted.

A note on how contributions land here, because the git history is easy to misread. A
contribution is credited by its **commit authorship**, not by a pull request's merge badge.
Where a PR could not be fast-forwarded — usually because a hardening pass touched the same
files first — the commit was applied with `git cherry-pick -x` and the author preserved, and
the PR closed with an explanation. Those contributions are in `main` under their author's name
even though GitHub shows the PR as closed rather than merged. Going forward the preference is
to rebase a contributor's branch onto `main` and merge it, so the badge and the authorship stay
together.

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
verifier cannot interpret rejects. (This is one of the cherry-picked cases described above —
the PR reads "closed", the work is in `main`.)

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

## [@0rkz](https://github.com/0rkz) — PayPerByte

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

Run `python3 tools/gen_vectors.py && python3 verify.py && node tools/cross_check_ts.mjs` before
opening a PR — CI runs all three, and the generator must reproduce `vectors/` and
`MANIFEST.json` byte-identically.
