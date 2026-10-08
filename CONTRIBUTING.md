# Contributing

Counter-vectors, cross-runs and adversarial additions are welcome. A vector that turns this suite
red is worth more than one that keeps it green.

A cross-run needs none of the terms below: run your own implementation over the vectors and publish
its output in an issue (README, *Reproduction*). The terms apply to pull requests. In short: what you
submit is Apache-2.0 to everyone, you keep your copyright, and the maintainers decide what merges.

## What is merged

Tersign maintains this repository. The maintainers decide what merges, when, in what form, and what
the suite pins. A contribution is judged against the suite's criteria: two-sided per kind; the
reject-reason closure pinned in the runner; author and origin recorded per vector. Independent
reproduction comes from outside runs published in issues (README, *Reproduction*).

A profile for a format defined outside this suite pins that format's requirements and this suite's
own rules, each labelled as one or the other. Where the format sets a behaviour at SHOULD strength,
the suite does not harden it into a pin. A new kind or profile starts as an issue.

One pull request per change. Each new vector's description names the requirement it rests on: the
section and sentence of the format it tests, or the `MANIFEST.json` key of the suite rule.

Every criterion carries an accepting and a rejecting twin, so an implementation that rejects a class
unconditionally fails just as one that accepts it unconditionally does. The reject-reason closure is
pinned in the verifier rather than derived from the manifest, so a fork that drops a class goes red.
Every new vector needs a provenance entry naming its author and origin (`vector_provenance` in
`MANIFEST.json`): `PROVENANCE` in `tools/gen_vectors.py` for the core (generation fails without
one), and the vector's own entry in its profile's generator under `crypto/`.

Before opening a pull request, run what CI runs:

```
python3 verify.py
python3 crypto/verify_crypto.py && python3 crypto/verify_crypto.py --mutants
python3 crypto/verify_eip712.py && python3 crypto/verify_eip712.py --mutants
npm i viem && node tools/cross_check_ts.mjs
python3 tools/differential.py
sh tools/regen_check.sh    # in a scratch clone: it moves each vector directory aside and regenerates it
```

Pull requests are squash-merged with a message the maintainers write, which carries the
`Signed-off-by:` line. Authorship is recorded per vector in the manifests; CONTRIBUTORS.md may credit
the account, a published personal name and what it contributed. Links to a contributor's own
projects, products, registries or endpoints are not carried into the suite's files; a vector's
origin is recorded in its manifest entry. After merge, the maintainers may edit, regenerate, rename,
move, reclassify or remove any file; while a vector stays in the suite, its manifest entry keeps its
author and origin source.

## Roles

A contribution, merged or not, confers no maintainer, reviewer, editor or co-owner role or title,
no right to review or approve other contributions, and no say over later changes. Commitments,
schedules and priority statements made in a thread are their author's own; the repository records
the merged bytes and who wrote them. Agreement with this suite makes no verifier a reference, this
suite's engines included, and conformance here is not a certification.

## Licence terms

1. **Repository licence.** This repository is licensed under Apache-2.0 (`LICENSE`). Your
   contributions are licensed to everyone under Apache-2.0, the licence they are submitted under,
   and you keep the copyright in what you write. Do not add licence headers, notices, attribution
   conditions or usage terms of your own; a pull request that carries them, or material you cannot
   license under Apache-2.0, is not merged.

2. **As is.** You are not expected to provide support for your contributions. Unless required by
   applicable law or agreed to in writing, you provide them on an "AS IS" basis, without warranties
   or conditions of any kind, either express or implied.

3. **No obligation.** The maintainers are not obliged to merge, use or keep any contribution.

## Sign-off and agreement

Every commit in a pull request is authored by the account that opens it and carries that author's
`Signed-off-by:` line (`git commit -s`), naming the person or organisation that gives these terms
and certifying the Developer Certificate of Origin 1.1 (https://developercertificate.org). If a
contribution is produced with software, an AI agent included, the person or organisation that
operates that account gives these terms. The description of every pull request contains this line,
written by the account that opens it:

```
I agree to the terms in CONTRIBUTING.md.
```

The `Signed-off-by:` line and the line above record your agreement to the terms in this file for
that contribution. A pull request without them is not merged.
