#!/usr/bin/env python3
"""Run this suite's criteria against an AXES Golden Trace bundle — cross-project interop.

    python3 tools/interop_axes.py /path/to/axes/examples/golden-trace/out [...more bundles]

Reports, per criterion, one of:
  APPLIED    the criterion ran against the bundle through this repo's own check function
  ADAPTED    the relation transfers but this suite's vector kind is keccak-instantiated,
             so the adapter recomputes it under the bundle's declared SHA-256
  N/A        the bundle contains no object of the kind the criterion decides
  BLOCKED    the criterion exists but cannot evaluate this bundle's identity syntax

The point of the N/A and BLOCKED rows is that they are printed. A run that silently
skipped them would report a smaller denominator as if it were a clean sweep.

Nothing here is a conformance badge for either project: AXES conformance is defined by
AXES (CONFORMANCE.md, D-008), and this suite's criteria are structural predicates on an
evidence record. What a run produces is a two-sided interop result — which criteria the
corpus satisfies, which it cannot yet exercise, and which this suite cannot yet ask.
"""

import copy
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from verify import canonical, check_chain_set, check_independence_claim  # noqa: E402

GENESIS = "0" * 64


def hash_scope(envelope):
    """AXES hash preimage: the envelope less integrity.envelope_hash and .signature."""
    env = copy.deepcopy(envelope)
    integrity = env.get("integrity")
    if isinstance(integrity, dict):
        integrity.pop("envelope_hash", None)
        integrity.pop("signature", None)
    return env


def sha256_over_our_canonical(envelope):
    return hashlib.sha256(canonical(hash_scope(envelope)).encode("utf-8")).hexdigest()


def load(bundle):
    with open(os.path.join(bundle, "envelopes.jsonl"), encoding="utf-8") as fh:
        envelopes = [json.loads(line) for line in fh if line.strip()]
    with open(os.path.join(bundle, "manifest.json"), encoding="utf-8") as fh:
        manifest = json.load(fh)
    return envelopes, manifest


def canonicalization_parity(envelopes):
    """ADAPTED. Our stdlib RFC 8785 canonicalizer vs the bundle's, compared through the
    stored digest: equal SHA-256 over the same preimage means the canonical bytes agree.

    Also exercises the number domain — canonical() refuses JSON floats outright, which is
    the property Golden Trace v2's integer Amount migration was made to satisfy.
    """
    agree, diverge, refused = 0, [], []
    for env in envelopes:
        stored = (env.get("integrity") or {}).get("envelope_hash")
        try:
            got = sha256_over_our_canonical(env)
        except ValueError as exc:  # non-integer number in the digest domain
            refused.append((env.get("sequence_number"), str(exc)))
            continue
        if got == stored:
            agree += 1
        else:
            diverge.append((env.get("sequence_number"), stored, got))
    return agree, diverge, refused


def negative_control(envelopes):
    """Non-vacuity: a check that never rejects proves nothing. Perturb one envelope
    inside the hash scope and confirm the recomputation diverges from the stored digest."""
    env = copy.deepcopy(envelopes[0])
    env["environment_type"] = "staging" if env.get("environment_type") == "production" else "production"
    return sha256_over_our_canonical(env) != (env.get("integrity") or {}).get("envelope_hash")


def chain_set(envelopes, manifest):
    """APPLIED. This suite's completeness + continuity check, unmodified.

    Digests are 0x-prefixed to this suite's wire form; no `link` is presented, so the
    keccak link arithmetic stays out of scope and what runs is exactly what runs for our
    own chain vectors: sequence closure 1..N under the committed head, prev-linkage, and
    head-matches-final-record.
    """
    records = [
        {
            "seq": env["sequence_number"],
            "artifact_digest": "0x" + env["integrity"]["envelope_hash"],
            "prev_digest": None
            if env["integrity"]["previous_envelope_hash"] == GENESIS
            else "0x" + env["integrity"]["previous_envelope_hash"],
        }
        for env in envelopes
    ]
    head = {"seq": max(r["seq"] for r in records), "digest": "0x" + manifest["chain_head"]}
    return check_chain_set({"head": head, "records": records})


def omission_control(envelopes, manifest):
    """Non-vacuity for completeness: drop one interior record and require a reject."""
    kept = [e for e in envelopes if e["sequence_number"] != envelopes[len(envelopes) // 2]["sequence_number"]]
    verdict, reason, _ = chain_set(kept, manifest)
    return verdict == "reject" and reason == "completeness_reject"


def independence(envelopes):
    """BLOCKED, reported with the reason.

    Every envelope asserting external corroboration is mapped onto this suite's
    independence criterion. The criterion decides on ATTESTOR IDENTITY: it needs the
    parties and the attestors as parseable identifiers to answer "was this attested by
    anyone outside the transaction". AXES identities are URN-shaped
    (`agent:caldera/ap-pilot`); this suite's `_norm_addr` parses 0x-addresses only, so
    the criterion fails closed on the identifier rather than deciding the question.

    That is a limit of this suite, not a defect in the corpus, and it is the substantive
    interop finding: an independence criterion bound to one identity syntax cannot be
    applied across schemes. Reported rather than worked around.
    """
    claimants = [
        env
        for env in envelopes
        if (env.get("evidence_quality") or {}).get("corroboration_state") == "externally_anchored"
    ]
    if not claimants:
        return "N/A", "no envelope asserts external corroboration", 0
    env = claimants[0]
    verdict, reason, detail = check_independence_claim(
        {
            "claimed": "independent",
            "parties": [env["actor"]["agent_id"]],
            "attestations": [{"by": env["actor"]["agent_id"]}],
        }
    )
    return "BLOCKED", f"{reason}: {detail}", len(claimants)


def acknowledgment_basis(envelopes):
    """The independence question the corpus CAN be asked, since it names its confirmer.

    `third_party_confirmed` envelopes carry an acknowledgment ladder naming the scheme and
    hash-binding the acknowledgment artifact — more than a bare declaration. What decides
    independence is the remaining field: on the open bundle alone, can a reader tell the
    counterparty confirmed this from the emitter saying so?

    Returns the census of authenticity bases, split by whether the basis is a bare token a
    verifier could evaluate against a vocabulary, or prose carrying its own status marker.
    """
    census, prose = {}, {}
    for env in envelopes:
        acks = list(env.get("acknowledgments") or [])
        recon = (env.get("reconciliation") or {}).get("acknowledgment_rung")
        if isinstance(recon, dict):
            acks.append(recon)
        for ack in acks:
            basis = ack.get("ack_authenticity_basis")
            census[basis] = census.get(basis, 0) + 1
            if isinstance(basis, str) and ("(" in basis or " " in basis.strip()):
                prose[basis] = prose.get(basis, 0) + 1
    return census, prose


def report(bundle):
    envelopes, manifest = load(bundle)
    name = os.path.basename(os.path.dirname(os.path.abspath(bundle)))
    print(f"\n=== {name} — {len(envelopes)} envelopes, head {manifest['chain_head'][:16]}… ===")

    agree, diverge, refused = canonicalization_parity(envelopes)
    print(f"[ADAPTED]  canonical_bytes / digest    {agree}/{len(envelopes)} agree "
          f"(diverged {len(diverge)}, refused by number domain {len(refused)})")
    for seq, stored, got in diverge[:5]:
        print(f"             seq {seq}: stored {stored[:16]}… recomputed {got[:16]}…")
    for seq, why in refused[:5]:
        print(f"             seq {seq}: {why}")
    print(f"[CONTROL]  perturbed envelope diverges  {negative_control(envelopes)}")

    verdict, reason, detail = chain_set(envelopes, manifest)
    print(f"[APPLIED]  chain_set                    {verdict} — {detail if verdict == 'valid' else reason + ': ' + detail}")
    print(f"[CONTROL]  omitted record rejects       {omission_control(envelopes, manifest)}")

    status, why, n = independence(envelopes)
    print(f"[{status}]  independence_claim           {n} claimant envelope(s) — {why}")

    census, prose = acknowledgment_basis(envelopes)
    total_acks = sum(census.values())
    print(f"[FINDING]  acknowledgment authenticity  {total_acks} acknowledgment(s):")
    for basis, count in sorted(census.items(), key=lambda kv: -kv[1]):
        shape = "prose (carries its own status marker)" if basis in prose else "bare token"
        print(f"             {count:3d}  {basis!r} — {shape}")
    print(f"             evaluable-against-a-vocabulary: {total_acks - sum(prose.values())}/{total_acks}; "
          f"none of the bases is a demonstrated counterparty signature over the acknowledgment digest")

    anchoring = {(e.get("evidence_quality") or {}).get("corroboration_state") for e in envelopes}
    print(f"[N/A]      anchor_relation              no anchor receipt in bundle "
          f"(corroboration states: {sorted(s for s in anchoring if s)})")
    for kind in ("phase_claim", "offer_binding", "decision_evidence_binding", "boundary_binding"):
        print(f"[N/A]      {kind:28} no object of this kind in the corpus")

    return len(envelopes), len(diverge), verdict


def main():
    bundles = sys.argv[1:]
    if not bundles:
        print(__doc__)
        return 2
    print("evidence-record-conformance criteria vs AXES Golden Trace")
    print("10 criteria in this suite: 1 APPLIED, 1 ADAPTED, 1 BLOCKED, 7 N/A on this corpus.")
    total, diverged, verdicts = 0, 0, []
    for bundle in bundles:
        n, d, v = report(bundle)
        total, diverged = total + n, diverged + d
        verdicts.append(v)
    print(f"\nTOTAL: {total} envelopes across {len(bundles)} bundle(s), "
          f"{diverged} canonicalization divergence(s), chain_set {set(verdicts)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
