#!/usr/bin/env python3
"""Run this suite's criteria against an AXES Golden Trace bundle — cross-project interop.

    python3 tools/interop_axes.py BUNDLE [BUNDLE ...]
    python3 tools/interop_axes.py --compare-v1 V1_BUNDLE BUNDLE

Prints one row for EVERY criterion in this suite's CHECKS table, with a status:

  APPLIED    ran through this repo's own check function against objects in the bundle
  ADAPTED    the relation transfers, but this suite's vector kind is keccak-instantiated,
             so the adapter recomputes it under the bundle's declared SHA-256
  N/A        the bundle carries no object in this criterion's vocabulary

Every criterion gets a printed row whether or not it ran. A run that only printed the
criteria it could exercise would report a smaller denominator as though it were a sweep.

APPLIED does not mean "passed": anchor_relation runs and REJECTS on this corpus, which is
a difference in the existence relation rather than a defect. Nothing here is a conformance
badge in either direction — AXES conformance is defined by AXES (CONFORMANCE.md, D-008),
and these criteria are structural predicates on an evidence record.
"""

import copy
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from verify import (  # noqa: E402
    CHECKS,
    canonical,
    check_anchor_relation,
    check_chain_set,
)

GENESIS = "0" * 64


# ------------------------------------------------------------------- bundle loading
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
    manifest_path = os.path.join(bundle, "manifest.json")
    manifest = {}
    if os.path.exists(manifest_path):
        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
    return envelopes, manifest


# ------------------------------------------------------------------------ criteria
def canonicalization(envelopes):
    """ADAPTED (canonical_bytes + digest_recompute).

    Our canonicalizer is independent of the bundle's: stdlib RFC 8785 with keys ordered by
    UTF-16 code units, computed rather than delegated to a library. Comparing SHA-256 over
    its bytes to the stored digest tests byte equality of the canonical forms.
    """
    agree, diverge, refused = 0, [], []
    for env in envelopes:
        stored = (env.get("integrity") or {}).get("envelope_hash")
        try:
            got = sha256_over_our_canonical(env)
        except ValueError as exc:  # our canonicalizer refuses non-integer JSON numbers
            refused.append((env.get("sequence_number"), str(exc)))
            continue
        if got == stored:
            agree += 1
        else:
            diverge.append((env.get("sequence_number"), stored, got))
    return agree, diverge, refused


def perturbation_control(envelopes):
    """Non-vacuity: perturb one field inside the hash scope; the digest must diverge."""
    env = copy.deepcopy(envelopes[0])
    env["environment_type"] = "staging" if env.get("environment_type") == "production" else "production"
    return sha256_over_our_canonical(env) != (env.get("integrity") or {}).get("envelope_hash")


def chain_records(envelopes, manifest):
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
    head_digest = manifest.get("chain_head") or envelopes[-1]["integrity"]["envelope_hash"]
    head = {"seq": max(r["seq"] for r in records), "digest": "0x" + head_digest}
    return {"head": head, "records": records}


def chain_set(envelopes, manifest):
    """APPLIED — this suite's completeness + continuity check, unmodified.

    Only the digest wire form is adapted (0x-prefixed). No per-record `link` is presented,
    so the keccak link arithmetic stays out of scope; what runs is sequence closure 1..N
    under the committed head, prev-linkage, and head-matches-final-record.
    """
    return check_chain_set(chain_records(envelopes, manifest))


def omission_control(envelopes, manifest):
    """Non-vacuity for completeness: drop one interior record; it must reject."""
    victim = envelopes[len(envelopes) // 2]["sequence_number"]
    kept = [e for e in envelopes if e["sequence_number"] != victim]
    verdict, reason, _ = check_chain_set(chain_records(kept, manifest))
    return verdict == "reject" and reason == "completeness_reject"


def anchor_receipts(envelopes):
    """Every anchor receipt in the bundle, with the chain head it binds."""
    found = []
    for env in envelopes:
        anchoring = env.get("anchoring")
        if isinstance(anchoring, dict):
            found.append((env["sequence_number"], anchoring, env["integrity"]["previous_envelope_hash"]))
        export = env.get("export")
        if isinstance(export, dict) and isinstance(export.get("final_anchor"), dict):
            found.append((env["sequence_number"], export["final_anchor"],
                          env["integrity"]["previous_envelope_hash"]))
    return found


def anchor_relation(envelopes):
    """APPLIED — and it rejects, which is a difference in the relation, not a defect.

    This suite binds existence as anchored_digest = SHA-256(subject_digest BYTES). AXES
    records the chain head itself as the anchored value, so the two differ by a hash.
    """
    results = []
    for seq, anchor, prev_hash in anchor_receipts(envelopes):
        head = anchor.get("chain_head_hash")
        verdict, reason, detail = check_anchor_relation(
            {"subject_digest": "0x" + prev_hash, "anchored_digest": "0x" + head}
        )
        results.append((seq, anchor.get("anchor_receipt_id"), anchor.get("anchoring_method"),
                        head == prev_hash, verdict, reason, detail))
    return results


def independence(envelopes):
    """N/A by vocabulary — stated as a correction, because we reported otherwise in July.

    This criterion decides a record that CLAIMS independence. AXES grades corroboration
    with an enumerated state (internally_corroborated / source_system_corroborated /
    third_party_confirmed / externally_anchored); none of those is an assertion of
    neutrality in this criterion's vocabulary, so there is no claim to decide.

    The identity-syntax limit this docstring used to describe (0x-only normaliser, URN
    identities rejected on the identifier) was closed 2026-08-19 — see `--custody-twins`,
    which now matches the AXES pinned verdicts 2/2 with identities as written, and
    vectors p21/n30, which pin it under the per-kind two-sided gate.
    """
    states = {}
    for env in envelopes:
        state = (env.get("evidence_quality") or {}).get("corroboration_state")
        if state:
            states[state] = states.get(state, 0) + 1
    return states


def acknowledgment_basis(envelopes):
    """The authenticity basis, per rung — the corpus's own independence-adjacent field."""
    by_rung, bases = {}, {}
    named_confirmer = 0
    hash_bound = 0
    for env in envelopes:
        acks = list(env.get("acknowledgments") or [])
        recon = (env.get("reconciliation") or {}).get("acknowledgment_rung")
        if isinstance(recon, dict):
            acks.append(recon)
        for ack in acks:
            basis = ack.get("ack_authenticity_basis")
            rung = ack.get("ack_layer")
            bases[basis] = bases.get(basis, 0) + 1
            by_rung.setdefault(rung, {})
            by_rung[rung][basis] = by_rung[rung].get(basis, 0) + 1
            if any(k in ack for k in ("ack_party_id", "ack_confirmer_id", "ack_attestor")):
                named_confirmer += 1
            if "ack_artifact_hash" in ack:
                hash_bound += 1
    return bases, by_rung, named_confirmer, hash_bound


# --------------------------------------------------------------------------- report
def report(bundle):
    envelopes, manifest = load(bundle)
    name = os.path.basename(os.path.dirname(os.path.abspath(bundle)))
    head = manifest.get("chain_head", envelopes[-1]["integrity"]["envelope_hash"])
    print(f"\n=== {name} — {len(envelopes)} envelopes, head {head[:16]}… ===")

    agree, diverge, refused = canonicalization(envelopes)
    n = len(envelopes)
    print(f"[ADAPTED]  canonical_bytes              {agree}/{n} byte-identical canonical forms "
          f"(diverged {len(diverge)})")
    print(f"[ADAPTED]  digest_recompute             {agree}/{n} stored digests reproduced; "
          f"refused by the number domain: {len(refused)}")
    for seq, stored, got in diverge[:5]:
        print(f"             seq {seq}: stored {stored[:16]}… recomputed {got[:16]}…")
    print(f"[CONTROL]  perturbed envelope diverges  {perturbation_control(envelopes)}")

    print(f"[N/A]      chain_link                   no per-record link presented; this suite's "
          f"link arithmetic is keccak-instantiated")

    verdict, reason, detail = chain_set(envelopes, manifest)
    shown = detail if verdict == "valid" else f"{reason}: {detail}"
    print(f"[APPLIED]  chain_set                    {verdict} — {shown}")
    print(f"[CONTROL]  omitted record rejects       {omission_control(envelopes, manifest)}")

    anchors = anchor_relation(envelopes)
    rejects = sum(1 for a in anchors if a[4] == "reject")
    identity = sum(1 for a in anchors if a[3])
    print(f"[APPLIED]  anchor_relation              {len(anchors)} anchor receipt(s); "
          f"{rejects} reject, {len(anchors) - rejects} valid")
    for seq, rid, method, is_identity, v, r, _d in anchors:
        print(f"             seq {seq:>2} {rid}: {v}/{r} — chain_head_hash "
              f"{'== previous_envelope_hash (identity relation)' if is_identity else 'differs'}"
              f"; method {method}")
    print(f"             {identity}/{len(anchors)} record the chain head itself; this suite "
          f"requires anchored = SHA-256(subject bytes), so the two relations differ by a hash")

    print(f"[N/A]      phase_claim                  different axis: this criterion decides an "
          f"ECONOMIC phase (funding|delivery|settlement|refund|reversal)")
    ex_phases = {}
    for env in envelopes:
        p = env.get("execution_phase")
        ex_phases[p] = ex_phases.get(p, 0) + 1
    print(f"             the corpus carries execution_phase {ex_phases} on {n}/{n} — a lifecycle "
          f"axis, not an economic one")

    states = independence(envelopes)
    print(f"[N/A]      independence_claim           no record asserts neutrality in this "
          f"criterion's vocabulary")
    print(f"             corroboration_state is graded, not claimed: {states}")

    for kind in ("offer_binding", "decision_evidence_binding", "boundary_binding"):
        print(f"[N/A]      {kind:28} no object of this kind in the corpus")

    bases, by_rung, named, hash_bound = acknowledgment_basis(envelopes)
    total = sum(bases.values())
    print(f"[FINDING]  acknowledgment authenticity  {total} rung(s) across the bundle")
    for rung, inner in sorted(by_rung.items(), key=lambda kv: str(kv[0])):
        for basis, count in sorted(inner.items(), key=lambda kv: -kv[1]):
            print(f"             {count:3d}  {rung:<10} {basis!r}")
    print(f"             hash-bound acknowledgment artifacts: {hash_bound}/{total}")
    print(f"             rungs naming a confirming PARTY: {named}/{total}")
    print(f"             no ack_authenticity_basis vocabulary is defined in the AXES repo, so "
          f"0/{total} are resolvable against one today")

    printed = 10
    print(f"[DENOMINATOR] {printed}/{len(CHECKS)} criteria in this suite printed a row "
          f"(2 adapted, 2 applied, 6 not applicable)")
    return {"envelopes": n, "refused": len(refused), "diverged": len(diverge),
            "chain": verdict, "anchor_rejects": rejects}


def custody_twins(vectors_dir):
    """The independence criterion against AXES's own two-sided custody pair.

    These are the objects the `out/` bundles lack: a declared independence relationship
    (`capture_relationship`) plus NAMED parties (`deployer_id`, `executor_id`, `capturer_id`),
    so the criterion can actually decide rather than merely have nothing to fire on.

    Run twice — once on the identities as written, once with the same identities rewritten
    as 0x-addresses. The difference between the two runs isolates what the identifier
    syntax costs, rather than asserting it.
    """
    from verify import check_independence_claim

    pairs = [
        ("custody_deployer_captured_reject", "reject"),
        ("custody_accept_independent_external", "accept"),
    ]
    rows = []
    for name, axes_verdict in pairs:
        path = os.path.join(vectors_dir, name + ".json")
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as fh:
            custody = json.load(fh)["custody"]
        as_written = check_independence_claim({
            "claimed": "independent",
            "parties": [custody["deployer_id"], custody["executor_id"]],
            "attestations": [{"by": custody["capturer_id"]}],
        })
        ids = {}
        for i, identity in enumerate((custody["deployer_id"], custody["executor_id"],
                                      custody["capturer_id"])):
            ids.setdefault(identity, "0x" + f"{i + 1:02d}" * 20)
        rewritten = check_independence_claim({
            "claimed": "independent",
            "parties": [ids[custody["deployer_id"]], ids[custody["executor_id"]]],
            "attestations": [{"by": ids[custody["capturer_id"]]}],
        })
        rows.append((name, axes_verdict, custody, as_written, rewritten))

    print("\n=== independence vs the AXES custody twins ===")
    for name, axes_verdict, custody, as_written, rewritten in rows:
        same_party = custody["capturer_id"] == custody["deployer_id"]
        print(f"  {name}")
        print(f"    AXES verdict: {axes_verdict}   (capturer {'==' if same_party else '!='} deployer)")
        print(f"    ours, identities as written:  {as_written[0]}/{as_written[1]} — {as_written[2]}")
        print(f"    ours, identities as 0x-addrs: {rewritten[0]}/{rewritten[1] or '—'} — {rewritten[2]}")
    if not rows:
        print("  (no custody twin vectors found at that path)")
        return rows
    agree_w = sum(1 for _n, a, _c, w, _r in rows if (w[0] == "valid") == (a == "accept"))
    agree_r = sum(1 for _n, a, _c, _w, r in rows if (r[0] == "valid") == (a == "accept"))
    print(f"  as written:     matches the AXES verdict on {agree_w}/{len(rows)}")
    print(f"  as 0x-addrs:    matches the AXES verdict on {agree_r}/{len(rows)}")
    if agree_w == len(rows):
        print("  the criterion now decides URN identities directly (p21/n30 pin this; before")
        print("  2026-08-19 it rejected both twins on the identifier — a false negative)")
    else:
        print("  as written it rejects on the identifier — a false negative produced by")
        print("  identifier syntax, not by the independence predicate")
    return rows


def float_nonvacuity(v1_bundle, v2_bundle):
    """The number-domain refusal fired 0 times on v2. A control that never fires proves
    nothing, so run the same canonicalizer over the archived v1 corpus it was built for."""
    out = []
    for label, bundle in (("v1", v1_bundle), ("v2", v2_bundle)):
        envelopes, _ = load(bundle)
        refused = 0
        for env in envelopes:
            try:
                sha256_over_our_canonical(env)
            except ValueError:
                refused += 1
        out.append((label, bundle, refused, len(envelopes)))
    print("\n=== number-domain control (non-vacuity) ===")
    for label, bundle, refused, total in out:
        print(f"  {label}: {refused}/{total} envelopes refused — "
              f"{os.path.basename(os.path.dirname(os.path.abspath(bundle)))}")
    print("  a refusal count that moves with the corpus is a control that can fire")
    return out


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 2
    if args[0] == "--compare-v1":
        if len(args) != 3:
            print("usage: --compare-v1 V1_BUNDLE V2_BUNDLE")
            return 2
        float_nonvacuity(args[1], args[2])
        return 0
    if args[0] == "--custody-twins":
        if len(args) != 2:
            print("usage: --custody-twins VECTORS_DIR")
            return 2
        custody_twins(args[1])
        return 0
    print("evidence-record-conformance criteria vs AXES Golden Trace")
    for bundle in args:
        report(bundle)
    return 0


if __name__ == "__main__":
    sys.exit(main())
