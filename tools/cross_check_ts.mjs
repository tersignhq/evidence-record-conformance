// Cross-implementation measurement: an INDEPENDENT TypeScript-stack implementation of
// every check in verify.py, run over the full committed corpus. Two implementations,
// one vector set, byte-level agreement required — conformance by measurement, not by
// resemblance. Run:  npm i viem  (in the repo root), then  node tools/cross_check_ts.mjs
//
// Profile note: JSON.parse keeps the LAST of duplicate object names where the Python
// loader rejects the file outright; the corpus contains no duplicate-name vectors, so
// the two loaders agree over the committed set.
import { keccak256, concatHex, numberToHex, stringToHex } from "viem";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

// ---------------------------------------------------------------- canonical form (JCS)
function canon(v) {
  if (v === null || v === true || v === false) return JSON.stringify(v);
  if (typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new NumberDomainError("non-integer JSON number in the digest domain");
    if (!Number.isSafeInteger(v)) throw new NumberDomainError("outside the I-JSON interoperable range (|n| > 2^53-1)");
    return String(v);
  }
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  // Default JS string comparison IS UTF-16 code-unit order — the JCS rule.
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
}
class NumberDomainError extends Error {}

const digestOf = (v) => keccak256(stringToHex(canon(v)));
const GENESIS_PREV = `0x${"0".repeat(64)}`;
const chainLink = (artifact, prev, seq) =>
  keccak256(concatHex([artifact, prev ?? GENESIS_PREV, numberToHex(seq, { size: 8 })]));
const sha256hex = (hex) => "0x" + createHash("sha256").update(Buffer.from(hex.slice(2), "hex")).digest("hex");

// -------------------------------------------------------- identifier normalization
const ADDR_RE = /^0x[0-9a-f]{40}$/;
const DIGEST_RE = /^0x[0-9a-f]{64}$/;
// Second identity syntax (2026-08-19): scheme-qualified identifiers, strict grammar so the
// aliasing defence still holds — no whitespace, no format characters; case + trailing punctuation folded.
const URN_RE = /^[a-z][a-z0-9+.-]*:[\x21-\x7e]+$/;
const normAddr = (a) => {
  if (typeof a !== "string") return null;
  const t = a.trim();
  const low = t.toLowerCase();
  if (ADDR_RE.test(low)) return low;
  // Fold toward "same party": case-insensitive, trailing / . # stripped. A verifier that does
  // not own a scheme's equivalence rules must treat possibly-equal identifiers as equal.
  if (URN_RE.test(t)) return low.replace(/[\/.#]+$/, "");
  return null;
};
const normDigest = (x) => (typeof x === "string" && DIGEST_RE.test(x.trim().toLowerCase()) ? x.trim().toLowerCase() : null);
const isSeq = (x) => typeof x === "number" && Number.isInteger(x);

const NO_CLAIM = new Set(["", "none", "issuer_attested"]);
const PHASES = new Set(["funding", "delivery", "settlement", "refund", "reversal"]);
const MAX_HEAD_SEQ = 100_000;

// Shared arithmetic only: the offer and decision-evidence kinds retain distinct
// semantic contracts and input shapes even though both bind canonical object bytes.
function checkObjectBinding(carrier, digestField, presented, { objectRequired = false } = {}) {
  if (typeof carrier !== "object" || carrier === null || Array.isArray(carrier)) {
    return ["reject", "binding_reject"];
  }
  if (objectRequired && (typeof presented !== "object" || presented === null || Array.isArray(presented))) {
    return ["reject", "binding_reject"];
  }
  const committed = normDigest(carrier[digestField]);
  if (committed === null) return ["reject", "binding_reject"];
  let got;
  try {
    got = digestOf(presented);
  } catch {
    return ["reject", "binding_reject"];
  }
  return got === committed ? ["valid", null] : ["reject", "binding_reject"];
}

// ------------------------------------------------------------------------ vector kinds
const CHECKS = {
  digest_recompute(inp) {
    let got;
    try {
      got = digestOf(inp.payload);
    } catch (e) {
      if (e instanceof NumberDomainError) return ["reject", "number_domain_reject"];
      throw e;
    }
    const expected = normDigest(inp.expected_digest);
    if (expected === null) return ["reject", "recompute_mismatch"];
    return got === expected ? ["valid", null] : ["reject", "recompute_mismatch"];
  },
  canonical_bytes(inp) {
    let got;
    try {
      got = canon(inp.payload);
    } catch (e) {
      if (e instanceof NumberDomainError) return ["reject", "number_domain_reject"];
      throw e;
    }
    return got === inp.claimed_canonical ? ["valid", null] : ["reject", "canonicalization_reject"];
  },
  chain_link(inp) {
    const artifact = normDigest(inp.artifact_digest);
    if (artifact === null) return ["reject", "continuity_reject"];
    let prev = null;
    if (inp.prev_digest !== null && inp.prev_digest !== undefined) {
      prev = normDigest(inp.prev_digest);
      if (prev === null) return ["reject", "continuity_reject"];
    }
    if (!isSeq(inp.seq) || inp.seq < 1) return ["reject", "continuity_reject"];
    const expected = normDigest(inp.expected_link);
    if (expected === null) return ["reject", "continuity_reject"];
    return chainLink(artifact, prev, inp.seq) === expected ? ["valid", null] : ["reject", "continuity_reject"];
  },
  chain_set(inp) {
    const head = inp.head;
    if (typeof head !== "object" || head === null || Array.isArray(head)) return ["reject", "completeness_reject"];
    if (!isSeq(head.seq) || head.seq < 1 || head.seq > MAX_HEAD_SEQ) return ["reject", "completeness_reject"];
    const headDigest = normDigest(head.digest);
    if (headDigest === null) return ["reject", "completeness_reject"];
    if (!Array.isArray(inp.records)) return ["reject", "completeness_reject"];
    for (const r of inp.records) {
      if (typeof r !== "object" || r === null || Array.isArray(r) || !isSeq(r.seq)) return ["reject", "completeness_reject"];
    }
    const records = [...inp.records].sort((a, b) => a.seq - b.seq);
    const seqs = records.map((r) => r.seq);
    const expected = Array.from({ length: head.seq }, (_, i) => i + 1);
    if (seqs.length !== expected.length || seqs.some((s, i) => s !== expected[i])) {
      return ["reject", "completeness_reject"];
    }
    let prev = null;
    for (const r of records) {
      const artifact = normDigest(r.artifact_digest);
      if (artifact === null) return ["reject", "continuity_reject"];
      let rPrev = null;
      if (r.prev_digest !== null && r.prev_digest !== undefined) {
        rPrev = normDigest(r.prev_digest);
        if (rPrev === null) return ["reject", "continuity_reject"];
        if (rPrev === GENESIS_PREV) rPrev = null;
      }
      if (rPrev !== prev) return ["reject", "continuity_reject"];
      if ("link" in r) {
        const claimed = normDigest(r.link);
        if (claimed === null) return ["reject", "continuity_reject"];
        if (chainLink(artifact, prev, r.seq) !== claimed) return ["reject", "continuity_reject"];
      }
      prev = artifact;
    }
    return prev === headDigest ? ["valid", null] : ["reject", "continuity_reject"];
  },
  anchor_relation(inp) {
    const subject = normDigest(inp.subject_digest);
    if (subject === null) return ["reject", "existence_reject"];
    const anchored = normDigest(inp.anchored_digest);
    if (anchored === null) return ["reject", "existence_reject"];
    return sha256hex(subject) === anchored ? ["valid", null] : ["reject", "existence_reject"];
  },
  phase_claim(inp) {
    const record = inp.record;
    if (typeof record !== "object" || record === null || !("economic_phase" in record)) return ["reject", "phase_reject"];
    if (!PHASES.has(record.economic_phase) || !PHASES.has(inp.presented_as)) return ["reject", "phase_reject"];
    return record.economic_phase === inp.presented_as ? ["valid", null] : ["reject", "phase_reject"];
  },
  // Mirrors verify.py's check_boundary_binding. A boundary event that changes a stream's
  // verification parameters must bind the prefix it extends AND its own position in that
  // prefix's continuation — naming the prefix alone is satisfiable by two conflicting
  // continuations at once. Coverage claimed over an empty attested prefix is a downgrade.
  boundary_binding(inp) {
    const event = inp.boundary_event;
    if (typeof event !== "object" || event === null || Array.isArray(event)) return ["reject", "boundary_reject"];
    const prefix = inp.prefix;
    if (!Array.isArray(prefix) || prefix.length === 0) return ["reject", "boundary_reject"];

    const claimed = normDigest(event.prefixDigest);
    if (claimed === null) return ["reject", "boundary_reject"];
    let actual;
    try {
      actual = digestOf(prefix);
    } catch {
      return ["reject", "boundary_reject"];
    }
    if (claimed !== actual) return ["reject", "boundary_reject"];

    const position = event.position;
    if (!Number.isInteger(position)) return ["reject", "boundary_reject"];
    if (position !== prefix.length) return ["reject", "boundary_reject"];

    const covered = inp.covered_through;
    if (covered !== null && covered !== undefined) {
      if (!Number.isInteger(covered) || covered < 0) return ["reject", "boundary_reject"];
      const attested = event.attestedPrefixLength;
      if (!Number.isInteger(attested)) return ["reject", "boundary_reject"];
      if (attested <= 0 && covered > 0) return ["reject", "boundary_reject"];
      if (covered > attested) return ["reject", "boundary_reject"];
    }
    return ["valid", null];
  },

  offer_binding(inp) {
    return checkObjectBinding(inp.receipt, "offerDigest", inp.offer);
  },

  decision_evidence_binding(inp) {
    return checkObjectBinding(
      inp.record,
      "decisionEvidenceDigest",
      inp.decision_evidence,
      { objectRequired: true },
    );
  },
  independence_claim(inp) {
    const claimed = inp.claimed;
    if (claimed === null || claimed === undefined) return ["valid", null];
    let claimedSet = null;
    if (typeof claimed === "string") {
      if (NO_CLAIM.has(claimed)) return ["valid", null];
      claimedSet = claimed === "independent" ? new Set([claimed]) : null;
    } else if (Array.isArray(claimed) && claimed.every((c) => typeof c === "string")) {
      const set = new Set(claimed.filter((c) => !NO_CLAIM.has(c)));
      if (set.size === 0) return ["valid", null];
      claimedSet = [...set].every((c) => c === "independent") ? set : null;
    }
    if (claimedSet === null) return ["reject", "independence_reject"];
    if (!Array.isArray(inp.parties) || inp.parties.length === 0) return ["reject", "independence_reject"];
    const parties = new Set();
    for (const p of inp.parties) {
      const norm = normAddr(p);
      if (norm === null) return ["reject", "independence_reject"];
      parties.add(norm);
    }
    if (!Array.isArray(inp.attestations) || inp.attestations.length === 0) return ["reject", "independence_reject"];
    let outside = 0;
    for (const a of inp.attestations) {
      if (typeof a !== "object" || a === null || Array.isArray(a) || !("by" in a)) return ["reject", "independence_reject"];
      const by = normAddr(a.by);
      if (by === null) return ["reject", "independence_reject"];
      if (!parties.has(by)) outside++;
    }
    if (outside === 0) return ["reject", "independence_reject"];
    // DERIVED, never declared — the declared field's PRESENCE is the reject, whatever it
    // holds (a list, an explicit null, anything) and whether or not a scope is asserted.
    // Key-presence (`in`) has identical semantics to Python's `in`; the previous
    // `=== undefined` guard read an explicit JSON null differently from verify.py's
    // `is None` and the two engines forked on it. See verify.py's commitment-scope branch —
    // both engines must share this exact shape.
    if ("record_commits" in inp) return ["reject", "independence_reject"];
    let covers = inp.covers;
    if (covers !== null && covers !== undefined) {
      if (typeof covers === "string") covers = [covers];
      if (!Array.isArray(covers) || covers.length === 0 || !covers.every((c) => typeof c === "string")) {
        return ["reject", "independence_reject"];
      }
      let committed;
      if (inp.settlement_result && typeof inp.settlement_result === "object" && !Array.isArray(inp.settlement_result)) {
        // Mirrors verify.py's derive_settlement_commits: §5.3.2 makes `transaction: ""` the
        // encoding of a failed settlement, so success+empty commits to no resolvable
        // settlement at all. (Array excluded to match Python's isinstance(dict) exactly.)
        const r = inp.settlement_result;
        committed = [];
        if (r.success === true && typeof r.transaction === "string" && r.transaction.trim() !== "") committed.push("settlement");
        if (typeof r.network === "string" && r.network.trim() !== "") committed.push("network");
      }
      if (!Array.isArray(committed) || !committed.every((c) => typeof c === "string")) {
        return ["reject", "independence_reject"];
      }
      const committedSet = new Set(committed);
      if (covers.some((c) => !committedSet.has(c))) return ["reject", "independence_reject"];
    }
    return ["valid", null];
  },
};

export { CHECKS, digestOf, canon };

// ------------------------------------------------------------------------------ runner
// Guarded so tools/differential.py can import CHECKS without running the corpus pass —
// the differential harness compares the two engines DIRECTLY (not through the manifest),
// which is the parity this runner cannot supply: its oracle is MANIFEST.json, so engine
// agreement here is transitive through the expectations and blind off-corpus.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const kats = [
    ["keccak256(empty)", keccak256("0x"), "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"],
    ["keccak256('abc')", keccak256(stringToHex("abc")), "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"],
  ];
  let bad = 0;
  for (const [name, got, want] of kats) {
    if (got !== want) {
      bad++;
      console.log(`DIVERGE ${name}: ${got}`);
    }
  }

  const manifest = JSON.parse(readFileSync(join(ROOT, "MANIFEST.json"), "utf-8"));
  for (const entry of manifest.vectors) {
    const vector = JSON.parse(readFileSync(join(ROOT, "vectors", entry.file), "utf-8"));
    let verdict, reason;
    try {
      [verdict, reason] = CHECKS[vector.kind](vector.input);
    } catch (e) {
      verdict = "malformed";
      reason = null;
    }
    const ok = verdict === entry.expect && (verdict === "valid" || reason === entry.reason);
    if (!ok) bad++;
    console.log(`${ok ? "MATCH " : "DIVERGE"} ${entry.file} -> ${verdict}${reason ? "/" + reason : ""}`);
  }

  const files = readdirSync(join(ROOT, "vectors")).filter((f) => f.endsWith(".json"));
  if (files.length !== manifest.vectors.length) {
    bad++;
    console.log(`DIVERGE vector count: ${files.length} files vs ${manifest.vectors.length} manifest entries`);
  }

  console.log(bad === 0 ? `\nCROSS-CHECK OK: ${manifest.vectors.length} vectors agree across both implementations` : `\n${bad} DIVERGENCE(S)`);
  process.exit(bad === 0 ? 0 : 1);
}
