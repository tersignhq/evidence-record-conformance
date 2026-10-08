// Cross-implementation measurement: a SECOND TypeScript-stack implementation of every
// check in verify.py, by the same authors, run over the full committed corpus. Two implementations,
// one vector set, byte-level agreement required — conformance by measurement, not by
// resemblance. Run:  npm i viem  (in the repo root), then  node tools/cross_check_ts.mjs
//
// Profile note: JSON.parse keeps the LAST of duplicate object names where the Python
// loader rejects the file outright. Vector FILES carry no duplicate names, so the two
// loaders agree over the committed set; duplicate names INSIDE a payload_text are checked
// by both engines (v0.5.4, n41/n42).
import { keccak256, concatHex, numberToHex, stringToHex } from "viem";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

// ---------------------------------------------------------------- canonical form (JCS)
// v0.5.5 — a name or string value holding a surrogate that is not half of a pair has no canonical
// form (RFC 7493 §2.1; RFC 8785 §3.2.2.2 requires a canonicalizer to terminate on it). Since
// ES2019 JSON.stringify writes such a code unit as a \u escape instead of failing, while verify.py
// kept it as is, so the engines read one input differently (n81-n84 forked them until v0.5.5); both
// now reject it before serializing.
// Mirrors verify.py's _well_formed: a high half followed by a low half is one code point, either
// half anywhere else is unpaired.
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
class NotIJSONText extends Error {}
const wellFormed = (s) => {
  if (LONE_SURROGATE.test(s)) {
    throw new NotIJSONText("a name or string value holds a surrogate that is not half of a pair");
  }
  return s;
};
function canon(v) {
  if (v === null || v === true || v === false) return JSON.stringify(v);
  if (typeof v === "string") return JSON.stringify(wellFormed(v));
  if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new NumberDomainError("non-integer JSON number in the digest domain");
    if (!Number.isSafeInteger(v)) throw new NumberDomainError("outside the I-JSON interoperable range (|n| > 2^53-1)");
    return String(v);
  }
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  // Default JS string comparison IS UTF-16 code-unit order — the JCS rule. Names are checked
  // before they are sorted, as in verify.py.
  const keys = Object.keys(v);
  keys.forEach(wellFormed);
  return "{" + keys.sort().map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
}
class NumberDomainError extends Error {}

const digestOf = (v) => keccak256(stringToHex(canon(v)));
const GENESIS_PREV = `0x${"0".repeat(64)}`;
const chainLink = (artifact, prev, seq) =>
  keccak256(concatHex([artifact, prev ?? GENESIS_PREV, numberToHex(seq, { size: 8 })]));
const sha256hex = (hex) => "0x" + createHash("sha256").update(Buffer.from(hex.slice(2), "hex")).digest("hex");
// Chain-commitment accumulator (v0.5.0) — mirrors verify.py's ACC_GENESIS / chain_acc_step:
// a tagged seed (utf8 of the schema string, never the zero link-genesis sentinel), then
// keccak256(acc || link) over raw 64 bytes, acc first.
const ACC_GENESIS = keccak256(stringToHex("tersign-chain-commitment-v1"));
const chainAccStep = (acc, link) => keccak256(concatHex([acc, link]));

// -------------------------------------------------------- identifier normalization
const ADDR_RE = /^0x[0-9a-f]{40}$/;
const DIGEST_RE = /^0x[0-9a-f]{64}$/;
// Second identity syntax (2026-08-19): scheme-qualified identifiers, strict grammar so the
// aliasing defence still holds — no whitespace, no format characters; case + trailing punctuation folded.
const URN_RE = /^[a-z][a-z0-9+.-]*:[\x21-\x7e]+$/;
// v0.5.4 — mirrors verify.py's _norm_addr step for step: ASCII grammar checked in either case,
// percent-encoded UNRESERVED characters decoded (RFC 3986 §6.2.2.2, either hex case, one
// left-to-right pass, never repeated), any `%` or `?` left over fails closed, a dot-segment in
// the path fails closed, then case fold, then every trailing / . # stripped, a `#` left after
// that fails closed, and the result must still match URN_RE (a non-empty path).
const URN_ANY_CASE_RE = /^[A-Za-z][A-Za-z0-9+.-]*:[\x21-\x7e]+$/;
const UNRESERVED_RE = /^[A-Za-z0-9._~-]$/;
const decodeUnreserved = (s) =>
  s.replace(/%([0-9A-Fa-f]{2})/g, (m, h) => {
    const c = String.fromCharCode(parseInt(h, 16));
    return UNRESERVED_RE.test(c) ? c : m;
  });
// verify.py's WHITESPACE (the Unicode White_Space property), by code point — never
// String.prototype.trim(), which also strips U+FEFF (a format character, not White_Space) and
// misses U+0085 (a control character that is White_Space).
const WHITESPACE = new Set(
  [0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0, 0x1680,
    0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a,
    0x2028, 0x2029, 0x202f, 0x205f, 0x3000].map((c) => String.fromCharCode(c)),
);
const stripWS = (s) => {
  let i = 0;
  let j = s.length;
  while (i < j && WHITESPACE.has(s[i])) i++;
  while (j > i && WHITESPACE.has(s[j - 1])) j--;
  return s.slice(i, j);
};
const normAddr = (a) => {
  if (typeof a !== "string") return null;
  const t = stripWS(a);
  const low = t.toLowerCase();
  if (ADDR_RE.test(low)) return low;
  // Fold toward "same party". A verifier that does not own a scheme's equivalence rules must
  // treat possibly-equal identifiers as equal, and cannot evaluate one it cannot decide.
  if (!URN_ANY_CASE_RE.test(t)) return null;
  const decoded = decodeUnreserved(t);
  if (decoded.includes("%") || decoded.includes("?")) return null;
  // RFC 3986 §3.3 dot-segments in the path (scheme colon to the first ? or #), checked before
  // the trailing strip — mirrors verify.py.
  const path = decoded.slice(decoded.indexOf(":") + 1).split(/[?#]/)[0];
  if (path.split("/").some((seg) => seg === "." || seg === "..")) return null;
  const id = decoded.toLowerCase().replace(/[\/.#]+$/, "");
  if (id.includes("#")) return null;
  return URN_RE.test(id) ? id : null;
};
// verify.py's _address_key: a 0x-address keys to itself; a scheme-qualified identifier whose
// final colon-separated component is a 0x-address keys to that address, whatever the scheme
// (CAIP-10, did:pkh, did:ethr, ethereum:, acct:; n63-n66, n69).
const addressKey = (id) => {
  if (ADDR_RE.test(id)) return id;
  const last = id.slice(id.lastIndexOf(":") + 1);
  return ADDR_RE.test(last) ? last : null;
};
const normDigest = (x) => {
  if (typeof x !== "string") return null;
  const d = stripWS(x).toLowerCase();
  return DIGEST_RE.test(d) ? d : null;
};

// Commitment derivation — mirrors verify.py's derive_settlement_commits /
// derive_delivery_commits / derive_record_commits, same branch shapes, same return shapes.
const deriveSettlementCommits = (r) => {
  const commits = [];
  if (r.success === true && typeof r.transaction === "string" && stripWS(r.transaction) !== "") commits.push("settlement");
  if (typeof r.network === "string" && stripWS(r.network) !== "") commits.push("network");
  return commits;
};
// Key PRESENCE decides evaluability (`in` — identical semantics to Python's `in`, the
// record_commits lesson); the recompute decides commitment. keccak256 over utf8 bytes in
// both engines: stringToHex encodes utf8, as Python's .encode("utf-8") does.
const deriveDeliveryCommits = (inp) => {
  if (!("deliverable_bytes" in inp) && !("deliverable_digest" in inp)) return null;
  const presented = inp.deliverable_bytes;
  const declared = normDigest(inp.deliverable_digest);
  if (typeof presented !== "string" || declared === null) return [];
  // A lone surrogate has no UTF-8 form: Python's .encode raises, TextEncoder would
  // substitute U+FFFD and hash on. Both engines read it as presented-and-empty.
  if (LONE_SURROGATE.test(presented)) return [];
  if (keccak256(stringToHex(presented)) === declared) return ["delivery"];
  return [];
};
const deriveRecordCommits = (inp) => {
  const parts = [];
  // Array excluded to match Python's isinstance(dict) exactly.
  if (inp.settlement_result && typeof inp.settlement_result === "object" && !Array.isArray(inp.settlement_result)) {
    parts.push(deriveSettlementCommits(inp.settlement_result));
  }
  const delivery = deriveDeliveryCommits(inp);
  if (delivery !== null) parts.push(delivery);
  if (parts.length === 0) return null;
  return parts.flat();
};
const isSeq = (x) => typeof x === "number" && Number.isInteger(x);
// The chain_link sequence domain, [1, SEQ_MAX] (v0.5.5): the I-JSON integer bound. Past it a
// double cannot tell adjacent integers apart, so this engine and verify.py would recompute
// different links for one token (2^53+1 forked them until v0.5.5).
const SEQ_MAX = 2 ** 53 - 1;

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

// v0.5.1 — number-TOKEN class on integer fields (B25). JSON.parse collapses the wire token
// `3.0` (or `3e0`) to the integer Number 3, while Python's json keeps it a float and every
// integer predicate in verify.py (`_is_seq`, the anchor position/covered/attested checks)
// rejects it. Loading vectors and differential cases through this reviver maps any number
// whose SOURCE token carries a fraction or exponent part to NaN, so `Number.isInteger`
// fails exactly where Python's `isinstance(x, int)` fails and both engines agree on the same
// wire bytes. (Node >= 21 reviver source access; the canonical_bytes raw-text pathway below
// keeps its own, throwing, variant because that kind names the reason `number_domain_reject`.)
export function parseVectorText(text) {
  return JSON.parse(text, (_key, value, context) => {
    if (typeof value === "number" && context && typeof context.source === "string"
        && /[.eE]/.test(context.source)) {
      return Number.NaN;
    }
    return value;
  });
}

function parseDigestDomainText(text) {
  return JSON.parse(text, (_key, value, context) => {
    if (typeof value === "number" && context && typeof context.source === "string"
        && /[.eE]/.test(context.source)) {
      throw new NumberDomainError("non-integer JSON number token in the digest domain");
    }
    return value;
  });
}

// v0.5.4 — the raw-text pathway carries the loader's rules (p30/n41-n44, issue #10). JSON.parse
// keeps the LAST of duplicate names and exposes no pairs hook, so duplicates are found by a
// scan over text JSON.parse has already accepted: one key set per open object, each name
// DECODED (JSON.parse of the string token) before comparison, matching Python's
// object_pairs_hook — a raw-token comparison misses an escaped spelling of the same name (n42),
// and a key set wider than one object rejects a name repeated across distinct objects (p30).
// Runs in full BEFORE any number token is read, as verify.py's first pass does.
function duplicateName(text) {
  const stack = [];
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      const top = stack[stack.length - 1];
      if (top && top.obj && top.atKey) {
        const name = JSON.parse(text.slice(i, j + 1));
        if (top.keys.has(name)) return name;
        top.keys.add(name);
        top.atKey = false;
      }
      i = j;
    } else if (c === "{") stack.push({ obj: true, keys: new Set(), atKey: true });
    else if (c === "[") stack.push({ obj: false });
    else if (c === "}" || c === "]") stack.pop();
    else if (c === ",") {
      const top = stack[stack.length - 1];
      if (top && top.obj) top.atKey = true;
    }
  }
  return null;
}
function assertIJSONText(text) {
  if (typeof text !== "string") throw new NotIJSONText("payload_text must be a JSON string");
  try {
    JSON.parse(text);
  } catch (e) {
    if (e instanceof SyntaxError) throw new NotIJSONText("payload_text is not JSON text");
    throw e;
  }
  if (duplicateName(text) !== null) throw new NotIJSONText("duplicate object name — not valid I-JSON");
  // v0.5.5: an unpaired surrogate in a name or a string value is part of the text's shape, found
  // here before any number token is read, as verify.py finds it on its first pass.
  checkStrings(JSON.parse(text));
}
function checkStrings(node) {
  if (typeof node === "string") wellFormed(node);
  else if (Array.isArray(node)) node.forEach(checkStrings);
  else if (node !== null && typeof node === "object") {
    for (const k of Object.keys(node)) {
      wellFormed(k);
      checkStrings(node[k]);
    }
  }
}

// ------------------------------------------------------------------------ vector kinds
const CHECKS = {
  digest_recompute(inp) {
    let got;
    try {
      got = digestOf(inp.payload);
    } catch (e) {
      if (e instanceof NotIJSONText) return ["reject", "canonicalization_reject"];
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
      // "payload_text" in inp (key presence, never a value sentinel): raw-text pathway
      // for distinctions JSON.parse erases. The digest-domain boundary is the number
      // TOKEN class: a token with a fraction or exponent part (2.0, 1e2) rejects even
      // when integer-valued, because JSON.parse collapses it to an integer Number and
      // the two engines would otherwise diverge on the same wire bytes (Python's json
      // preserves float-ness and its canonical() already rejects). Enforced here at the
      // token level via JSON.parse source access (Node >= 21).
      if ("payload_text" in inp) assertIJSONText(inp.payload_text);
      const payload = "payload_text" in inp ? parseDigestDomainText(inp.payload_text) : inp.payload;
      got = canon(payload);
    } catch (e) {
      if (e instanceof NotIJSONText) return ["reject", "canonicalization_reject"];
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
    if (!isSeq(inp.seq) || inp.seq < 1 || inp.seq > SEQ_MAX) return ["reject", "continuity_reject"];
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
  // Mirrors verify.py's check_chain_commitment: chain_set first (any non-valid verdict
  // propagates unchanged), then head.acc must parse and must equal the fold of
  // keccak256(acc || link) over the RECOMPUTED links (prev = previous artifact digest) from
  // ACC_GENESIS. Same branch order, same reason codes.
  chain_commitment(inp) {
    const [verdict, reason] = CHECKS.chain_set(inp);
    if (verdict !== "valid") return [verdict, reason];
    const claimed = normDigest(inp.head.acc);
    if (claimed === null) return ["reject", "continuity_reject"];
    const records = [...inp.records].sort((a, b) => a.seq - b.seq);
    let acc = ACC_GENESIS;
    let prev = null;
    for (const r of records) {
      const artifact = normDigest(r.artifact_digest);
      acc = chainAccStep(acc, chainLink(artifact, prev, r.seq));
      prev = artifact;
    }
    return acc === claimed ? ["valid", null] : ["reject", "continuity_reject"];
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
    const partyKeys = new Set();
    for (const p of inp.parties) {
      const norm = normAddr(p);
      if (norm === null) return ["reject", "independence_reject"];
      parties.add(norm);
      if (addressKey(norm) !== null) partyKeys.add(addressKey(norm));
    }
    if (!Array.isArray(inp.attestations) || inp.attestations.length === 0) return ["reject", "independence_reject"];
    let outside = 0;
    for (const a of inp.attestations) {
      if (typeof a !== "object" || a === null || Array.isArray(a) || !("by" in a)) return ["reject", "independence_reject"];
      const by = normAddr(a.by);
      if (by === null) return ["reject", "independence_reject"];
      if (!parties.has(by) && !partyKeys.has(addressKey(by))) outside++;
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
      // Mirrors verify.py's derive_record_commits — settlement/network off the settlement
      // result (§5.3.2 makes `transaction: ""` a failed settlement, so success+empty commits
      // to nothing resolvable), delivery off the presented bytes. null = nothing presented;
      // [] = presented and found to commit to nothing. Both engines must share this shape.
      const committed = deriveRecordCommits(inp);
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
    const vector = parseVectorText(readFileSync(join(ROOT, "vectors", entry.file), "utf-8"));
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
