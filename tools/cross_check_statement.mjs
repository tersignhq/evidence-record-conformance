// Chain-statement profile, SECOND implementation (TypeScript stack: viem for keccak256 and secp256k1 recovery, node's
// sha256), by the same authors as statement/verify_statement.py, run over every vector in statement/MANIFEST.json.
// The rules, their order and the reason codes are the runner's; this file implements them again rather than importing
// them. It shares the core TypeScript engine's canonical form (tools/cross_check_ts.mjs `canon`), as the Python runner
// shares verify.py's. Run:  npm i viem  (in the repo root), then  node tools/cross_check_statement.mjs
//
// Profile note: the served body is TEXT. JSON.parse keeps the last of two equal member names and turns the token 1.0
// into 1, so the duplicate-member, number-token and nesting rules are checked on the text itself (scanText), after
// JSON.parse has accepted its syntax. JSON.parse also joins a surrogate written raw in the text with an escaped one next
// to it into a pair, which a code-point reader never does, so a surrogate code unit written raw that is not half of a
// raw pair is refused on the text before the decoded strings are read.
import { concatHex, keccak256, numberToHex, recoverMessageAddress, stringToHex } from "viem";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { canon } from "./cross_check_ts.mjs";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

const SCHEMA = "tersign-chain-statement-v1";
const COMMITMENT_SCHEMA = "tersign-chain-commitment-v1";
const SIGNATURE_PREFIX = `${SCHEMA}:`;
const LIMITS =
  "This statement covers only records counter-signed on this chain at ledger seq from..to, and the attachment entries it lists. " +
  "Records never submitted to this ledger are outside it, and nothing here says the issuer issued no other records. " +
  "An attachment entry names the position of a record on this chain at or before seq to; Tersign lists entries and does not verify them. " +
  "Binding declared: the attachment is the record at that position, bound by the counter-signed link at that position. " +
  "Binding sealed: the attachment is sealed inside the v2 chain link at that position. " +
  "Issuer-sequence gaps and duplicates are reported only for records whose counter-signed link binds the issuer seq, only between the lowest and highest such seq in the range, and only against records counter-signed at or before seq to; an omission after the highest bound seq is not detectable. " +
  "It restates the ledger's contemporaneous counter-signatures and the anchor named, and its own signature adds no earlier time. " +
  "It is not a statement about record content, tax treatment or compliance with any law.";
const SCOPES = ["range"];
const ATTACHMENTS_VERSION = 1;
const BINDINGS = ["declared", "sealed"];
const ANCHOR_STATUSES = ["pending", "confirmed"];
const MAX_RANGE = 5000;
const LIST_CAP = 256;
const BRIDGE_CAP = 1000;
const MAX_DEPTH = 64;
const TYPE_HEX_DIGITS = 32;
const SAFE = 2n ** 53n - 1n;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const ZERO32 = `0x${"00".repeat(32)}`;
const ACC_GENESIS = keccak256(stringToHex(COMMITMENT_SCHEMA));
const REJECT_REASONS = ["parse", "shape", "scope", "attachments_version", "attachment_entry", "range", "chain_key",
  "consistency", "anchor", "digest", "signature", "signer", "records"];
const ENVELOPE = ["statement", "statementDigest", "signature", "signer"];
const MEMBERS = ["anchor", "attachments", "before", "bridge", "chain", "commitmentSchema", "issuerSeq", "ledger", "limits",
  "linkVersions", "range", "schema", "scope", "through"];
const ANCHOR_MEMBERS = ["acc", "anchoredDigest", "batchRoot", "bitcoinBlockHeight", "head", "id", "proofUrl", "seq", "status",
  "subjectDigest", "subjectSchema"];
const ISSUER_COUNTS = ["boundRecords", "unboundRecords", "absentRecords", "listCap"];

const HEX32 = /^0x[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const SIGNATURE = /^0x[0-9a-fA-F]{130}$/;
const TYPE = /^[a-z][a-z0-9-]{0,62}[a-z0-9]$/;
const HEXLIKE_TYPE = /^[0-9a-f-]+$/;
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const isObj = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
const isInt = (v) => typeof v === "number" && Number.isSafeInteger(v);
const isHex32 = (v) => typeof v === "string" && HEX32.test(v);
const exactly = (o, members) => isObj(o) && Object.keys(o).length === members.length && members.every((m) => own(o, m));
const sha256hex = (hex) => "0x" + createHash("sha256").update(Buffer.from(hex.slice(2), "hex")).digest("hex");
const digestOf = (v) => keccak256(stringToHex(canon(v)));
const accStep = (acc, link) => keccak256(concatHex([acc, link]));
const chainLink = (artifact, prev, seq) => keccak256(concatHex([artifact, prev ?? ZERO32, numberToHex(seq, { size: 8 })]));

// The text-level parse rules, over text JSON.parse has already accepted: objects and arrays nested more than MAX_DEPTH
// deep (the body object counts 1), a member name twice in one object, and a number token that is not an integer in
// [-(2**53 - 1), 2**53 - 1]. Returns true when the text breaks one.
function scanText(text) {
  const stack = [];
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      const top = stack[stack.length - 1];
      if (top && top.keys && top.expectKey) {
        const name = JSON.parse(text.slice(i, j + 1));
        if (top.keys.has(name)) return true;
        top.keys.add(name);
        top.expectKey = false;
      }
      i = j + 1;
    } else if (c === "{" || c === "[") {
      stack.push(c === "{" ? { keys: new Set(), expectKey: true } : { keys: null, expectKey: false });
      if (stack.length > MAX_DEPTH) return true;
      i++;
    } else if (c === "}" || c === "]") {
      stack.pop();
      i++;
    } else if (c === ",") {
      const top = stack[stack.length - 1];
      if (top && top.keys) top.expectKey = true;
      i++;
    } else if (c === "-" || (c >= "0" && c <= "9")) {
      let j = i + 1;
      while (j < text.length && /[0-9.eE+-]/.test(text[j])) j++;
      const token = text.slice(i, j);
      if (/[.eE]/.test(token)) return true;
      const v = BigInt(token);
      if (v > SAFE || v < -SAFE) return true;
      i = j;
    } else i++;
  }
  return false;
}

function illFormed(v) {
  if (typeof v === "string") return LONE_SURROGATE.test(v);
  if (Array.isArray(v)) return v.some(illFormed);
  if (isObj(v)) return Object.keys(v).some((k) => LONE_SURROGATE.test(k) || illFormed(v[k]));
  return false;
}

function typeOk(t) {
  if (typeof t !== "string" || !TYPE.test(t)) return false;
  return !(HEXLIKE_TYPE.test(t) && t.replace(/-/g, "").length >= TYPE_HEX_DIGITS);
}

// null, or the reason of the first rule the statement breaks (the order of statement/verify_statement.py).
function statementRefusal(st) {
  if (illFormed(st)) return "parse";
  if (!exactly(st, MEMBERS)) return "shape";
  if (st.schema !== SCHEMA || st.limits !== LIMITS || st.commitmentSchema !== COMMITMENT_SCHEMA) return "shape";
  if (typeof st.ledger !== "string" || !ADDRESS.test(st.ledger)) return "shape";
  if (typeof st.scope !== "string" || !SCOPES.includes(st.scope)) return "scope";

  const chain = st.chain;
  if (!isObj(chain) || !own(chain, "sellerId") || !Object.keys(chain).every((k) => k === "sellerId" || k === "key")) return "shape";
  if (typeof chain.sellerId !== "string" || chain.sellerId === "") return "shape";
  if (own(chain, "key") && (!isHex32(chain.key) || chain.key === ZERO32)) return "chain_key";

  if (!exactly(st.range, ["from", "to"])) return "shape";
  const { from, to } = st.range;
  if (!isInt(from) || !isInt(to) || from < 1 || from > to) return "range";
  if (to - from + 1 > MAX_RANGE) return "range";
  const count = to - from + 1;

  const att = st.attachments;
  if (!exactly(att, ["version", "entries"])) return "attachments_version";
  if (!isInt(att.version) || att.version !== ATTACHMENTS_VERSION) return "attachments_version";
  if (!Array.isArray(att.entries)) return "attachment_entry";
  let last = 0;
  for (const e of att.entries) {
    if (!exactly(e, ["position", "type", "binding"])) return "attachment_entry";
    if (!isInt(e.position) || e.position <= last || e.position > to) return "attachment_entry";
    last = e.position;
    if (!typeOk(e.type)) return "attachment_entry";
    if (typeof e.binding !== "string" || !BINDINGS.includes(e.binding)) return "attachment_entry";
  }

  const { before, through } = st;
  if (!exactly(before, ["seq", "head", "acc"]) || !isInt(before.seq) || !isHex32(before.acc) || !(before.head === null || isHex32(before.head))) return "shape";
  if (!exactly(through, ["seq", "head", "acc"]) || !isInt(through.seq) || !isHex32(through.acc) || !isHex32(through.head)) return "shape";
  if (before.seq !== from - 1) return "consistency";
  if ((before.seq === 0) !== (before.head === null)) return "consistency";
  if (before.seq === 0 && before.acc !== ACC_GENESIS) return "consistency";
  if (through.seq !== to) return "consistency";

  const lv = st.linkVersions;
  if (!exactly(lv, ["v1", "v2"]) || !isInt(lv.v1) || !isInt(lv.v2) || lv.v1 < 0 || lv.v2 < 0) return "shape";
  if (lv.v1 + lv.v2 !== count) return "consistency";
  const firstV2 = from + lv.v1;
  if (lv.v1 > 0 && att.entries.some((e) => e.binding === "sealed" && e.position < firstV2)) return "attachment_entry";

  const iq = st.issuerSeq;
  if (!exactly(iq, [...ISSUER_COUNTS, "series", "truncated"]) || !ISSUER_COUNTS.every((k) => isInt(iq[k]) && iq[k] >= 0) ||
    typeof iq.truncated !== "boolean" || !Array.isArray(iq.series)) return "shape";
  if (iq.listCap !== LIST_CAP) return "consistency";
  if (iq.unboundRecords !== lv.v1 || iq.boundRecords + iq.absentRecords !== lv.v2) return "consistency";
  if (iq.boundRecords === 0 && iq.series.length !== 0) return "consistency";
  if (iq.series.length > LIST_CAP) return "consistency";
  // rules.issuer_report: a series is reported only when a bound record in the range names it, and a record names one
  // series, so there are at most boundRecords series.
  if (iq.series.length > iq.boundRecords) return "consistency";
  const grouped = new Set(); // every ledger seq a duplicate names, across all series
  let lastSeries = "";
  for (const s of iq.series) {
    if (!exactly(s, ["series", "min", "max", "missing", "duplicates"]) || !isHex32(s.series) || !isInt(s.min) || !isInt(s.max) ||
      !Array.isArray(s.missing) || !Array.isArray(s.duplicates)) return "shape";
    if (s.series <= lastSeries || s.min < 0 || s.min > s.max) return "consistency";
    lastSeries = s.series;
    let prev = -1;
    for (const m of s.missing) {
      if (!isInt(m) || m <= prev || m < s.min || m > s.max) return "consistency";
      prev = m;
    }
    if (s.missing.length > LIST_CAP || s.duplicates.length > LIST_CAP) return "consistency";
    const missing = new Set(s.missing);
    for (const d of s.duplicates) {
      if (!exactly(d, ["seq", "correctionSeq", "ledgerSeqs"]) || !isInt(d.seq) ||
        !(d.correctionSeq === null || (isInt(d.correctionSeq) && d.correctionSeq >= 0)) || !Array.isArray(d.ledgerSeqs)) return "shape";
      const ls = d.ledgerSeqs;
      if (ls.length < 2 || !ls.every((q, k) => isInt(q) && q >= 1 && q <= to && (k === 0 || q > ls[k - 1]))) return "consistency";
      // rules.issuer_report: one of a duplicate's bindings is in the range, over which min and max are taken; an
      // original binding makes its number present; and a record binds one (series, seq, correctionSeq).
      if (d.seq < s.min || d.seq > s.max) return "consistency";
      if (d.correctionSeq === null && missing.has(d.seq)) return "consistency";
      if (ls.some((q) => grouped.has(q))) return "consistency";
      for (const q of ls) grouped.add(q);
    }
  }

  const a = st.anchor;
  const bridge = st.bridge;
  if (a === null) return bridge === null ? null : "anchor";
  if (!exactly(a, ANCHOR_MEMBERS)) return "anchor";
  if (a.subjectSchema !== st.commitmentSchema) return "anchor";
  if (!isInt(a.seq) || a.seq < to) return "anchor";
  if (![a.head, a.acc, a.subjectDigest, a.anchoredDigest].every(isHex32)) return "anchor";
  if (!(a.batchRoot === null || isHex32(a.batchRoot))) return "anchor";
  if (typeof a.status !== "string" || !ANCHOR_STATUSES.includes(a.status)) return "anchor";
  if (!(a.bitcoinBlockHeight === null || (isInt(a.bitcoinBlockHeight) && a.bitcoinBlockHeight >= 0))) return "anchor";
  if (a.subjectDigest !== digestOf({ acc: a.acc, head: a.head, schema: a.subjectSchema, seq: a.seq })) return "anchor";
  if (a.id !== `seller:${a.subjectDigest}`) return "anchor";
  if (a.anchoredDigest !== sha256hex(a.subjectDigest)) return "anchor";
  if (typeof a.proofUrl !== "string" || !a.proofUrl.endsWith(`/v1/anchors/${a.id}/proof.ots`)) return "anchor";
  if (a.seq === to && (a.acc !== through.acc || a.head !== through.head)) return "anchor";
  if (a.seq === to || a.seq - to > BRIDGE_CAP) return bridge === null ? null : "anchor";
  if (!exactly(bridge, ["from", "to", "links"]) || bridge.from !== to + 1 || bridge.to !== a.seq || !Array.isArray(bridge.links)) return "anchor";
  if (bridge.links.length !== a.seq - to || !bridge.links.every(isHex32)) return "anchor";
  return bridge.links.reduce(accStep, through.acc) === a.acc ? null : "anchor";
}

// The address the signature recovers to (lower case), or null when it is not the one accepted encoding or defines no key.
async function recoverSigner(statementDigest, signature) {
  if (typeof signature !== "string" || !SIGNATURE.test(signature)) return null;
  const v = Number.parseInt(signature.slice(130, 132), 16);
  if (v !== 27 && v !== 28) return null;
  const r = BigInt(`0x${signature.slice(2, 66)}`);
  const s = BigInt(`0x${signature.slice(66, 130)}`);
  if (s > N / 2n || r < 1n || r >= N || s < 1n) return null;
  try {
    return (await recoverMessageAddress({ message: SIGNATURE_PREFIX + statementDigest, signature })).toLowerCase();
  } catch {
    return null;
  }
}

/** [verdict, reason] for one vector input {body_text, expected_signer?, records?}. */
export async function checkStatement(input) {
  const text = input.body_text;
  let body;
  try {
    if (typeof text !== "string") return ["reject", "parse"];
    if (LONE_SURROGATE.test(text)) return ["reject", "parse"];
    body = JSON.parse(text);
    if (scanText(text) || illFormed(body)) return ["reject", "parse"];
  } catch {
    return ["reject", "parse"];
  }
  if (!exactly(body, ENVELOPE)) return ["reject", "shape"];
  const st = body.statement;
  const why = statementRefusal(st);
  if (why !== null) return ["reject", why];
  if (body.signer !== st.ledger) return ["reject", "shape"];
  const digest = digestOf(st);
  if (body.statementDigest !== digest) return ["reject", "digest"];
  const who = await recoverSigner(digest, body.signature);
  if (who === null || who !== st.ledger.toLowerCase()) return ["reject", "signature"];
  if (own(input, "expected_signer") && input.expected_signer.toLowerCase() !== st.ledger.toLowerCase()) return ["reject", "signer"];
  if (own(input, "records")) {
    const recs = input.records;
    const { from, to } = st.range;
    if (recs.length !== to - from + 1 || !recs.every(isHex32)) return ["reject", "records"];
    let acc = st.before.acc;
    let prev = st.before.head;
    recs.forEach((d, k) => {
      acc = accStep(acc, chainLink(d, prev, from + k));
      prev = d;
    });
    if (acc !== st.through.acc || prev !== st.through.head) return ["reject", "records"];
  }
  return ["valid", null];
}

export const PINNED = {
  schema: SCHEMA, commitment_schema: COMMITMENT_SCHEMA, signature_prefix: SIGNATURE_PREFIX, limits: LIMITS, scopes: SCOPES,
  attachments_version: ATTACHMENTS_VERSION, bindings: BINDINGS, anchor_statuses: ANCHOR_STATUSES, max_range: MAX_RANGE,
  list_cap: LIST_CAP, bridge_cap: BRIDGE_CAP, max_depth: MAX_DEPTH, type_hex_digits: TYPE_HEX_DIGITS, statement_members: MEMBERS,
  anchor_members: ANCHOR_MEMBERS, envelope: ENVELOPE,
};

// ------------------------------------------------------------------------------ runner (guarded: importable)
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const manifest = JSON.parse(readFileSync(join(ROOT, "statement", "MANIFEST.json"), "utf-8"));
  let bad = 0;
  for (const [k, want] of Object.entries(PINNED)) {
    if (JSON.stringify(manifest.format?.[k]) !== JSON.stringify(want)) {
      bad++;
      console.log(`DIVERGE format.${k}: statement/MANIFEST.json differs from the value pinned in this engine`);
    }
  }
  if (JSON.stringify(manifest.reject_reasons) !== JSON.stringify(REJECT_REASONS)) {
    bad++;
    console.log("DIVERGE reject_reasons: statement/MANIFEST.json differs from the closure pinned in this engine");
  }
  const used = new Set();
  for (const entry of manifest.vectors) {
    const vector = JSON.parse(readFileSync(join(ROOT, "statement", "vectors", entry.file), "utf-8"));
    let verdict, reason;
    try {
      [verdict, reason] = await checkStatement(vector.input);
    } catch (e) {
      [verdict, reason] = ["crash", e.constructor.name];
    }
    const ok = verdict === entry.expect && (reason ?? null) === (entry.reason ?? null);
    if (entry.expect === "reject") used.add(entry.reason);
    if (!ok) bad++;
    console.log(`${ok ? "MATCH  " : "DIVERGE"} ${entry.file} -> ${verdict}${reason ? "/" + reason : ""}`);
  }
  for (const r of REJECT_REASONS) {
    if (!used.has(r)) {
      bad++;
      console.log(`DIVERGE reject reason never exercised: ${r}`);
    }
  }
  const files = readdirSync(join(ROOT, "statement", "vectors")).filter((f) => f.endsWith(".json"));
  if (files.length !== manifest.vectors.length || manifest.vectors.length === 0) {
    bad++;
    console.log(`DIVERGE vector count: ${files.length} files vs ${manifest.vectors.length} manifest entries`);
  }
  console.log(bad === 0
    ? `\nSTATEMENT CROSS-CHECK OK: ${manifest.vectors.length} vectors agree across both implementations`
    : `\n${bad} DIVERGENCE(S)`);
  process.exit(bad === 0 ? 0 : 1);
}
