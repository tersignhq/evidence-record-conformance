#!/usr/bin/env python3
"""EIP-712 payload-signature profile (x402 offer-and-receipt Receipt), stdlib only + the suite's keccak.py.
Pinned (never read from the record): domain {name: "x402 receipt", version: "1", chainId: 1}, primaryType Receipt,
Receipt(uint256 version,string network,string resourceUrl,string payer,uint256 issuedAt,string transaction).
Input: {format, payload, signature, signer}, exactly those four top-level keys, else malformed_input (an envelope
carrying extra keys such as domain or types is not silently ignored). Order: format == "eip712" else unsupported_format;
payload carries all six Receipt fields (version, network, resourceUrl, payer, issuedAt, transaction) and no field the type
does not have; uint256 fields are integer tokens in [0, 2**256); string fields are str and UTF-8 encodable (a lone UTF-16
surrogate rejects instead of crashing the hasher); otherwise malformed_input. The payload is hashed exactly as transmitted
(x402 extension-offer-and-receipt.md Sec 5.5 step 3): an omitted `transaction` is a missing field, not "" -- the extension
asks signers to SET unused fields to "" and verifiers to treat "" as equivalent to absence, which maps "" to absence and
does not license filling an omitted key in (en10). version must equal the integer 1; a well-typed but different version rejects as unsupported_version, not
malformed_input -- the schema is understood, just not this edition of it. signer a 0x-address (normalized as the
core's identifier_normalization) else malformed_input; signature exactly 0x + 130 hex, v in {27, 28} else
malformed_signature; low-s before recovery else non_canonical_s; recovery over the EIP-712 digest defines a point else
unrecoverable; its address equals signer else signer_mismatch. String fields are hashed exactly as written: `payer` is a
string, so a re-cased address is a different message (unlike an identifier)."""
import glob, json, os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.dirname(HERE))
from keccak import keccak256  # noqa: E402
import secp256k1_recover as S  # noqa: E402
from verify_crypto import norm_hex, _SIG_RE  # noqa: E402

DOMAIN = {"name": "x402 receipt", "version": "1", "chainId": 1}
DOMAIN_TYPE = "EIP712Domain(string name,string version,uint256 chainId)"
RECEIPT_TYPE = "Receipt(uint256 version,string network,string resourceUrl,string payer,uint256 issuedAt,string transaction)"
FIELDS = (("version", "uint256"), ("network", "string"), ("resourceUrl", "string"), ("payer", "string"),
          ("issuedAt", "uint256"), ("transaction", "string"))
REQUIRED_FIELDS = {k for k, _ in FIELDS}
ALL_FIELD_KEYS = {k for k, _ in FIELDS}
TOP_LEVEL_KEYS = {"format", "payload", "signature", "signer"}
SUPPORTED_VERSION = 1
REJECT_REASONS = ("unsupported_format", "malformed_input", "unsupported_version", "malformed_signature",
                   "non_canonical_s", "unrecoverable", "signer_mismatch")


def _u(x):
    return int(x).to_bytes(32, "big")


def _h(s):
    return keccak256(s.encode("utf-8"))


def digest(message, domain=DOMAIN, receipt_type=RECEIPT_TYPE, fields=FIELDS):
    dom = keccak256(_h(DOMAIN_TYPE) + _h(domain["name"]) + _h(domain["version"]) + _u(domain["chainId"]))
    enc = b"".join(
        _u(message[k]) if t == "uint256" else _h(message[k])
        for k, t in fields
    )
    return keccak256(b"\x19\x01" + dom + keccak256(_h(receipt_type) + enc))


def check(inp):
    if not isinstance(inp, dict) or set(inp) != TOP_LEVEL_KEYS:
        return "reject", "malformed_input"
    if inp.get("format") != "eip712":
        return "reject", "unsupported_format"
    m = inp.get("payload")
    if not isinstance(m, dict) or set(m) != ALL_FIELD_KEYS:
        return "reject", "malformed_input"
    for k, t in FIELDS:
        v = m[k]
        if t == "uint256" and not (isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 2 ** 256):
            return "reject", "malformed_input"
        if t == "string":
            if not isinstance(v, str):
                return "reject", "malformed_input"
            try:
                v.encode("utf-8")
            except UnicodeEncodeError:
                return "reject", "malformed_input"
    if m["version"] != SUPPORTED_VERSION:
        return "reject", "unsupported_version"
    signer = norm_hex(inp.get("signer"), 20)
    if signer is None:
        return "reject", "malformed_input"
    sig = inp.get("signature")
    if not (isinstance(sig, str) and _SIG_RE.match(sig)):
        return "reject", "malformed_signature"
    b = bytes.fromhex(sig[2:])
    if b[64] not in (27, 28):
        return "reject", "malformed_signature"
    r, s = int.from_bytes(b[:32], "big"), int.from_bytes(b[32:64], "big")
    if s > S.N // 2:
        return "reject", "non_canonical_s"
    Q = S.recover(digest(m), r, s, b[64] - 27)
    if Q is None:
        return "reject", "unrecoverable"
    return ("valid", None) if S.address(Q) == signer else ("reject", "signer_mismatch")


MANIFEST = os.path.join(HERE, "EIP712_MANIFEST.json")
ORIGIN_CLASSES = ("synthetic", "live-ledger-derived", "contributed")


def _no_dup_keys(pairs):
    """object_pairs_hook: a duplicate key at ANY nesting level is a load error, not last-value-wins.
    json.load alone cannot distinguish {"payer": a, "payer": b} from a single {"payer": b} -- by the time a
    dict exists the duplicate is already gone. Detecting it is a property of the loader, not of check()."""
    seen = set()
    for k, _ in pairs:
        if k in seen:
            raise ValueError(f"duplicate key {k!r} in JSON object")
        seen.add(k)
    return dict(pairs)


def load_strict(path):
    with open(path) as fh:
        return json.load(fh, object_pairs_hook=_no_dup_keys)


def load_set():
    """-> (vectors by id, problems). The runner reads EIP712_MANIFEST.json, never a directory listing."""
    m = json.load(open(MANIFEST))
    vecs, problems = {}, []
    listed = {e["file"] for e in m["vectors"]}
    on_disk = {os.path.basename(f) for f in glob.glob(os.path.join(HERE, "eip712_vectors", "*.json"))}
    problems += [f"on disk, not in MANIFEST: {f}" for f in sorted(on_disk - listed)]
    problems += [f"in MANIFEST, not on disk: {f}" for f in sorted(listed - on_disk)]
    files = [e["file"] for e in m["vectors"]]
    problems += [f"listed more than once in MANIFEST: {f}" for f in sorted({f for f in files if files.count(f) > 1})]
    for e in m["vectors"]:
        if e["file"] not in on_disk:
            continue
        try:
            v = load_strict(os.path.join(HERE, "eip712_vectors", e["file"]))
        except ValueError as exc:
            problems.append(f"{e['file']}: {exc}")
            continue
        stem = e["file"][:-len(".json")]
        if v.get("id") != stem:
            problems.append(f"{e['file']}: id {v.get('id')!r} != file stem {stem!r}")
        if (v["expect"], v["kind"]) != (e["expect"], e["kind"]):
            problems.append(f"{e['file']}: MANIFEST expect/kind disagrees with the vector")
        if e.get("origin", {}).get("class") not in ORIGIN_CLASSES:
            problems.append(f"{e['file']}: origin.class not in {ORIGIN_CLASSES}")
        vecs[stem] = v
    if not vecs:
        problems.append("empty vector set")
    kinds = {}
    for v in vecs.values():
        kinds.setdefault(v["kind"], set()).add(v["expect"])
    problems += [f"kind {k} is one-sided ({sorted(x)})" for k, x in kinds.items() if x != {"valid", "reject"}]
    exercised = {v.get("reject_reason") for v in vecs.values() if v["expect"] == "reject"}
    if tuple(m.get("reject_reasons", ())) != REJECT_REASONS:
        problems.append(f"MANIFEST reject_reasons {m.get('reject_reasons')} != the runner's pinned closure {REJECT_REASONS}")
    problems += [f"reject reason never exercised: {r}" for r in REJECT_REASONS if r not in exercised]
    problems += [f"vector uses an undeclared reason: {r}" for r in sorted(exercised - set(REJECT_REASONS) - {None})]
    if len(vecs) != len(m["vectors"]):
        problems.append(f"loaded {len(vecs)} vectors for {len(m['vectors'])} MANIFEST entries")
    return vecs, problems


def main():
    vecs, problems = load_set()
    bad = len(problems)
    for p in problems:
        print("SET  ", p)
    ran = 0
    for vid in sorted(vecs, key=lambda i: (i[:2], int("".join(c for c in i.split("-")[0] if c.isdigit()) or 0))):
        v = vecs[vid]; got, why = check(v["input"]); ran += 1
        ok = got == v["expect"] and (why == v.get("reject_reason"))
        bad += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {vid:40s} expect={v['expect']:6s} got={got}{' ('+why+')' if why else ''}")
    n_manifest = len(json.load(open(MANIFEST))["vectors"])
    if ran != n_manifest:
        bad += 1; problems.append(f"ran {ran} vectors for {n_manifest} MANIFEST entries")
        print("SET  ", problems[-1])
    print(f"{ran - (bad - len(problems))}/{n_manifest} EIP-712 payload-signature vectors match" +
          ("" if not problems else f"; {len(problems)} set problem(s)"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
