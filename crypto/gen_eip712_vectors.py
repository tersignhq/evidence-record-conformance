#!/usr/bin/env python3
"""Generates the EIP-712 payload-signature vectors (crypto/eip712_vectors/) and crypto/EIP712_MANIFEST.json. Stdlib only."""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.dirname(HERE))
from keccak import keccak256  # noqa: E402
import secp256k1_recover as S  # noqa: E402
import verify_eip712 as E  # noqa: E402
from gen_crypto_vectors import PRIV, K, TEST_ADDR, sighex, with_sig, off_curve_r, TEST_KEY_DERIVATION, TEST_NONCE_DERIVATION  # noqa: E402

P1 = json.load(open(os.path.join(os.path.dirname(HERE), "vectors", "p1-live-genesis-receipt.json")))["input"]["payload"]
LEDGER = "0x9d38BA84730271eb27Ac9bD4Bd2620c08dB4FDa6"
# This suite's own rules, not x402's; a vector that rests on one names its key in its source (CONTRIBUTING.md).
INTEGER_DOMAIN = ("version and issuedAt (uint256, x402 Sec 5.3) are JSON integer tokens, and the token 1.0 is not one (en26); "
                  "every integer in [0, 2**256 - 1] passes the field check, with no freshness "
                  "or other policy bound on issuedAt (ep7, ep8, ep9); x402 Sec 5.5 step 6 leaves issuedAt to verifier policy")
SIGNER_SHAPE = ("signer, the envelope key this suite adds beside x402's format, payload and signature, is 0x + 40 hex digits, compared "
                "case-insensitively with the recovered address (ep1 declares a mixed-case signer and accepts; en28, 0x + 39 hex, rejects "
                "as malformed_input); surrounding whitespace and a 0X prefix on the signer are not pinned")


def tsign(msg, **kw):
    return sighex(*S.sign(E.digest(msg, **kw), PRIV, K))


def main():
    live = {"format": P1["format"], "payload": P1["payload"], "signature": P1["signature"], "signer": P1["payload"]["payer"]}
    m = P1["payload"]
    tmsg = {**m, "payer": TEST_ADDR}
    t = {"format": "eip712", "payload": tmsg, "signature": tsign(tmsg), "signer": TEST_ADDR}
    reordered = "Receipt(uint256 version,string network,string resourceUrl,string payer,string transaction,uint256 issuedAt)"
    reorder_fields = tuple(f for f in E.FIELDS if f[0] != "issuedAt" and f[0] != "transaction") + (("transaction", "string"), ("issuedAt", "uint256"))
    s_int = int(P1["signature"][66:130], 16); v_live = int(P1["signature"][130:], 16)
    LIVE_SRC = "p1's payload, signature and payer as served (core vector p1, live-ledger)"
    tmsg_v2 = {**m, "payer": TEST_ADDR, "version": 2}
    srv = {"format": "eip712", "payload": dict(m), "signature": tsign(m), "signer": TEST_ADDR}
    d28 = 0
    while True:                                   # deterministic: first issuedAt offset whose low-s signature has v = 28
        d28 += 1
        m28 = {**m, "payer": TEST_ADDR, "issuedAt": m["issuedAt"] + d28}
        sig28 = tsign(m28)
        if int(sig28[130:], 16) == 28:
            break
    t28 = {"format": "eip712", "payload": m28, "signature": sig28, "signer": TEST_ADDR}
    mna = {**m, "payer": TEST_ADDR, "resourceUrl": m["resourceUrl"].rstrip("/") + "/r\u00e9sum\u00e9-\u20ac-\u65e5\u672c"}
    nonascii = {"format": "eip712", "payload": mna, "signature": tsign(mna), "signer": TEST_ADDR}
    ml1 = {**m, "payer": TEST_ADDR, "resourceUrl": m["resourceUrl"].rstrip("/") + "/r\u00e9sum\u00e9"}
    latin1 = {"format": "eip712", "payload": ml1, "signature": tsign(ml1), "signer": TEST_ADDR}
    mmax = {**m, "payer": TEST_ADDR, "issuedAt": 2 ** 256 - 1}
    tmax = {"format": "eip712", "payload": mmax, "signature": tsign(mmax), "signer": TEST_ADDR}
    m0 = {**m, "payer": TEST_ADDR, "issuedAt": 0}
    t0 = {"format": "eip712", "payload": m0, "signature": tsign(m0), "signer": TEST_ADDR}
    m1 = {**m, "payer": TEST_ADDR, "issuedAt": 1}
    t1 = {"format": "eip712", "payload": m1, "signature": tsign(m1), "signer": TEST_ADDR}
    TERSIGN = "Tersign (@wowlegend)"   # a row's optional 7th element is its author; without one it is @babyblueviper1 (PR #11, #13)
    DERIVED = "live-ledger-derived"
    V = [
        ("ep1-live-p1-payload-signature", "valid", None, live, "live-ledger", LIVE_SRC),
        ("ep2-test-key-accepting-twin", "valid", None, t, DERIVED, "test key signs a Receipt naming itself as payer"),
        ("ep3-server-key-not-payer", "valid", None, srv, "live-ledger-derived", "p1's payload as served (payer = p1's payer), signed by the published test key standing in for a server key that is not the payer"),
        ("ep4-recovery-byte-28", "valid", None, t28, "live-ledger-derived", f"p1's payload with the test key as payer and issuedAt + {d28} (the first offset whose low-s signature has recovery id 1), signed with v = 28"),
        ("ep5-non-ascii-string", "valid", None, nonascii, "live-ledger-derived", "p1's payload with the test key as payer and a non-ASCII resourceUrl (UTF-8 multi-byte, not Latin-1), signed by the test key"),
        ("ep6-non-ascii-latin1-range-string", "valid", None, latin1, "live-ledger-derived", "p1's payload with the test key as payer and a non-ASCII resourceUrl whose every character is below U+0100 (r\u00e9sum\u00e9), signed by the test key over its UTF-8 bytes: a verifier that hashes Latin-1-representable strings as Latin-1 recovers a different address. Written on the surviving mutant No\u00fbs (@robertolocatelli81-dev) reported on PR #13"),
        ("en1-domain-chainid-8453", "reject", "signer_mismatch", {**t, "signature": tsign(tmsg, domain={**E.DOMAIN, "chainId": 8453})}, DERIVED, "test key signs under chainId 8453 (Base), the record's own network, not the pinned domain"),
        ("en2-domain-name-altered", "reject", "signer_mismatch", {**t, "signature": tsign(tmsg, domain={**E.DOMAIN, "name": "x402 receipts"})}, DERIVED, "test key signs under a domain name one letter off"),
        ("en3-type-fields-reordered", "reject", "signer_mismatch", {**t, "signature": tsign(tmsg, receipt_type=reordered, fields=reorder_fields)}, DERIVED, "test key signs with issuedAt and transaction swapped in the type string"),
        ("en4-issuedat-drift", "reject", "signer_mismatch", {**live, "payload": {**m, "issuedAt": m["issuedAt"] + 1}}, "live-ledger-derived", "p1 with issuedAt + 1"),
        ("en5-payer-recased", "reject", "signer_mismatch", {**live, "payload": {**m, "payer": m["payer"].lower()}}, "live-ledger-derived", "p1 with payer written lower-case: payer is a string, hashed as written"),
        ("en6-high-s-malleated", "reject", "non_canonical_s", {**live, "signature": with_sig(P1["signature"], s=S.N - s_int, v=55 - v_live)}, "live-ledger-derived", "p1's signature malleated to s' = n - s, v flipped"),
        ("en7-personal-sign-over-struct", "reject", "signer_mismatch", {**t, "signature": sighex(*S.sign(S.personal_sign_hash(E.digest(tmsg)), PRIV, K))}, DERIVED, "test key personal_signs the EIP-712 digest instead of signing it"),
        ("en8-version-string", "reject", "malformed_input", {**live, "payload": {**m, "version": "1"}}, "live-ledger-derived", "p1 with version as the string \"1\""),
        ("en9-issuedat-negative", "reject", "malformed_input", {**live, "payload": {**m, "issuedAt": -1}}, "live-ledger-derived", "p1 with issuedAt -1"),
        ("en10-field-missing", "reject", "malformed_input", {**live, "payload": {k: v for k, v in m.items() if k != "transaction"}}, "live-ledger-derived", "p1 with transaction removed: the payload is used exactly as transmitted (Sec 5.5 step 3); \"\" means absence, an omitted key is not filled in as \"\""),
        ("en12-format-not-eip712", "reject", "unsupported_format", {**live, "format": "eip191"}, "live-ledger-derived", "p1 labelled eip191"),
        ("en13-ledger-key-is-not-payload-signer", "reject", "signer_mismatch", {**live, "signer": LEDGER}, "live-ledger-derived", "p1 with the ledger's counter-signing key declared as the payload signer"),
        ("en14-recovery-byte-29", "reject", "malformed_signature", {**live, "signature": with_sig(P1["signature"], v=29)}, "live-ledger-derived", "p1's signature with v = 29"),
        ("en15-unrecoverable-r-off-curve", "reject", "unrecoverable", {**live, "signature": with_sig(P1["signature"], r=off_curve_r())}, "live-ledger-derived", "p1's s and v with r off the curve"),
        ("en16-required-field-missing", "reject", "malformed_input", {**live, "payload": {k: v for k, v in m.items() if k != "payer"}}, "live-ledger-derived", "p1 with payer (a required field, not the optional transaction) removed"),
        ("en17-unsupported-version", "reject", "unsupported_version", {"format": "eip712", "payload": tmsg_v2, "signature": tsign(tmsg_v2), "signer": TEST_ADDR}, DERIVED, "test key correctly signs a Receipt with version 2; the profile pins version 1, a well-typed but unsupported edition. Written on the class Noûs (@robertolocatelli81-dev) reported in their cleanroom cross-check on PR #13"),
        ("en19-payer-lone-surrogate", "reject", "malformed_input", {**live, "payload": {**m, "payer": "\ud800"}}, "live-ledger-derived", "p1 with payer replaced by an unpaired UTF-16 surrogate, unencodable as UTF-8. Written on the class Noûs (@robertolocatelli81-dev) reported on PR #13"),
        ("en20-recovery-byte-zero", "reject", "malformed_signature", {**t, "signature": with_sig(t["signature"], v=0)}, "live-ledger-derived", "ep2's signature with v = 0 (the raw recovery id, not 27/28; cn21's class)"),
        ("en21-recovery-byte-one", "reject", "malformed_signature", {**t28, "signature": with_sig(t28["signature"], v=1)}, "live-ledger-derived", "ep4's signature with v = 1 (cn22's class)"),
        ("en22-low-s-boundary-accepted-then-mismatch", "reject", "signer_mismatch", {**t, "signature": with_sig(t["signature"], s=S.N // 2)}, "live-ledger-derived", "ep2's r and v with s = n/2 exactly: passes the low-s check, recovers some other address (cn23's class)"),
        ("en23-low-s-boundary-plus-one", "reject", "non_canonical_s", {**t, "signature": with_sig(t["signature"], s=S.N // 2 + 1)}, "live-ledger-derived", "ep2's r and v with s = n/2 + 1, the first high s (cn24's class)"),
        ("ep7-issuedat-max-uint256", "valid", None, tmax, DERIVED, "p1's payload with the test key as payer and issuedAt = 2**256 - 1, the top of the uint256 domain, signed by the test key (a runner that caps integers at 2**53 - 1 or 2**64 - 1 rejects it)"),
        ("en25-issuedat-2pow256", "reject", "malformed_input", {**tmax, "payload": {**mmax, "issuedAt": 2 ** 256}}, DERIVED, "ep7 with issuedAt = 2**256, one above the uint256 domain"),
        ("en26-version-integral-float-token", "reject", "malformed_input", {**live, "payload": {**m, "version": 1.0}}, DERIVED, "p1 with version written as the token 1.0: not an integer token (a loader-level case, like the duplicate-key one: JSON.parse turns 1.0 into 1, so a runner must read number tokens to see it; the counter-signature profile's cn29 is the same class)"),
        ("en27-malformed-payload-and-signature", "reject", "malformed_input", {**live, "payload": {**m, "issuedAt": -1}, "signature": with_sig(P1["signature"], v=29)}, DERIVED, "two faults in one input, en9's payload and en14's signature: the payload is checked before the signature (this suite's check order), so a runner that checks the signature first reports malformed_signature (cn34's class)"),
        ("en24-signature-uppercase-0X-prefix", "reject", "malformed_signature", {**t, "signature": "0X" + t["signature"][2:]}, "live-ledger-derived", "ep2's signature with a 0X prefix (cn18's class)"),
        ("en28-signer-not-an-address", "reject", "malformed_input", {**live, "signer": live["signer"][:-1]}, DERIVED, "p1 with the declared signer one hex digit short (0x + 39 hex). Rests on this suite's rule signer_shape (this manifest): signer is 0x + 40 hex digits. ep1 is its accepting twin; a runner that skips the shape check reports signer_mismatch", TERSIGN),
        ("ep8-issuedat-zero", "valid", None, t0, DERIVED, "p1's payload with the test key as payer and issuedAt = 0, the bottom of the uint256 range [0, 2**256 - 1], signed by the test key. Rests on this suite's rule integer_domain (this manifest): every integer in that range passes, with no policy bound on issuedAt. A runner that starts the domain at 1, or reads 0 as absent, rejects it", TERSIGN),
        ("en29-issuedat-minus-one", "reject", "malformed_input", {**t0, "payload": {**m0, "issuedAt": -1}}, DERIVED, "ep8 with issuedAt = -1, on ep8's signature. x402 extension-offer-and-receipt.md Sec 5.3 (EIP-712 Types for Receipt, Normative Schema) types it { \"name\": \"issuedAt\", \"type\": \"uint256\" }, and -1 is not a uint256. ep8 is its accepting twin (en9 is the same fault on p1)", TERSIGN),
        ("en30-version-bool-true", "reject", "malformed_input", {**live, "payload": {**m, "version": True}}, DERIVED, "p1 with version written as true. x402 extension-offer-and-receipt.md types version three times: Sec 5.2 (Receipt Payload Fields), row `version` | number | Yes; Sec 5.3 (Normative Schema), { \"name\": \"version\", \"type\": \"uint256\" }; Sec 6.5's receipt schema, \"version\": { \"type\": \"integer\" }. A JSON boolean is none of these (the counter-signature profile's cn11 class). ep1 is its accepting twin; a runner that reads true as 1 recovers p1's payer and accepts it", TERSIGN),
        ("ep9-issuedat-one", "valid", None, t1, DERIVED, "p1's payload with the test key as payer and issuedAt = 1, signed by the test key: the accepting twin of en31. Rests on this suite's rule integer_domain (this manifest)", TERSIGN),
        ("en31-issuedat-bool-true", "reject", "malformed_input", {**t1, "payload": {**m1, "issuedAt": True}}, DERIVED, "ep9 with issuedAt written as true, on ep9's signature. x402 extension-offer-and-receipt.md types issuedAt three times: Sec 5.2 (Receipt Payload Fields), row `issuedAt` | number | Yes; Sec 5.3 (Normative Schema), { \"name\": \"issuedAt\", \"type\": \"uint256\" }; Sec 6.5's receipt schema, \"issuedAt\": { \"type\": \"integer\" }. A JSON boolean is none of these. ep9 is its accepting twin; a runner that reads true as 1 accepts it", TERSIGN),
        ("en32-transaction-null", "reject", "malformed_input", {**live, "payload": {**m, "transaction": None}}, DERIVED, "p1 with transaction written as null, not \"\": the pinned Receipt type declares string transaction and the payload is hashed exactly as transmitted, so null is not read as \"\". ep1 is its accepting twin; a runner that reads null as \"\" recovers p1's payer and accepts it", TERSIGN),
        ("en33-payer-number", "reject", "malformed_input", {**live, "payload": {**m, "payer": int(m["payer"], 16)}}, DERIVED, "p1 with payer written as a JSON number, the address's integer value: the pinned Receipt type declares string payer. ep1 is its accepting twin", TERSIGN),
    ]
    out = os.path.join(HERE, "eip712_vectors")
    os.makedirs(out, exist_ok=True)
    for f in os.listdir(out):
        os.remove(os.path.join(out, f))
    entries = []
    for vid, expect, reason, inp, cls, src, *by in V:
        v = {"id": vid, "kind": "payload_signature", "expect": expect}
        if reason:
            v["reject_reason"] = reason
        v["input"] = inp
        if vid.startswith("ep1-"):     # live-ledger: name the public record, as cp1 does
            v["provenance"] = {"ledger": "https://tersign.ai", "record": "curl https://tersign.ai/v1/genesis",
                               "payload_signature": P1["signature"], "payer": P1["payload"]["payer"],
                               "note": "payload, signature and payer are p1's genesis receipt as served"}
        with open(os.path.join(out, vid + ".json"), "w") as fh:
            fh.write(json.dumps(v, indent=2) + "\n")
        entries.append({"file": vid + ".json", "kind": "payload_signature", "expect": expect, "author": by[0] if by else "@babyblueviper1", "origin": {"class": cls, "source": src}})
    man = {"profile": "EIP-712 payload signature (x402 offer-and-receipt Receipt)", "runner": "crypto/verify_eip712.py",
           "generator": "crypto/gen_eip712_vectors.py", "licence": "Apache-2.0, as the repository (LICENSE)", "domain": E.DOMAIN, "primary_type": "Receipt", "type": E.RECEIPT_TYPE,
           "integer_domain": INTEGER_DOMAIN, "signer_shape": SIGNER_SHAPE,
           "reject_reasons": list(E.REJECT_REASONS), "test_key_address": TEST_ADDR, "test_key_derivation": TEST_KEY_DERIVATION,
           "test_nonce_derivation": TEST_NONCE_DERIVATION, "vectors": entries}
    with open(os.path.join(HERE, "EIP712_MANIFEST.json"), "w") as fh:
        fh.write(json.dumps(man, indent=1, ensure_ascii=False) + "\n")
    bad = 0
    for vid, expect, reason, inp, *_ in V:
        got = E.check(inp)
        ok = got == (expect, reason); bad += not ok
        print(("ok  " if ok else "FAIL"), vid, got)
    print(f"{len(V) - bad}/{len(V)}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
