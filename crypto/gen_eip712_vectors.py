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
    ]
    out = os.path.join(HERE, "eip712_vectors")
    os.makedirs(out, exist_ok=True)
    for f in os.listdir(out):
        os.remove(os.path.join(out, f))
    entries = []
    for vid, expect, reason, inp, cls, src in V:
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
        entries.append({"file": vid + ".json", "kind": "payload_signature", "expect": expect, "author": "@babyblueviper1", "origin": {"class": cls, "source": src}})
    man = {"profile": "EIP-712 payload signature (x402 offer-and-receipt Receipt)", "runner": "crypto/verify_eip712.py",
           "generator": "crypto/gen_eip712_vectors.py", "licence": "Apache-2.0, as the repository (LICENSE)", "domain": E.DOMAIN, "primary_type": "Receipt", "type": E.RECEIPT_TYPE,
           "reject_reasons": list(E.REJECT_REASONS), "test_key_address": TEST_ADDR, "test_key_derivation": TEST_KEY_DERIVATION,
           "test_nonce_derivation": TEST_NONCE_DERIVATION, "vectors": entries}
    with open(os.path.join(HERE, "EIP712_MANIFEST.json"), "w") as fh:
        fh.write(json.dumps(man, indent=1, ensure_ascii=False) + "\n")
    bad = 0
    for vid, expect, reason, inp, _, _ in V:
        got = E.check(inp)
        ok = got == (expect, reason); bad += not ok
        print(("ok  " if ok else "FAIL"), vid, got)
    print(f"{len(V) - bad}/{len(V)}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
