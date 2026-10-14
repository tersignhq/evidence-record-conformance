#!/usr/bin/env python3
"""Direct engine parity for the chain-statement profile: both implementations, same inputs, verdicts compared.

The corpus runs of statement/verify_statement.py and tools/cross_check_statement.mjs each compare an engine with
statement/MANIFEST.json, so their agreement is transitive through the shared expectations, and an input the corpus does
not carry is never compared. This harness feeds both engines every corpus input PLUS an off-corpus battery built from
eight accepting vectors, and compares [verdict, reason] directly, with no expectation in between:

  - every member of the statement, at every depth, removed, and replaced by null, true, false, 0, -1, 1, 2**53 - 1,
    "", "x", [] and {}; each hex string also upper-cased, without 0x, one digit short, one digit long and with a
    trailing space; each integer also plus one and minus one; each object also given an undefined member, once with
    the value 1 and once with null; each array also with its last element repeated, dropped and the order reversed.
    A changed statement whose rules the Python engine accepts is signed again by the test key, so the comparison
    reaches the digest, signature, signer and records steps rather than stopping at the signature;
  - the served text: each member name written twice, each integer token written as N.0, Ne0, 2**53 and 2**53 + 1, a
    surrogate that is not half of a pair, and a pair written as escapes, in each string; the text pretty-printed,
    padded with whitespace, with a byte-order mark, truncated, and as a top-level array;
  - the envelope: each member removed, an undefined member, signer in another letter case, statementDigest in upper
    case, and the signature with upper-case digits, a 0X prefix, v = 0, 1 and 29, s = 0, n/2 and n/2 + 1, r = 0 and n, a
    trailing newline, one byte short and a number;
  - expected_signer and records: the other test key, letter case, whitespace, empty; records dropped, repeated,
    swapped, extended, upper-cased, non-hex and non-string.

A form not on this list is not compared. Any divergence exits non-zero and prints the input.

Run:  npm i viem  (repo root), then  python3 tools/differential_statement.py
"""
import copy
import json
import multiprocessing
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "statement"))
import verify_statement as V  # noqa: E402
import gen_statement_vectors as G  # noqa: E402

BASES = ("sp1-", "sp3-", "sp4-", "sp8-", "sp9-", "sp10-", "sp23-", "sp27-")
VALUES = (None, True, False, 0, -1, 1, 2 ** 53 - 1, "", "x", [], {})
DROP = object()


def py(inp):
    try:
        return list(V.check(inp))
    except Exception as exc:   # a crash is reported as such, never as a verdict
        return ["crash", type(exc).__name__]


def paths(v, at=()):
    yield at
    if isinstance(v, dict):
        for k in v:
            yield from paths(v[k], at + (k,))
    elif isinstance(v, list):
        for i, x in enumerate(v[:3]):
            yield from paths(x, at + (i,))


def get(v, path):
    for k in path:
        v = v[k]
    return v


def replaced(st, path, value):
    st = copy.deepcopy(st)
    parent = get(st, path[:-1])
    if value is DROP:
        if isinstance(parent, dict):
            del parent[path[-1]]
        else:
            parent.pop(path[-1])
    else:
        parent[path[-1]] = value
    return st


def variants(v):
    out = [DROP] + list(VALUES)
    if isinstance(v, str) and v.startswith("0x"):
        out += [v.upper()[0] + "x" + v[2:].upper(), v[2:], v[:-1], v + "0", v + " "]
    if isinstance(v, int) and not isinstance(v, bool):
        out += [v + 1, v - 1]
    if isinstance(v, dict):
        out += [dict(v, x_unknown_2026=1), dict(v, x_undefined=None)]
    if isinstance(v, list) and v:
        out += [v + v[-1:], v[:-1], v[::-1]]
    return out


def materialize(spec):
    """A case from a spec: a ready input, or (opts, statement, base digest, base signature) for a changed statement,
    signed again when the Python engine's statement rules accept it, otherwise carrying the base digest and signature
    (both engines then reject on a rule first, if they agree on the rules)."""
    if isinstance(spec, dict):
        return spec
    opts, st, digest, sig = spec
    try:
        accepted = V.statement_refusal(st) is None
    except Exception:   # the Python engine crashed on this statement: the comparison reports it, the battery goes on
        accepted = False
    if accepted:
        return dict(opts, body_text=G.envelope(st))
    signer = st.get("ledger") if isinstance(st, dict) else None
    return dict(opts, body_text=G.js_text({"statement": st, "statementDigest": digest, "signature": sig, "signer": signer}))


def battery(vectors):
    cases = []
    for vid, v in sorted(vectors.items()):
        cases.append(v["input"])
        if not vid.startswith(BASES):
            continue
        inp = v["input"]
        opts = {k: x for k, x in inp.items() if k != "body_text"}
        text = inp["body_text"]
        body = json.loads(text)
        st, sig, digest = body["statement"], body["signature"], body["statementDigest"]
        # statement members
        for path in paths(st):
            if not path:
                continue
            for value in variants(get(st, path)):
                cases.append((opts, replaced(st, path, value), digest, sig))
        # served text
        for name in sorted({k for p in paths(st) for k in p if isinstance(k, str)}):
            needle = '"%s":' % name
            at = text.find(needle)
            cases.append(dict(opts, body_text=text[:at] + needle + 'null,' + text[at:]))
            cases.append(dict(opts, body_text=text[:at] + text[at:text.find(",", at) + 1] + text[at:]))
        for token in ('"from":', '"seq":', '"version":', '"listCap":', '"v1":'):
            at = text.find(token)
            end = at + len(token)
            while text[end].isdigit():
                end += 1
            number = text[at + len(token):end]
            for form in (number + ".0", number + "e0", str(2 ** 53), str(2 ** 53 + 1), "-" + str(2 ** 53 - 1)):
                cases.append(dict(opts, body_text=text[:at + len(token)] + form + text[end:]))
        for needle, form in (('"sellerId":"', "\\ud800"), ('"sellerId":"', "\\udc00"), ('"sellerId":"', "\\ud83d\\ude00"),
                             ('"sellerId":"', "\U0001F600"), ('"scope":"', "\\ud800"), ('"type":"', "\\ud800")):
            at = text.find(needle)
            if at >= 0:
                cases.append(dict(opts, body_text=text[:at + len(needle)] + form + text[at + len(needle):]))
        cases.append(dict(opts, body_text=json.dumps(body, indent=2, ensure_ascii=False)))
        cases.append(dict(opts, body_text=" \n" + text + "\t "))
        cases.append(dict(opts, body_text=chr(0xFEFF) + text))
        cases.append(dict(opts, body_text=text[:-1]))
        cases.append(dict(opts, body_text="[" + text + "]"))
        # envelope
        for k in V.ENVELOPE:
            cases.append(dict(opts, body_text=G.js_text({m: x for m, x in body.items() if m != k})))
        cases.append(dict(opts, body_text=G.js_text(dict(body, x_unknown_2026=1))))
        cases.append(dict(opts, body_text=G.js_text(dict(body, signer=body["signer"].lower()))))
        cases.append(dict(opts, body_text=G.js_text(dict(body, statementDigest="0x" + body["statementDigest"][2:].upper()))))
        r, s, vv = int(sig[2:66], 16), int(sig[66:130], 16), int(sig[130:], 16)

        def sig_with(r=r, s=s, v=vv):
            return "0x" + r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + bytes([v]).hex()
        for form in ("0x" + sig[2:].upper(), "0X" + sig[2:], sig_with(v=vv - 27), sig_with(v=(vv - 27) ^ 1),
                     sig_with(v=29), sig_with(s=V.S.N // 2), sig_with(s=V.S.N // 2 + 1), sig_with(r=0),
                     sig_with(r=V.S.N), sig_with(s=0), sig + "\n", sig[:-2], 7):
            cases.append(dict(opts, body_text=G.js_text(dict(body, signature=form))))
        # what a relying party brings
        ledger = body["statement"]["ledger"]
        for es in (G.OTHER, ledger.lower(), "0x" + ledger[2:].upper(), " " + ledger, "", ledger[:-1]):
            cases.append(dict(opts, body_text=text, expected_signer=es))
        recs = opts.get("records")
        if recs:
            for rs in (recs[:-1], recs + recs[-1:], recs[::-1], [recs[0].upper()] + recs[1:], ["0x" + "zz" * 32] + recs[1:],
                       [1] + recs[1:], [], recs[1:] + recs[:1]):
                cases.append(dict(opts, body_text=text, records=rs))
    return cases


def main():
    vectors, problems = V.load_set()
    if problems:
        print("set problems: %s" % problems[:3])
        return 1
    with multiprocessing.Pool() as pool:
        cases = pool.map(materialize, battery(vectors), chunksize=25)
        pyv = pool.map(py, cases, chunksize=25)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
        json.dump(cases, fh)
        path = fh.name
    try:
        proc = subprocess.run(["node", os.path.join(ROOT, "tools", "differential_statement_helper.mjs"), path],
                              capture_output=True, text=True, check=False)
    finally:
        os.unlink(path)
    if proc.returncode != 0:
        print("TypeScript engine failed to run:\n" + proc.stderr[-2000:])
        return 1
    ts = json.loads(proc.stdout)
    if len(ts) != len(cases) or not cases:
        print("case count mismatch or empty battery: %d cases, %d TypeScript results" % (len(cases), len(ts)))
        return 1
    bad = 0
    verdicts = {}
    for inp, p, t in zip(cases, pyv, ts):
        verdicts[tuple(p)] = verdicts.get(tuple(p), 0) + 1
        if p != t or "crash" in (p[0], t[0]):
            bad += 1
            if bad <= 20:
                print("DIVERGE python=%s typescript=%s input=%s" % (p, t, json.dumps(inp)[:400]))
    n_corpus = len(vectors)
    print("verdicts seen: %s" % ", ".join("%s/%s %d" % (k[0], k[1], c) for k, c in sorted(verdicts.items(), key=str)))
    print("STATEMENT DIFFERENTIAL %s: %d cases (%d off-corpus), %d divergence(s)"
          % ("OK" if bad == 0 else "FAILED", len(cases), len(cases) - n_corpus, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
