#!/usr/bin/env python3
"""Compare a runner's per-vector output with MANIFEST.json, verdict and reason as exact strings.

    python3 tools/compare_run.py <output.json> [--manifest <path>]

The output is DATA, never code: a JSON array with one object per vector, each with exactly the
keys `file` (the vector's file name as the manifest lists it), `verdict` and, for a reject,
`reason` (README, Reproduction). Nothing in it is executed or imported.

Prints `agrees on N/M verdicts and reasons at v<version> (MANIFEST.json sha256 <digest>)`, where
M is the number of vectors in the manifest. A vector the output leaves out counts as a
disagreement; an entry for a file the manifest does not list is named on its own line, counted on
that line, and fails the comparison.

Exit 0 only when all M agree and the output names nothing else; 1 on any disagreement; 2 on
input it refuses: unreadable or duplicate-named JSON, a shape other than the one above, two
entries for one file, an empty output or a manifest with no vectors (an empty denominator is
not agreement).

It compares outputs and nothing else. It does not establish that a runner is independent of
this suite's engines; that is for readers to judge from the runner's repository.
"""

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MANIFEST = os.path.join(os.path.dirname(HERE), "MANIFEST.json")
ENTRY_KEYS = frozenset({"file", "verdict", "reason"})


class Refused(Exception):
    """Input this tool will not compare (exit 2)."""


def _no_duplicate_names(pairs):
    names = [k for k, _ in pairs]
    if len(names) != len(set(names)):
        raise Refused(f"duplicate object name(s) {sorted({n for n in names if names.count(n) > 1})}")
    return dict(pairs)


def _reject_constant(token):
    raise Refused(f"{token} is not a JSON token")


def _load(path, what):
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as exc:
        raise Refused(f"cannot read {what} {path}: {exc.strerror}") from None
    try:
        return raw, json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_names,
                               parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refused(f"{what} is not UTF-8 JSON text: {exc}") from None


def expected_from(manifest):
    """{file: (verdict, reason)} from the manifest; a valid expects no reason."""
    vectors = manifest.get("vectors") if isinstance(manifest, dict) else None
    if not isinstance(vectors, list) or not vectors:
        raise Refused("the manifest lists no vectors; an empty denominator is not agreement")
    expected = {}
    for e in vectors:
        if not (isinstance(e, dict) and isinstance(e.get("file"), str)
                and e.get("expect") in ("valid", "reject")):
            raise Refused(f"manifest entry without a file name and an expect of valid or reject: {e!r}")
        if e["file"] in expected:
            raise Refused(f"manifest lists {e['file']} twice")
        reason = e.get("reason") if e["expect"] == "reject" else None
        if e["expect"] == "reject" and not isinstance(reason, str):
            raise Refused(f"manifest reject {e['file']} names no reason")
        expected[e["file"]] = (e["expect"], reason)
    return expected


def reported_from(output):
    """{file: (verdict, reason)} from a runner's output; `null` and an absent reason are both none."""
    if not isinstance(output, list):
        raise Refused(f"the output must be a JSON array, not {type(output).__name__}")
    if not output:
        raise Refused("the output is an empty array; an empty denominator is not agreement")
    reported = {}
    for i, e in enumerate(output):
        if not isinstance(e, dict):
            raise Refused(f"entry {i} is not an object")
        extra = sorted(set(e) - ENTRY_KEYS)
        if extra:
            raise Refused(f"entry {i} carries key(s) {extra}; an entry has file, verdict and reason only")
        if not isinstance(e.get("file"), str):
            raise Refused(f"entry {i} has no string `file`")
        if not isinstance(e.get("verdict"), str):
            raise Refused(f"entry {i} ({e['file']}) has no string `verdict`")
        reason = e.get("reason")
        if reason is not None and not isinstance(reason, str):
            raise Refused(f"entry {i} ({e['file']}) has a `reason` that is neither a string nor null")
        if e["file"] in reported:
            raise Refused(f"two entries for {e['file']}")
        reported[e["file"]] = (e["verdict"], reason)
    return reported


def _show(pair):
    verdict, reason = pair
    return verdict if reason is None else f"{verdict}/{reason}"


def main(argv):
    args = list(argv)
    manifest_path = DEFAULT_MANIFEST
    if "--manifest" in args:
        i = args.index("--manifest")
        if i + 1 >= len(args):
            print("usage: compare_run.py <output.json> [--manifest <path>]", file=sys.stderr)
            return 2
        manifest_path = args[i + 1]
        del args[i:i + 2]
    if len(args) != 1:
        print("usage: compare_run.py <output.json> [--manifest <path>]", file=sys.stderr)
        return 2
    try:
        manifest_raw, manifest = _load(manifest_path, "manifest")
        expected = expected_from(manifest)
        _, output = _load(args[0], "output")
        reported = reported_from(output)
    except Refused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2

    version = manifest.get("version") if isinstance(manifest.get("version"), str) else "?"
    ref = f"v{version} ({os.path.basename(manifest_path)} sha256 {hashlib.sha256(manifest_raw).hexdigest()})"
    agree, lines = 0, []
    for name, want in expected.items():
        got = reported.get(name)
        if got is None:
            lines.append(f"  not in the output: {name} (expected {_show(want)})")
        elif got == want:
            agree += 1
        else:
            lines.append(f"  disagrees: {name}: expected {_show(want)}, output {_show(got)}")
    unknown = sorted(set(reported) - set(expected))
    for name in unknown:
        lines.append(f"  not in the manifest: {name}")
    for line in lines:
        print(line)
    tail = f"; {len(unknown)} entr{'y names a file' if len(unknown) == 1 else 'ies name files'} the manifest does not list" if unknown else ""
    print(f"agrees on {agree}/{len(expected)} verdicts and reasons at {ref}{tail}")
    return 0 if agree == len(expected) and not unknown else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
