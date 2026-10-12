#!/usr/bin/env python3
"""Mutation run for the defined-members rule (v0.5.8, issue #17), stdlib only.

Each mutant is a one-site change to verify.py or tools/cross_check_ts.mjs, applied in a scratch
copy of the repository. A mutant is KILLED when the engine's run exits non-zero AND every vector
named for it fails; the unmutated copy must pass first and again at the end. The TypeScript
mutants need `node` and `viem` (`npm i viem` in the repository root, as CI does).

    python3 tools/mutate_members.py              # every mutant
    python3 tools/mutate_members.py NAME ...     # only the named mutants

Exit 0 only if every mutant is killed by its named vectors and both controls pass.
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ONLY = sys.argv[1:]


def ids(lo, hi, prefix="n"):
    return [f"{prefix}{i}" for i in range(lo, hi + 1)]


ALL_REJECTS = ids(107, 152)
ORDER = {"chain_set": "n133", "digest_recompute": "n134", "canonical_bytes": "n135", "chain_link": "n136",
         "chain_commitment": "n137", "anchor_relation": "n138", "phase_claim": "n139",
         "independence_claim": "n140", "offer_binding": "n141", "decision_evidence_binding": "n142",
         "boundary_binding": "n143"}
TOP = {"digest_recompute": "n107", "canonical_bytes": "n108", "chain_link": "n109", "chain_set": "n110",
       "chain_commitment": "n111", "anchor_relation": "n112", "phase_claim": "n113",
       "independence_claim": "n114", "offer_binding": "n115", "decision_evidence_binding": "n116",
       "boundary_binding": "n117"}

# ---------------------------------------------------------------- verify.py: (old, new, killers)
PY_CHECK = ("    if not isinstance(inp, dict):\n        return None\n"
            "    for path, obj, names in _closed_objects(kind, inp):\n")
PY_NAMES = "if name not in names]"
PY_LOOP = "                for i, entry in enumerate(entries):\n"
PY_ENTRY = ("                    if isinstance(entry, dict):\n"
            "                        yield f\"input.{key[:-2]}[{i}]\", entry, names\n")
PY_COMPOSE = "        return check_defined_members(kind, inp) or criterion(inp)\n"
PY_CRITERION_FIRST = ("        r = criterion(inp)\n"
                      "        return r if r[0] != 'valid' else (check_defined_members(kind, inp) or r)\n")
PY = {
    "disable": (PY_CHECK, "    return None\n" + PY_CHECK, ALL_REJECTS),
    "top-level-only": ("        if path == \"input\":\n            yield path, inp, names\n            continue\n",
                       "        if path == \"input\":\n            yield path, inp, names\n        continue\n",
                       ["n118", "n119", "n120", "n121", "n122", "n127", "n128", "n130", "n144", "n145",
                        "n146", "n147", "n148", "n150", "n151", "n152"]),
    "no-array-entries": (PY_LOOP, PY_LOOP.replace("enumerate(entries)", "enumerate(entries[:0])"),
                         ["n119", "n121", "n122", "n127", "n128", "n145", "n146", "n147", "n148", "n150", "n152"]),
    "first-entry-only": (PY_LOOP, PY_LOOP.replace("enumerate(entries)", "enumerate(entries[:1])"),
                         ["n119", "n121", "n122", "n128"]),
    "last-entry-only": (PY_LOOP, PY_LOOP.replace("enumerate(entries)", "list(enumerate(entries))[-1:]"),
                        ["n127", "n145", "n146", "n147"]),
    "skip-first-entry": (PY_LOOP, PY_LOOP.replace("enumerate(entries)", "list(enumerate(entries))[1:]"),
                         ["n127", "n145", "n146", "n147"]),
    "attestations-last-only": (PY_LOOP, PY_LOOP.replace(
        "enumerate(entries)", "(list(enumerate(entries))[-1:] if key == 'attestations[]' else enumerate(entries))"),
        ["n145", "n146", "n147"]),
    "attestations-skip-first": (PY_LOOP, PY_LOOP.replace(
        "enumerate(entries)", "(list(enumerate(entries))[1:] if key == 'attestations[]' else enumerate(entries))"),
        ["n145", "n146", "n147"]),
    "attestations-outside-only": (PY_ENTRY, PY_ENTRY.replace(
        "if isinstance(entry, dict):",
        "if isinstance(entry, dict) and not (key == 'attestations[]' and entry.get('by') in (inp.get('parties') or [])):"),
        ["n145", "n146", "n147"]),
    "attestations-only-under-claim": ("        if key.endswith(\"[]\"):\n",
                                      "        if key == 'attestations[]' and inp.get('claimed') in (None, 'none'):\n"
                                      "            continue\n        if key.endswith(\"[]\"):\n",
                                      ["n147", "n148"]),
    "stop-at-non-object-entry": (PY_ENTRY, "                    if not isinstance(entry, dict):\n"
                                           "                        break\n"
                                           "                    yield f\"input.{key[:-2]}[{i}]\", entry, names\n",
                                 ["n148"]),
    "case-insensitive": (PY_NAMES, "if name.lower() not in {n.lower() for n in names}]", ["n126"]),
    "nfkc-names": (PY_NAMES, "if __import__('unicodedata').normalize('NFKC', name) not in names]", ["n128"]),
    "confusable-skeleton": (PY_NAMES, "if name.replace('\\u0435', 'e') not in names]", ["n127"]),
    "strip-names": (PY_NAMES, "if name.strip() not in names]", ["n149"]),
    "skip-null-values": (PY_NAMES, "if name not in names and obj[name] is not None]", ["n123"]),
    "skip-falsy-values": (PY_NAMES, "if name not in names and obj[name]]", ["n123", "n124", "n125"]),
    "one-list-for-all": (PY_NAMES,
                         "if name not in frozenset().union(*(s for t in DEFINED_MEMBERS.values() for s in t.values()))]",
                         ["n129", "n130"]),
    "criterion-first": (PY_COMPOSE, PY_CRITERION_FIRST, ids(133, 145) + ids(150, 152)),
    "nested-after-criterion": (PY_COMPOSE,
                               "        if isinstance(inp, dict) and any(n not in DEFINED_MEMBERS[kind]['input'] for n in inp):\n"
                               "            return check_defined_members(kind, inp)\n" + PY_CRITERION_FIRST,
                               ["n144", "n145", "n150", "n151", "n152"]),
    "close-not-read-chain-set": (
        "    \"chain_set\": {\"input\": _CHAIN_INPUT, \"input.head\": frozenset({\"seq\", \"digest\"}),\n",
        "    \"chain_set\": {\"input\": _CHAIN_INPUT, \"input.witness\": frozenset({\"checkpoint\", \"inclusion\"}), "
        "\"input.attestations[]\": frozenset({\"by\", \"role\"}), \"input.head\": frozenset({\"seq\", \"digest\"}),\n",
        ["p58"]),
    "commitment-omits-not-read": ("    \"chain_commitment\": {\"input\": _CHAIN_INPUT,",
                                  "    \"chain_commitment\": {\"input\": frozenset({\"head\", \"records\"}),",
                                  ["p57", "p61"]),
    "commitment-closes-attestations": ("    \"chain_commitment\": {\"input\": _CHAIN_INPUT,",
                                       "    \"chain_commitment\": {\"input\": _CHAIN_INPUT, "
                                       "\"input.attestations[]\": frozenset({\"by\", \"role\"}),",
                                       ["p61"]),
    "commitment-closes-witness": ("    \"chain_commitment\": {\"input\": _CHAIN_INPUT,",
                                  "    \"chain_commitment\": {\"input\": _CHAIN_INPUT, "
                                  "\"input.witness\": frozenset({\"checkpoint\", \"inclusion\"}),",
                                  ["p61"]),
    "close-settlement-result": ("        \"input.attestations[]\": frozenset({\"by\", \"role\"}),\n",
                                "        \"input.attestations[]\": frozenset({\"by\", \"role\"}),\n"
                                "        \"input.settlement_result\": frozenset({\"success\", \"transaction\", \"network\"}),\n",
                                ["p59"]),
    "close-receipt": ("    \"offer_binding\": {\"input\": frozenset({\"offer\", \"receipt\"})},",
                      "    \"offer_binding\": {\"input\": frozenset({\"offer\", \"receipt\"}), "
                      "\"input.receipt\": frozenset({\"offerDigest\"})},",
                      ["p60"]),
}
for _kind, _vid in ORDER.items():
    PY[f"criterion-first:{_kind}"] = (
        PY_COMPOSE,
        f"        if kind == {_kind!r}:\n" + PY_CRITERION_FIRST.replace("        ", "            ") + PY_COMPOSE,
        [_vid])
for _kind, _vid in TOP.items():
    PY[f"kind-open:{_kind}"] = (PY_CHECK, PY_CHECK.replace("if not isinstance(inp, dict):",
                                                           f"if not isinstance(inp, dict) or kind == {_kind!r}:"),
                                [_vid])

# ---------------------------------------------------- tools/cross_check_ts.mjs: (old, new, killers)
TS_LINE = "      if (Object.keys(obj).some((name) => !names.has(name))) return [\"reject\", \"unknown_member_reject\"];\n"
TS_ENTRIES = "objects = Array.isArray(entries) ? entries.filter(isObject) : [];"
TS_COMPOSE = "[kind, (inp) => checkDefinedMembers(kind, inp) ?? criterion(inp)]"
TS = {
    "ts-disable": ("  if (!isObject(inp)) return null;\n", "  return null;\n", ALL_REJECTS),
    "ts-plain-object-table": (TS_LINE,
                              "      const table = Object.fromEntries([...names].map((n) => [n, true]));\n"
                              + TS_LINE.replace("!names.has(name)", "!(name in table)"),
                              ["n131", "n132"]),
    "ts-copy-by-assignment": (TS_LINE,
                              "      const copy = {}; for (const k of Object.keys(obj)) copy[k] = obj[k];\n"
                              + TS_LINE.replace("Object.keys(obj)", "Object.keys(copy)"),
                              ["n132"]),
    "ts-criterion-first": (TS_COMPOSE,
                           "[kind, (inp) => ((r) => (r[0] !== \"valid\" ? r : checkDefinedMembers(kind, inp) ?? r))(criterion(inp))]",
                           ids(133, 145) + ids(150, 152)),
    "ts-first-entry-only": (TS_ENTRIES, TS_ENTRIES.replace("entries.filter(isObject)", "entries.filter(isObject).slice(0, 1)"),
                            ["n119", "n121", "n122", "n128"]),
    "ts-last-entry-only": (TS_ENTRIES, TS_ENTRIES.replace("entries.filter(isObject)", "entries.filter(isObject).slice(-1)"),
                           ["n127", "n145", "n146", "n147"]),
    "ts-stop-at-non-object-entry": (TS_ENTRIES, TS_ENTRIES.replace(
        "entries.filter(isObject)",
        "entries.slice(0, entries.findIndex((e) => !isObject(e)) < 0 ? entries.length : entries.findIndex((e) => !isObject(e)))"),
        ["n148"]),
    "ts-case-insensitive": (TS_LINE, TS_LINE.replace(
        "!names.has(name)", "![...names].some((n) => n.toLowerCase() === name.toLowerCase())"), ["n126"]),
    "ts-nfkc-names": (TS_LINE, TS_LINE.replace("!names.has(name)", "!names.has(name.normalize(\"NFKC\"))"), ["n128"]),
    "ts-strip-names": (TS_LINE, TS_LINE.replace("!names.has(name)", "!names.has(name.trim())"), ["n149"]),
}


def scratch():
    d = tempfile.mkdtemp(prefix="mutate-members-")
    dst = os.path.join(d, "repo")
    shutil.copytree(ROOT, dst, symlinks=True,
                    ignore=shutil.ignore_patterns(".git", "__pycache__", ".claude", "node_modules"))
    if os.path.exists(os.path.join(ROOT, "node_modules")):
        os.symlink(os.path.realpath(os.path.join(ROOT, "node_modules")), os.path.join(dst, "node_modules"))
    return d, dst


def _vid(file_name):
    return file_name.split("-", 1)[0]


def run_py(root):
    p = subprocess.run([sys.executable, "-B", "verify.py"], cwd=root, capture_output=True, text=True, timeout=200)
    fails = {_vid(line.split("]", 1)[1].split()[0]) for line in p.stdout.splitlines() if line.startswith("  [FAIL]")}
    return p.returncode, fails


def run_ts(root):
    p = subprocess.run(["node", "tools/cross_check_ts.mjs"], cwd=root, capture_output=True, text=True, timeout=200)
    fails = {_vid(line.split()[1]) for line in p.stdout.splitlines()
             if line.startswith("DIVERGE ") and line.split()[1].endswith(".json")}
    return p.returncode, fails


def run(py_table, ts_table, only=()):
    """Apply each mutant in a scratch copy and require its named vectors to fail; exit status."""
    d, root = scratch()
    try:
        controls = [("py", run_py(root)), ("ts", run_ts(root))]
        for name, (rc, fails) in controls:
            print(f"control {name}: rc={rc} failing={sorted(fails)}")
        if any(rc or fails for _, (rc, fails) in controls):
            return 1
        total = killed = 0
        for table, fname, runner in ((py_table, "verify.py", run_py), (ts_table, "tools/cross_check_ts.mjs", run_ts)):
            path = os.path.join(root, fname)
            with open(path, encoding="utf-8") as f:
                orig = f.read()
            for name, (old, new, killers) in table.items():
                if only and name not in only:
                    continue
                total += 1
                if orig.count(old) != 1:
                    print(f"NOT APPLIED {name}: its site occurs {orig.count(old)} times in {fname}")
                    continue
                with open(path, "w", encoding="utf-8") as f:
                    f.write(orig.replace(old, new))
                try:
                    rc, fails = runner(root)
                finally:
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(orig)
                missed = [k for k in killers if k not in fails]
                ok = rc != 0 and not missed
                killed += ok
                print(f"{'KILLED' if ok else 'SURVIVED':8s} {name:36s} rc={rc} named={','.join(killers)}"
                      + (f" missed={','.join(missed)}" if missed else ""))
        after = [("py", run_py(root)), ("ts", run_ts(root))]
        for name, (rc, fails) in after:
            print(f"restored {name}: rc={rc} failing={sorted(fails)}")
        print(f"{killed}/{total} mutants killed by their named vectors")
        return 0 if total and killed == total and not any(rc or fails for _, (rc, fails) in after) else 1
    finally:
        shutil.rmtree(d)


def main():
    return run(PY, TS, ONLY)


if __name__ == "__main__":
    sys.exit(main())
