#!/usr/bin/env python3
"""
generate_dataset.py - Build detection datasets from the LATEST Atomic Red Team on GitHub.

Pulls atomics/T####/T####.yaml, extracts every test command, and writes:

  <out>/atomic_commands.csv          full corpus (all platforms), rich schema
  <out>/atomic_commands.csv.gz       gzip of the above
  <out>/atomic_linux_commands.csv    Linux-only, DROP-IN schema for aishield_check.py
  <out>/atomic_linux_commands.csv.gz gzip of the above
  <out>/technique_index.csv          INDEX of every ATT&CK technique id + coverage stats
  <out>/SOURCES.md                   provenance + exact commit pin (reproducibility)

Key improvements over the original corpus:
  * platform-aware  -> no macOS rows inside an 'linux' file
  * #{placeholders} substituted from each test's input_arguments defaults
  * pinned to an exact git commit, so the dataset can be regenerated

Usage
  python generate_dataset.py                       # use default source + ./dataset out
  python generate_dataset.py --source <atomics dir> --out <dir>
  python generate_dataset.py --no-resolve          # keep raw #{} text

Restrict to specific technique ids (hardcoded list)
  python generate_dataset.py --techniques T1059.004,T1105,T1048
  python generate_dataset.py --techniques T1105 --techniques T1048   # repeatable
  python generate_dataset.py --techniques ids.txt                    # one id per line
  python generate_dataset.py --techniques all                        # everything (default)
  ids.txt may contain comments (#) and/or comma-separated values.

  Requested ids that could not be found are reported, and it tells you
  whether the YAML is absent entirely or present-but-blocked on disk.
"""
import argparse
import csv
import gzip
import io
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, OrderedDict, defaultdict
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("Missing dependency: pip install pyyaml")

HERE = Path(__file__).resolve().parent
DEFAULT_SOURCE = Path(os.environ.get("ATOMIC_SRC", r"C:\Users\rp485\AppData\Local\Temp\opencode\atomic-red-team\atomics"))
AISHIELD_SCHEMA = ["command", "attack_technique", "technique_name"]

PLACEHOLDER = re.compile(r"#\{([A-Za-z_]\w*)\}")
SKIP_EXECUTORS = {"manual", "none", ""}


# ----------------------------------------------------------------------------- helpers
def load_yaml(path):
    with io.open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        return yaml.safe_load(f)


def resolve_placeholders(cmd, input_args, keep_unknown=True):
    """Replace #{name} with the test's declared default value."""
    args = input_args or {}
    known = {k: str(v.get("default", "")) for k, v in (args or {}).items() if isinstance(v, dict)}
    unknown = []

    def sub(m):
        key = m.group(1)
        if key in known and known[key]:
            return known[key]
        unknown.append(key)
        return m.group(0) if keep_unknown else "ARG"

    return PLACEHOLDER.sub(sub, cmd), sorted(set(unknown))


def git_info(repo_dir):
    try:
        sha = subprocess.run(["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=30).stdout.strip()
        date = subprocess.run(["git", "-C", str(repo_dir), "log", "-1", "--format=%cI"],
                              capture_output=True, text=True, timeout=30).stdout.strip()
        url = subprocess.run(["git", "-C", str(repo_dir), "remote", "get-url", "origin"],
                             capture_output=True, text=True, timeout=30).stdout.strip()
        return sha, date, url
    except Exception:
        return "", "", ""


def executor_commands(test):
    """Atomic tests can carry command / content / steps. Return (name, elevation, [cmds])."""
    ex = test.get("executor") or {}
    if not isinstance(ex, dict):
        return "", False, []
    name = str(ex.get("name", "")).strip()
    elev = bool(ex.get("elevation_required", False))
    cmds = []
    for key in ("command", "content"):
        v = ex.get(key)
        if isinstance(v, str) and v.strip():
            cmds.append(v)
    steps = ex.get("steps")
    if isinstance(steps, list):
        for s in steps:
            if isinstance(s, dict) and isinstance(s.get("command"), str) and s["command"].strip():
                cmds.append(s["command"])
            elif isinstance(s, str) and s.strip():
                cmds.append(s)
    return name, elev, cmds


# ----------------------------------------------------------------------------- extract
def extract(atomics_dir, resolve=True, only=None):
    """only: optional set of UPPER-CASE technique ids to keep (None = keep everything)."""
    rows = []
    tech_names = OrderedDict()
    skipped = Counter()
    files = sorted(atomics_dir.glob("T*/T*.yaml"))

    for yml in files:
        try:
            doc = load_yaml(yml)
        except Exception as e:
            skipped[f"yaml-error:{type(e).__name__}"] += 1
            continue
        if not isinstance(doc, dict) or not doc.get("attack_technique"):
            skipped["no-technique-id"] += 1
            continue

        tid = str(doc["attack_technique"]).strip()
        if only is not None and tid.upper() not in only:
            continue
        # display_name lives at top level; fall back to index.yaml style keys
        tname = str(doc.get("display_name") or doc.get("technique_name") or "").strip()
        tech_names.setdefault(tid, tname or tid)

        tests = doc.get("atomic_tests") or []
        if not tests:
            skipped["no-tests"] += 1

        for idx, test in enumerate(tests, 1):
            if not isinstance(test, dict):
                continue
            platforms = [str(p).strip().lower() for p in (test.get("supported_platforms") or [])]
            exname, elev, cmds = executor_commands(test)
            if not cmds:
                skipped["no-command"] += 1
                continue
            if exname.lower() in SKIP_EXECUTORS and not cmds:
                skipped["manual-executor"] += 1
                continue

            iargs = test.get("input_arguments") or {}
            for raw in cmds:
                if resolve:
                    cmd, unknown = resolve_placeholders(raw, iargs)
                else:
                    cmd, unknown = raw, sorted(set(PLACEHOLDER.findall(raw)))
                cmd = cmd.replace("\r\n", "\n").strip("\n")
                if not cmd.strip():
                    skipped["empty-command"] += 1
                    continue
                rows.append({
                    "attack_technique": tid,
                    "technique_name": tname,
                    "platforms": "|".join(platforms),
                    "test_name": str(test.get("name", "")).strip(),
                    "test_index": idx,
                    "executor": exname,
                    "elevation_required": "yes" if elev else "no",
                    "placeholders_left": "|".join(unknown),
                    "command": cmd,
                })

    return rows, tech_names, skipped, len(files)


# ----------------------------------------------------------------------------- writers
def write_csv(path, rows, cols, gz=False):
    path = Path(path)
    opener = gzip.open if gz else io.open
    kw = {"mode": "wt", "newline": "", "encoding": "utf-8", "errors": "replace"}
    with opener(path, **kw) as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)
    return path


def parse_techniques(values):
    """Turn --techniques input into a set of UPPER-CASE ids, or None for 'all'.

    Accepts any mix of: comma lists, repeated flags, whitespace, and a path to a
    text file (one id per line; '# comments' and commas allowed).
    Returns (ids_or_None, source_description).
    """
    if not values:
        return None, "all"

    raw = []
    for v in values:
        v = v.strip()
        if not v:
            continue
        if v.lower() == "all":
            return None, "all"
        looks_like_file = (v.lower().endswith((".txt", ".lst", ".csv", ".ids"))
                           or Path(v).is_file())
        if looks_like_file and Path(v).exists():
            text = Path(v).read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                line = line.split("#", 1)[0]
                raw.append(line)
        else:
            raw.append(v)

    ids, junk = set(), []
    for chunk in raw:
        for tok in re.split(r"[,\s;]+", str(chunk)):
            tok = tok.strip().strip("'\"").upper()
            if not tok:
                continue
            if re.fullmatch(r"T\d{3,4}(?:\.\d{1,3})?", tok):
                ids.add(tok)
            else:
                junk.append(tok)
    if junk:
        print(f"  ! ignoring {len(junk)} value(s) that are not a technique id: {junk[:6]}")
    if not ids:
        sys.exit("--techniques produced no valid technique ids (expected e.g. T1059.004)")
    return ids, f"{len(ids)} id(s)"


def report_missing(requested, found, atomics_dir):
    """Explain every requested id we did not produce a row for."""
    missing = sorted(requested - found)
    if not missing:
        return
    print(f"\n  {len(missing)} requested technique id(s) NOT found:")
    for t in missing:
        yml = Path(atomics_dir) / t / f"{t}.yaml"
        if yml.exists():
            why = "YAML EXISTS but could not be read (likely antivirus quarantine)"
        elif (Path(atomics_dir) / t).exists():
            why = "folder exists but has no T*.yaml inside"
        else:
            why = "not present in Atomic Red Team"
        print(f"    {t:<12} {why}")


def main():
    ap = argparse.ArgumentParser(description="Build datasets from Atomic Red Team")
    ap.add_argument("--source", default=str(DEFAULT_SOURCE), help="path to the atomics/ directory")
    ap.add_argument("--out", default=str(HERE), help="output folder for the datasets")
    ap.add_argument("--no-resolve", action="store_true", help="keep raw #{placeholders}")
    ap.add_argument("--techniques", action="append", metavar="IDS",
                    help="only these technique ids: comma list, repeatable flag, "
                         "a .txt file (one per line), or 'all'")
    args = ap.parse_args()

    src = Path(args.source)
    out = Path(args.out)
    if not src.exists():
        sys.exit(f"Source not found: {src}\nClone it first:\n"
                 f"  git clone --depth 1 --filter=blob:none --sparse "
                 f"https://github.com/redcanaryco/atomic-red-team.git\n"
                 f"  git -C <repo> sparse-checkout set atomics")
    out.mkdir(parents=True, exist_ok=True)

    print(f"Source : {src}")
    print(f"Output : {out}")
    only, filt_desc = parse_techniques(args.techniques)
    if only is not None:
        print(f"Filter  : {filt_desc} -> {', '.join(sorted(only))}")
    print("Extracting ...")
    rows, tech_names, skipped, nfiles = extract(src, resolve=not args.no_resolve, only=only)
    if only is not None:
        report_missing(only, set(tech_names), src)
    print(f"  atomic test files : {nfiles}")
    print(f"  command rows      : {len(rows)}")
    if skipped:
        print(f"  skipped           : {dict(skipped)}")

    # ---- index of technique ids ----
    by_tech = defaultdict(list)
    for r in rows:
        by_tech[r["attack_technique"]].append(r)

    index = []
    for tid, tname in tech_names.items():
        rs = by_tech.get(tid, [])
        plats = sorted({p for r in rs for p in r["platforms"].split("|") if p})
        linux = sum(1 for r in rs if "linux" in r["platforms"].split("|"))
        macos = sum(1 for r in rs if "macos" in r["platforms"].split("|"))
        index.append({
            "attack_technique": tid,
            "technique_name": tname,
            "is_subtechnique": "yes" if "." in tid else "no",
            "atomic_files": 1,
            "tests_with_command": len({(r["test_name"], r["test_index"]) for r in rs}),
            "command_rows": len(rs),
            "linux_rows": linux,
            "macos_rows": macos,
            "platforms": "|".join(plats),
            "has_placeholder_rows": sum(1 for r in rs if r["placeholders_left"]),
        })
    index.sort(key=lambda r: r["attack_technique"])

    FULL_COLS = ["attack_technique", "technique_name", "platforms", "test_name",
                 "test_index", "executor", "elevation_required", "placeholders_left", "command"]
    IDX_COLS = ["attack_technique", "technique_name", "is_subtechnique", "atomic_files",
                "tests_with_command", "command_rows", "linux_rows", "macos_rows",
                "platforms", "has_placeholder_rows"]

    # ---- full corpus ----
    write_csv(out / "atomic_commands.csv", rows, FULL_COLS)
    write_csv(out / "atomic_commands.csv.gz", rows, FULL_COLS, gz=True)

    # ---- linux-only, drop-in compatible with aishield_check.py ----
    linux_rows = [r for r in rows if "linux" in r["platforms"].split("|")]
    write_csv(out / "atomic_linux_commands.csv", linux_rows, AISHIELD_SCHEMA)
    write_csv(out / "atomic_linux_commands.csv.gz", linux_rows, AISHIELD_SCHEMA, gz=True)

    # ---- technique index ----
    write_csv(out / "technique_index.csv", index, IDX_COLS)

    # ---- provenance ----
    repo = src.parent
    sha, date, url = git_info(repo)
    left = sum(1 for r in rows if r["placeholders_left"])
    md = f"""# Dataset sources

Generated by `generate_dataset.py`.

## Origin

| | |
|---|---|
| Project | **Atomic Red Team** - Red Canary |
| Repository | https://github.com/redcanaryco/atomic-red-team |
| License | Apache License 2.0 |
| Retrieved | {date or 'unknown'} |
| Commit | `{sha or 'unknown'}` |
| ATT&CK taxonomy | MITRE ATT&CK - https://attack.mitre.org |

> Attribution: technique IDs and names originate from MITRE ATT&CK.
> Commands originate from Atomic Red Team (Apache-2.0), Red Canary.

## Generated files

| File | Rows | Description |
|---|---|---|
| `atomic_commands.csv` | {len(rows)} | Full corpus, all platforms |
| `atomic_commands.csv.gz` | {len(rows)} | gzip |
| `atomic_linux_commands.csv` | {len(linux_rows)} | Linux-only, schema `command,attack_technique,technique_name` |
| `atomic_linux_commands.csv.gz` | {len(linux_rows)} | gzip |
| `technique_index.csv` | {len(index)} | Index of every ATT&CK technique id + coverage stats |

## Stats

- atomic test files parsed: {nfiles}
- unique technique ids: {len(tech_names)}
- rows with unresolved placeholders: {left}
- skipped: `{json.dumps(skipped)}`

## Reproduce

```
git clone --depth 1 --filter=blob:none --sparse https://github.com/redcanaryco/atomic-red-team.git
git -C atomic-red-team sparse-checkout set atomics
python generate_dataset.py --source atomic-red-team/atomics --out .
```
"""
    (out / "SOURCES.md").write_text(md, encoding="utf-8")

    print("\nWrote:")
    for p in ["atomic_commands.csv", "atomic_commands.csv.gz",
              "atomic_linux_commands.csv", "atomic_linux_commands.csv.gz",
              "technique_index.csv", "SOURCES.md"]:
        f = out / p
        print(f"  {p:<34} {f.stat().st_size:>10,} bytes")

    print(f"\nTechnique ids indexed : {len(index)}")
    print(f"  with linux rows      : {sum(1 for r in index if r['linux_rows'])}")
    print(f"  with macos rows      : {sum(1 for r in index if r['macos_rows'])}")
    print(f"  sub-techniques       : {sum(1 for r in index if r['is_subtechnique'] == 'yes')}")
    print(f"Linux rows             : {len(linux_rows)}")
    print(f"Unresolved placeholders: {left}")


if __name__ == "__main__":
    main()
