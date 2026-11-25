"""Measure skillaudit against a corpus: legitimate tools on one side, the malicious demo skills on the other.

Nothing that is scanned is ever executed. The malicious samples are the demo fixtures (tests/fixtures.py), built in
a temporary folder and deleted afterwards. Legitimate samples are folders already on this machine, listed in a
git-ignored config file (see samples.example.json).

    python benchmark/run.py --tag baseline-1.0.0            scan everything, write reports
    python benchmark/run.py --tag baseline-1.0.0 --report   rebuild the reports from the last scan (after labelling)
    python benchmark/run.py --spotcheck 20                  pick labelled findings for a human spot-check

Committed output (results/): named public samples in detail, local samples only as group totals.
Private output (local/, git-ignored): everything, plus the labelling worksheet. Held-back samples are reported
only as totals, everywhere, so they stay unseen while rules are tuned.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import shutil
import sys
import tempfile
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from multiprocessing import Pool

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

from skillaudit import __version__, correlate  # noqa: E402
from skillaudit.cli import discover  # noqa: E402
from skillaudit.model import Finding, sev_rank  # noqa: E402
from skillaudit.rules import RULES  # noqa: E402
from skillaudit.scanner import ScanOptions, Scanner, discover_units  # noqa: E402

VERDICTS = ["CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
VRANK = {v: i for i, v in enumerate(VERDICTS)}
SEVS = ["critical", "high", "medium", "low", "info"]
LABELS = ["wrong match", "real but normal here", "needs a human"]
LIMIT = ("The malicious samples and the rules were written by the same author, so these numbers show that known "
         "techniques are covered. They are not a real-world detection rate. The legitimate samples are what was "
         "installed on one developer machine, so they over-represent browser automation, design skills and "
         "front-end packages.")
# What the test suite requires of each demo (tests/test_skillaudit.py).
DEMO_EXPECTED = {"clawhavoc": "CRITICAL", "skillject": "CRITICAL", "unicode": "CRITICAL", "hidden": "CRITICAL",
                 "persistence": "CRITICAL", "obfuscated": "CRITICAL", "mcp_poison": "CRITICAL", "reviewer": "HIGH",
                 "binary": "CRITICAL", "archive": "CRITICAL"}
# Built-in (non-regex) checks that can report CRITICAL. They are listed even when nothing triggers them, so a
# missing malicious example shows up as "unknown" instead of disappearing from the table.
BUILTIN_CRITICAL = ["CHAIN-CREDENTIAL-EXFILTRATION", "CHAIN-FILE-SWEEP-EXFILTRATION", "CHAIN-HIDDEN-INSTRUCTIONS",
                    "CHAIN-INSTALL-LURE", "CHAIN-MEMORY-POISONING", "CHAIN-SKILLJECT", "IOC-KNOWN-BAD",
                    "IOC-KNOWN-BAD-IP", "IOC-KNOWN-BAD-STRING", "IOC-KNOWN-BAD-PACKAGE", "IOC-KNOWN-BAD-HASH",
                    "IOC-KNOWN-BAD-SKILL-NAME", "OBF-EMBEDDED-BINARY", "OBF-ENCODED-PAYLOAD", "BIN-PICKLE-CODE-EXEC",
                    "BIN-PDF-LAUNCH", "FS-LINK-TO-SENSITIVE", "FS-NAME-HIDDEN-CHARS", "FS-NAME-HOMOGLYPH",
                    "META-YAML-TAGS", "META-PREREQUISITE-LURE", "UNI-TAG-SMUGGLING",
                    "UNI-VARIATION-SELECTOR-SMUGGLING", "UNI-ZERO-WIDTH"]
KEEP = ("rule_id", "title", "severity", "category", "path", "line", "confidence", "snippet", "origin",
        "capabilities", "tags", "occurrences", "fingerprint")
LOCAL = os.path.join(HERE, "local")


# ----------------------------------------------------------------------------- helpers

def expand(p):
    return os.path.abspath(os.path.expandvars(os.path.expanduser(p)))


def scanner_hash():
    h = hashlib.sha256()
    d = os.path.join(ROOT, "skillaudit")
    for n in sorted(os.listdir(d)):
        if n.endswith(".py"):
            h.update(n.encode())
            with open(os.path.join(d, n), "rb") as fh:
                h.update(fh.read())
    return h.hexdigest()


def tree_hash(path):
    """Content fingerprint of a file or folder. Links are never followed (their target text is hashed)."""
    h = hashlib.sha256()
    n = size = 0

    def add(p, rel):
        nonlocal n, size
        if os.path.islink(p):
            data = ("<link>" + os.readlink(p)).encode("utf-8", "replace")
        else:
            try:
                with open(p, "rb") as fh:
                    data = fh.read()
            except OSError:
                data = b"<unreadable>"
        h.update(rel.encode("utf-8", "replace") + b"\0" + hashlib.sha256(data).digest())
        n += 1
        size += len(data)

    if os.path.isfile(path):
        add(path, os.path.basename(path))
    else:
        for d, dirs, files in os.walk(path):
            dirs.sort()
            for f in sorted(files):
                p = os.path.join(d, f)
                add(p, os.path.relpath(p, path).replace(os.sep, "/"))
    return h.hexdigest(), n, size


def quick_size(path):
    if os.path.isfile(path):
        return os.path.getsize(path)
    total = 0
    for d, _, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(d, f)).st_size
            except OSError:
                pass
    return total


def holdout(sample_id):
    return int(hashlib.sha256(sample_id.encode("utf-8")).hexdigest()[:8], 16) % 2 == 1


def bucket(path):
    """Where in a package a finding sits (for reporting only; the scanner does not use this)."""
    p = (path or "").replace("\\", "/").lower()
    if not p or p == "(skill)":
        return "whole package"
    name = p.rsplit("/", 1)[-1].split("!/")[-1]
    if name == "skill.md":
        return "SKILL.md"
    if name.endswith((".d.ts", ".d.mts", ".d.cts")):
        return "type definitions"
    segs = set(p.split("/"))
    if segs & {"node_modules", "third_party", "third-party", "thirdparty", "vendor", "vendored", "_vendor"} or \
            "bundle" in name or ".min." in name:
        return "bundled / third-party"
    if name.endswith((".md", ".markdown", ".mdx", ".txt", ".rst", ".html", ".htm")):
        return "documentation"
    return "own code"


def npm_version(path):
    try:
        with open(os.path.join(path, "package.json"), encoding="utf-8") as fh:
            return json.load(fh).get("version", "")
    except (OSError, ValueError):
        return ""


# ----------------------------------------------------------------------------- corpus

def load_corpus(cfg_path):
    with open(cfg_path, encoding="utf-8") as fh:
        cfg = json.load(fh)
    samples, missing = [], []

    def add(sid, path, side, group, named, split="tune", base=None):
        if not os.path.exists(path):
            missing.append({"id": sid if named else group, "reason": "folder not found"})
            return
        samples.append({"id": sid, "base": base or sid, "path": path, "side": side, "group": group, "named": named,
                        "split": split, "mode": "split"})

    for e in cfg.get("named", []):
        if "each_subdir" in e:
            base = expand(e["each_subdir"])
            if not os.path.isdir(base):
                missing.append({"id": e["each_subdir"], "reason": "folder not found"})
                continue
            for n in sorted(os.listdir(base)):
                if os.path.isdir(os.path.join(base, n)):
                    add(e.get("prefix", "") + n, os.path.join(base, n), "legit", "named", True)
        else:
            path = expand(e["path"])
            sid = e["id"] + ("@" + npm_version(path) if e.get("npm_version") and npm_version(path) else "")
            add(sid, path, "legit", "named", True, base=e["id"])
    for e in cfg.get("needs_human", []):
        add(e["id"], expand(e["path"]), "needs-human", "needs-human", True)
    for e in cfg.get("local", []):
        g = e["group"]
        if e.get("discover"):
            for d in discover():
                if "/.staging/" in d.replace("\\", "/"):
                    continue  # half-written copies left by an interrupted sync, not installed skills
                sid = "%s:%s" % (g, os.path.relpath(d, os.path.expanduser("~")).replace(os.sep, "/"))
                add(sid, d, "legit", g, False, "holdout" if holdout(sid) else "tune")
        elif "each_package" in e:
            base = expand(e["each_package"])
            if not os.path.isdir(base):
                missing.append({"id": g, "reason": "folder not found"})
                continue
            for n in sorted(os.listdir(base)):
                p = os.path.join(base, n)
                if not os.path.isdir(p) or n.startswith("."):
                    continue
                subs = [os.path.join(n, s) for s in sorted(os.listdir(p))] if n.startswith("@") else [n]
                for s in subs:
                    sp = os.path.join(base, s)
                    if os.path.isdir(sp):
                        sid = "%s:%s" % (g, s.replace(os.sep, "/"))
                        add(sid, sp, "legit", g, False, "holdout" if holdout(sid) else "tune")
        else:
            sid = "%s:%s" % (g, e["id"])
            add(sid, expand(e["path"]), "legit", g, False, "holdout" if holdout(sid) else "tune")
    return cfg, samples, missing


def build_generated(tmp, samples, cfg):
    """Demo fixtures (malicious side + the benign control) and the size-check variants, in a temp folder."""
    import fixtures
    out, missing = [], []
    droot = os.path.join(tmp, "demos")
    fx = fixtures.build_all(droot)
    for path, why, kind in fixtures.missing_samples(droot):
        missing.append({"id": "demo:" + path, "reason": why})
    for key, path in fx.items():
        name = os.path.basename(path)
        if key == "benign":
            out.append({"id": "demo:" + name, "path": path, "side": "legit", "group": "named", "named": True,
                        "split": "tune", "mode": "first"})
        else:
            out.append({"id": "demo:" + name, "path": path, "side": "malicious", "group": "demo", "named": True,
                        "split": "tune", "mode": "first", "demo_key": key, "expected": DEMO_EXPECTED[key]})
    host = next((s for s in samples if s["base"] == cfg.get("size_check_host")), None)
    if host:
        for n in (1, 4, 16):
            d = os.path.join(tmp, "size", "legit-x%d" % n)
            for i in range(n):
                shutil.copytree(host["path"], os.path.join(d, "copy%d" % i) if n > 1 else d)
            out.append({"id": "size:%s x%d" % (host["id"], n), "path": d, "side": "size-legit", "group": "size",
                        "named": True, "split": "tune", "mode": "split", "copies": n})
        for n in (1, 4, 16):
            d = os.path.join(tmp, "size", "demo-x%d" % n)
            shutil.copytree(fx["skillject"], d)
            for i in range(n - 1):
                shutil.copytree(host["path"], os.path.join(d, "vendor-copy%d" % i))
            out.append({"id": "size:demo:code-reviewer + %d copies of %s" % (n - 1, host["id"]), "path": d,
                        "side": "size-malicious", "group": "size", "named": True, "split": "tune", "mode": "first",
                        "copies": n, "expected": "CRITICAL"})
    else:
        missing.append({"id": "size check", "reason": "size_check_host not among the samples"})
    return out, missing


# ----------------------------------------------------------------------------- scanning (worker processes)

def compact(f):
    d = {k: getattr(f, k) for k in KEEP}
    d["snippet"] = (d["snippet"] or "")[:300]
    return d


def scan_task(task):
    t0 = time.time()
    try:
        tree, nfiles, nbytes = tree_hash(task["path"])
        key = hashlib.sha256((task["shash"] + tree + task["mode"]).encode()).hexdigest()
        cp = os.path.join(task["cache"], key + ".json") if task["cache"] else ""
        if cp and os.path.exists(cp):
            with open(cp, encoding="utf-8") as fh:
                units = json.load(fh)
            return {"id": task["id"], "tree": tree, "files": nfiles, "bytes": nbytes, "units": units,
                    "seconds": round(time.time() - t0, 2), "cached": True}
        found = discover_units(task["path"], split=True)
        if task["mode"] == "first":
            found = found[:1]
        sc = Scanner(ScanOptions(embed="none"))
        units = []
        for name, r, excl in found:
            s = sc.scan_unit(name, r, excl)
            units.append({"name": name, "verdict": s.verdict, "score": s.risk_score, "files": len(s.files),
                          "findings": [compact(f) for f in s.findings], "skills": s.skill.get("manifests", []),
                          "coverage": {"unreadable": len(s.coverage.get("unreadable", [])),
                                       "partial": len(s.coverage.get("partial", []))}})
        if cp:
            with open(cp, "w", encoding="utf-8") as fh:
                json.dump(units, fh)
        return {"id": task["id"], "tree": tree, "files": nfiles, "bytes": nbytes, "units": units,
                "seconds": round(time.time() - t0, 2), "cached": False}
    except Exception as exc:  # one broken sample must not stop the run; it is listed as an error
        return {"id": task["id"], "error": "%s: %s" % (type(exc).__name__, exc), "units": [],
                "seconds": round(time.time() - t0, 2)}


# ----------------------------------------------------------------------------- analysis

def findings_of(unit):
    return [Finding(**{k: d[k] for k in KEEP if k in d}) for d in unit["findings"]]


def rescore(unit, drop_rules=(), drop_cats=()):
    """Verdict and score with some rules or categories removed; chains are recomputed from what is left."""
    base = [f for f in findings_of(unit) if f.origin != "correlation" and f.rule_id not in drop_rules
            and f.category not in drop_cats]
    chained = [c for c in correlate.chains(base, unit["skills"]) if c.rule_id not in drop_rules]
    score, verdict, _ = correlate.score_and_verdict(base + chained)
    return verdict, score


def sample_verdict(r):
    if not r.get("units"):
        return "ERROR", 0
    v = max((u["verdict"] for u in r["units"]), key=lambda x: VRANK.get(x, -1))
    return v, max(u["score"] for u in r["units"])


def sev_counts(r):
    c = Counter(f["severity"] for u in r["units"] for f in u["findings"])
    return {s: c.get(s, 0) for s in SEVS}


def load_labels():
    labels = {}
    for p in (os.path.join(HERE, "labels.json"), os.path.join(LOCAL, "labels.local.json")):
        if os.path.exists(p):
            with open(p, encoding="utf-8") as fh:
                for e in json.load(fh)["labels"]:
                    labels[(e["sample"], e["unit"], e["fingerprint"])] = e
    return labels


def analyse(meta, results, labels):
    by_id = {s["id"]: s for s in meta["samples"]}
    rows = []
    for r in results:
        s = dict(by_id[r["id"]])
        s.update({k: r.get(k) for k in ("tree", "files", "bytes", "units", "seconds", "cached", "error")})
        s["verdict"], s["score"] = sample_verdict(r)
        s["sev"] = sev_counts(r) if r.get("units") else {}
        rows.append(s)

    # sanity: recomputing each unit's verdict from its stored findings must reproduce the scanner's verdict
    mismatch = []
    for s in rows:
        for u in s["units"] or []:
            if rescore(u) != (u["verdict"], u["score"]):
                mismatch.append((s["id"], u["name"], (u["verdict"], u["score"]), rescore(u)))

    # labels on CRITICAL / HIGH findings of legitimate tuning samples
    worksheet = []
    for s in rows:
        s["labels"] = Counter()
        if s["side"] != "legit" or s["split"] != "tune":
            continue
        for u in s["units"] or []:
            for f in u["findings"]:
                if f["severity"] not in ("critical", "high"):
                    continue
                lab = labels.get((s["id"], u["name"], f["fingerprint"]))
                s["labels"][(f["severity"], lab["label"] if lab else "unlabelled")] += 1
                if not lab:
                    worksheet.append({"sample": s["id"], "unit": u["name"], "fingerprint": f["fingerprint"],
                                      "rule": f["rule_id"], "severity": f["severity"], "confidence": f["confidence"],
                                      "where": "%s:%s" % (f["path"], f["line"]), "bucket": bucket(f["path"]),
                                      "snippet": f["snippet"], "named": s["named"]})

    # malicious demos: caught? which rules carry the verdict? verdict without the known-bad lists
    for s in rows:
        if s["side"] not in ("malicious", "size-malicious") or not s["units"]:
            continue
        u = s["units"][0]
        s["caught"] = VRANK.get(s["verdict"], -1) >= VRANK[s["expected"]]
        s["no_known_bad"] = rescore(u, drop_cats=("known-ioc",))
        load = []
        for rid in sorted({f["rule_id"] for f in u["findings"]}):
            v, _ = rescore(u, drop_rules=(rid,))
            if VRANK[v] < VRANK[s["expected"]]:
                load.append(rid)
        s["load_bearing"] = load

    # per-rule table (tuning samples only; held-back samples never enter it)
    import test_rule_patterns
    catalog = {r.id: {"severity": r.severity, "kind": "regex", "category": r.category} for r in RULES}
    for rid in BUILTIN_CRITICAL:
        catalog.setdefault(rid, {"severity": "critical", "kind": "built-in", "category": ""})
    stats = defaultdict(lambda: {"legit_samples": set(), "legit_hits": 0, "legit_sev": Counter(), "where": Counter(),
                                 "labels": Counter(), "mal_samples": set(), "load_bearing": set()})
    for s in rows:
        if s["split"] != "tune" or not s["units"]:
            continue
        for u in s["units"]:
            for f in u["findings"]:
                st = stats[f["rule_id"]]
                if f["rule_id"] not in catalog:
                    catalog[f["rule_id"]] = {"severity": f["severity"], "kind": "built-in", "category": f["category"]}
                elif catalog[f["rule_id"]]["kind"] == "built-in" and \
                        sev_rank(f["severity"]) > sev_rank(catalog[f["rule_id"]]["severity"]):
                    catalog[f["rule_id"]]["severity"] = f["severity"]
                if s["side"] == "legit":
                    st["legit_samples"].add(s["id"])
                    st["legit_hits"] += 1
                    st["legit_sev"][f["severity"]] += 1
                    st["where"][bucket(f["path"])] += 1
                    if f["severity"] in ("critical", "high"):
                        lab = labels.get((s["id"], u["name"], f["fingerprint"]))
                        st["labels"][lab["label"] if lab else "unlabelled"] += 1
                elif s["side"] == "malicious" and sev_rank(f["severity"]) >= sev_rank("low"):
                    st["mal_samples"].add(s["id"])
        if s["side"] == "malicious":
            for rid in s.get("load_bearing", []):
                stats[rid]["load_bearing"].add(s["id"])
    rules = []
    for rid, c in catalog.items():
        st = stats[rid]
        status = ("malicious example" if st["mal_samples"] else
                  "pattern-tested" if rid in test_rule_patterns.PATTERN_TESTED else "unknown")
        rules.append({"rule": rid, "severity": c["severity"], "kind": c["kind"], "category": c["category"],
                      "legit_samples": len(st["legit_samples"]), "legit_hits": st["legit_hits"],
                      "legit_by_severity": {k: st["legit_sev"].get(k, 0) for k in SEVS if st["legit_sev"].get(k)},
                      "where": dict(st["where"]), "labels": dict(st["labels"]),
                      "malicious_samples": len(st["mal_samples"]), "load_bearing_for": len(st["load_bearing"]),
                      "status": status})
    rules.sort(key=lambda x: (-sev_rank(x["severity"]), -x["legit_samples"], x["rule"]))
    return rows, rules, worksheet, mismatch


# ----------------------------------------------------------------------------- reports

def group_totals(rows, side="legit"):
    g = defaultdict(lambda: {"samples": 0, "verdicts": Counter(), "files": 0})
    for s in rows:
        if s["side"] != side:
            continue
        key = ("named" if s["named"] else s["group"], s["split"])
        g[key]["samples"] += 1
        g[key]["verdicts"][s["verdict"]] += 1
        g[key]["files"] += s.get("files") or 0
    return g


def public_doc(meta, rows, rules, mismatch):
    def unit_rows(s):
        return [{"unit": u["name"], "verdict": u["verdict"], "score": u["score"], "files": u["files"]}
                for u in s["units"] or []]

    def crit_rules(s):
        return sorted({f["rule_id"] for u in s["units"] or [] for f in u["findings"]
                       if f["severity"] == "critical" and f["confidence"] != "low"})
    named = [s for s in rows if s["named"] and s["side"] in ("legit", "needs-human")]
    doc = {
        "schema": "skillaudit-benchmark/1", "tool": "skillaudit %s" % __version__, "scanner_sha256": meta["shash"],
        "date": meta["date"], "limit": LIMIT, "missing_samples": meta["missing"],
        "errors": [{"id": s["id"] if s["named"] else s["group"], "error": s["error"]} for s in rows if s.get("error")],
        "recompute_mismatches": len(mismatch),
        "legitimate": {
            "named": [{"id": s["id"], "files": s["files"], "verdict": s["verdict"], "score": s["score"],
                       "findings": s["sev"], "critical_rules": crit_rules(s), "units": unit_rows(s),
                       "critical_high_labels": {"%s / %s" % k: v for k, v in sorted(s["labels"].items())}}
                      for s in named if s["side"] == "legit"],
            "groups": [{"group": k[0], "split": k[1], "samples": v["samples"], "files": v["files"],
                        "verdicts": dict(v["verdicts"])} for k, v in sorted(group_totals(rows).items())],
        },
        "needs_human": [{"id": s["id"], "files": s["files"], "verdict": s["verdict"], "score": s["score"],
                         "findings": s["sev"], "critical_rules": crit_rules(s)} for s in named
                        if s["side"] == "needs-human"],
        "malicious": [{"id": s["id"], "expected": s["expected"], "verdict": s["verdict"], "score": s["score"],
                       "caught": s.get("caught"), "without_known_bad_lists": s.get("no_known_bad"),
                       "load_bearing_rules": s.get("load_bearing", [])} for s in rows if s["side"] == "malicious"],
        "size_check": [{"id": s["id"], "files": s["files"], "verdict": s["verdict"], "score": s["score"],
                        "findings": s["sev"]} for s in rows if s["side"].startswith("size")],
        "rules": rules,
    }
    return doc


def fmt_verdicts(c):
    return ", ".join("%s %d" % (v, c[v]) for v in reversed(VERDICTS) if c.get(v)) or "-"


def markdown(doc, rows, private):
    L = []
    w = L.append
    w("# skillaudit benchmark: %s" % doc["tag"])
    w("")
    w("> **Limit.** " + LIMIT)
    w("")
    w("Scanner: %s (source sha256 `%s`), run %s. Nothing scanned was executed." %
      (doc["tool"], doc["scanner_sha256"][:16], doc["date"]))
    w("")
    w("## Samples")
    w("")
    w("| Side | Group | Split | Samples | Files | Verdicts |")
    w("|---|---|---|---|---|---|")
    for g in doc["legitimate"]["groups"]:
        w("| legitimate | %s | %s | %d | %d | %s |" % (g["group"], g["split"], g["samples"], g["files"],
                                                     fmt_verdicts(g["verdicts"])))
    nh = doc["needs_human"]
    w("| needs a human | | | %d | %d | %s |" % (len(nh), sum(x["files"] or 0 for x in nh),
                                                fmt_verdicts(Counter(x["verdict"] for x in nh))))
    mal = doc["malicious"]
    w("| malicious | demo skills | | %d | | %s |" % (len(mal), fmt_verdicts(Counter(x["verdict"] for x in mal))))
    w("")
    w("Held-back samples are reported only as totals and are not used for tuning or labelling.")
    w("")
    if doc["missing_samples"]:
        w("**Not on disk, so not scanned:**")
        w("")
        for m in doc["missing_samples"]:
            w("- `%s`: %s" % (m["id"], m["reason"]))
        w("")
    if doc["errors"]:
        w("**Errors:** " + "; ".join("%s (%s)" % (e["id"], e["error"]) for e in doc["errors"]))
        w("")
    if doc["recompute_mismatches"]:
        w("**Warning:** %d unit(s) whose verdict could not be reproduced from stored findings; rule-removal numbers "
          "for those are approximate." % doc["recompute_mismatches"])
        w("")

    legit = [s for s in rows if s["side"] == "legit"]
    w("## False alarms on legitimate samples")
    w("")
    w("A CRITICAL verdict on a legitimate sample always counts as a false alarm. HIGH is reported separately: "
      "CRITICAL and HIGH findings on tuning samples are labelled *wrong match* (the text is not what the rule "
      "describes), *real but normal here* (true, and expected for this kind of tool) or *needs a human*.")
    w("")
    w("| Group | Split | Samples | CRITICAL (false alarm) | HIGH | MEDIUM or lower |")
    w("|---|---|---|---|---|---|")
    for g in doc["legitimate"]["groups"]:
        v = g["verdicts"]
        w("| %s | %s | %d | %d | %d | %d |" % (g["group"], g["split"], g["samples"], v.get("CRITICAL", 0),
                                              v.get("HIGH", 0), g["samples"] - v.get("CRITICAL", 0) - v.get("HIGH", 0)))
    w("")
    lab = Counter()
    for s in legit:
        if s["split"] == "tune":
            lab.update(s["labels"])
    w("CRITICAL and HIGH findings on tuning samples, by label:")
    w("")
    w("| Severity | %s | unlabelled |" % " | ".join(LABELS))
    w("|---|%s---|" % ("---|" * len(LABELS)))
    for sev in ("critical", "high"):
        w("| %s | %s | %d |" % (sev, " | ".join(str(lab.get((sev, l), 0)) for l in LABELS),
                               lab.get((sev, "unlabelled"), 0)))
    w("")
    w("### Named samples")
    w("")
    w("| Sample | Files | Verdict | Score | crit / high / med / low | Rules behind CRITICAL |")
    w("|---|---|---|---|---|---|")
    for x in doc["legitimate"]["named"] + [dict(y, needs=True) for y in doc["needs_human"]]:
        f = x["findings"]
        w("| %s%s | %s | %s | %s | %d / %d / %d / %d | %s |" % (
            x["id"], " *(needs a human)*" if x.get("needs") else "", x["files"], x["verdict"], x["score"],
            f.get("critical", 0), f.get("high", 0), f.get("medium", 0), f.get("low", 0),
            ", ".join(x["critical_rules"]) or "-"))
    w("")
    holders = Counter()
    for s in legit:
        if s["split"] == "tune" and s["verdict"] == "CRITICAL":
            for r in {f["rule_id"] for u in s["units"] for f in u["findings"]
                      if f["severity"] == "critical" and f["confidence"] != "low"}:
                holders[r] += 1
    if holders:
        w("Rules that put legitimate tuning samples at CRITICAL (number of samples; one is enough):")
        w("")
        for r, n in holders.most_common():
            w("- `%s`: %d" % (r, n))
        w("")

    w("## Malicious demo skills")
    w("")
    w("| Demo | Expected | Verdict | Score | Caught | Without known-bad lists | Rules the verdict depends on |")
    w("|---|---|---|---|---|---|---|")
    for m in mal:
        nk = m["without_known_bad_lists"]
        w("| %s | %s | %s | %s | %s | %s %s | %s |" % (m["id"], m["expected"], m["verdict"], m["score"],
                                                    "yes" if m["caught"] else "**no**", nk[0], nk[1],
                                                    ", ".join(m["load_bearing_rules"]) or "none alone"))
    w("")
    w("*Rules the verdict depends on*: removing that one rule (and the chains built on it) drops the verdict below "
      "what is expected. *none alone* means several rules each hold it up.")
    w("")
    w("## Size check")
    w("")
    w("The same content, copied more times. A size-independent score would not move.")
    w("")
    w("| Sample | Files | Verdict | Score | crit / high / med / low |")
    w("|---|---|---|---|---|")
    for x in doc["size_check"]:
        f = x["findings"]
        w("| %s | %s | %s | %s | %d / %d / %d / %d |" % (x["id"], x["files"], x["verdict"], x["score"],
                                                        f.get("critical", 0), f.get("high", 0), f.get("medium", 0),
                                                        f.get("low", 0)))
    w("")
    st = Counter(r["status"] for r in doc["rules"])
    crit = [r for r in doc["rules"] if r["severity"] == "critical"]
    w("## Rule coverage")
    w("")
    w("| Status | All rules | Critical rules |")
    w("|---|---|---|")
    for k in ("malicious example", "pattern-tested", "unknown"):
        w("| %s | %d | %d |" % (k, st.get(k, 0), sum(1 for r in crit if r["status"] == k)))
    w("")
    w("*unknown*: no malicious sample triggers the rule, so the benchmark cannot show whether a change to it stops "
      "real detections. Per-rule numbers are in `%s-rules.md`." % doc["tag"])
    w("")
    if private:
        w("## Private detail (not committed)")
        w("")
        w("| Sample | Group | Verdict | Score | Rules behind CRITICAL |")
        w("|---|---|---|---|---|")
        for s in sorted(legit, key=lambda s: (-VRANK.get(s["verdict"], -1), s["id"])):
            if s["named"] or s["split"] != "tune":
                continue
            cr = sorted({f["rule_id"] for u in s["units"] for f in u["findings"]
                         if f["severity"] == "critical" and f["confidence"] != "low"})
            w("| %s | %s | %s | %s | %s |" % (s["id"], s["group"], s["verdict"], s["score"], ", ".join(cr) or "-"))
        w("")
    return "\n".join(L) + "\n"


def rules_markdown(doc):
    L = ["# skillaudit benchmark: per-rule numbers (%s)" % doc["tag"], "", "> **Limit.** " + LIMIT, "",
         "Tuning samples only. *Legit samples*: legitimate samples the rule fires on. *Labels*: CRITICAL and HIGH "
         "findings on legitimate samples (w = wrong match, r = real but normal here, h = needs a human, "
         "u = unlabelled). *Malicious*: demo skills it fires on at low or above. *Holds up*: demos whose verdict "
         "drops if the rule is removed. Rules that never fired and have no malicious example are listed only if "
         "they can report CRITICAL.", "",
         "| Rule | Severity | Legit samples | Legit hits | Where on legit samples | Labels w/r/h/u | Malicious | "
         "Holds up | Status |", "|---|---|---|---|---|---|---|---|---|"]
    for r in doc["rules"]:
        if not r["legit_hits"] and not r["malicious_samples"] and r["severity"] != "critical" \
                and r["status"] != "pattern-tested":
            continue
        lab = r["labels"]
        labs = "%d/%d/%d/%d" % tuple(lab.get(k, 0) for k in LABELS + ["unlabelled"]) if lab else "-"
        where = ", ".join("%s %d" % kv for kv in sorted(r["where"].items(), key=lambda kv: -kv[1])) or "-"
        L.append("| `%s` | %s | %d | %d | %s | %s | %d | %d | %s |" % (
            r["rule"], r["severity"], r["legit_samples"], r["legit_hits"], where, labs, r["malicious_samples"],
            r["load_bearing_for"], r["status"]))
    return "\n".join(L) + "\n"


def write_worksheet(worksheet):
    by_rule = defaultdict(list)
    for w in worksheet:
        by_rule[w["rule"]].append(w)
    with open(os.path.join(LOCAL, "worksheet.json"), "w", encoding="utf-8") as fh:
        json.dump(worksheet, fh, indent=1)
    lines = ["# Unlabelled CRITICAL / HIGH findings on legitimate tuning samples (%d)" % len(worksheet), ""]
    for rid, items in sorted(by_rule.items(), key=lambda kv: -len(kv[1])):
        lines.append("## %s (%d)" % (rid, len(items)))
        for w in items:
            lines.append("- [%s] %s | %s | %s | %s" % (w["fingerprint"], w["sample"], w["unit"], w["where"],
                                                     w["snippet"][:220].replace("\n", " ")))
        lines.append("")
    with open(os.path.join(LOCAL, "worksheet.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def spotcheck(n, seed=20261126):
    with open(os.path.join(LOCAL, "last-run.raw.json"), encoding="utf-8") as fh:
        raw = json.load(fh)
    labels = load_labels()
    split = {s["id"]: (s["side"], s["split"]) for s in raw["meta"]["samples"]}
    pool = defaultdict(list)
    for r in raw["results"]:
        if split.get(r["id"]) != ("legit", "tune"):
            continue
        for u in r["units"]:
            for f in u["findings"]:
                lab = labels.get((r["id"], u["name"], f["fingerprint"]))
                if lab and f["severity"] in ("critical", "high"):
                    pool[lab["label"]].append((r["id"], u["name"], f, lab))
    rng = random.Random(seed)
    picked = []
    share = {k: max(3, round(n * len(v) / max(1, sum(len(x) for x in pool.values())))) for k, v in pool.items()}
    for k, v in pool.items():
        by_rule = defaultdict(list)
        for item in v:
            by_rule[item[2]["rule_id"]].append(item)
        rules = list(by_rule)
        rng.shuffle(rules)
        i = 0
        while len([p for p in picked if p[3]["label"] == k]) < min(share[k], len(v)):
            lst = by_rule[rules[i % len(rules)]]
            if lst:
                picked.append(lst.pop(rng.randrange(len(lst))))
            i += 1
            if i > 10000:
                break
    rng.shuffle(picked)
    picked = picked[:n]
    out = ["# Spot-check: %d labelled findings (seed %d)" % (len(picked), seed), ""]
    for i, (sid, unit, f, lab) in enumerate(picked, 1):
        out += ["%d. **%s** [%s] `%s` %s:%s" % (i, f["rule_id"], f["severity"], sid, f["path"], f["line"]),
                "   - matched line: `%s`" % f["snippet"][:240].replace("`", "'"),
                "   - label: **%s** - %s" % (lab["label"], lab["reason"]), ""]
    with open(os.path.join(LOCAL, "spotcheck.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(out))
    print("\n".join(out))


# ----------------------------------------------------------------------------- main

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=os.path.join(HERE, "samples.local.json"))
    ap.add_argument("--tag", default="run")
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 2))
    ap.add_argument("--no-cache", action="store_true")
    ap.add_argument("--report", action="store_true", help="rebuild reports from the last scan, no rescanning")
    ap.add_argument("--spotcheck", type=int, metavar="N")
    a = ap.parse_args(argv)
    os.makedirs(os.path.join(LOCAL, "cache"), exist_ok=True)
    if a.spotcheck:
        spotcheck(a.spotcheck)
        return 0
    raw_path = os.path.join(LOCAL, "last-run.raw.json")
    if a.report:
        with open(raw_path, encoding="utf-8") as fh:
            raw = json.load(fh)
        meta, results = raw["meta"], raw["results"]
    else:
        t0 = time.time()
        cfg, samples, missing = load_corpus(a.config)
        tmp = tempfile.mkdtemp(prefix="skillaudit-bench-")
        try:
            gen, gmissing = build_generated(tmp, samples, cfg)
            samples += gen
            missing += gmissing
            shash = scanner_hash()
            cache = "" if a.no_cache else os.path.join(LOCAL, "cache")
            tasks = [{"id": s["id"], "path": s["path"], "mode": s["mode"], "shash": shash, "cache": cache}
                     for s in samples]
            tasks.sort(key=lambda t: -quick_size(t["path"]))
            results = []
            with Pool(a.jobs) as pool:
                for i, r in enumerate(pool.imap_unordered(scan_task, tasks), 1):
                    results.append(r)
                    if i % 25 == 0 or i == len(tasks):
                        print("  scanned %d/%d (%.0fs)" % (i, len(tasks), time.time() - t0), flush=True)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        meta = {"samples": [{k: v for k, v in s.items() if k != "path"} for s in samples], "missing": missing,
                "shash": shash, "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "seconds": round(time.time() - t0, 1)}
        prev = {}
        if os.path.exists(raw_path):
            with open(raw_path, encoding="utf-8") as fh:
                prev = {r["id"]: r.get("tree") for r in json.load(fh)["results"]}
        meta["changed_since_last_run"] = sorted(r["id"] for r in results if r["id"] in prev and r.get("tree")
                                                and prev[r["id"]] != r.get("tree") and not r["id"].startswith(
                                                    ("demo:", "size:")))
        with open(raw_path, "w", encoding="utf-8") as fh:
            json.dump({"meta": meta, "results": results}, fh)
    labels = load_labels()
    rows, rules, worksheet, mismatch = analyse(meta, results, labels)
    doc = public_doc(meta, rows, rules, mismatch)
    doc["tag"] = a.tag
    os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
    with open(os.path.join(HERE, "results", a.tag + ".json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, indent=1, ensure_ascii=True)
        fh.write("\n")
    with open(os.path.join(HERE, "results", a.tag + ".md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(markdown(doc, rows, private=False))
    with open(os.path.join(HERE, "results", a.tag + "-rules.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(rules_markdown(doc))
    with open(os.path.join(LOCAL, "last-run.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(markdown(doc, rows, private=True))
    write_worksheet(worksheet)
    print("samples %d, missing %d, errors %d, unlabelled CRITICAL/HIGH %d, recompute mismatches %d, %ss" % (
        len(rows), len(meta["missing"]), len(doc["errors"]), len(worksheet), len(mismatch), meta.get("seconds")))
    if meta.get("changed_since_last_run"):
        print("changed since last run: %d sample(s)" % len(meta["changed_since_last_run"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
