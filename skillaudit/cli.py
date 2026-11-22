"""Command-line interface."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime
from typing import List, Optional

from . import TOOL_NAME, __version__
from .model import ScanResult, sev_rank
from .rules import CATEGORY_INFO, all_rules, load_custom_rules
from .scanner import ScanOptions, Scanner, discover_units

DISCOVER_ROOTS = [
    "~/.claude/skills", "~/.claude/plugins", "./.claude/skills", "~/.codex/skills", "~/.agents/skills",
    "~/.openclaw/skills", "~/.openclaw/workspace/skills", "~/.clawdbot/skills", "~/.moltbot/skills",
    "~/.cursor/skills", "~/.gemini/skills", "~/.config/opencode/skill", "~/.config/opencode/skills",
    "~/.copilot/skills", "~/.windsurf/skills", "~/.config/goose/skills",
]

COLORS = {"critical": "\033[97;41m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[94m", "info": "\033[90m",
          "CRITICAL": "\033[97;41m", "HIGH": "\033[30;101m", "MEDIUM": "\033[30;103m", "LOW": "\033[30;104m",
          "CLEAN": "\033[30;102m", "bold": "\033[1m", "dim": "\033[2m", "reset": "\033[0m"}


def _enable_ansi() -> bool:
    if not sys.stdout.isatty():
        return False
    if sys.platform == "win32":
        try:
            import ctypes
            k32 = ctypes.windll.kernel32
            h = k32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if k32.GetConsoleMode(h, ctypes.byref(mode)):
                k32.SetConsoleMode(h, mode.value | 0x0004)
        except Exception:
            return False
    return True


def _c(enabled: bool, key: str, text: str) -> str:
    return "%s%s%s" % (COLORS.get(key, ""), text, COLORS["reset"]) if enabled else text


def _shown_path(p: str) -> str:
    """Relative to the current folder when possible, otherwise with the home folder shown as ~."""
    from .sanitize import redact_home
    try:
        rel = os.path.relpath(p)
        if not rel.startswith(".."):
            return rel
    except ValueError:
        pass
    return redact_home(p)


def _safe(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._") or "unit"
    return s[:80]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Offline, LLM-free static security auditor for AI-agent skills (SKILL.md folders, archives, "
                    "plugin/marketplace repos, rules files, MCP server folders). Writes Markdown/JSON/HTML/SARIF "
                    "reports for human or LLM review. Never executes scanned content.",
        epilog="Exit codes: 0 = nothing at/above --fail-on, 1 = findings at/above --fail-on, 2 = error.")
    p.add_argument("paths", nargs="*", help="skill folder, SKILL.md, archive (.zip/.skill/.tar.gz), or a folder of skills")
    p.add_argument("-o", "--output", help="output directory (default: ./skillaudit-reports/<name>-<timestamp>)")
    p.add_argument("-f", "--format", default="md,json,html,sarif",
                   help="comma-separated report formats: md,json,html,sarif (default: all)")
    p.add_argument("--stdout", choices=["md", "json", "sarif", "none"], default="none",
                   help="also print one report format to stdout (single unit only)")
    p.add_argument("--fail-on", default="high", choices=["critical", "high", "medium", "low", "info", "none"],
                   help="exit 1 if any finding is at or above this severity (default: high)")
    p.add_argument("--min-severity", default="info", choices=["critical", "high", "medium", "low", "info"],
                   help="omit findings below this severity from reports (scoring still uses all)")
    p.add_argument("--max-file-size", type=float, default=64, metavar="MB",
                   help="max bytes read per file in MB (default 64; larger files are flagged as partially scanned)")
    p.add_argument("--rules", action="append", default=[], metavar="FILE", help="extra rules JSON (repeatable)")
    p.add_argument("--allowlist", metavar="FILE", help="auditor-controlled suppressions JSON")
    p.add_argument("--baseline", metavar="REPORT_JSON", help="previous report.json to diff against (rug-pull detection)")
    p.add_argument("--embed", choices=["none", "flagged", "all"], default="flagged",
                   help="embed sanitised source in the reports: SKILL.md + flagged files (default), all, or none")
    p.add_argument("--no-split", action="store_true", help="treat a folder of many skills as one unit")
    p.add_argument("--show-full-paths", action="store_true",
                   help="keep your real home-folder path in reports (default: shown as ~ so shared reports "
                        "do not reveal your username)")
    p.add_argument("--discover", action="store_true", help="find and scan installed skills in well-known locations")
    p.add_argument("--dry-run", action="store_true", help="with --discover: only list what would be scanned")
    p.add_argument("--list-rules", action="store_true", help="print the rule catalog and exit")
    p.add_argument("--list-rules-md", action="store_true", help="print the rule catalog as Markdown and exit")
    p.add_argument("-q", "--quiet", action="store_true", help="minimal console output")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    p.add_argument("--color", choices=["auto", "always", "never"], default="auto", help="ANSI colours (default: auto)")
    p.add_argument("--version", action="version", version="%s %s" % (TOOL_NAME, __version__))
    return p


def list_rules(md: bool) -> str:
    rules = sorted(all_rules(), key=lambda r: (r.category, -sev_rank(r.severity), r.id))
    if not md:
        lines = ["%-34s %-9s %-20s %s" % ("ID", "SEVERITY", "CATEGORY", "TITLE")]
        lines += ["%-34s %-9s %-20s %s" % (r.id, r.severity, r.category, r.title) for r in rules]
        lines.append("\n%d regex rules (plus built-in Unicode, hidden-content, structure, archive, binary, manifest, "
                     "IOC and correlation analyzers)." % len(rules))
        return "\n".join(lines)
    out = ["# skillaudit rule catalog", "", "%d regex rules. Additional built-in analyzers (Unicode smuggling, hidden "
           "content, filesystem structure, archives, binaries, SKILL.md manifest, IOCs, correlation) emit the rule ids "
           "listed in docs/DESIGN.md." % len(rules), ""]
    cur = None
    for r in rules:
        if r.category != cur:
            cur = r.category
            title, refs = CATEGORY_INFO.get(cur, (cur, []))
            out += ["", "## %s (`%s`)" % (title, cur), "", "References: %s" % (", ".join(refs) or "-"), "",
                    "| ID | Severity | Confidence | Title |", "|---|---|---|---|"]
        out.append("| `%s` | %s | %s | %s |" % (r.id, r.severity, r.confidence, r.title.replace("|", "\\|")))
    return "\n".join(out) + "\n"


def discover() -> List[str]:
    found = []
    for root in DISCOVER_ROOTS:
        base = os.path.abspath(os.path.expanduser(root))
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            depth = os.path.relpath(dirpath, base).count(os.sep)
            dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".git", "__pycache__")]
            if depth > 8:
                dirnames[:] = []
                continue
            if any(f.lower() == "skill.md" for f in filenames):
                if dirpath not in found:
                    found.append(dirpath)
                dirnames[:] = []
    return found


def write_reports(res: ScanResult, outdir: str, formats: List[str]) -> List[str]:
    from . import report_data, report_html, report_md
    os.makedirs(outdir, exist_ok=True)
    written = []
    if "md" in formats:
        p = os.path.join(outdir, "report.md")
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(report_md.render(res))
        written.append(p)
    if "json" in formats:
        p = os.path.join(outdir, "report.json")
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(report_data.to_json(res))
        written.append(p)
    if "html" in formats:
        p = os.path.join(outdir, "report.html")
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(report_html.render(res))
        written.append(p)
    if "sarif" in formats:
        p = os.path.join(outdir, "report.sarif")
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(report_data.to_sarif(res))
        written.append(p)
    return written


def print_summary(res: ScanResult, color: bool, quiet: bool) -> None:
    s = res.stats.get("by_severity", {})
    print("")
    print(_c(color, "bold", "%s  " % res.unit_name) + _c(color, res.verdict, " %s " % res.verdict) +
          "  risk %d/100  |  critical %d  high %d  medium %d  low %d  info %d  |  %d files, %.1fs" % (
              res.risk_score, s.get("critical", 0), s.get("high", 0), s.get("medium", 0), s.get("low", 0),
              s.get("info", 0), res.coverage.get("files", 0), res.duration_s))
    if quiet:
        return
    print("  " + res.verdict_detail)
    shown = [f for f in res.findings if sev_rank(f.severity) >= sev_rank("medium")][:15]
    for f in shown:
        loc = (f.path or "(package)") + (":%d" % f.line if f.line else "")
        print("  %s %s  %s" % (_c(color, f.severity, "%-8s" % f.severity.upper()), f.title,
                               _c(color, "dim", "%s  [%s]" % (loc.encode("ascii", "backslashreplace").decode(), f.rule_id))))
    more = len([f for f in res.findings if sev_rank(f.severity) >= sev_rank("medium")]) - len(shown)
    if more > 0:
        print(_c(color, "dim", "  ... %d more medium+ findings in the report" % more))


def main(argv: Optional[List[str]] = None) -> int:
    try:
        sys.stdout.reconfigure(errors="replace")  # type: ignore[attr-defined]
        sys.stderr.reconfigure(errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass
    args = build_parser().parse_args(argv)
    if args.list_rules or args.list_rules_md:
        print(list_rules(args.list_rules_md))
        return 0
    if args.color == "always":
        _enable_ansi()
        color = True
    else:
        color = args.color == "auto" and not args.no_color and _enable_ansi()
    formats = [x.strip().lower() for x in args.format.split(",") if x.strip()]
    bad = set(formats) - {"md", "json", "html", "sarif"}
    if bad:
        print("unknown format(s): %s" % ", ".join(sorted(bad)), file=sys.stderr)
        return 2

    targets = list(args.paths)
    if args.discover:
        found = discover()
        if not args.quiet:
            print("Discovered %d installed skill folder(s):" % len(found))
            for d in found:
                print("  " + _shown_path(d))
        if args.dry_run:
            return 0
        targets += found
    if not targets:
        build_parser().print_help()
        return 2

    extra = []
    try:
        for rf in args.rules:
            extra += load_custom_rules(rf)
        allow = json.load(open(args.allowlist, encoding="utf-8")) if args.allowlist else None
        baseline = json.load(open(args.baseline, encoding="utf-8")) if args.baseline else None
    except (OSError, ValueError, KeyError) as exc:
        print("error loading configuration: %s" % exc, file=sys.stderr)
        return 2

    opts = ScanOptions(max_file_bytes=int(args.max_file_size * 1024 * 1024), embed=args.embed, extra_rules=extra,
                       allowlist=allow, baseline=baseline, split=not args.no_split,
                       redact_home=not args.show_full_paths)
    try:
        scanner = Scanner(opts)
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    units = []
    for t in targets:
        try:
            units += discover_units(t, split=opts.split)
        except FileNotFoundError:
            print("error: not found: %s" % t, file=sys.stderr)
            return 2
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    base_name = _safe(units[0][0] if len(units) == 1 else (os.path.basename(os.path.abspath(targets[0])) or "scan"))
    outroot = os.path.abspath(args.output or os.path.join("skillaudit-reports", "%s-%s" % (base_name, stamp)))

    if not args.quiet:
        print("%s %s - offline static skill audit (%d rules). Scanning %d unit(s)..." % (
            TOOL_NAME, __version__, len(scanner.rules), len(units)))
    results: List[ScanResult] = []
    used = set()
    for name, root, exclude in units:
        try:
            res = scanner.scan_unit(name, root, exclude)
        except Exception as exc:  # never die on one hostile unit
            print("error scanning %s: %s: %s" % (name, type(exc).__name__, exc), file=sys.stderr)
            continue
        if args.min_severity != "info":
            res.findings = [f for f in res.findings if sev_rank(f.severity) >= sev_rank(args.min_severity)]
        folder = _safe(name)
        while folder in used:
            folder += "_"
        used.add(folder)
        res.options["_folder"] = folder
        outdir = outroot if len(units) == 1 else os.path.join(outroot, folder)
        written = write_reports(res, outdir, formats)
        results.append(res)
        print_summary(res, color, args.quiet)
        if not args.quiet:
            for w in written:
                print(_c(color, "dim", "    -> " + _shown_path(w)))
        if args.stdout != "none" and len(units) == 1:
            from . import report_data, report_md
            print({"md": report_md.render, "json": report_data.to_json, "sarif": report_data.to_sarif}[args.stdout](res))

    if len(results) > 1:
        from . import report_html, report_md
        os.makedirs(outroot, exist_ok=True)
        with open(os.path.join(outroot, "index.md"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(report_md.render_index(results, TOOL_NAME, __version__))
        with open(os.path.join(outroot, "index.html"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(report_html.render_index(results, TOOL_NAME, __version__))
        if not args.quiet:
            print("\nSummary index: %s" % _shown_path(os.path.join(outroot, "index.html")))
    if not results:
        return 2
    if args.fail_on == "none":
        return 0
    worst = max((sev_rank(f.severity) for r in results for f in r.findings), default=-1)
    return 1 if worst >= sev_rank(args.fail_on) else 0
