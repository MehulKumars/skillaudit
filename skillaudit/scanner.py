"""Scan orchestration: discover units, walk files, run every analyzer, correlate, score."""
from __future__ import annotations

import fnmatch
import json
import os
import posixpath
import re
import time
import zlib
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence, Tuple

from . import TOOL_NAME, __version__, correlate, iocs, skillmd, structure
from .engine import ContentEngine, IOCSink
from .filetypes import (ARCHIVE_MAGICS, EXECUTABLE_MAGICS, EXT_EXPECT, OPENABLE_ARCHIVES, TEXT_EXTS, decode_text,
                        entropy, is_pyc, kind_for, sniff_magic, surface_for)
from .formats import Limits, analyze_binary, office_text, open_archive, rtf_checks, svg_html_checks
from .formats import _pickle as pickle_findings
from .model import FileRecord, Finding, ScanResult, TextUnit, max_sev, sev_rank
from .rules import CATEGORY_INFO, Rule, all_rules
from .sanitize import redact_home, visible
from .walker import Entry, read_ads, walk

BINARY_FIRST = EXECUTABLE_MAGICS | ARCHIVE_MAGICS | {"pdf", "ole", "png", "jpeg", "gif", "webp", "bmp", "ico", "tiff",
                                                     "mp4", "mp3", "wav", "ogg", "flac", "webm", "avi", "woff", "woff2",
                                                     "ttf", "sqlite", "lnk", "chm", "ds_store", "pickle", "pyc"}
LIMITATIONS = [
    "Static analysis only: nothing was executed. Runtime-only behaviour (remote content fetched later, server-side "
    "rug pulls, time/condition-triggered logic) cannot be observed.",
    "Natural-language attacks have no fixed syntax; novel phrasing can evade the injection rules.",
    "Compiled code (.pyc, native binaries, wasm) is only inspected via printable strings.",
    "Text inside images (pixels) is not OCR'd; only image metadata and appended data are inspected.",
    "7z/rar/cab/dmg/iso archives and encrypted zip members cannot be opened offline with the standard library.",
    "Packed git history (.pack files) is not decompressed; loose git objects are.",
    "A clean result is not proof of safety. Pair this report with a sandboxed test run and author verification.",
]


@dataclass
class ScanOptions:
    max_file_bytes: int = 64 * 1024 * 1024
    max_files: int = 50000
    max_archive_depth: int = 4
    embed: str = "flagged"           # none | flagged | all
    embed_line_cap: int = 800
    embed_total_cap: int = 800_000
    extra_rules: Sequence[Rule] = ()
    allowlist: Optional[dict] = None
    baseline: Optional[dict] = None
    split: bool = True
    redact_home: bool = True         # show the home folder as "~" in reports


def discover_units(target: str, split: bool = True) -> List[Tuple[str, str, List[str]]]:
    """Return [(unit_name, root_path, exclude_paths)]."""
    target = os.path.abspath(target)
    if os.path.isfile(target) or os.path.islink(target):
        if os.path.basename(target).lower() == "skill.md":
            d = os.path.dirname(target)
            return [(os.path.basename(d) or d, d, [])]
        return [(os.path.basename(target), target, [])]
    if not os.path.isdir(target):
        raise FileNotFoundError(target)

    def has_skill_md(d: str) -> bool:
        try:
            return any(n.lower() == "skill.md" and os.path.isfile(os.path.join(d, n)) for n in os.listdir(d))
        except OSError:
            return False

    if has_skill_md(target) or not split:
        return [(os.path.basename(target) or target, target, [])]
    skill_dirs = []
    for dirpath, dirnames, filenames in os.walk(target):
        rel_depth = os.path.relpath(dirpath, target).count(os.sep)
        dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".git", "__pycache__", ".venv", "venv")
                       and not os.path.islink(os.path.join(dirpath, d))]
        if rel_depth > 6:
            dirnames[:] = []
            continue
        if any(f.lower() == "skill.md" for f in filenames):
            skill_dirs.append(dirpath)
            dirnames[:] = []  # a skill's own subfolders belong to it
    if len(skill_dirs) < 2:
        return [(os.path.basename(target) or target, target, [])]
    units = [(os.path.relpath(d, target).replace(os.sep, "/"), d, []) for d in sorted(skill_dirs)]
    units.append(("%s (files outside skills)" % (os.path.basename(target) or target), target, list(skill_dirs)))
    return units


def _load_allowlist(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


class Scanner:
    def __init__(self, options: Optional[ScanOptions] = None):
        self.opts = options or ScanOptions()
        self.rules = all_rules(self.opts.extra_rules)

    # ------------------------------------------------------------------
    def scan_unit(self, name: str, root: str, exclude: Sequence[str] = ()) -> ScanResult:
        t0 = time.time()
        started = datetime.now(timezone.utc).isoformat(timespec="seconds")
        res = ScanResult(tool=TOOL_NAME, version=__version__, unit_name=name, target=root, started=started)
        sink = IOCSink()
        engine = ContentEngine(self.rules, sink)
        findings: List[Finding] = []
        records: List[FileRecord] = []
        errors: List[str] = []
        texts: Dict[str, str] = {}
        skill_units: List[TextUnit] = []
        cov = {"files": 0, "text_files": 0, "binary_files": 0, "archives_opened": 0, "archive_members": 0,
               "bytes_read": 0, "partial": [], "unreadable": [], "encrypted": [], "ads_streams": 0, "errors": errors}
        limits = Limits()
        excl = {os.path.abspath(e) for e in exclude}

        queue = deque()
        all_entries: List[Entry] = []
        for e in walk(root, self.opts.max_files, errors=errors):
            if excl and any(e.abspath == x or e.abspath.startswith(x + os.sep) for x in excl):
                continue
            queue.append(e)
        root_for_links = root if os.path.isdir(root) else os.path.dirname(root)

        while queue:
            e = queue.popleft()
            all_entries.append(e)
            findings.extend(structure.check_entry(e, root_for_links))
            for stream, size in e.ads:
                cov["ads_streams"] += 1
                try:
                    data = read_ads(e.abspath, stream, self.opts.max_file_bytes)
                except OSError as exc:
                    errors.append("cannot read ADS %s:%s: %s" % (e.relpath, stream, exc))
                    continue
                if stream.lower() == "zone.identifier":
                    txt = data.decode("utf-8", "replace")
                    urls = re.findall(r"(?:HostUrl|ReferrerUrl)=(\S+)", txt)
                    for u in urls:
                        sink.add("urls", u, e.relpath + ":Zone.Identifier", 0, iocs.classify_host(iocs.parse_url(u)[0], u))
                    if urls:
                        findings.append(Finding(rule_id="FS-MARK-OF-THE-WEB", title="File was downloaded from the internet",
                                                severity="info", category="filesystem", path=e.relpath, confidence="high",
                                                message="Zone.Identifier source: %s" % ", ".join(visible(u, 200) for u in urls),
                                                origin="ads"))
                    continue
                sub = Entry(relpath="%s:%s" % (e.relpath, stream), size=size, data=data, container=e.relpath,
                            depth=e.depth)
                sub.meta["ads"] = True
                queue.append(sub)
            if e.is_dir or e.is_link or e.is_junction or e.special:
                rec = FileRecord(path=e.relpath, kind="directory" if e.is_dir else ("link" if (e.is_link or e.is_junction)
                                                                                    else "special"),
                                 size=e.size, link_target=visible(e.link_target, 300), container=e.container,
                                 flags=self._flags(e))
                if not e.is_dir:
                    records.append(rec)
                continue
            if e.meta.get("encrypted"):
                cov["encrypted"].append(e.relpath)
                records.append(FileRecord(path=e.relpath, kind="encrypted", size=e.size, container=e.container,
                                          flags=self._flags(e) + ["encrypted-unscannable"]))
                continue
            rec, subs, unit = self._process_file(e, engine, findings, cov, limits, texts)
            records.append(rec)
            if unit is not None and unit.is_skill_md:
                skill_units.append(unit)
            for s in subs:
                queue.append(s)

        findings.extend(structure.check_tree(all_entries, root_for_links))

        # ---- SKILL.md analysis
        all_paths = {e.relpath for e in all_entries if not e.is_dir}
        skills = []
        for u in sorted(skill_units, key=lambda x: x.path.count("/")):
            skill_dir = posixpath.dirname(u.path)
            dir_name = posixpath.basename(skill_dir.replace("!/", "/")) if skill_dir else os.path.basename(
                root if os.path.isdir(root) else os.path.dirname(root))
            f, meta = skillmd.analyze_skill_md(u, skill_dir, dir_name, all_paths)
            findings.extend(f)
            skills.append(meta)
        if not skills:
            findings.append(Finding(rule_id="META-NO-SKILL-MD", title="No SKILL.md found", severity="info",
                                    category="manifest", path="", confidence="high", origin="manifest",
                                    message="Scanned as a generic folder/file. Skill-manifest checks were skipped."))

        # ---- correlation
        findings.extend(correlate.chains(findings, skills))

        # ---- known-bad file hashes
        for r in records:
            if r.sha256 and r.sha256 in iocs.KNOWN_BAD_SHA256:
                findings.append(Finding(rule_id="IOC-KNOWN-BAD-HASH", title="File hash matches known malware",
                                        severity="critical", category="known-ioc", path=r.path, confidence="high",
                                        message="SHA-256 %s - %s" % (r.sha256, iocs.KNOWN_BAD_SHA256[r.sha256]),
                                        origin="ioc"))

        findings = self._dedupe(findings)
        for f in findings:
            if not f.references:
                f.references = list(CATEGORY_INFO.get(f.category, ("", []))[1])
            f.compute_fingerprint()
        kept, suppressed = self._apply_allowlist(findings, records)
        kept.sort(key=lambda f: (-sev_rank(f.severity), f.path, f.line, f.rule_id))

        per_file: Dict[str, List[Finding]] = {}
        for f in kept:
            per_file.setdefault(f.path, []).append(f)
        for r in records:
            fs = per_file.get(r.path, [])
            r.finding_count = len(fs)
            r.max_severity = max_sev(*[f.severity for f in fs]) if fs else ""

        res.files = records
        res.findings = kept
        res.suppressed = suppressed
        res.is_skill = bool(skills)
        res.skill = {"manifests": skills}
        res.iocs = sink.export()
        res.capabilities = correlate.capability_summary(kept)
        res.risk_score, res.verdict, res.verdict_detail = correlate.score_and_verdict(kept)
        cov["files"] = len(records)
        cov["limitations"] = LIMITATIONS
        res.coverage = cov
        res.stats = self._stats(kept, records)
        res.sources = self._embed_sources(kept, texts, skills)
        res.options = {"max_file_bytes": self.opts.max_file_bytes, "embed": self.opts.embed,
                       "custom_rules": len(self.opts.extra_rules), "rules": len(self.rules),
                       "allowlist": bool(self.opts.allowlist), "baseline": bool(self.opts.baseline)}
        if self.opts.baseline:
            res.baseline = self._baseline_diff(self.opts.baseline, records, kept)
        if self.opts.redact_home:
            self._redact_home(res)
        res.finished = datetime.now(timezone.utc).isoformat(timespec="seconds")
        res.duration_s = round(time.time() - t0, 2)
        return res

    # ------------------------------------------------------------------
    def _flags(self, e: Entry) -> List[str]:
        flags = []
        if e.name.startswith(".") or e.win_attrs & 0x2:
            flags.append("hidden")
        if e.win_attrs & 0x4:
            flags.append("system")
        if e.is_link:
            flags.append("symlink")
        if e.is_junction:
            flags.append("junction")
        if e.ads:
            flags.append("has-ads")
        if e.meta.get("ads"):
            flags.append("alternate-data-stream")
        if e.container:
            flags.append("archive-member" if "!/" in e.relpath else "derived")
        if e.special:
            flags.append(e.special)
        return flags

    def _process_file(self, e: Entry, engine: ContentEngine, findings: List[Finding], cov: dict, limits: Limits,
                      texts: Dict[str, str]):
        name = e.name
        subs: List[Entry] = []
        try:
            data = e.read(self.opts.max_file_bytes)
            tail = data[-65536:] if e.data is not None or len(data) >= e.size else e.read_tail(65536)
            sha = e.sha256()
        except OSError as exc:
            cov["unreadable"].append(e.relpath)
            findings.append(Finding(rule_id="COVERAGE-UNREADABLE", title="File could not be read", severity="medium",
                                    category="filesystem", path=e.relpath, confidence="high", origin="coverage",
                                    message="%s - its content was NOT scanned." % visible(str(exc), 200)))
            return FileRecord(path=e.relpath, kind="unreadable", size=e.size, flags=self._flags(e) + ["unreadable"]), [], None
        cov["bytes_read"] += len(data)
        partial = len(data) < e.size or bool(e.meta.get("partial"))
        magic = sniff_magic(data[:65536], tail)
        if is_pyc(data, name):
            magic = "pyc"
        if magic in BINARY_FIRST:
            text, enc = None, "binary"
        else:
            text, enc = decode_text(data)
        is_text = text is not None
        kind = kind_for(name, magic, data[:4096], is_text)
        ext = os.path.splitext(name)[1].lower()
        flags = self._flags(e)
        if partial:
            flags.append("partially-scanned")
        rec = FileRecord(path=e.relpath, kind=kind, size=e.size, sha256=sha, magic=magic, ext=ext, encoding=enc,
                         is_text=is_text, entropy=round(entropy(data[:1_000_000]), 2), surface=surface_for(kind, name),
                         flags=flags, container=e.container,
                         mode=oct(e.mode & 0o7777) if e.mode else "",
                         mtime=datetime.fromtimestamp(e.mtime, timezone.utc).isoformat(timespec="seconds") if e.mtime else "")
        if partial:
            cov["partial"].append(e.relpath)
            findings.append(Finding(rule_id="COVERAGE-PARTIAL", title="File only partially scanned", severity="medium",
                                    category="filesystem", path=e.relpath, confidence="high", origin="coverage",
                                    message="Only the first %d of %d bytes were analysed. Raise --max-file-size to scan "
                                            "everything (padding attacks rely on scanners truncating)." % (len(data), e.size)))

        # extension / content mismatch
        expected = EXT_EXPECT.get(ext)
        if expected and magic not in expected and magic != "empty" and data:
            danger = magic in EXECUTABLE_MAGICS | ARCHIVE_MAGICS or magic == "shebang" or (is_text and ext in (
                ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".webp", ".ico", ".zip"))
            findings.append(Finding(rule_id="FS-EXTENSION-MISMATCH", title="File content does not match its extension",
                                    severity="high" if danger else "medium", category="filesystem", path=e.relpath,
                                    confidence="high", origin="structure",
                                    message="Extension %s but content is %s." % (ext, magic or ("text" if is_text else
                                                                                               "unknown binary")),
                                    capabilities=["hidden"]))
        elif ext in TEXT_EXTS and not is_text and data and magic not in ("empty", "shebang") and ext not in EXT_EXPECT:
            findings.append(Finding(rule_id="FS-TEXT-EXTENSION-BINARY", title="Binary content behind a text extension",
                                    severity="high" if magic in EXECUTABLE_MAGICS | ARCHIVE_MAGICS else "medium",
                                    category="filesystem", path=e.relpath, confidence="high", origin="structure",
                                    message="Extension %s but content is %s." % (ext, magic or "unidentified binary"),
                                    capabilities=["hidden"]))
        if is_text and enc.startswith(("utf-16", "utf-32")) and kind not in ("registry",):
            findings.append(Finding(rule_id="FS-UTF16-TEXT", title="Text stored as UTF-16/32", severity="low",
                                    category="obfuscation", path=e.relpath, confidence="high", origin="structure",
                                    message="Encoding %s. grep-based reviews and many scanners miss UTF-16 content "
                                            "(decoded and scanned here)." % enc))

        # git loose objects (history)
        if "/.git/objects/" in "/" + e.relpath and re.search(r"/objects/[0-9a-f]{2}/[0-9a-f]{38}$", e.relpath):
            try:
                obj = zlib.decompressobj().decompress(data, 20_000_000)
                hdr, _, body = obj.partition(b"\0")
                if hdr.startswith(b"blob"):
                    t2, _ = decode_text(body)
                    if t2:
                        unit = TextUnit(e.relpath + " (git blob)", t2, "text", origin="git-history")
                        findings.extend(engine.scan(unit))
                return rec, subs, None
            except zlib.error:
                pass

        if magic in ARCHIVE_MAGICS:
            if e.depth >= self.opts.max_archive_depth + 64 or e.relpath.count("!/") >= self.opts.max_archive_depth:
                findings.append(Finding(rule_id="ARC-NESTING-LIMIT", title="Nested archive depth limit reached",
                                        severity="medium", category="archive", path=e.relpath, confidence="high",
                                        origin="coverage", message="Deeply nested archives were not opened further."))
            elif partial and magic in ("zip",):
                findings.append(Finding(rule_id="ARC-TOO-LARGE", title="Archive larger than the scan limit",
                                        severity="medium", category="archive", path=e.relpath, confidence="high",
                                        origin="coverage", message="Raise --max-file-size to inspect it."))
            else:
                if magic in OPENABLE_ARCHIVES:
                    cov["archives_opened"] += 1
                af, members = open_archive(e.relpath, data, magic, e.depth + 1, limits)
                findings.extend(af)
                cov["archive_members"] += len(members)
                for mem in members:
                    if mem.data is not None:
                        otext = office_text(mem.relpath, mem.data)
                        if otext:
                            findings.extend(engine.scan(TextUnit(mem.relpath, otext, "text", origin="office-text")))
                subs.extend(members)
            cov["binary_files"] += 1
            return rec, subs, None

        if not is_text:
            cov["binary_files"] += 1
            bf, units, bsubs = analyze_binary(e.relpath, data, magic, name)
            findings.extend(bf)
            for u in units:
                findings.extend(engine.scan(u))
            subs.extend(bsubs)
            return rec, subs, None

        cov["text_files"] += 1
        rec.lines = text.count("\n") + 1
        origin = "ads" if e.meta.get("ads") else "file"
        unit = TextUnit(e.relpath, text, kind, origin=origin, is_skill_md=(name.lower() == "skill.md"))
        findings.extend(engine.scan(unit))
        findings.extend(structure.special_content_checks(e.relpath, text))
        if kind in ("svg", "html"):
            findings.extend(svg_html_checks(e.relpath, text))
        if magic == "rtf" or ext == ".rtf":
            findings.extend(rtf_checks(e.relpath, text))
        if ext in (".pkl", ".pickle", ".joblib", ".dill", ".pck"):
            findings.extend(pickle_findings(e.relpath, data))  # protocol-0 pickles are plain ASCII
        if kind == "notebook":
            cells = self._notebook_cells(text)
            if cells:
                findings.extend(engine.scan(TextUnit(e.relpath + "#cells", cells, "python", origin="notebook-cells")))
        if len(text) <= 4_000_000:
            texts[e.relpath] = text
        return rec, subs, unit

    @staticmethod
    def _redact_home(res: ScanResult) -> None:
        res.target = redact_home(res.target)
        for f in list(res.findings) + list(res.suppressed):
            f.message = redact_home(f.message)
            f.snippet = redact_home(f.snippet)
            f.evidence = [redact_home(e) for e in f.evidence]
        for r in res.files:
            r.link_target = redact_home(r.link_target)
        res.coverage["errors"] = [redact_home(e) for e in res.coverage.get("errors", [])]
        for s in res.sources:
            s["content"] = redact_home(s.get("content", ""))

    @staticmethod
    def _notebook_cells(text: str) -> str:
        try:
            nb = json.loads(text)
        except ValueError:
            return ""
        parts = []
        for i, cell in enumerate(nb.get("cells", []) if isinstance(nb, dict) else []):
            src = cell.get("source", "")
            src = "".join(src) if isinstance(src, list) else str(src)
            parts.append("# --- cell %d (%s) ---\n%s" % (i, cell.get("cell_type", "?"), src))
            for out in cell.get("outputs", []) or []:
                t = out.get("text") or (out.get("data") or {}).get("text/plain") or ""
                parts.append("".join(t) if isinstance(t, list) else str(t))
        return "\n".join(parts)

    @staticmethod
    def _dedupe(findings: List[Finding]) -> List[Finding]:
        seen = {}
        out = []
        for f in findings:
            key = (f.rule_id, f.path, f.line, f.origin.split(">")[0], f.snippet[:120], f.message[:80])
            if key in seen:
                continue
            seen[key] = f
            out.append(f)
        return out

    def _apply_allowlist(self, findings: List[Finding], records: List[FileRecord]):
        al = self.opts.allowlist or {}
        rules = al.get("suppress", [])
        if not rules:
            return findings, []
        hashes = {r.path: r.sha256 for r in records}
        kept, supp = [], []
        for f in findings:
            reason = None
            for s in rules:
                if not fnmatch.fnmatchcase(f.rule_id, s.get("rule", "*")):
                    continue
                if not fnmatch.fnmatchcase(f.path, s.get("path", "*")):
                    continue
                if s.get("sha256") and hashes.get(f.path) != s["sha256"].lower():
                    continue
                if s.get("max_severity") and sev_rank(f.severity) > sev_rank(s["max_severity"]):
                    continue
                reason = s.get("reason", "allowlisted")
                break
            if reason:
                f.suppressed = True
                f.suppression_reason = reason
                supp.append(f)
            else:
                kept.append(f)
        return kept, supp

    @staticmethod
    def _stats(findings: List[Finding], records: List[FileRecord]) -> dict:
        by_sev = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
        by_cat: Dict[str, int] = {}
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            by_cat[f.category] = by_cat.get(f.category, 0) + 1
        surfaces: Dict[str, int] = {}
        for r in records:
            surfaces[r.surface or r.kind] = surfaces.get(r.surface or r.kind, 0) + 1
        return {"by_severity": by_sev, "by_category": dict(sorted(by_cat.items(), key=lambda x: -x[1])),
                "files": len(records), "surfaces": surfaces, "total_findings": len(findings),
                "total_bytes": sum(r.size for r in records if not r.container)}

    def _embed_sources(self, findings: List[Finding], texts: Dict[str, str], skills: List[dict]) -> List[dict]:
        if self.opts.embed == "none":
            return []
        worst: Dict[str, str] = {}
        lines_of: Dict[str, set] = {}
        for f in findings:
            worst[f.path] = max_sev(worst.get(f.path, "info"), f.severity)
            if f.line:
                lines_of.setdefault(f.path, set()).add(f.line)
        chosen = []
        for sk in skills:
            if sk["path"] in texts:
                chosen.append(sk["path"])
        for path in texts:
            if path in chosen:
                continue
            if self.opts.embed == "all" or sev_rank(worst.get(path, "info")) >= sev_rank("medium"):
                chosen.append(path)
        chosen.sort(key=lambda p: (0 if p.lower().endswith("skill.md") else 1, -sev_rank(worst.get(p, "info")), p))
        out, total = [], 0
        for p in chosen:
            text = texts[p]
            lines = text.split("\n")
            truncated = False
            if len(lines) > self.opts.embed_line_cap:
                lines = lines[: self.opts.embed_line_cap]
                truncated = True
            rendered = []
            flagged = lines_of.get(p, set())
            for i, ln in enumerate(lines, 1):
                v = visible(ln.rstrip("\r"), 2000)
                rendered.append("%s%5d | %s" % ("!" if i in flagged else " ", i, v))
            body = "\n".join(rendered)
            if total + len(body) > self.opts.embed_total_cap:
                out.append({"path": p, "content": "", "truncated": True, "omitted": True,
                            "max_severity": worst.get(p, "")})
                continue
            total += len(body)
            out.append({"path": p, "content": body, "truncated": truncated, "omitted": False,
                        "total_lines": text.count("\n") + 1, "max_severity": worst.get(p, "")})
        return out

    @staticmethod
    def _baseline_diff(base: dict, records: List[FileRecord], findings: List[Finding]) -> dict:
        old_files = {f["path"]: f.get("sha256", "") for f in base.get("files", [])}
        new_files = {r.path: r.sha256 for r in records}
        old_fp = {f.get("fingerprint"): f for f in base.get("findings", [])}
        new_fp = {f.fingerprint: f for f in findings}
        return {
            "baseline_scan": base.get("started", ""),
            "added_files": sorted(set(new_files) - set(old_files)),
            "removed_files": sorted(set(old_files) - set(new_files)),
            "changed_files": sorted(p for p in set(new_files) & set(old_files) if new_files[p] != old_files[p]),
            "new_findings": [{"rule_id": f.rule_id, "severity": f.severity, "path": f.path, "line": f.line,
                              "title": f.title} for fp, f in new_fp.items() if fp not in old_fp],
            "resolved_findings": [{"rule_id": f.get("rule_id"), "severity": f.get("severity"), "path": f.get("path"),
                                   "title": f.get("title")} for fp, f in old_fp.items() if fp not in new_fp],
        }
