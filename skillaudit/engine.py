"""Content engine: runs every text-level analysis on a TextUnit, recursively."""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Dict, List, Optional, Sequence, Set, Tuple

from . import iocs
from .decoders import find_encoded, looks_like_code
from .filetypes import str_entropy
from .hidden import scan_hidden
from .model import Finding, TextUnit, bump, lower_conf, max_sev, sev_rank
from .rules import CATEGORY_INFO, CODE, Rule
from .sanitize import clip_around, redact, visible
from .unicode_checks import normalized_view, scan_unicode

MAX_DEPTH = 4
NORMALIZED_CATS = {"prompt-injection", "concealment", "remote-exec", "exfiltration", "credential-access",
                   "agent-tampering", "social-engineering", "dynamic-exec", "obfuscation", "reverse-shell"}
HIDDEN_ESCALATE = {"prompt-injection", "concealment", "remote-exec", "exfiltration", "credential-access",
                   "agent-tampering", "social-engineering", "reverse-shell", "destructive", "persistence"}
EDU_CATS = {"remote-exec", "destructive", "reverse-shell", "dynamic-exec", "credential-access", "persistence",
            "defense-evasion", "obfuscation"}
EDU_RE = re.compile(r"\b(?:never|don'?t|do\s+not|avoid|dangerous|malicious|attackers?|example\s+of|e\.g\.|"
                    r"such\s+as|warning|beware|red\s+flags?|detect(?:s|ion)?|flag(?:s|ged)?|block(?:s|ed)?|deny)\b", re.I)
QUOTE_CATS = {"prompt-injection", "concealment", "agent-tampering", "social-engineering"}
QUOTE_CHARS = "\"'`\u201c\u2018\u00ab"
LONG_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_-]{80,}")
PAD_RUN_RE = re.compile(r"[ \t]{256,}")


def _is_quoted(line: str, col: int) -> bool:
    """True when the match starts right after a quote or inside an inline code span."""
    before = line[:col]
    stripped = before.rstrip()
    if stripped[-1:] and stripped[-1] in QUOTE_CHARS:
        return True
    return before.count("`") % 2 == 1
SCRIPT_KINDS_FOR_LONGLINES = {"javascript", "python", "shell", "powershell", "batch", "vbscript", "php", "ruby", "perl"}


def _refs(cat: str) -> List[str]:
    return list(CATEGORY_INFO.get(cat, ("", []))[1])


class IOCSink:
    def __init__(self):
        self.items: Dict[str, Dict[str, dict]] = defaultdict(dict)

    def add(self, kind: str, value: str, path: str, line: int, tags: Sequence[str] = ()):
        bucket = self.items[kind]
        rec = bucket.get(value)
        if rec is None:
            rec = bucket[value] = {"value": value, "tags": sorted(set(tags)), "locations": []}
        else:
            rec["tags"] = sorted(set(rec["tags"]) | set(tags))
        if len(rec["locations"]) < 10:
            loc = "%s:%d" % (path, line)
            if loc not in rec["locations"]:
                rec["locations"].append(loc)

    def export(self) -> Dict[str, List[dict]]:
        return {k: sorted(v.values(), key=lambda r: r["value"]) for k, v in self.items.items()}


class ContentEngine:
    def __init__(self, rules: Sequence[Rule], ioc_sink: Optional[IOCSink] = None):
        self.rules = list(rules)
        self.iocs = ioc_sink or IOCSink()

    # ------------------------------------------------------------------ public
    def scan(self, unit: TextUnit) -> List[Finding]:
        out: List[Finding] = []

        uf, hidden_children = scan_unicode(unit)
        out.extend(uf)

        hf, spans = scan_hidden(unit)
        out.extend(hf)

        # Padding already reported above; collapse giant space runs for the remaining analyzers
        # (newlines are kept, so line numbers stay exact).
        work = unit
        if len(unit.text) > 1_000_000:
            compact = PAD_RUN_RE.sub(" ", unit.text)
            if len(compact) < len(unit.text) // 2:
                work = TextUnit(unit.path, compact, unit.kind, unit.origin, unit.depth, unit.parent_line,
                                unit.is_skill_md)
                spans = []

        rf = self._apply_rules(work, work.text, spans)
        out.extend(rf)

        if not work.text.isascii():
            norm = normalized_view(work.text)
            if norm and norm != work.text:
                seen = {(f.rule_id, f.line) for f in rf}
                out.extend(self._apply_rules(work, norm, spans, normalized=True, seen=seen))

        out.extend(self._ioc_findings(work))
        out.extend(self._structure_checks(work))

        if unit.depth < MAX_DEPTH:
            out.extend(self._decode_layer(work))
            for child in hidden_children:
                for f in self.scan(child):
                    if f.category in HIDDEN_ESCALATE:
                        f.severity = max_sev(bump(f.severity), "high")
                    if "hidden" not in f.tags:
                        f.tags.append("hidden")
                    out.append(f)
        return out

    # ------------------------------------------------------------------ rules
    def _apply_rules(self, unit: TextUnit, text: str, spans, normalized: bool = False,
                     seen: Optional[Set[Tuple[str, int]]] = None) -> List[Finding]:
        low = text.lower()
        view = unit if not normalized else TextUnit(unit.path, text, unit.kind, unit.origin, unit.depth, unit.parent_line)
        out: List[Finding] = []
        is_doc = unit.kind in ("markdown", "text")
        for rule in self.rules:
            if not rule.applies_to(unit.kind):
                continue
            if normalized and rule.category not in NORMALIZED_CATS:
                continue
            if rule.hints and not any(h in low for h in rule.hints):
                continue
            matches = []
            try:
                for m in rule.regex.finditer(text):
                    if m.end() == m.start():
                        continue
                    if rule.validator is not None:
                        try:
                            if not rule.validator(m, ""):
                                continue
                        except Exception:
                            continue
                    matches.append(m)
                    if len(matches) >= 400:
                        break
            except RecursionError:
                continue
            if len(matches) < rule.min_count:
                continue
            shown = matches[: (1 if rule.min_count > 1 else rule.max_hits)]
            for idx, m in enumerate(shown):
                line, col = view.line_col(m.start())
                rline = unit.report_line(line)
                if seen is not None and (rule.id, rline) in seen:
                    continue
                raw_line = unit.line_text(line) if normalized else view.line_text(line)
                ltxt = view.line_text(line)
                mstart = col - 1
                mend = min(len(ltxt), mstart + (m.end() - m.start()))
                snippet_src = raw_line if normalized else ltxt
                snippet = clip_around(snippet_src, mstart, mend)
                if rule.redact:
                    snippet = snippet.replace(m.group(0), redact(m.group(0)))
                snippet = visible(snippet, 400)
                origin = unit.origin
                tags: List[str] = []
                for a, b, label in spans:
                    if a <= m.start() < b:
                        origin = label
                        tags.append("hidden")
                        break
                sev = rule.severity
                conf = rule.confidence
                msg = rule.description
                if unit.kind == "binary-strings":
                    conf = lower_conf(conf)
                    msg = (msg + " " if msg else "") + "(Found in printable strings of a binary file.)"
                if normalized:
                    sev = bump(sev)
                    tags.append("evasion")
                    msg = ("Only visible after removing invisible / look-alike characters - deliberate filter "
                           "evasion. " + msg).strip()
                if "hidden" in tags and rule.category in HIDDEN_ESCALATE:
                    sev = max_sev(bump(sev), "high")
                if is_doc and rule.category in EDU_CATS and origin == "file" and EDU_RE.search(ltxt):
                    sev = bump(sev, -1)
                    conf = "low"
                    tags.append("documentation-context")
                if rule.category in QUOTE_CATS and origin == "file" and not normalized and _is_quoted(ltxt, mstart):
                    sev = bump(sev, -1)
                    conf = "low"
                    tags.append("quoted")
                    msg = ("The phrase appears quoted / in a code span (often a skill warning ABOUT this attack). "
                           + msg).strip()
                if rule.category == "remote-exec" and iocs.is_known_installer(ltxt[mstart:mstart + (m.end() - m.start()) + 250]):
                    sev = bump(sev, -1)
                    tags.append("official-installer")
                    msg = ("Uses a well-known official installer URL - still remote code execution with no review "
                           "or pinning; verify the URL character by character. " + msg).strip()
                f = Finding(
                    rule_id=rule.id, title=rule.title, severity=sev, category=rule.category, path=unit.path,
                    line=rline, column=0 if unit.parent_line else col, confidence=conf, snippet=snippet,
                    message=msg, origin=origin, remediation=rule.remediation, references=rule.references,
                    capabilities=list(rule.caps), tags=tags,
                )
                if idx == len(shown) - 1 and len(matches) > len(shown):
                    f.occurrences = len(matches) - len(shown) + 1
                    f.message = (f.message + " " if f.message else "") + "(%d matches in total in this file.)" % len(matches)
                if rule.min_count > 1:
                    f.occurrences = len(matches)
                    f.message = (f.message + " " if f.message else "") + "(%d occurrences.)" % len(matches)
                out.append(f)
        return out

    # ------------------------------------------------------------------ IOCs
    def _ioc_findings(self, unit: TextUnit) -> List[Finding]:
        text = unit.text
        found = iocs.extract(text)
        out: List[Finding] = []
        emitted: Set[Tuple[str, str]] = set()
        for url, off, _ in found["urls"]:
            host, port, has_user = iocs.parse_url(url)
            tags = iocs.classify_host(host, url)
            if has_user:
                tags.append("url-credentials")
            if url.lower().startswith("http://") and "private-ip" not in tags and host not in ("localhost",):
                tags.append("plain-http")
            line, col = unit.line_col(off)
            self.iocs.add("urls", url, unit.path, unit.report_line(line), tags)
            if host:
                self.iocs.add("domains", host.lower(), unit.path, unit.report_line(line), tags)
            for tag in tags:
                if tag not in iocs.TAG_SEVERITY:
                    continue
                sev, cat, title = iocs.TAG_SEVERITY[tag]
                if sev == "info":
                    continue
                key = (tag, host.lower())
                if key in emitted:
                    continue
                emitted.add(key)
                desc = ""
                if tag == "known-bad":
                    desc = (iocs.KNOWN_BAD_DOMAINS.get(host.lower()) or iocs.KNOWN_BAD_IPS.get(host.lower()) or
                            next((v for k, v in iocs.KNOWN_BAD_URL_FRAGMENTS.items() if k in url.lower()), ""))
                elif tag == "research-poc":
                    desc = next((v for k, v in iocs.RESEARCH_POC_DOMAINS.items() if host.lower().endswith(k)), "")
                caps = ["network"]
                if cat == "exfiltration":
                    caps.append("exfil-endpoint")
                if tag in ("paste-site", "file-share", "known-bad"):
                    caps.append("download")
                out.append(self._ioc_finding(unit, "IOC-" + tag.upper(), title, sev, cat, off,
                                             "%s%s" % (visible(url, 300), (" - " + desc) if desc else ""), caps))
        seen_ips: Set[str] = set()
        for ip, off, _ in found["ips"]:
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            if len(seen_ips) > 500:
                break
            bare = ip.split(":")[0]
            tags = iocs.classify_host(bare)
            line, col = unit.line_col(off)
            self.iocs.add("ips", ip, unit.path, unit.report_line(line), tags)
            full = unit.line_text(line)
            ltxt = full[max(0, col - 200):col + 200]  # bounded context window (linear time on huge lines)
            if "known-bad" in tags:
                out.append(self._ioc_finding(unit, "IOC-KNOWN-BAD-IP", "Known malicious IP address", "critical",
                                             "known-ioc", off, "%s - %s" % (ip, iocs.KNOWN_BAD_IPS.get(bare, "")),
                                             ["network", "download"]))
            elif "public-ip" in tags and iocs.NET_CONTEXT.search(ltxt) and not re.search(r"version|v\d|\d+\.\d+\.\d+\.\d+-", ltxt, re.I):
                if ("ip", bare) not in emitted:
                    emitted.add(("ip", bare))
                    out.append(self._ioc_finding(unit, "IOC-RAW-PUBLIC-IP", "Raw public IP used in a network context",
                                                 "medium", "network", off, ip, ["network"]))
        for email, off, _ in found["emails"]:
            line, _ = unit.line_col(off)
            self.iocs.add("emails", email, unit.path, unit.report_line(line))
        for wallet, off, kind in found["wallets"]:
            line, _ = unit.line_col(off)
            self.iocs.add("wallets", wallet, unit.path, unit.report_line(line), [kind])

        low = text.lower()
        for s, desc in iocs.KNOWN_BAD_STRINGS.items():
            pos = low.find(s)
            if pos >= 0:
                out.append(self._ioc_finding(unit, "IOC-KNOWN-BAD-STRING", "Known malicious indicator string", "critical",
                                             "known-ioc", pos, "'%s' - %s" % (s, desc), ["download"]))
        for pkg, desc in iocs.KNOWN_BAD_PACKAGES.items():
            for m in re.finditer(r"(?<![\w@/.-])" + re.escape(pkg) + r"(?![\w/-])", low):
                ltxt = unit.line_text(unit.line_col(m.start())[0]).lower()
                if unit.kind in ("json", "requirements", "toml", "yaml") or re.search(
                        r"install|add|require|import|npx|uvx|dependenc|from\s", ltxt):
                    out.append(self._ioc_finding(unit, "IOC-KNOWN-BAD-PACKAGE", "Known malicious package", "critical",
                                                 "known-ioc", m.start(), "'%s' - %s" % (pkg, desc), ["install-packages"]))
                    break
        return out

    def _ioc_finding(self, unit, rid, title, sev, cat, off, message, caps) -> Finding:
        line, col = unit.line_col(off)
        lt = unit.line_text(line)
        return Finding(rule_id=rid, title=title, severity=sev, category=cat, path=unit.path,
                       line=unit.report_line(line), column=0 if unit.parent_line else col, confidence="high",
                       snippet=visible(clip_around(lt, col - 1, col + 20), 400), message=message, origin=unit.origin,
                       references=_refs(cat), capabilities=list(caps))

    # ------------------------------------------------------------------ structure
    def _structure_checks(self, unit: TextUnit) -> List[Finding]:
        out: List[Finding] = []
        if unit.kind in SCRIPT_KINDS_FOR_LONGLINES and unit.origin == "file":
            longest, at = 0, 0
            for i, ln in enumerate(unit.text.split("\n"), 1):
                if len(ln) > longest:
                    longest, at = len(ln), i
            if longest > 3000:
                lt = unit.line_text(at)
                ws = sum(1 for c in lt if c.isspace()) / max(1, len(lt))
                sev = "high" if ws < 0.02 else "medium"
                out.append(Finding(rule_id="OBF-MINIFIED-CODE", title="Minified / single-line code (not reviewable)",
                                   severity=sev, category="obfuscation", path=unit.path, line=at, confidence="medium",
                                   snippet=visible(lt[:200], 260),
                                   message="A %d-character line. Minified or packed code hides behaviour from review; "
                                           "obtain the original source." % longest, origin=unit.origin,
                                   references=_refs("obfuscation"), capabilities=["obfuscation"]))
        if unit.kind in CODE or unit.is_skill_md:
            blobs = []
            for m in LONG_TOKEN_RE.finditer(unit.text):
                tok = m.group(0)
                if str_entropy(tok) >= 5.2:
                    blobs.append(m)
                if len(blobs) >= 50:
                    break
            if blobs:
                line, _ = unit.line_col(blobs[0].start())
                out.append(Finding(rule_id="OBF-HIGH-ENTROPY-BLOB", title="High-entropy encoded blob(s)", severity="low",
                                   category="obfuscation", path=unit.path, line=unit.report_line(line), confidence="low",
                                   snippet=visible(blobs[0].group(0)[:120], 160),
                                   message="%d long random-looking token(s) that did not decode to text. Could be "
                                           "encrypted/packed payloads or just keys/data." % len(blobs),
                                   origin=unit.origin, references=_refs("obfuscation"), capabilities=["obfuscation"]))
        return out

    # ------------------------------------------------------------------ decoding
    def _decode_layer(self, unit: TextUnit) -> List[Finding]:
        out: List[Finding] = []
        for d in find_encoded(unit.text):
            line, col = unit.line_col(d.offset)
            rline = unit.report_line(line)
            origin = "decoded:%s" % d.method if unit.origin == "file" else "%s>%s" % (unit.origin, d.method)
            if d.binary_magic:
                exe = d.binary_magic in ("pe", "elf", "macho", "macho-fat", "mz-dos", "java-class", "wasm")
                out.append(Finding(
                    rule_id="OBF-EMBEDDED-BINARY", title="Encoded embedded %s" % ("executable" if exe else "binary"),
                    severity="critical" if exe else ("medium" if d.binary_magic in ("zip", "gzip", "7z", "rar") else "info"),
                    category="obfuscation", path=unit.path, line=rline, column=col, confidence="high",
                    snippet=visible(clip_around(unit.line_text(line), col - 1, col + 40), 300),
                    message="A %s blob (%d chars) decodes to %s data." % (d.method, d.raw_len, d.binary_magic),
                    origin=origin, references=_refs("obfuscation"),
                    capabilities=["obfuscation", "decode"] + (["execute"] if exe else []), tags=["decoded"]))
                continue
            if d.note:
                out.append(Finding(rule_id="OBF-BYTE-ARRAY", title="Large non-text byte array", severity="medium",
                                   category="obfuscation", path=unit.path, line=rline, column=col, confidence="low",
                                   snippet=visible(clip_around(unit.line_text(line), col - 1, col + 40), 300),
                                   message=d.note + " - possible shellcode or encrypted payload.", origin=origin,
                                   references=_refs("obfuscation"), capabilities=["obfuscation"], tags=["decoded"]))
                continue
            if not d.text or len(d.text.strip()) < 6:
                continue
            child = TextUnit(unit.path, d.text, "decoded", origin=origin, depth=unit.depth + 1, parent_line=rline)
            child_findings = self.scan(child)
            significant = [f for f in child_findings if sev_rank(f.severity) >= sev_rank("low")]
            for f in child_findings:
                if "decoded" not in f.tags:
                    f.tags.append("decoded")
            out.extend(child_findings)
            preview = visible(d.text, 600)
            if significant:
                worst = max_sev(*[f.severity for f in significant])
                cats = sorted({f.category for f in significant})
                out.append(Finding(
                    rule_id="OBF-ENCODED-PAYLOAD", title="Encoded payload hides suspicious content",
                    severity=bump(worst) if sev_rank(worst) >= sev_rank("medium") else worst,
                    category="obfuscation", path=unit.path, line=rline, column=col, confidence="high",
                    snippet=visible(clip_around(unit.line_text(line), col - 1, col + 40), 300),
                    message="A %s-encoded string (%d chars) decodes to content flagged for: %s."
                            % (d.method, d.raw_len, ", ".join(cats)),
                    evidence=["Decoded: " + preview], origin=origin, references=_refs("obfuscation"),
                    capabilities=["obfuscation", "decode"], tags=["decoded"]))
            elif looks_like_code(d.text) and len(d.text) >= 20:
                out.append(Finding(
                    rule_id="OBF-ENCODED-CODE", title="Encoded string decodes to code / command text", severity="low",
                    category="obfuscation", path=unit.path, line=rline, column=col, confidence="medium",
                    snippet=visible(clip_around(unit.line_text(line), col - 1, col + 40), 300),
                    message="A %s-encoded string decodes to code-like text. Why is it encoded?" % d.method,
                    evidence=["Decoded: " + preview], origin=origin, references=_refs("obfuscation"),
                    capabilities=["decode"], tags=["decoded"]))
        return out
