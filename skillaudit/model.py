"""Core data structures shared by every module."""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
CONFIDENCES = ("low", "medium", "high")
CONF_RANK = {c: i for i, c in enumerate(CONFIDENCES)}


def sev_rank(sev: str) -> int:
    return SEV_RANK.get(sev, 0)


def bump(sev: str, steps: int = 1) -> str:
    i = max(0, min(len(SEVERITIES) - 1, sev_rank(sev) + steps))
    return SEVERITIES[i]


def max_sev(*sevs: str) -> str:
    sevs = tuple(s for s in sevs if s)
    return max(sevs, key=sev_rank) if sevs else "info"


def lower_conf(conf: str, steps: int = 1) -> str:
    i = max(0, CONF_RANK.get(conf, 1) - steps)
    return CONFIDENCES[i]


_WS = re.compile(r"\s+")


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    path: str = ""            # display path relative to the scan root ("(skill)" for skill-level)
    line: int = 0
    column: int = 0
    confidence: str = "medium"
    snippet: str = ""         # sanitised one-line excerpt (never raw)
    message: str = ""         # finding-specific explanation
    evidence: List[str] = field(default_factory=list)   # sanitised extra lines (decoded payloads, ...)
    origin: str = "file"      # file | decoded:<how> | hidden-unicode | html-comment | ads | strings | ...
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    occurrences: int = 1
    fingerprint: str = ""
    suppressed: bool = False
    suppression_reason: str = ""

    def compute_fingerprint(self) -> str:
        """Stable id that survives line shifts (used for baseline diffs)."""
        snippet = _WS.sub(" ", self.snippet or "")[:160]
        raw = "|".join([self.rule_id, self.path, self.origin.split(":")[0], snippet])
        self.fingerprint = hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:16]
        return self.fingerprint

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TextUnit:
    """A piece of text to scan: a file, an archive member, a decoded payload, hidden text..."""
    path: str
    text: str
    kind: str
    origin: str = "file"
    depth: int = 0
    parent_line: int = 0          # >0 when the text was derived from a specific line of `path`
    is_skill_md: bool = False
    _starts: Optional[List[int]] = None

    def _line_starts(self) -> List[int]:
        if self._starts is None:
            starts = [0]
            find = self.text.find
            i = find("\n")
            while i != -1:
                starts.append(i + 1)
                i = find("\n", i + 1)
            self._starts = starts
        return self._starts

    def line_col(self, offset: int):
        import bisect
        starts = self._line_starts()
        idx = bisect.bisect_right(starts, offset) - 1
        return idx + 1, offset - starts[idx] + 1

    def line_text(self, line: int) -> str:
        starts = self._line_starts()
        if line < 1 or line > len(starts):
            return ""
        a = starts[line - 1]
        b = starts[line] - 1 if line < len(starts) else len(self.text)
        return self.text[a:b].rstrip("\r")

    def report_line(self, line: int) -> int:
        return self.parent_line if self.parent_line else line


@dataclass
class FileRecord:
    path: str
    kind: str = "unknown"
    size: int = 0
    sha256: str = ""
    magic: str = ""
    ext: str = ""
    encoding: str = ""
    is_text: bool = False
    lines: int = 0
    entropy: float = 0.0
    surface: str = ""         # agent-instructions | executable-code | config | data | binary | archive | media | other
    flags: List[str] = field(default_factory=list)
    link_target: str = ""
    mode: str = ""
    mtime: str = ""
    container: str = ""       # archive path if this is an archive member
    max_severity: str = ""
    finding_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    tool: str
    version: str
    unit_name: str
    target: str
    started: str = ""
    finished: str = ""
    duration_s: float = 0.0
    is_skill: bool = False
    skill: Dict[str, Any] = field(default_factory=dict)
    files: List[FileRecord] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    suppressed: List[Finding] = field(default_factory=list)
    iocs: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    capabilities: Dict[str, List[str]] = field(default_factory=dict)
    stats: Dict[str, Any] = field(default_factory=dict)
    coverage: Dict[str, Any] = field(default_factory=dict)
    risk_score: int = 0
    verdict: str = ""
    verdict_detail: str = ""
    baseline: Optional[Dict[str, Any]] = None
    options: Dict[str, Any] = field(default_factory=dict)
    sources: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
