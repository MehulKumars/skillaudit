"""Hidden content in Markdown / HTML: comments, invisible elements, deceptive links.

Returns findings plus "hidden spans" (offset ranges). The engine uses the spans
to re-label rule hits that fall inside hidden regions (origin=html-comment etc.)
so the correlation engine can escalate hidden instructions.
"""
from __future__ import annotations

import re
from typing import List, Tuple
from urllib.parse import urlsplit

from .model import Finding, TextUnit
from .rules import CATEGORY_INFO
from .sanitize import visible
from .unicode_checks import INSTRUCTION_WORDS

COMMENT_RE = re.compile(r"<!--(.*?)(-->|\Z)", re.S)
LINKREF_COMMENT_RE = re.compile(r"^[ \t]{0,3}\[(?://|comment|_|#|hidden|note)\]:\s*<?#?>?\s*[(\"'](.*?)[)\"']\s*$",
                                re.M | re.I)
HIDDEN_STYLE_RE = re.compile(
    r"<(\w+)\b[^>]{0,400}?style\s*=\s*[\"'][^\"']{0,400}?(?:display\s*:\s*none|visibility\s*:\s*hidden|"
    r"font-size\s*:\s*0(?:\.0+)?(?:px|pt|em|rem|%)?\s*(?:;|[\"'])|opacity\s*:\s*0(?:\.0+)?\s*(?:;|[\"'])|"
    r"color\s*:\s*(?:#fff(?:fff)?\b|white\b|transparent\b|rgba\([^)]*,\s*0(?:\.0+)?\s*\))|"
    r"(?:max-)?(?:height|width)\s*:\s*0(?:px)?\s*(?:;|[\"'])|(?:left|top|text-indent)\s*:\s*-\d{3,}px|"
    r"clip\s*:\s*rect\(\s*0)[^>]{0,400}>(.*?)</\1\s*>", re.S | re.I)
HIDDEN_ATTR_RE = re.compile(r"<(\w+)\b[^>]{0,300}?\s(?:hidden|aria-hidden\s*=\s*[\"']true[\"'])(?:\s|>|=)[^>]{0,300}>(.*?)</\1\s*>",
                            re.S | re.I)
MD_LINK_RE = re.compile(r"\[([^\]\n]{1,200})\]\((https?://[^)\s]{1,500})\)")
DOMAIN_IN_TEXT_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+(?:com|net|org|io|dev|app|ai|co|gov|edu|sh|so|me|xyz|info|biz|us|uk))\b", re.I)
FENCE_RE = re.compile(r"^[ \t]{0,3}(`{3,}|~{3,})", re.M)
STRONG_WORDS = re.compile(
    r"\b(?:ignore|disregard|curl|wget|bash|powershell|password|secret|token|api.?key|credential|ssh|silently|"
    r"secretly|exfiltrat\w*|upload|send\s+(?:it|this|the|all|them)|do\s+not\s+(?:tell|mention|show)|don't\s+(?:tell|"
    r"mention|show)|execute|base64|webhook|\.env\b|override)\b", re.I)


def _refs(cat):
    return list(CATEGORY_INFO.get(cat, ("", []))[1])


def _finding(unit, rid, title, sev, cat, offset, message, evidence=(), caps=("hidden",), conf="high", tags=("hidden",)):
    line, col = unit.line_col(offset)
    return Finding(rule_id=rid, title=title, severity=sev, category=cat, path=unit.path, line=unit.report_line(line),
                   column=col, confidence=conf, snippet=visible(unit.line_text(line)[:240], 300), message=message,
                   evidence=list(evidence), origin=unit.origin, references=_refs(cat), capabilities=list(caps),
                   tags=list(tags))


def scan_hidden(unit: TextUnit) -> Tuple[List[Finding], List[Tuple[int, int, str]]]:
    text = unit.text
    findings: List[Finding] = []
    spans: List[Tuple[int, int, str]] = []
    if unit.kind not in ("markdown", "text", "html", "svg", "hidden", "decoded") and not unit.is_skill_md:
        return findings, spans
    low = text.lower()

    # ---- HTML comments ------------------------------------------------------------
    if "<!--" in text:
        n = 0
        weak = []
        for m in COMMENT_RE.finditer(text):
            n += 1
            if n > 300:
                break
            body = m.group(1).strip()
            spans.append((m.start(), m.end(), "html-comment"))
            if m.group(2) == "":
                findings.append(_finding(unit, "HIDE-UNCLOSED-COMMENT", "Unclosed HTML comment hides the rest of the file",
                                         "high", "hidden-content", m.start(),
                                         "Everything after this '<!--' (%d chars) is invisible when rendered but "
                                         "still read by the model." % (len(text) - m.start()),
                                         ["Hidden text starts: " + visible(body[:300], 300)]))
                continue
            if not body or re.fullmatch(r"[-=*#\s.]*|(?:TODO|FIXME|NOTE|prettier-ignore|markdownlint-\S+.*)", body, re.I):
                continue
            hits = INSTRUCTION_WORDS.findall(body)
            strong = set(h.lower() for h in STRONG_WORDS.findall(body))
            if len(set(h.lower() for h in hits)) >= 2:
                sev = "high" if strong and unit.kind not in ("html", "svg") else "medium"
                findings.append(_finding(unit, "HIDE-COMMENT-INSTRUCTIONS", "Instruction-like text inside an HTML comment",
                                         sev, "hidden-content", m.start(),
                                         "HTML comments are invisible in rendered Markdown but fully visible to the "
                                         "agent. This comment contains instruction-like words: %s."
                                         % ", ".join(sorted(set(h.lower() for h in hits))[:10]),
                                         ["Comment text: " + visible(body, 800)], caps=("inject", "hidden")))
            else:
                weak.append((m.start(), body))
        if weak:
            sev = "low" if unit.is_skill_md or unit.kind == "markdown" else "info"
            if unit.kind in ("html", "svg"):
                sev = "info"
            total = sum(len(b) for _, b in weak)
            if total > 400 and sev == "low":
                sev = "medium"
            findings.append(_finding(unit, "HIDE-HTML-COMMENTS", "HTML comments (invisible when rendered)", sev,
                                     "hidden-content", weak[0][0],
                                     "%d comment(s), %d chars total. Review them - rendered views hide them."
                                     % (len(weak), total),
                                     ["line %d: %s" % (unit.report_line(unit.line_col(o)[0]), visible(b, 200))
                                      for o, b in weak[:6]], conf="medium"))

    # ---- Markdown link-reference "comments" ---------------------------------------
    for m in LINKREF_COMMENT_RE.finditer(text):
        body = m.group(1)
        spans.append((m.start(), m.end(), "md-comment"))
        sev = "high" if len(set(INSTRUCTION_WORDS.findall(body))) >= 2 else "low"
        findings.append(_finding(unit, "HIDE-MARKDOWN-COMMENT", "Markdown link-reference comment ([//]: # ...)", sev,
                                 "hidden-content", m.start(), "This syntax never renders; only the model sees it.",
                                 ["Hidden text: " + visible(body, 600)]))

    # ---- invisible HTML elements ----------------------------------------------------
    if "<" in text and ("style" in low or "hidden" in low):
        for rx, label in ((HIDDEN_STYLE_RE, "CSS-hidden element"), (HIDDEN_ATTR_RE, "hidden-attribute element")):
            for k, m in enumerate(rx.finditer(text)):
                if k >= 20:
                    break
                inner = re.sub(r"<[^>]+>", " ", m.group(2)).strip()
                spans.append((m.start(), m.end(), "hidden-html"))
                if not inner:
                    continue
                words = len(set(w.lower() for w in INSTRUCTION_WORDS.findall(inner)))
                if unit.kind in ("html", "svg") and words < 2:
                    continue  # UI toggling (display:none) is normal in real web pages
                sev = "high" if words >= 2 else "medium"
                findings.append(_finding(unit, "HIDE-INVISIBLE-HTML", "Text inside an invisible HTML element (%s)" % label,
                                         sev, "hidden-content", m.start(),
                                         "Styled to be invisible to a human viewer but present in the raw text.",
                                         ["Hidden text: " + visible(inner, 600)], caps=("inject", "hidden")))

    # ---- deceptive links --------------------------------------------------------------
    if "](" in text:
        k = 0
        for m in MD_LINK_RE.finditer(text):
            label, url = m.group(1), m.group(2)
            dm = DOMAIN_IN_TEXT_RE.search(label)
            host = (urlsplit(url).hostname or "").lower()
            if dm and host:
                shown = dm.group(1).lower()
                if not (host == shown or host.endswith("." + shown) or shown.endswith("." + host)):
                    k += 1
                    if k > 10:
                        break
                    findings.append(_finding(unit, "HIDE-DECEPTIVE-LINK", "Link text shows a different domain than the target",
                                             "medium", "social-engineering", m.start(),
                                             "Displayed '%s' but links to '%s'." % (shown, host),
                                             ["Link: " + visible(m.group(0), 400)], caps=("social-engineering",),
                                             tags=()))

    # ---- unbalanced code fences ---------------------------------------------------------
    if unit.kind == "markdown":
        fences = FENCE_RE.findall(text)
        if len(fences) % 2 == 1:
            findings.append(_finding(unit, "HIDE-UNBALANCED-FENCE", "Unclosed code fence", "info", "hidden-content",
                                     text.rfind(fences[-1]) if fences else 0,
                                     "An odd number of ``` fences changes how the rest of the file renders.",
                                     conf="medium", tags=()))
    return findings, spans
