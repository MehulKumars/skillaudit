"""Make untrusted content safe to place in a report.

Everything copied out of a scanned file goes through `visible()` so that
invisible / bidi / control characters cannot hide text from a human reader or
smuggle instructions to an LLM reading the report. Fences are sized so that
embedded content cannot break out of its code block.
"""
from __future__ import annotations

import html
import re

from .charclass import classify, short_label

_BACKTICK_RUN = re.compile(r"`+")


def visible(s: str, max_len: int = 0, keep_newlines: bool = False) -> str:
    """Render suspicious code points as visible ASCII markers like [U+202E RLO]."""
    if not s:
        return ""
    out = []
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if ch == "\n":
            out.append("\n" if keep_newlines else "\\n")
            i += 1
            continue
        if ch == "\r":
            if not keep_newlines:
                out.append("\\r")
            i += 1
            continue
        if ch == "\t":
            out.append("\t" if keep_newlines else " ")
            i += 1
            continue
        cp = ord(ch)
        cls = classify(cp)
        if cls is None:
            out.append(ch)
            i += 1
            continue
        j = i + 1
        while j < n and classify(ord(s[j])) == cls:
            j += 1
        run = j - i
        label = short_label(cp)
        if run == 1:
            out.append("[U+%04X%s]" % (cp, (" " + label) if label else ""))
        else:
            out.append("[%dx %s U+%04X..]" % (run, cls, cp))
        i = j
    res = "".join(out)
    if max_len and len(res) > max_len:
        res = res[:max_len] + " ...[truncated]"
    return res


def clip_around(line: str, start: int, end: int, width: int = 240) -> str:
    """Cut a long line down to a window around [start, end)."""
    if len(line) <= width:
        return line
    mid = (start + end) // 2
    lo = max(0, mid - width // 2)
    hi = min(len(line), lo + width)
    lo = max(0, hi - width)
    prefix = "..." if lo > 0 else ""
    suffix = "..." if hi < len(line) else ""
    return prefix + line[lo:hi] + suffix


def fence(text: str, lang: str = "text") -> str:
    """Wrap text in a Markdown code fence that the text cannot close."""
    longest = max((len(m.group(0)) for m in _BACKTICK_RUN.finditer(text or "")), default=0)
    ticks = "`" * max(3, longest + 1)
    return "%s%s\n%s\n%s" % (ticks, lang, text, ticks)


def code_span(text: str) -> str:
    """Inline code span safe for tables (no pipes / newlines)."""
    text = (text or "").replace("\n", " ").replace("|", "\\|")
    longest = max((len(m.group(0)) for m in _BACKTICK_RUN.finditer(text)), default=0)
    ticks = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return "%s%s%s%s%s" % (ticks, pad, text, pad, ticks)


def md_text(text: str) -> str:
    """Escape prose for Markdown table cells / list items."""
    text = (text or "").replace("\r", " ").replace("\n", " ")
    text = re.sub(r"([\\`*_{}\[\]<>|#])", r"\\\1", text)
    return text


def h(text) -> str:
    return html.escape(str(text if text is not None else ""), quote=True)


def _home_pattern():
    import os
    home = os.path.expanduser("~")
    if not home or home == "~" or len(home) < 3:
        return None
    variants = {home, home.replace("\\", "/"), home.replace("\\", "\\\\")}
    flags = re.I if os.name == "nt" else 0
    return re.compile("|".join(re.escape(v) for v in sorted(variants, key=len, reverse=True)), flags)


_HOME_RE = _home_pattern()


def redact_home(text: str) -> str:
    """Replace the user's home directory with '~' so shared reports do not leak the username."""
    if not text or _HOME_RE is None:
        return text
    return _HOME_RE.sub("~", text)


def redact(secret: str) -> str:
    if len(secret) <= 12:
        return secret[:2] + "*" * max(0, len(secret) - 2)
    return secret[:6] + "*" * 8 + secret[-4:]
