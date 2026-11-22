"""Deceptive Unicode and whitespace-hiding detection.

Covers: Unicode tag smuggling (decoded), variation-selector smuggling (decoded),
zero-width binary steganography (decoded), bidi controls (Trojan Source),
ANSI/OSC terminal escapes, private-use payloads, blank glyphs, homoglyph /
mixed-script tokens, styled (math/fullwidth) letters, and whitespace padding.

All special code points are built with chr() so this source file stays pure ASCII.
"""
from __future__ import annotations

import itertools
import re
import unicodedata
from collections import Counter, defaultdict
from typing import List, Tuple

from .charclass import classify, cp_name, is_emoji_like
from .model import Finding, TextUnit
from .rules import CATEGORY_INFO
from .sanitize import clip_around, visible


def _cls(*items) -> str:
    """Build a regex character class body from code points and (lo, hi) ranges."""
    out = []
    for it in items:
        if isinstance(it, tuple):
            out.append("%s-%s" % (re.escape(chr(it[0])), re.escape(chr(it[1]))))
        else:
            out.append(re.escape(chr(it)))
    return "".join(out)


SUSPICIOUS_RE = re.compile("[" + _cls(
    (0x00, 0x08), 0x0B, 0x0C, (0x0E, 0x1F), (0x7F, 0x9F), 0xAD, 0x34F, 0x61C, 0x115F, 0x1160, 0x17B4, 0x17B5,
    0x180E, (0x200B, 0x200F), (0x202A, 0x202E), 0x2028, 0x2029, (0x2060, 0x2064), (0x206A, 0x206F), 0x2800,
    0x3164, (0xFE00, 0xFE0F), 0xFEFF, 0xFFA0, (0xFFF9, 0xFFFB), (0xE000, 0xF8FF), (0xE0000, 0xE007F),
    (0xE0100, 0xE01EF), (0xF0000, 0x10FFFF), (0x1D173, 0x1D17A)) + "]+")
ANSI_RE = re.compile(r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]{0,2000}(?:\x07|\x1b\\)?|[@-Z\\-_])")
H_RUN_RE = re.compile("[ \t\f\v" + chr(0xA0) + "]{120,}")
WORD_RE = re.compile(r"[^\W\d_]{2,}", re.UNICODE)

# Cyrillic / Greek letters that look like Latin letters -> their Latin skeleton
_SKEL = {chr(k): v for k, v in {
    0x0430: "a", 0x0435: "e", 0x043E: "o", 0x0440: "p", 0x0441: "c", 0x0443: "y", 0x0445: "x", 0x0455: "s",
    0x0456: "i", 0x0458: "j", 0x0501: "d", 0x051B: "q", 0x051D: "w", 0x04BB: "h", 0x04CF: "l", 0x0410: "A",
    0x0412: "B", 0x0415: "E", 0x041A: "K", 0x041C: "M", 0x041D: "H", 0x041E: "O", 0x0420: "P", 0x0421: "C",
    0x0422: "T", 0x0425: "X", 0x0406: "I", 0x0408: "J", 0x0405: "S", 0x03BF: "o", 0x03B1: "a", 0x03BD: "v",
    0x03B9: "i", 0x03BA: "k", 0x03C1: "p", 0x039F: "O", 0x0391: "A", 0x0392: "B", 0x0395: "E", 0x0396: "Z",
    0x0397: "H", 0x0399: "I", 0x039A: "K", 0x039C: "M", 0x039D: "N", 0x03A1: "P", 0x03A4: "T", 0x03A5: "Y",
    0x03A7: "X",
}.items()}
CONFUSABLE = set(_SKEL)
RTL_RANGES = ((0x0590, 0x08FF), (0xFB1D, 0xFDFF), (0xFE70, 0xFEFF))
JOINING_SCRIPTS = ((0x0600, 0x06FF), (0x0750, 0x077F), (0x0900, 0x0DFF), (0x0F00, 0x0FFF), (0x1780, 0x17FF))
ZWJ, ZWNJ, VS16, BOM, SHY, BLACK_FLAG, CANCEL_TAG = 0x200D, 0x200C, 0xFE0F, 0xFEFF, 0xAD, 0x1F3F4, 0xE007F

INSTRUCTION_WORDS = re.compile(
    r"\b(?:ignore|disregard|instruction|assistant|claude|agent|model|system|prompt|execute|run|curl|wget|bash|"
    r"powershell|send|upload|post|password|secret|token|api.?key|credential|ssh|do not|don't|never|silently|"
    r"secretly|important|must|always|tell|user|install|download|http)\b", re.I)


def _cat_refs(cat: str) -> List[str]:
    return list(CATEGORY_INFO.get(cat, ("", []))[1])


def _mk(unit: TextUnit, rule_id, title, sev, cat, offset, message, evidence=None, confidence="high", caps=(), tags=()):
    line, col = unit.line_col(offset) if offset >= 0 else (0, 0)
    lt = unit.line_text(line) if line else ""
    snippet = visible(clip_around(lt, col - 1, col + 1), 300) if lt else ""
    return Finding(
        rule_id=rule_id, title=title, severity=sev, category=cat, path=unit.path, line=unit.report_line(line),
        column=col if not unit.parent_line else 0, confidence=confidence, snippet=snippet, message=message,
        evidence=list(evidence or []), origin=unit.origin, references=_cat_refs(cat), capabilities=list(caps),
        tags=list(tags),
    )


def _script_of(ch: str) -> str:
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return ""
    first = name.split(" ", 1)[0]
    if first in ("MATHEMATICAL", "FULLWIDTH"):
        return "STYLED"
    return first


def _in(cp: int, ranges) -> bool:
    return any(a <= cp <= b for a, b in ranges)


def decode_variation_selectors(run: str) -> bytes:
    out = bytearray()
    for ch in run:
        cp = ord(ch)
        if 0xFE00 <= cp <= 0xFE0F:
            out.append(cp - 0xFE00)
        elif 0xE0100 <= cp <= 0xE01EF:
            out.append(cp - 0xE0100 + 16)
    return bytes(out)


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(1 for c in s if c.isprintable() or c in "\n\r\t") / len(s)


def decode_zero_width_binary(run: str) -> str:
    """Try to read a run of invisible characters as binary / base-4 steganography."""
    symbols = sorted(set(run))
    if len(run) < 16:
        return ""
    candidates = []
    if len(symbols) == 2:
        for zero, one in ((symbols[0], symbols[1]), (symbols[1], symbols[0])):
            bits = "".join("0" if c == zero else "1" for c in run)
            candidates.append(bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8)))
    elif len(symbols) == 4:
        for perm in itertools.permutations(symbols):
            mp = {c: i for i, c in enumerate(perm)}
            vals = [mp[c] for c in run]
            candidates.append(bytes((vals[i] << 6) | (vals[i + 1] << 4) | (vals[i + 2] << 2) | vals[i + 3]
                                    for i in range(0, len(vals) - 3, 4)))
    best = ""
    for data in candidates:
        try:
            s = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if len(s) >= 3 and _printable_ratio(s) > 0.95 and sum(c.isalpha() for c in s) >= len(s) * 0.4:
            if len(s) > len(best):
                best = s
    return best


def scan_unicode(unit: TextUnit) -> Tuple[List[Finding], List[TextUnit]]:
    text = unit.text
    findings: List[Finding] = []
    children: List[TextUnit] = []
    if not text:
        return findings, children

    _scan_whitespace(unit, findings)

    has_rtl = False
    if not text.isascii():
        has_rtl = any(_in(ord(c), RTL_RANGES) for c in text[:200000] if ord(c) > 0x58F)

    stats = defaultdict(lambda: {"count": 0, "first": -1, "longest": 0, "locs": []})
    tag_messages = []
    vs_messages = []
    zw_messages = []

    for m in SUSPICIOUS_RE.finditer(text):
        seg = m.group(0)
        pos = m.start()
        i = 0
        while i < len(seg):
            cls = classify(ord(seg[i]))
            j = i + 1
            while j < len(seg) and classify(ord(seg[j])) == cls:
                j += 1
            run = seg[i:j]
            start = pos + i
            i = j
            if cls is None:
                continue
            prev = text[start - 1] if start > 0 else ""
            nxt = text[start + len(run)] if start + len(run) < len(text) else ""

            # ---- legitimate uses --------------------------------------------------
            if cls == "tag":
                if prev and ord(prev) == BLACK_FLAG and len(run) <= 8 and ord(run[-1]) == CANCEL_TAG:
                    continue  # subdivision flag emoji (England / Scotland / Wales)
            if cls == "variation-selector" and len(run) == 1:
                cp = ord(run)
                pcp = ord(prev) if prev else 0
                if cp in (0xFE0E, VS16) and (is_emoji_like(pcp) or prev in "0123456789#*" or pcp > 0x2000):
                    continue
                if pcp >= 0x2E80:  # CJK ideographic variation sequences
                    continue
            if cls == "zero-width":
                if all(ord(c) in (ZWJ, VS16) for c in run) and prev and nxt and (
                        is_emoji_like(ord(prev)) or ord(prev) == VS16) and is_emoji_like(ord(nxt)):
                    continue  # emoji ZWJ sequence
                if all(ord(c) in (ZWNJ, ZWJ) for c in run) and (
                        (prev and _in(ord(prev), JOINING_SCRIPTS)) or (nxt and _in(ord(nxt), JOINING_SCRIPTS))):
                    continue  # ZWNJ / ZWJ in Arabic / Indic text
                if len(run) == 1 and ord(run) == BOM and start == 0:
                    continue
                if len(run) == 1 and ord(run) == SHY and prev.isalpha() and nxt.isalpha():
                    cls = "soft-hyphen"  # pasted web text; counted at low weight
            if cls == "bidi-mark" and has_rtl:
                continue
            if cls == "control" and all(c in "\x0c\x0b" for c in run):
                continue  # form feed / vertical tab (old source files)

            st = stats[cls]
            st["count"] += len(run)
            st["longest"] = max(st["longest"], len(run))
            if st["first"] < 0:
                st["first"] = start
            if len(st["locs"]) < 6:
                ln, col = unit.line_col(start)
                st["locs"].append((unit.report_line(ln), col, len(run), ord(run[0])))

            if cls == "tag":
                decoded = "".join(chr(ord(c) - 0xE0000) for c in run if 0x20 <= ord(c) - 0xE0000 <= 0x7E)
                if decoded:
                    tag_messages.append((start, decoded))
            elif cls == "variation-selector" and len(run) >= 2:
                data = decode_variation_selectors(run)
                try:
                    s = data.decode("utf-8")
                except UnicodeDecodeError:
                    s = ""
                vs_messages.append((start, s if len(s) >= 3 and _printable_ratio(s) > 0.9 else "", len(run)))
            elif cls == "zero-width" and len(run) >= 16:
                s = decode_zero_width_binary(run)
                if s:
                    zw_messages.append((start, s))

    # ---- tag smuggling ----------------------------------------------------------
    if "tag" in stats:
        st = stats["tag"]
        full = "".join(msg for _, msg in tag_messages)
        sev = "critical" if len(full.strip()) >= 3 else "high"
        ev = ["Decoded hidden text: " + visible(full, 1500)] if full else []
        ev += ["at line %d col %d (%d chars)" % (l, c, n) for l, c, n, _ in st["locs"]]
        findings.append(_mk(unit, "UNI-TAG-SMUGGLING", "Invisible Unicode tag characters (ASCII smuggling)", sev,
                            "unicode", st["first"],
                            "%d Unicode TAG characters (U+E0000-E007F) are invisible to humans but read by LLMs. "
                            "They decode to the text shown in evidence." % st["count"], ev,
                            caps=("inject", "hidden", "obfuscation"), tags=["hidden"]))
        for start, msg in tag_messages:
            if len(msg.strip()) >= 3:
                ln, _ = unit.line_col(start)
                children.append(TextUnit(unit.path, msg, "hidden", origin="hidden-unicode:tags",
                                         depth=unit.depth + 1, parent_line=unit.report_line(ln)))

    # ---- variation selector smuggling -------------------------------------------------
    if "variation-selector" in stats:
        st = stats["variation-selector"]
        decoded = [(s, msg, n) for s, msg, n in vs_messages if msg]
        longest = st["longest"]
        sev = "critical" if decoded or longest >= 32 else ("high" if longest >= 2 else "medium")
        ev = ["Decoded hidden bytes: " + visible(msg, 1500) for _, msg, _ in decoded[:5]]
        ev += ["at line %d col %d (%d selectors)" % (l, c, n) for l, c, n, _ in st["locs"]]
        findings.append(_mk(unit, "UNI-VARIATION-SELECTOR-SMUGGLING",
                            "Variation selectors outside emoji (byte smuggling)", sev, "unicode", st["first"],
                            "%d variation selectors not attached to emoji; longest run %d. Runs of selectors can "
                            "encode arbitrary bytes (GlassWorm / 'emoji smuggling')." % (st["count"], longest), ev,
                            caps=("obfuscation", "hidden"), tags=["hidden"]))
        for start, msg, _ in decoded:
            ln, _ = unit.line_col(start)
            children.append(TextUnit(unit.path, msg, "hidden", origin="hidden-unicode:variation-selectors",
                                     depth=unit.depth + 1, parent_line=unit.report_line(ln)))

    # ---- zero width ---------------------------------------------------------------------
    if "zero-width" in stats:
        st = stats["zero-width"]
        total, longest = st["count"], st["longest"]
        if zw_messages or longest >= 40:
            sev = "critical"
        elif longest >= 10 or total > 100:
            sev = "high"
        elif total >= 3:
            sev = "medium"
        else:
            sev = "low"
        ev = ["Decoded zero-width steganography: " + visible(msg, 1500) for _, msg in zw_messages[:5]]
        ev += ["at line %d col %d: %d x %s" % (l, c, n, cp_name(cp)) for l, c, n, cp in st["locs"]]
        findings.append(_mk(unit, "UNI-ZERO-WIDTH", "Zero-width / invisible characters", sev, "unicode", st["first"],
                            "%d invisible characters (longest run %d). They can split keywords to dodge filters "
                            "or encode hidden data." % (total, longest), ev,
                            caps=("obfuscation", "hidden"), tags=["hidden"]))
        for start, msg in zw_messages:
            ln, _ = unit.line_col(start)
            children.append(TextUnit(unit.path, msg, "hidden", origin="hidden-unicode:zero-width",
                                     depth=unit.depth + 1, parent_line=unit.report_line(ln)))

    simple = {
        "bidi": ("UNI-BIDI-CONTROL", "Bidirectional override / isolate characters (Trojan Source)", "high",
                 "Bidi controls reorder how text is displayed, so reviewers see different code or text than "
                 "what is executed or read by the model (CVE-2021-42574)."),
        "bidi-mark": ("UNI-BIDI-MARK", "Invisible directional marks in non-RTL text", "low",
                      "LRM/RLM/ALM marks have no purpose in left-to-right text and can split keywords."),
        "control": ("UNI-CONTROL-CHARS", "Non-printing control characters", "medium",
                    "C0/C1 control characters (other than tab/newline) can hide or corrupt content in editors "
                    "and terminals."),
        "private-use": ("UNI-PRIVATE-USE", "Private-use-area code points", "medium",
                        "Private-use characters render as blanks/boxes; runs of them have been used to carry "
                        "encoded payloads (GlassWorm)."),
        "blank-glyph": ("UNI-BLANK-GLYPH", "Blank-rendering 'filler' characters", "medium",
                        "Hangul fillers / Braille blank render as empty space and are used to make invisible "
                        "text or names."),
        "interlinear": ("UNI-INTERLINEAR", "Interlinear annotation characters", "medium",
                        "U+FFF9-FFFB can hide annotation text in some renderers."),
        "format-control": ("UNI-DEPRECATED-FORMAT", "Deprecated invisible format controls (U+206A-206F)", "medium",
                           "Deprecated format characters are invisible and have no legitimate modern use."),
        "line-separator": ("UNI-LINE-SEPARATOR", "Unicode line/paragraph separators", "low",
                           "U+2028/2029 break lines in some tools but not others (parser confusion)."),
        "soft-hyphen": ("UNI-SOFT-HYPHEN", "Soft hyphens inside words", "low",
                        "Usually pasted from the web, but they also split keywords invisibly."),
    }
    for cls, (rid, title, sev, msg) in simple.items():
        if cls not in stats:
            continue
        st = stats[cls]
        s = sev
        if cls == "private-use" and st["longest"] >= 16:
            s = "high"
        if cls == "bidi" and unit.kind in ("markdown", "text") and st["count"] <= 2:
            s = "medium"
        ev = ["at line %d col %d: %d x %s" % (l, c, n, cp_name(cp)) for l, c, n, cp in st["locs"]]
        findings.append(_mk(unit, rid, title, s, "unicode", st["first"], "%d occurrence(s). %s" % (st["count"], msg),
                            ev, caps=("hidden",), tags=["hidden"]))

    # ---- terminal escapes ------------------------------------------------------------------
    if "escape" in stats:
        st = stats["escape"]
        kinds = Counter()
        for m in ANSI_RE.finditer(text):
            seq = m.group(0)
            if seq.startswith("\x1b]8;"):
                kinds["OSC-8 hyperlink (displayed text can differ from target)"] += 1
            elif seq.startswith("\x1b]"):
                kinds["OSC sequence"] += 1
            elif re.match(r"\x1b\[[0-9;]*[ABCDEFGHJKSTf]", seq):
                kinds["cursor movement / erase (can overwrite displayed lines)"] += 1
            elif seq.endswith("m"):
                kinds["colour/style (e.g. invisible text)"] += 1
            else:
                kinds["other escape"] += 1
        ev = ["%d x %s" % (n, k) for k, n in kinds.most_common()]
        ev += ["at line %d col %d" % (l, c) for l, c, _, _ in st["locs"]]
        findings.append(_mk(unit, "UNI-ANSI-ESCAPE", "ANSI / OSC terminal escape sequences", "high", "unicode",
                            st["first"], "%d ESC characters. Escape sequences can hide, recolour or overwrite text "
                            "when viewed in a terminal (Trail of Bits MCP research)." % st["count"], ev,
                            caps=("hidden",), tags=["hidden"]))

    distinct = [k for k in stats if k not in ("soft-hyphen", "line-separator", "bidi-mark")]
    if len(distinct) >= 3:
        findings.append(_mk(unit, "UNI-MULTIPLE-HIDDEN-TYPES", "Several kinds of hidden characters in one file",
                            "high", "unicode", min(stats[k]["first"] for k in distinct),
                            "Hidden character classes present: %s. Mixing techniques is a strong evasion signal."
                            % ", ".join(sorted(distinct)), caps=("hidden",), tags=["hidden"]))

    if not text.isascii():
        _scan_homoglyphs(unit, findings)
    return findings, children


def _scan_whitespace(unit: TextUnit, findings: List[Finding]) -> None:
    """Linear-time padding detection (regex lookaheads here would be quadratic on huge whitespace runs)."""
    text = unit.text
    hits = 0
    for m in H_RUN_RE.finditer(text):
        if m.end() >= len(text) or text[m.end()] == "\n":
            continue  # trailing whitespace, nothing hidden after it
        after = text[m.end():m.end() + 160].split("\n", 1)[0]
        line_start = text.rfind("\n", 0, m.start()) + 1
        if text[line_start:m.start()].lstrip().startswith("|") or after.lstrip().startswith("|") \
                or sum(c.isalnum() for c in after) < 4:
            continue  # Markdown table / column alignment padding
        hits += 1
        if hits > 3:
            break
        findings.append(_mk(unit, "HIDE-HORIZONTAL-PADDING", "Content pushed off-screen by a long run of spaces",
                            "medium" if not INSTRUCTION_WORDS.search(after) else "high", "hidden-content", m.end(),
                            "%d whitespace characters precede this content, hiding it beyond the visible width."
                            % (m.end() - m.start()), ["Hidden text: " + visible(after, 300)],
                            caps=("hidden",), tags=["hidden"]))
    offset, blank = 0, 0
    for ln in text.split("\n"):
        if not ln.strip():
            blank += 1
        else:
            if blank >= 40:
                after = ln.strip()[:200]
                sev = "high" if blank >= 1000 or INSTRUCTION_WORDS.search(after) else "medium"
                findings.append(_mk(unit, "HIDE-VERTICAL-PADDING", "Content hidden after a large block of blank lines",
                                    sev, "hidden-content", offset,
                                    "%d blank lines precede this content. Padding hides payloads from reviewers and "
                                    "can truncate LLM/AV scanners (Trail of Bits csv-summarizer, Unit 42 omnicogg)."
                                    % blank, ["Text after the gap: " + visible(after, 300)],
                                    caps=("hidden",), tags=["hidden"]))
                break
            blank = 0
        offset += len(ln) + 1
    if len(text) > 1_000_000:
        sample = text[::97]
        ws = sum(1 for c in sample if c.isspace()) / max(1, len(sample))
        if ws > 0.9:
            findings.append(_mk(unit, "HIDE-PADDED-FILE", "File is mostly whitespace padding", "high", "hidden-content",
                                0, "%.0f%% of this %.1f MB file is whitespace - a known scanner-evasion trick."
                                % (ws * 100, len(text) / 1e6), caps=("hidden",), tags=["hidden"]))


def _scan_homoglyphs(unit: TextUnit, findings: List[Finding]) -> None:
    text = unit.text
    latin = sum(1 for c in text[:50000] if "a" <= c.lower() <= "z")
    letters = sum(1 for c in text[:50000] if c.isalpha()) or 1
    latin_doc = latin / letters > 0.8
    mixed, whole, styled = [], [], []
    for m in WORD_RE.finditer(text):
        w = m.group(0)
        if w.isascii():
            continue
        scripts = {_script_of(c) for c in w if c.isalpha()}
        scripts.discard("")
        if "STYLED" in scripts:
            styled.append((m.start(), w))
            continue
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE", "COPTIC"}:
            if any(c in CONFUSABLE for c in w):  # only look-alike letters; real Greek math symbols are fine
                mixed.append((m.start(), w))
        elif latin_doc and len(w) >= 3 and all(c in CONFUSABLE for c in w):
            whole.append((m.start(), w))
        if len(mixed) + len(whole) + len(styled) > 60:
            break
    code_like = unit.kind not in ("markdown", "text")
    if mixed:
        sev = "high" if code_like else "medium"
        ev = ["line %d: %s -> looks like '%s'" % (unit.report_line(unit.line_col(o)[0]), visible(w), _skeleton(w))
              for o, w in mixed[:8]]
        findings.append(_mk(unit, "UNI-HOMOGLYPH-MIXED-SCRIPT", "Words mixing Latin with look-alike scripts",
                            sev, "unicode", mixed[0][0], "%d token(s) mix Latin letters with Cyrillic/Greek look-alikes"
                            " - used to dodge keyword filters or spoof names/domains." % len(mixed), ev,
                            caps=("obfuscation",)))
    if whole:
        ev = ["line %d: %s -> looks like '%s'" % (unit.report_line(unit.line_col(o)[0]), visible(w), _skeleton(w))
              for o, w in whole[:8]]
        findings.append(_mk(unit, "UNI-HOMOGLYPH-WHOLE-WORD", "Words spelled entirely with look-alike letters",
                            "medium", "unicode", whole[0][0],
                            "%d token(s) in a Latin document consist only of Cyrillic/Greek characters that look "
                            "like Latin letters." % len(whole), ev, confidence="medium", caps=("obfuscation",)))
    if styled:
        ev = ["line %d: %s -> '%s'" % (unit.report_line(unit.line_col(o)[0]), visible(w),
                                       unicodedata.normalize("NFKC", w)) for o, w in styled[:8]]
        findings.append(_mk(unit, "UNI-STYLED-LETTERS", "Mathematical / full-width letters used as text", "low",
                            "unicode", styled[0][0], "%d token(s) use styled Unicode letters that normalise to ASCII "
                            "(keyword-filter evasion)." % len(styled), ev, confidence="medium",
                            caps=("obfuscation",)))


def _skeleton(w: str) -> str:
    return "".join(_SKEL.get(c, c) for c in w)


def normalized_view(text: str) -> str:
    """Strip invisible characters and fold confusables/styled letters, line by line (keeps line numbers)."""
    stripped = SUSPICIOUS_RE.sub(lambda m: "".join(c for c in m.group(0) if c == "\t"), text)
    folded = unicodedata.normalize("NFKC", stripped)
    folded = "".join(_SKEL.get(c, c) for c in folded)
    if folded.count("\n") != text.count("\n"):
        return ""  # normalisation changed line structure; skip to keep line mapping honest
    return folded
