"""Classification of deceptive / invisible Unicode code points."""
from __future__ import annotations

import unicodedata
from typing import Optional

ZERO_WIDTH = {
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x2060: "WORD JOINER",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE (BOM)",
    0x180E: "MONGOLIAN VOWEL SEPARATOR",
    0x00AD: "SOFT HYPHEN",
    0x034F: "COMBINING GRAPHEME JOINER",
    0x2061: "FUNCTION APPLICATION",
    0x2062: "INVISIBLE TIMES",
    0x2063: "INVISIBLE SEPARATOR",
    0x2064: "INVISIBLE PLUS",
    0x17B4: "KHMER VOWEL INHERENT AQ",
    0x17B5: "KHMER VOWEL INHERENT AA",
}
BLANK_GLYPHS = {
    0x115F: "HANGUL CHOSEONG FILLER",
    0x1160: "HANGUL JUNGSEONG FILLER",
    0x3164: "HANGUL FILLER",
    0xFFA0: "HALFWIDTH HANGUL FILLER",
    0x2800: "BRAILLE PATTERN BLANK",
}
BIDI_CONTROLS = {
    0x202A: "LEFT-TO-RIGHT EMBEDDING (LRE)",
    0x202B: "RIGHT-TO-LEFT EMBEDDING (RLE)",
    0x202C: "POP DIRECTIONAL FORMATTING (PDF)",
    0x202D: "LEFT-TO-RIGHT OVERRIDE (LRO)",
    0x202E: "RIGHT-TO-LEFT OVERRIDE (RLO)",
    0x2066: "LEFT-TO-RIGHT ISOLATE (LRI)",
    0x2067: "RIGHT-TO-LEFT ISOLATE (RLI)",
    0x2068: "FIRST STRONG ISOLATE (FSI)",
    0x2069: "POP DIRECTIONAL ISOLATE (PDI)",
}
BIDI_MARKS = {
    0x200E: "LEFT-TO-RIGHT MARK",
    0x200F: "RIGHT-TO-LEFT MARK",
    0x061C: "ARABIC LETTER MARK",
}

SHORT = {
    0x200B: "ZWSP", 0x200C: "ZWNJ", 0x200D: "ZWJ", 0x2060: "WJ", 0xFEFF: "BOM",
    0x00AD: "SHY", 0x202A: "LRE", 0x202B: "RLE", 0x202C: "PDF", 0x202D: "LRO",
    0x202E: "RLO", 0x2066: "LRI", 0x2067: "RLI", 0x2068: "FSI", 0x2069: "PDI",
    0x200E: "LRM", 0x200F: "RLM", 0x1B: "ESC", 0x2028: "LSEP", 0x2029: "PSEP",
}


def classify(cp: int) -> Optional[str]:
    """Return a category for suspicious code points, or None for ordinary ones."""
    if cp < 0x80:
        if cp in (9, 10, 13):
            return None
        if cp == 0x1B:
            return "escape"
        if cp < 0x20 or cp == 0x7F:
            return "control"
        return None
    if cp <= 0x9F:
        return "control"
    if 0xE0000 <= cp <= 0xE007F:
        return "tag"
    if cp in BIDI_CONTROLS:
        return "bidi"
    if cp in BIDI_MARKS:
        return "bidi-mark"
    if cp in ZERO_WIDTH:
        return "zero-width"
    if cp in BLANK_GLYPHS:
        return "blank-glyph"
    if 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:
        return "variation-selector"
    if 0xE000 <= cp <= 0xF8FF or cp >= 0xF0000:
        return "private-use"
    if 0xFFF9 <= cp <= 0xFFFB:
        return "interlinear"
    if 0x206A <= cp <= 0x206F:
        return "format-control"
    if cp in (0x2028, 0x2029):
        return "line-separator"
    if 0x1D173 <= cp <= 0x1D17A:
        return "zero-width"
    return None


def cp_name(cp: int) -> str:
    for table in (ZERO_WIDTH, BLANK_GLYPHS, BIDI_CONTROLS, BIDI_MARKS):
        if cp in table:
            return table[cp]
    if 0xE0000 <= cp <= 0xE007F:
        inner = cp - 0xE0000
        if 0x20 <= inner <= 0x7E:
            return "TAG %r" % chr(inner)
        return "TAG CHARACTER"
    try:
        return unicodedata.name(chr(cp))
    except ValueError:
        return "U+%04X" % cp


def short_label(cp: int) -> str:
    if cp in SHORT:
        return SHORT[cp]
    if 0xE0000 <= cp <= 0xE007F:
        return "TAG"
    if 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:
        return "VS"
    if cp < 0x20 or 0x7F <= cp <= 0x9F:
        return "CTRL"
    return ""


def is_emoji_like(cp: int) -> bool:
    return (
        cp >= 0x1F000 and cp <= 0x1FAFF
        or 0x2600 <= cp <= 0x27BF
        or 0x2300 <= cp <= 0x23FF
        or 0x2B00 <= cp <= 0x2BFF
        or 0x2190 <= cp <= 0x21FF
        or cp in (0x00A9, 0x00AE, 0x203C, 0x2049, 0x2122, 0x2139, 0x3030, 0x303D, 0x3297, 0x3299, 0x20E3)
        or 0x1F3FB <= cp <= 0x1F3FF
    )
