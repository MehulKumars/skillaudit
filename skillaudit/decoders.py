"""Find encoded blobs, decode them (never execute), and hand back text for re-scanning.

Supported layers: base64 / base64url / base32, hex (plain, \\x, 0x-arrays),
\\u / octal escapes, %-encoding, char-code arrays (fromCharCode, chr(), [char]),
reversed literals, ROT13, PowerShell -EncodedCommand (UTF-16LE), and gzip /
zlib / bz2 / lzma wrapped payloads. Decoding is bounded in size and depth.
"""
from __future__ import annotations

import base64
import binascii
import bz2
import codecs
import gzip
import lzma
import re
import zlib
from dataclasses import dataclass
from typing import Iterator, List, Optional
from urllib.parse import unquote_to_bytes

from .filetypes import sniff_magic

MAX_CANDIDATES = 400
MAX_DECODED_TOTAL = 4_000_000
MAX_DECOMPRESS = 2_000_000

B64_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=_-])")
B64URL_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9_-]{32,}={0,2}(?![A-Za-z0-9+/=_-])")
B32_RE = re.compile(r"(?<![A-Z2-7=])[A-Z2-7]{24,}={0,6}(?![A-Z2-7=])")
HEX_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){16,}(?![0-9A-Fa-f])")
XHEX_RE = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){8,}")
UESC_RE = re.compile(r"(?:\\u[0-9A-Fa-f]{4}){6,}")
OCT_RE = re.compile(r"(?:\\[0-7]{3}){8,}")
PCT_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){8,}")
BYTEARR_RE = re.compile(r"(?:0x[0-9A-Fa-f]{2}\s*,\s*){8,}0x[0-9A-Fa-f]{2}")
DECARR_RE = re.compile(r"[\[(]\s*(?:\d{1,3}\s*,\s*){8,}\d{1,3}\s*[\])]")
FROMCHAR_RE = re.compile(r"fromCharCode\s*\(\s*((?:\d{1,6}\s*,\s*){3,}\d{1,6})\s*\)", re.I)
CHR_CHAIN_RE = re.compile(r"(?:chr\(\s*\d{1,6}\s*\)\s*\+\s*){3,}chr\(\s*\d{1,6}\s*\)")
PSCHAR_RE = re.compile(r"(?:\[char\]\s*\d{1,6}\s*[+,]\s*){3,}\[char\]\s*\d{1,6}", re.I)
REV_PY_RE = re.compile(r"([\"'])([^\"'\n]{8,})\1\s*\[\s*::\s*-1\s*\]")
REV_JS_RE = re.compile(r"([\"'])([^\"'\n]{8,})\1\s*\.split\(\s*['\"]{2}\s*\)\.reverse\(\)\.join\(\s*['\"]{2}\s*\)")
ROT13_RE = re.compile(r"codecs\.(?:decode|encode)\(\s*([\"'])(.{4,}?)\1\s*,\s*[\"']rot[_-]?13[\"']", re.I)
PS_ENC_RE = re.compile(r"\s[-/](?:e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s+([A-Za-z0-9+/=]{16,})", re.I)

DECODE_CONTEXT = re.compile(r"b64decode|base64|atob|frombase64string|decode|unhexlify|fromhex|b32decode|-enc", re.I)


@dataclass
class Decoded:
    method: str
    offset: int
    text: str
    raw_len: int
    binary_magic: str = ""
    note: str = ""


def _printable(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for c in s if c.isprintable() or c in "\r\n\t")
    return ok / len(s)


def _bytes_to_text(data: bytes) -> Optional[str]:
    """Interpret decoded bytes as text if plausible (utf-8, then utf-16le)."""
    if not data:
        return None
    if data.count(0) > len(data) // 4 and len(data) >= 8:
        try:
            s = data.decode("utf-16-le")
            if _printable(s) > 0.95:
                return s
        except UnicodeDecodeError:
            pass
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if _printable(s) > 0.92 and sum(c.isalnum() for c in s) >= len(s) * 0.35:
        return s
    return None


def _decompress(data: bytes) -> Optional[bytes]:
    try:
        if data[:2] == b"\x1f\x8b":
            return gzip.GzipFile(fileobj=__import__("io").BytesIO(data)).read(MAX_DECOMPRESS)
        if data[:1] == b"\x78" and len(data) > 2 and (data[0] * 256 + data[1]) % 31 == 0:
            d = zlib.decompressobj()
            return d.decompress(data, MAX_DECOMPRESS)
        if data[:3] == b"BZh":
            return bz2.BZ2Decompressor().decompress(data, MAX_DECOMPRESS)
        if data[:6] == b"\xfd7zXZ\x00":
            return lzma.LZMADecompressor().decompress(data, MAX_DECOMPRESS)
    except Exception:
        return None
    try:  # raw deflate (no header) - common in obfuscated JS/Python
        d = zlib.decompressobj(-15)
        out = d.decompress(data, MAX_DECOMPRESS)
        if out and _bytes_to_text(out):
            return out
    except Exception:
        pass
    return None


def _from_bytes(method: str, offset: int, data: bytes, raw_len: int) -> Optional[Decoded]:
    magic = sniff_magic(data[:4096])
    if magic in ("gzip", "bzip2", "xz") or data[:1] == b"\x78":
        inner = _decompress(data)
        if inner:
            t = _bytes_to_text(inner)
            if t:
                return Decoded(method + "+" + (magic or "zlib"), offset, t, raw_len)
            m2 = sniff_magic(inner[:4096])
            if m2:
                return Decoded(method + "+" + (magic or "zlib"), offset, "", raw_len, binary_magic=m2)
    t = _bytes_to_text(data)
    if t is not None:
        return Decoded(method, offset, t, raw_len)
    if magic and magic not in ("shebang",):
        return Decoded(method, offset, "", raw_len, binary_magic=magic)
    return None


def _b64(s: str, urlsafe: bool = False) -> Optional[bytes]:
    s = s.rstrip("=")
    pad = "=" * (-len(s) % 4)
    try:
        if urlsafe:
            return base64.urlsafe_b64decode(s + pad)
        return base64.b64decode(s + pad, validate=True)
    except (binascii.Error, ValueError):
        return None


def find_encoded(text: str) -> Iterator[Decoded]:
    total = 0
    count = 0
    seen = set()

    def emit(d: Optional[Decoded]):
        nonlocal total, count
        if d is None:
            return None
        key = (d.method.split("+")[0], d.offset)
        if key in seen:
            return None
        seen.add(key)
        count += 1
        total += len(d.text)
        return d

    def budget() -> bool:
        return count < MAX_CANDIDATES and total < MAX_DECODED_TOTAL

    # PowerShell -EncodedCommand: UTF-16LE base64
    for m in PS_ENC_RE.finditer(text):
        if not budget():
            return
        raw = _b64(m.group(1))
        if raw:
            d = emit(_from_bytes("powershell-encodedcommand", m.start(1), raw, len(m.group(1))))
            if d:
                yield d

    for rx, urlsafe, name, minlen in ((B64_RE, False, "base64", 24), (B64URL_RE, True, "base64url", 32)):
        for m in rx.finditer(text):
            if not budget():
                return
            s = m.group(0)
            if len(s) < minlen:
                continue
            if name == "base64url" and not re.search(r"[-_]", s):
                continue  # plain alnum already handled by base64
            if s.isdigit() or s.isalpha() and (s.islower() or s.isupper()):
                continue  # words, numbers
            if re.fullmatch(r"[0-9a-fA-F]+", s):
                continue  # hex, handled below
            raw = _b64(s, urlsafe)
            if not raw or len(raw) < 12:
                continue
            d = emit(_from_bytes(name, m.start(), raw, len(s)))
            if d:
                yield d

    if "b32decode" in text.lower():
        for m in B32_RE.finditer(text):
            if not budget():
                return
            try:
                raw = base64.b32decode(m.group(0) + "=" * (-len(m.group(0)) % 8))
            except (binascii.Error, ValueError):
                continue
            d = emit(_from_bytes("base32", m.start(), raw, len(m.group(0))))
            if d:
                yield d

    for m in HEX_RE.finditer(text):
        if not budget():
            return
        s = m.group(0)
        if len(s) in (32, 40, 56, 64, 96, 128) and not DECODE_CONTEXT.search(text[max(0, m.start() - 80):m.start()]):
            continue  # looks like a hash digest
        d = emit(_from_bytes("hex", m.start(), bytes.fromhex(s), len(s)))
        if d:
            yield d

    simple = (
        (XHEX_RE, "hex-escapes", lambda s: bytes(int(x, 16) for x in re.findall(r"\\x([0-9A-Fa-f]{2})", s))),
        (OCT_RE, "octal-escapes", lambda s: bytes(int(x, 8) & 0xFF for x in re.findall(r"\\([0-7]{3})", s))),
        (PCT_RE, "url-encoding", lambda s: unquote_to_bytes(s)),
        (BYTEARR_RE, "byte-array", lambda s: bytes(int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", s))),
    )
    for rx, name, fn in simple:
        for m in rx.finditer(text):
            if not budget():
                return
            try:
                raw = fn(m.group(0))
            except ValueError:
                continue
            d = emit(_from_bytes(name, m.start(), raw, len(m.group(0))))
            if d:
                yield d
            elif name == "byte-array" and len(raw) >= 64:
                yield Decoded(name, m.start(), "", len(m.group(0)), note="non-text byte array (%d bytes)" % len(raw))

    for m in UESC_RE.finditer(text):
        if not budget():
            return
        try:
            s = "".join(chr(int(x, 16)) for x in re.findall(r"\\u([0-9A-Fa-f]{4})", m.group(0)))
        except ValueError:
            continue
        if _printable(s) > 0.9:
            d = emit(Decoded("unicode-escapes", m.start(), s, len(m.group(0))))
            if d:
                yield d

    def codes_to_text(nums: List[int]) -> Optional[str]:
        try:
            s = "".join(chr(n) for n in nums)
        except (ValueError, OverflowError):
            return None
        return s if _printable(s) > 0.9 else None

    for rx, name in ((FROMCHAR_RE, "fromCharCode"), (CHR_CHAIN_RE, "chr-chain"), (PSCHAR_RE, "ps-char-cast"),
                     (DECARR_RE, "decimal-array")):
        for m in rx.finditer(text):
            if not budget():
                return
            nums = [int(x) for x in re.findall(r"\d{1,6}", m.group(1) if name == "fromCharCode" else m.group(0))]
            if name == "decimal-array" and not all(9 <= n <= 126 for n in nums):
                continue
            s = codes_to_text(nums)
            if s and sum(c.isalpha() for c in s) >= len(s) * 0.4:
                d = emit(Decoded(name, m.start(), s, len(m.group(0))))
                if d:
                    yield d

    for rx, name in ((REV_PY_RE, "reversed-string"), (REV_JS_RE, "reversed-string")):
        for m in rx.finditer(text):
            if not budget():
                return
            d = emit(Decoded(name, m.start(), m.group(2)[::-1], len(m.group(0))))
            if d:
                yield d

    for m in ROT13_RE.finditer(text):
        if not budget():
            return
        d = emit(Decoded("rot13", m.start(), codecs.decode(m.group(2), "rot13"), len(m.group(0))))
        if d:
            yield d


CODE_HINT = re.compile(r"https?://|\|\s*\w|;\s*\w|\$\(|`|\bimport\b|\bfunction\b|\bcurl\b|\bwget\b|\beval\b|\bexec\b|"
                       r"\bpowershell\b|\bbash\b|/bin/|\bsubprocess\b|\brequire\(|\bsocket\b|\bchmod\b|\.sh\b|\.exe\b",
                       re.I)


def looks_like_code(s: str) -> bool:
    return bool(CODE_HINT.search(s))
