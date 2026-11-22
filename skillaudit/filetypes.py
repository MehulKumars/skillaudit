"""File-type detection: magic bytes, text decoding, language kind, entropy."""
from __future__ import annotations

import math
import os
import re
from collections import Counter
from typing import Optional, Tuple

# --------------------------------------------------------------------------
# Magic bytes
# --------------------------------------------------------------------------

EXECUTABLE_MAGICS = {"pe", "elf", "macho", "macho-fat", "mz-dos", "wasm", "java-class", "pyc"}
ARCHIVE_MAGICS = {"zip", "gzip", "bzip2", "xz", "tar", "7z", "rar", "cab", "zstd", "lz4", "xar", "ar", "iso", "dmg", "lzma"}
OPENABLE_ARCHIVES = {"zip", "gzip", "bzip2", "xz", "tar", "lzma"}
MEDIA_MAGICS = {"png", "jpeg", "gif", "webp", "bmp", "ico", "tiff", "mp4", "mp3", "wav", "ogg", "flac", "webm", "avi", "woff", "woff2", "ttf", "otf"}
DOCUMENT_MAGICS = {"pdf", "ole", "rtf"}


def sniff_magic(head: bytes, tail: bytes = b"") -> str:
    """Identify a file by its leading (and sometimes trailing) bytes."""
    if not head:
        return "empty"
    h = head
    if h.startswith(b"MZ"):
        if len(h) >= 0x40:
            off = int.from_bytes(h[0x3C:0x40], "little")
            if 0 < off < len(h) - 4 and h[off:off + 4] == b"PE\x00\x00":
                return "pe"
        return "mz-dos"
    if h.startswith(b"\x7fELF"):
        return "elf"
    if h[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macho"
    if h[:4] == b"\xca\xfe\xba\xbe" and len(h) >= 8:
        return "macho-fat" if int.from_bytes(h[4:8], "big") < 64 else "java-class"
    if h.startswith(b"\x00asm"):
        return "wasm"
    if h.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if h.startswith(b"\x1f\x8b"):
        return "gzip"
    if h.startswith(b"BZh"):
        return "bzip2"
    if h.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if h.startswith(b"\x5d\x00\x00"):
        return "lzma"
    if h.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if h.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if h.startswith(b"MSCF"):
        return "cab"
    if h.startswith(b"\x28\xb5\x2f\xfd"):
        return "zstd"
    if h.startswith(b"\x04\x22\x4d\x18"):
        return "lz4"
    if h.startswith(b"xar!"):
        return "xar"
    if h.startswith(b"!<arch>\n"):
        return "ar"
    if len(h) > 262 and h[257:262] == b"ustar":
        return "tar"
    if len(h) > 0x8006 and h[0x8001:0x8006] == b"CD001":
        return "iso"
    if h.startswith(b"%PDF"):
        return "pdf"
    if h.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if h.startswith(b"{\\rtf"):
        return "rtf"
    if h.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if h.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if h.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if h.startswith(b"RIFF") and h[8:12] == b"WEBP":
        return "webp"
    if h.startswith(b"RIFF") and h[8:12] == b"WAVE":
        return "wav"
    if h.startswith(b"RIFF") and h[8:12] == b"AVI ":
        return "avi"
    if h.startswith(b"BM") and len(h) > 14 and int.from_bytes(h[2:6], "little") > 14:
        return "bmp"
    if h.startswith(b"\x00\x00\x01\x00"):
        return "ico"
    if h.startswith((b"II*\x00", b"MM\x00*")):
        return "tiff"
    if h[4:8] == b"ftyp":
        return "mp4"
    if h.startswith(b"ID3") or h[:2] in (b"\xff\xfb", b"\xff\xf3"):
        return "mp3"
    if h.startswith(b"OggS"):
        return "ogg"
    if h.startswith(b"fLaC"):
        return "flac"
    if h.startswith(b"\x1a\x45\xdf\xa3"):
        return "webm"
    if h.startswith(b"wOFF"):
        return "woff"
    if h.startswith(b"wOF2"):
        return "woff2"
    if h.startswith((b"\x00\x01\x00\x00\x00", b"OTTO")):
        return "ttf"
    if h.startswith(b"SQLite format 3\x00"):
        return "sqlite"
    if h.startswith(b"\x4c\x00\x00\x00\x01\x14\x02\x00"):
        return "lnk"
    if h.startswith(b"ITSF"):
        return "chm"
    if h.startswith(b"\x00\x00\x00\x01Bud1"):
        return "ds_store"
    if h[:1] == b"\x80" and len(h) > 2 and h[1:2] in (b"\x02", b"\x03", b"\x04", b"\x05"):
        return "pickle"
    if tail and len(tail) >= 512 and tail[-512:-508] == b"koly":
        return "dmg"
    if h.startswith(b"#!"):
        return "shebang"
    return ""


def is_pyc(head: bytes, name: str) -> bool:
    return name.lower().endswith((".pyc", ".pyo")) and len(head) >= 16 and head[2:4] == b"\r\n"


# --------------------------------------------------------------------------
# Text decoding
# --------------------------------------------------------------------------

_BOMS = (
    (b"\xef\xbb\xbf", "utf-8", "utf-8-bom"),
    (b"\xff\xfe\x00\x00", "utf-32-le", "utf-32-le-bom"),
    (b"\x00\x00\xfe\xff", "utf-32-be", "utf-32-be-bom"),
    (b"\xff\xfe", "utf-16-le", "utf-16-le-bom"),
    (b"\xfe\xff", "utf-16-be", "utf-16-be-bom"),
)


def _control_ratio(text: str) -> float:
    sample = text[:8192]
    if not sample:
        return 0.0
    bad = sum(1 for c in sample if (ord(c) < 32 and c not in "\t\n\r\f\x1b") or ord(c) == 0xFFFD)
    return bad / len(sample)


def decode_text(data: bytes) -> Tuple[Optional[str], str]:
    """Return (text, encoding) or (None, 'binary')."""
    if not data:
        return "", "empty"
    for bom, codec, label in _BOMS:
        if data.startswith(bom):
            try:
                body = data[len(bom):]
                if codec.startswith("utf-16") and len(body) % 2:
                    body = body[:-1]
                text = body.decode(codec)
                if _control_ratio(text) < 0.05:
                    return text, label
            except UnicodeDecodeError:
                pass
            break
    sample = data[:8192]
    if b"\x00" in sample:
        half = max(1, len(sample) // 2)
        even_zero = sample[0::2].count(0) / half
        odd_zero = sample[1::2].count(0) / half
        codec = None
        if odd_zero > 0.35 and even_zero < 0.05:
            codec = "utf-16-le"
        elif even_zero > 0.35 and odd_zero < 0.05:
            codec = "utf-16-be"
        if codec:
            body = data if len(data) % 2 == 0 else data[:-1]
            try:
                text = body.decode(codec)
                if _control_ratio(text) < 0.05:
                    return text, codec + " (no BOM)"
            except UnicodeDecodeError:
                pass
        return None, "binary"
    try:
        text = data.decode("utf-8")
        if _control_ratio(text) < 0.05:
            return text, "utf-8"
        return None, "binary"
    except UnicodeDecodeError as e:
        if e.start >= len(data) - 4:  # multibyte char cut off by the read cap
            try:
                return data[:e.start].decode("utf-8"), "utf-8"
            except UnicodeDecodeError:
                pass
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13)) / len(sample)
    if printable > 0.92:
        return data.decode("cp1252", errors="replace"), "cp1252 (fallback)"
    return None, "binary"


# --------------------------------------------------------------------------
# Language / kind detection
# --------------------------------------------------------------------------

EXT_KIND = {
    ".md": "markdown", ".markdown": "markdown", ".mdx": "markdown", ".mdc": "markdown", ".mkd": "markdown",
    ".txt": "text", ".rst": "text", ".adoc": "text", ".org": "text", ".log": "text", ".csv": "data", ".tsv": "data",
    ".py": "python", ".pyw": "python", ".pyi": "python", ".pyx": "python",
    ".ipynb": "notebook",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "javascript", ".tsx": "javascript", ".mts": "javascript", ".cts": "javascript", ".vue": "javascript",
    ".svelte": "javascript",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".ksh": "shell", ".fish": "shell", ".command": "shell",
    ".tool": "shell", ".csh": "shell",
    ".ps1": "powershell", ".psm1": "powershell", ".psd1": "powershell", ".ps1xml": "powershell",
    ".bat": "batch", ".cmd": "batch",
    ".vbs": "vbscript", ".vbe": "vbscript", ".wsf": "vbscript", ".wsh": "vbscript", ".vba": "vbscript", ".bas": "vbscript",
    ".hta": "html", ".html": "html", ".htm": "html", ".xhtml": "html", ".shtml": "html",
    ".svg": "svg", ".xml": "xml", ".plist": "xml", ".xsl": "xml", ".xslt": "xml", ".rels": "xml",
    ".json": "json", ".jsonc": "json", ".json5": "json", ".jsonl": "json", ".geojson": "json",
    ".yaml": "yaml", ".yml": "yaml", ".toml": "toml", ".lock": "data",
    ".ini": "config", ".cfg": "config", ".conf": "config", ".env": "config", ".properties": "config", ".editorconfig": "config",
    ".rb": "ruby", ".erb": "ruby", ".pl": "perl", ".pm": "perl", ".php": "php", ".phtml": "php",
    ".go": "go", ".rs": "rust", ".lua": "lua", ".java": "java", ".kt": "java", ".kts": "java", ".scala": "java",
    ".groovy": "java", ".gradle": "java", ".c": "c-family", ".h": "c-family", ".cpp": "c-family", ".cc": "c-family",
    ".hpp": "c-family", ".cs": "c-family", ".m": "c-family", ".mm": "c-family", ".swift": "c-family", ".dart": "c-family",
    ".r": "r", ".jl": "julia", ".ex": "elixir", ".exs": "elixir", ".applescript": "applescript",
    ".css": "css", ".scss": "css", ".less": "css", ".sql": "sql", ".tf": "config", ".hcl": "config",
    ".reg": "registry", ".inf": "config", ".desktop": "config", ".service": "config", ".timer": "config",
    ".url": "config", ".mk": "makefile",
}

NAME_KIND = {
    "makefile": "makefile", "gnumakefile": "makefile", "dockerfile": "dockerfile", "containerfile": "dockerfile",
    ".envrc": "shell", ".bashrc": "shell", ".zshrc": "shell", ".profile": "shell", ".bash_profile": "shell",
    ".zprofile": "shell", "justfile": "makefile", "rakefile": "ruby", "gemfile": "ruby", "vagrantfile": "ruby",
    "procfile": "config", ".gitconfig": "config", "config": "config", ".npmrc": "config", ".pypirc": "config",
    ".netrc": "config", "requirements.txt": "requirements", ".gitattributes": "config", ".gitmodules": "config",
}

SCRIPT_KINDS = {
    "python", "javascript", "shell", "powershell", "batch", "vbscript", "ruby", "perl", "php", "go", "rust",
    "lua", "java", "c-family", "applescript", "makefile", "dockerfile", "notebook", "html", "svg", "r", "julia",
    "elixir", "registry",
}
DOC_KINDS = {"markdown", "text"}
CONFIG_KINDS = {"json", "yaml", "toml", "config", "xml", "requirements", "data", "css", "sql"}

SHEBANG_KIND = (
    (re.compile(rb"python"), "python"), (re.compile(rb"node|deno|bun"), "javascript"),
    (re.compile(rb"pwsh|powershell"), "powershell"), (re.compile(rb"perl"), "perl"),
    (re.compile(rb"ruby"), "ruby"), (re.compile(rb"osascript"), "applescript"), (re.compile(rb"php"), "php"),
    (re.compile(rb"(ba|z|k|da|fi|c|tc)?sh\b"), "shell"),
)


def kind_for(name: str, magic: str, head: bytes, is_text: bool) -> str:
    base = os.path.basename(name).lower()
    ext = os.path.splitext(base)[1]
    if magic and magic not in ("shebang", "empty"):
        return magic
    if is_text and head.startswith(b"#!"):
        first = head.split(b"\n", 1)[0]
        for rx, kind in SHEBANG_KIND:
            if rx.search(first):
                return kind
        return "shell"
    if base in NAME_KIND:
        return NAME_KIND[base]
    if base.startswith("requirements") and ext == ".txt":
        return "requirements"
    if ext in EXT_KIND:
        return EXT_KIND[ext]
    if base.startswith(".env"):
        return "config"
    if is_text:
        sniff = head[:2048].lstrip().lower()
        if sniff.startswith(b"<svg") or b"<svg" in sniff[:400]:
            return "svg"
        if sniff.startswith((b"<!doctype html", b"<html")):
            return "html"
        if sniff.startswith(b"<?xml"):
            return "xml"
        if sniff.startswith((b"{", b"[")):
            return "json"
        return "text"
    return "binary"


def surface_for(kind: str, base: str) -> str:
    if base.lower() == "skill.md" or kind in DOC_KINDS:
        return "agent-instructions"
    if kind in SCRIPT_KINDS:
        return "executable-code"
    if kind in CONFIG_KINDS:
        return "config"
    if kind in EXECUTABLE_MAGICS:
        return "binary-executable"
    if kind in ARCHIVE_MAGICS:
        return "archive"
    if kind in MEDIA_MAGICS:
        return "media"
    if kind in DOCUMENT_MAGICS:
        return "document"
    return "other"


# Extensions whose content must match a specific magic
EXT_EXPECT = {
    ".png": {"png"}, ".jpg": {"jpeg"}, ".jpeg": {"jpeg"}, ".gif": {"gif"}, ".webp": {"webp"},
    ".bmp": {"bmp"}, ".ico": {"ico", "png"}, ".tif": {"tiff"}, ".tiff": {"tiff"},
    ".pdf": {"pdf"}, ".zip": {"zip"}, ".skill": {"zip"}, ".jar": {"zip"}, ".whl": {"zip"}, ".docx": {"zip"},
    ".xlsx": {"zip"}, ".pptx": {"zip"}, ".odt": {"zip"}, ".apk": {"zip"}, ".vsix": {"zip"}, ".nupkg": {"zip"},
    ".gz": {"gzip"}, ".tgz": {"gzip"}, ".bz2": {"bzip2"}, ".xz": {"xz"}, ".7z": {"7z"}, ".rar": {"rar"},
    ".tar": {"tar"}, ".exe": {"pe", "mz-dos"}, ".dll": {"pe"}, ".mp4": {"mp4"}, ".mp3": {"mp3"},
    ".wav": {"wav"}, ".woff": {"woff"}, ".woff2": {"woff2"}, ".ttf": {"ttf"}, ".otf": {"ttf"},
    ".wasm": {"wasm"}, ".class": {"java-class"}, ".sqlite": {"sqlite"}, ".db": {"sqlite", ""},
    ".doc": {"ole"}, ".xls": {"ole"}, ".ppt": {"ole"}, ".msi": {"ole"}, ".lnk": {"lnk"}, ".chm": {"chm"},
}
TEXT_EXTS = {e for e, k in EXT_KIND.items()} | {".txt"}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def str_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


_ASCII_STR = re.compile(rb"[\x20-\x7e\t]{6,}")
_UTF16_STR = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")


def extract_strings(data: bytes, limit: int = 2_000_000) -> str:
    """Printable ASCII and UTF-16LE strings from binary data (like `strings`)."""
    data = data[:limit]
    out = [m.group(0).decode("ascii", "replace") for m in _ASCII_STR.finditer(data)]
    out += [m.group(0).decode("utf-16-le", "replace") for m in _UTF16_STR.finditer(data)]
    return "\n".join(out)
