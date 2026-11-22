"""Binary formats and archives - inspected in memory, never executed or extracted to disk."""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import pickletools
import re
import stat
import tarfile
import zipfile
import zlib
from typing import List, Optional, Tuple

from .filetypes import entropy, extract_strings, sniff_magic
from .model import Finding, TextUnit
from .rules import CATEGORY_INFO
from .sanitize import visible
from .unicode_checks import INSTRUCTION_WORDS
from .walker import Entry

EXECUTABLE = {"pe", "elf", "macho", "macho-fat", "mz-dos"}
UNSCANNABLE_ARCHIVES = {"7z", "rar", "cab", "zstd", "lz4", "xar", "iso", "dmg", "ar"}


def _refs(cat):
    return list(CATEGORY_INFO.get(cat, ("", []))[1])


def F(rid, title, sev, cat, path, message, evidence=(), conf="high", caps=(), tags=(), origin="format") -> Finding:
    return Finding(rule_id=rid, title=title, severity=sev, category=cat, path=path, confidence=conf, message=message,
                   evidence=list(evidence), origin=origin, references=_refs(cat), capabilities=list(caps),
                   tags=list(tags))


class Limits:
    def __init__(self, member_cap: int = 50_000_000, total_cap: int = 500_000_000, max_members: int = 20000):
        self.member_cap = member_cap
        self.total_cap = total_cap
        self.max_members = max_members
        self.used = 0


def _bad_member_path(name: str) -> str:
    n = name.replace("\\", "/")
    if n.startswith("/") or re.match(r"^[A-Za-z]:", n):
        return "absolute path"
    if any(part == ".." for part in n.split("/")):
        return "parent-directory traversal (..)"
    return ""


# ---------------------------------------------------------------------- archives

def open_archive(path: str, data: bytes, magic: str, depth: int, limits: Limits) -> Tuple[List[Finding], List[Entry]]:
    findings: List[Finding] = []
    entries: List[Entry] = []
    if magic in UNSCANNABLE_ARCHIVES:
        findings.append(F("ARC-UNSCANNABLE", "Archive format that cannot be inspected offline (%s)" % magic, "high",
                          "archive", path, "Contents are invisible to this scanner. Unpack it in an isolated "
                          "environment and scan the extracted folder.", caps=("obfuscation",)))
        return findings, entries
    try:
        if magic == "zip":
            return _zip(path, data, depth, limits)
        if magic == "tar":
            return _tar(path, data, depth, limits)
        if magic in ("gzip", "bzip2", "xz", "lzma"):
            return _single(path, data, magic, depth, limits)
    except Exception as exc:  # crafted / corrupt archives
        findings.append(F("ARC-PARSE-ERROR", "Archive could not be fully parsed", "medium", "archive", path,
                          "%s: %s. Corrupt or deliberately malformed archives can hide content from scanners."
                          % (type(exc).__name__, visible(str(exc), 200))))
    return findings, entries


def _member_entry(container: str, name: str, data: Optional[bytes], size: int, depth: int, **meta) -> Entry:
    rel = "%s!/%s" % (container, name.lstrip("/"))
    e = Entry(relpath=rel, size=size, data=data, container=container, depth=depth)
    e.meta.update(meta)
    return e


def _zip(path: str, data: bytes, depth: int, limits: Limits) -> Tuple[List[Finding], List[Entry]]:
    findings: List[Finding] = []
    entries: List[Entry] = []
    zf = zipfile.ZipFile(io.BytesIO(data))
    infos = zf.infolist()
    names = [i.filename for i in infos]
    if len(set(names)) != len(names):
        dups = sorted({n for n in names if names.count(n) > 1})[:10]
        findings.append(F("ARC-DUPLICATE-MEMBERS", "Duplicate member names in archive", "high", "archive", path,
                          "Different extractors pick different copies: %s" % ", ".join(visible(d) for d in dups)))
    if infos and min(i.header_offset for i in infos) > 0:
        findings.append(F("ARC-PREPENDED-DATA", "Data before the first archive entry (polyglot / SFX)", "medium",
                          "archive", path, "%d bytes precede the zip data." % min(i.header_offset for i in infos)))
    if zf.comment:
        findings.append(F("ARC-ZIP-COMMENT", "Archive comment present", "low", "archive", path,
                          visible(zf.comment.decode("utf-8", "replace"), 300)))
    encrypted = []
    is_office = "[Content_Types].xml" in names
    for idx, info in enumerate(infos):
        if idx >= limits.max_members:
            findings.append(F("ARC-TOO-MANY-MEMBERS", "Archive member limit reached", "medium", "archive", path,
                              "Only the first %d members were scanned." % limits.max_members))
            break
        name = info.filename
        why = _bad_member_path(name)
        if why:
            findings.append(F("ARC-PATH-TRAVERSAL", "Archive member path escapes the extraction folder (zip-slip)",
                              "high", "archive", path, "%s: %s" % (why, visible(name, 200))))
        # local header name vs central directory name
        off = info.header_offset
        if data[off:off + 4] == b"PK\x03\x04":
            nlen = int.from_bytes(data[off + 26:off + 28], "little")
            local = data[off + 30:off + 30 + nlen]
            try:
                local_name = local.decode("utf-8" if info.flag_bits & 0x800 else "cp437")
            except UnicodeDecodeError:
                local_name = local.decode("latin-1")
            if local_name != name and local_name.replace("\\", "/") != name:
                findings.append(F("ARC-HEADER-MISMATCH", "Local header name differs from central directory", "high",
                                  "archive", path, "central '%s' vs local '%s' - a scanner/extractor confusion trick."
                                  % (visible(name, 120), visible(local_name, 120))))
        unix_mode = (info.external_attr >> 16) & 0xFFFF
        if info.flag_bits & 0x1:
            encrypted.append(name)
            entries.append(_member_entry(path, name, None, info.file_size, depth, encrypted=True, unix_mode=unix_mode))
            continue
        if info.is_dir():
            e = _member_entry(path, name.rstrip("/"), None, 0, depth, unix_mode=unix_mode)
            e.is_dir = True
            entries.append(e)
            continue
        ratio = info.file_size / max(1, info.compress_size)
        if ratio > 100 and info.file_size > 20_000_000:
            findings.append(F("ARC-COMPRESSION-BOMB", "Extreme compression ratio (decompression bomb)", "high", "archive",
                              path, "%s: %d bytes -> %d bytes (x%d)" % (visible(name), info.compress_size,
                                                                        info.file_size, ratio)))
        if limits.used >= limits.total_cap:
            findings.append(F("ARC-BUDGET-EXHAUSTED", "Archive scan budget exhausted", "medium", "archive", path,
                              "Remaining members were not read."))
            break
        cap = min(limits.member_cap, limits.total_cap - limits.used)
        try:
            with zf.open(info) as fh:
                content = fh.read(cap + 1)
        except (NotImplementedError, RuntimeError, zipfile.BadZipFile, zlib.error, EOFError, OSError) as exc:
            findings.append(F("ARC-MEMBER-UNREADABLE", "Archive member could not be read", "medium", "archive", path,
                              "%s: %s" % (visible(name), visible(str(exc), 160))))
            continue
        partial = len(content) > cap
        content = content[:cap]
        limits.used += len(content)
        if stat.S_ISLNK(unix_mode):
            e = _member_entry(path, name, None, info.file_size, depth, unix_mode=unix_mode)
            e.is_link = True
            e.link_target = content.decode("utf-8", "replace")[:500]
            entries.append(e)
            continue
        entries.append(_member_entry(path, name, content, info.file_size, depth, unix_mode=unix_mode, partial=partial))
    if encrypted:
        findings.append(F("ARC-ENCRYPTED-MEMBERS", "Password-protected archive members", "high", "archive", path,
                          "%d encrypted member(s) cannot be scanned: %s. Encrypted archives are a classic way to "
                          "smuggle malware past scanners (ClawHavoc used passwords like 'openclaw')."
                          % (len(encrypted), ", ".join(visible(n) for n in encrypted[:8])),
                          caps=("obfuscation",)))
    if is_office:
        findings.extend(_office_checks(path, zf, names, entries))
    return findings, entries


def _office_checks(path: str, zf: zipfile.ZipFile, names: List[str], entries: List[Entry]) -> List[Finding]:
    out: List[Finding] = []
    if any(n.lower().endswith("vbaproject.bin") for n in names):
        out.append(F("BIN-OFFICE-MACROS", "Office document contains VBA macros", "high", "binary", path,
                     "vbaProject.bin present. Macros execute code when enabled.", caps=("execute",)))
    if any("activex" in n.lower() for n in names):
        out.append(F("BIN-OFFICE-ACTIVEX", "Office document contains ActiveX controls", "medium", "binary", path, ""))
    if any(n.lower().startswith(("word/embeddings/", "xl/embeddings/", "ppt/embeddings/")) for n in names):
        out.append(F("BIN-OFFICE-EMBEDDED-OBJECT", "Office document embeds objects/files", "medium", "binary", path,
                     "Embedded OLE objects or packages can carry executables."))
    allowed = re.compile(r"\.(?:xml|rels|bin|png|jpe?g|gif|emf|wmf|bmp|tiff?|svg|vml|xlsx|docx|pptx|odttf|fntdata|"
                         r"ttf|otf|wdp|jfif|txt|dat|json|mp4|mp3|wav)$|/$", re.I)
    odd = [n for n in names if not allowed.search(n) and not n.endswith("/")]
    if odd:
        out.append(F("BIN-OFFICE-UNEXPECTED-MEMBER", "Unexpected files inside an Office document", "high", "binary",
                     path, "Office files are ZIPs; these members do not belong: %s (Trail of Bits 'context-loader' "
                     "hid sync1.sh inside a .docx)." % ", ".join(visible(n) for n in odd[:10]), caps=("hidden",)))
    for e in entries:
        if e.data is not None and e.relpath.lower().endswith(".rels"):
            txt = e.data.decode("utf-8", "replace")
            for m in re.finditer(r"<Relationship\b[^>]*>", txt):
                tag = m.group(0)
                if 'TargetMode="External"' in tag:
                    typ = re.search(r'Type="[^"]*/(\w+)"', tag)
                    tgt = re.search(r'Target="([^"]*)"', tag)
                    t = typ.group(1) if typ else "?"
                    if t.lower() in ("attachedtemplate", "oleobject", "frame", "subdocument", "control", "package"):
                        out.append(F("BIN-OFFICE-REMOTE-TEMPLATE", "Office document loads a remote %s" % t, "high",
                                     "remote-exec", e.relpath, "External target: %s (remote template injection)."
                                     % visible(tgt.group(1) if tgt else "?", 300), caps=("download",)))
    return out


def office_text(member_name: str, data: bytes) -> Optional[str]:
    n = member_name.lower()
    if not (n.endswith("document.xml") or re.search(r"(slides/slide\d+|notesslides/notesslide\d+)\.xml$", n)
            or n.endswith("sharedstrings.xml") or re.search(r"(header|footer|comments|footnotes)\d*\.xml$", n)):
        return None
    txt = data.decode("utf-8", "replace")
    parts = re.findall(r"<(?:w:t|a:t|t)(?:\s[^>]*)?>([^<]*)</(?:w:t|a:t|t)>", txt)
    hidden = re.findall(r"<w:vanish/>", txt)
    out = " ".join(parts)
    if hidden:
        out = "[document contains %d hidden-text runs (w:vanish)]\n" % len(hidden) + out
    return out or None


def _tar(path: str, data: bytes, depth: int, limits: Limits) -> Tuple[List[Finding], List[Entry]]:
    findings: List[Finding] = []
    entries: List[Entry] = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        for idx, m in enumerate(tf):
            if idx >= limits.max_members:
                findings.append(F("ARC-TOO-MANY-MEMBERS", "Archive member limit reached", "medium", "archive", path, ""))
                break
            why = _bad_member_path(m.name)
            if why:
                findings.append(F("ARC-PATH-TRAVERSAL", "Archive member path escapes the extraction folder", "high",
                                  "archive", path, "%s: %s" % (why, visible(m.name, 200))))
            if m.issym() or m.islnk():
                e = _member_entry(path, m.name, None, 0, depth, unix_mode=m.mode)
                e.is_link = True
                e.link_target = m.linkname
                entries.append(e)
                continue
            if m.ischr() or m.isblk() or m.isfifo():
                e = _member_entry(path, m.name, None, 0, depth, unix_mode=m.mode)
                e.special = "device/fifo"
                entries.append(e)
                continue
            if m.isdir():
                e = _member_entry(path, m.name, None, 0, depth, unix_mode=m.mode)
                e.is_dir = True
                entries.append(e)
                continue
            if not m.isfile():
                continue
            cap = min(limits.member_cap, limits.total_cap - limits.used)
            if cap <= 0:
                findings.append(F("ARC-BUDGET-EXHAUSTED", "Archive scan budget exhausted", "medium", "archive", path, ""))
                break
            fh = tf.extractfile(m)
            content = fh.read(cap) if fh else b""
            limits.used += len(content)
            entries.append(_member_entry(path, m.name, content, m.size, depth, unix_mode=m.mode,
                                         partial=m.size > len(content)))
    return findings, entries


def _single(path: str, data: bytes, magic: str, depth: int, limits: Limits) -> Tuple[List[Finding], List[Entry]]:
    cap = min(limits.member_cap, limits.total_cap - limits.used)
    if magic == "gzip":
        content = gzip.GzipFile(fileobj=io.BytesIO(data)).read(cap)
    elif magic == "bzip2":
        content = bz2.BZ2Decompressor().decompress(data, cap)
    else:
        content = lzma.LZMADecompressor().decompress(data, cap)
    limits.used += len(content)
    inner = re.sub(r"\.(?:gz|tgz|bz2|xz|lzma)$", "", path.rsplit("/", 1)[-1], flags=re.I) or "content"
    if path.lower().endswith(".tgz"):
        inner += ".tar"
    return [], [_member_entry(path, inner, content, len(content), depth)]


# ---------------------------------------------------------------------- binaries

def analyze_binary(path: str, data: bytes, magic: str, name: str) -> Tuple[List[Finding], List[TextUnit], List[Entry]]:
    findings: List[Finding] = []
    units: List[TextUnit] = []
    subs: List[Entry] = []
    lname = name.lower()
    want_strings = False

    if magic in EXECUTABLE:
        desc = {"pe": "Windows PE executable/DLL", "elf": "Linux ELF binary", "macho": "macOS Mach-O binary",
                "macho-fat": "macOS universal binary", "mz-dos": "DOS/Windows MZ executable"}[magic]
        findings.append(F("BIN-NATIVE-EXECUTABLE", "Native executable bundled (%s)" % desc, "high", "binary", path,
                          "Skills rarely need native binaries; this code cannot be reviewed. Verify its origin and "
                          "hash, or rebuild from source.", caps=("execute",)))
        want_strings = True
    elif magic in ("java-class", "wasm"):
        findings.append(F("BIN-COMPILED-CODE", "Compiled bytecode bundled (%s)" % magic, "high", "binary", path,
                          "Compiled code cannot be reviewed as text.", caps=("execute",)))
        want_strings = True
    elif magic == "pickle" or lname.endswith((".pkl", ".pickle", ".joblib", ".dill")):
        findings.extend(_pickle(path, data))
    elif magic == "ole":
        findings.extend(_ole(path, data))
        want_strings = True
    elif magic == "pdf":
        f, u = _pdf(path, data)
        findings.extend(f)
        units.extend(u)
    elif magic in ("png", "jpeg", "gif"):
        f, u, s = _image(path, data, magic)
        findings.extend(f)
        units.extend(u)
        subs.extend(s)
    elif magic == "sqlite":
        findings.append(F("BIN-SQLITE-DATABASE", "SQLite database bundled", "medium", "binary", path,
                          "Could contain harvested data (browser stores are SQLite). Inspect its tables."))
        want_strings = True
    elif magic == "lnk":
        want_strings = True
    elif magic == "chm":
        findings.append(F("BIN-CHM", "Compiled HTML help file", "high", "binary", path, "CHM files can run scripts."))
        want_strings = True
    elif magic in ("pyc",) or lname.endswith((".pyc", ".pyo")):
        want_strings = True
    elif magic in ("", "binary") or magic not in ("mp4", "mp3", "wav", "ogg", "flac", "webm", "avi", "woff", "woff2",
                                                    "ttf", "webp", "bmp", "ico", "tiff", "ds_store"):
        ent = entropy(data[:1_000_000])
        if ent > 7.6 and len(data) > 4096:
            findings.append(F("BIN-HIGH-ENTROPY-UNKNOWN", "Unidentified high-entropy binary (encrypted / packed?)",
                              "medium", "binary", path, "Entropy %.2f bits/byte and no known file signature." % ent,
                              caps=("obfuscation",)))
        want_strings = True

    if magic in ("png", "jpeg", "gif", "webp", "bmp", "ico", "mp4", "mp3", "wav", "ttf", "woff", "woff2", "pdf"):
        poly = _polyglot(data)
        if poly:
            findings.append(F("BIN-POLYGLOT", "Media/document file contains an embedded %s signature" % poly, "high",
                              "obfuscation", path, "The file is also another file type - a common smuggling trick.",
                              caps=("obfuscation", "hidden")))

    if want_strings:
        s = extract_strings(data)
        if s:
            units.append(TextUnit(path, s, "binary-strings", origin="strings"))
    return findings, units, subs


def _polyglot(data: bytes) -> str:
    body = data[64:]
    for sig, label in ((b"PK\x03\x04", "ZIP"), (b"\x7fELF", "ELF"), (b"<script", "HTML script"),
                       (b"<?php", "PHP"), (b"#!/bin/", "shell script"), (b"#!/usr/bin/", "script")):
        if sig in body:
            if label == "ZIP" and b"PK\x01\x02" not in body:
                continue
            return label
    i = body.find(b"MZ")
    while 0 <= i < len(body) - 0x40:
        off = int.from_bytes(body[i + 0x3C:i + 0x40], "little")
        if 0 < off < 4096 and body[i + off:i + off + 4] == b"PE\x00\x00":
            return "PE executable"
        i = body.find(b"MZ", i + 2)
    return ""


DANGEROUS_PICKLE = re.compile(
    r"^(?:os|posix|nt|subprocess|builtins|__builtin__|sys|socket|shutil|runpy|importlib|pty|commands|webbrowser|"
    r"requests|urllib\w*|http\.\w+|ctypes|marshal|code|codeop|asyncio|multiprocessing|tempfile|pickle|_pickle|"
    r"dill|platform|signal|telnetlib|ftplib|smtplib)\.|\.(?:eval|exec|system|popen|spawn\w*|getattr|compile|"
    r"__import__|open|call|check_output|run|Popen|load|loads)$")


def _pickle(path: str, data: bytes) -> List[Finding]:
    imports, strings = [], []
    try:
        for op, arg, _ in pickletools.genops(io.BytesIO(data[:20_000_000])):
            if op.name in ("GLOBAL", "INST") and isinstance(arg, str):
                imports.append(arg.replace(" ", "."))
            elif op.name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "BINUNICODE8", "SHORT_BINSTRING",
                             "BINSTRING", "STRING") and isinstance(arg, (str, bytes)):
                strings.append(arg if isinstance(arg, str) else arg.decode("latin-1"))
            elif op.name == "STACK_GLOBAL" and len(strings) >= 2:
                imports.append(strings[-2] + "." + strings[-1])
            if len(imports) > 500:
                break
    except Exception:
        pass
    bad = sorted({i for i in imports if DANGEROUS_PICKLE.search(i)})
    if bad:
        return [F("BIN-PICKLE-CODE-EXEC", "Pickle file imports code-execution callables", "critical", "dynamic-exec",
                  path, "Unpickling calls: %s. Loading this file runs code." % ", ".join(visible(b) for b in bad[:10]),
                  caps=("execute",))]
    return [F("BIN-PICKLE", "Pickle / serialized Python object", "medium", "dynamic-exec", path,
              "Pickle can execute code on load. Imports referenced: %s" % (", ".join(sorted(set(imports))[:10]) or "none"),
              conf="medium", caps=("execute",))]


def _ole(path: str, data: bytes) -> List[Finding]:
    markers = [m.decode() for m in (b"_VBA_PROJECT", b"VBA", b"Macros", b"AutoOpen", b"Auto_Open", b"Document_Open",
                                    b"Workbook_Open", b"AutoExec", b"Shell", b"CreateObject", b"WScript")
               if m in data]
    if any(m in markers for m in ("_VBA_PROJECT", "Macros", "AutoOpen", "Auto_Open", "Document_Open", "Workbook_Open",
                                  "AutoExec")):
        return [F("BIN-OLE-MACROS", "Legacy Office/OLE file with macro indicators", "high", "binary", path,
                  "Markers: %s" % ", ".join(markers), caps=("execute",))]
    return [F("BIN-OLE-FILE", "Legacy OLE compound file (doc/xls/msi)", "medium", "binary", path,
              "Binary office/installer format; cannot be reviewed as text.")]


def _pdf(path: str, data: bytes) -> Tuple[List[Finding], List[TextUnit]]:
    findings: List[Finding] = []
    raw = data[:30_000_000]
    blobs = [raw]
    texts = []
    total = 0
    for k, m in enumerate(re.finditer(rb"stream\r?\n", raw)):
        if k > 400 or total > 20_000_000:
            break
        end = raw.find(b"endstream", m.end())
        if end < 0:
            break
        chunk = raw[m.end():end]
        try:
            dec = zlib.decompressobj().decompress(chunk, 2_000_000)
        except zlib.error:
            continue
        total += len(dec)
        blobs.append(dec)
    joined = b"\n".join(blobs)
    checks = (
        (rb"/JavaScript\b|/JS\b", "BIN-PDF-JAVASCRIPT", "PDF contains JavaScript", "high"),
        (rb"/Launch\b", "BIN-PDF-LAUNCH", "PDF /Launch action (runs programs)", "critical"),
        (rb"/OpenAction\b|/AA\b", "BIN-PDF-AUTO-ACTION", "PDF automatic action on open", "medium"),
        (rb"/EmbeddedFiles?\b", "BIN-PDF-EMBEDDED-FILE", "PDF embeds files", "medium"),
        (rb"/XFA\b|/RichMedia\b", "BIN-PDF-XFA-RICHMEDIA", "PDF XFA forms / rich media", "medium"),
        (rb"/SubmitForm\b|/GoToR\b|/ImportData\b", "BIN-PDF-REMOTE-ACTION", "PDF remote submit / remote go-to", "medium"),
    )
    for rx, rid, title, sev in checks:
        n = len(re.findall(rx, joined))
        if n:
            findings.append(F(rid, title, sev, "binary", path, "%d occurrence(s)." % n,
                              caps=("execute",) if sev in ("high", "critical") else ()))
    for blob in blobs[1:]:
        for m in re.finditer(rb"\(((?:\\.|[^\\)]){1,800})\)\s*T[Jj]|\[((?:[^\]]){1,4000})\]\s*TJ", blob):
            if m.group(1):
                texts.append(m.group(1).decode("latin-1"))
            else:
                texts.append("".join(re.findall(r"\(((?:\\.|[^\\)])*)\)", m.group(2).decode("latin-1"))))
            if len(texts) > 20000:
                break
    units = []
    if texts:
        units.append(TextUnit(path, " ".join(texts), "text", origin="pdf-text"))
    return findings, units


def _image(path: str, data: bytes, magic: str) -> Tuple[List[Finding], List[TextUnit], List[Entry]]:
    findings: List[Finding] = []
    texts: List[str] = []
    end = None
    if magic == "png":
        pos = 8
        while pos + 8 <= len(data):
            length = int.from_bytes(data[pos:pos + 4], "big")
            ctype = data[pos + 4:pos + 8]
            if length > len(data) - pos:
                break
            body = data[pos + 8:pos + 8 + length]
            try:
                if ctype == b"tEXt":
                    k, _, v = body.partition(b"\0")
                    texts.append("%s: %s" % (k.decode("latin-1"), v.decode("latin-1")))
                elif ctype == b"zTXt":
                    k, _, rest = body.partition(b"\0")
                    texts.append("%s: %s" % (k.decode("latin-1"),
                                             zlib.decompressobj().decompress(rest[1:], 1_000_000).decode("latin-1")))
                elif ctype == b"iTXt":
                    k, _, rest = body.partition(b"\0")
                    flag, rest = rest[0], rest[2:]
                    _, _, rest = rest.partition(b"\0")
                    _, _, txt = rest.partition(b"\0")
                    if flag:
                        txt = zlib.decompressobj().decompress(txt, 1_000_000)
                    texts.append("%s: %s" % (k.decode("latin-1"), txt.decode("utf-8", "replace")))
            except Exception:
                pass
            pos += 12 + length
            if ctype == b"IEND":
                end = pos
                break
    elif magic == "jpeg":
        pos = 2
        while pos + 4 <= len(data) and data[pos] == 0xFF:
            marker = data[pos + 1]
            if marker == 0xDA:
                break
            if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                pos += 2
                continue
            length = int.from_bytes(data[pos + 2:pos + 4], "big")
            seg = data[pos + 4:pos + 2 + length]
            if marker == 0xFE:
                texts.append(seg.decode("latin-1"))
            elif 0xE0 <= marker <= 0xEF:
                s = extract_strings(seg, 200_000)
                s = "\n".join(x for x in s.splitlines() if len(x) >= 12 and not re.fullmatch(r"[\W\d_]+", x))
                if s:
                    texts.append(s)
            pos += 2 + length
        eoi = data.rfind(b"\xff\xd9")
        if eoi > 0:
            end = eoi + 2
    elif magic == "gif":
        for m in re.finditer(rb"\x21\xfe", data):
            p = m.end()
            buf = b""
            while p < len(data) and data[p] != 0 and len(buf) < 100_000:
                n = data[p]
                buf += data[p + 1:p + 1 + n]
                p += 1 + n
            if buf:
                texts.append(buf.decode("latin-1"))
        stripped = data.rstrip(b"\x00")
        if stripped and stripped[-1:] != b";":
            end = None
    units: List[TextUnit] = []
    subs: List[Entry] = []
    meta = "\n".join(t for t in texts if t.strip())
    if meta:
        units.append(TextUnit(path, meta, "text", origin="image-metadata"))
        if INSTRUCTION_WORDS.search(meta) and len(meta) > 40:
            findings.append(F("BIN-IMAGE-METADATA-TEXT", "Image metadata contains instruction-like text", "medium",
                              "hidden-content", path, "Metadata is invisible in image viewers but readable by tools "
                              "and multimodal agents.", [visible(meta, 400)], caps=("hidden",), tags=("hidden",)))
    if end is not None and end < len(data):
        trailing = data[end:]
        if len(trailing) > 16 and trailing.strip(b"\x00\r\n ") != b"":
            tmagic = sniff_magic(trailing[:4096])
            sev = "high" if tmagic in EXECUTABLE | {"zip", "rar", "7z", "gzip", "shebang", "pdf"} else "medium"
            findings.append(F("BIN-APPENDED-DATA", "Data appended after the end of the image", sev, "hidden-content",
                              path, "%d bytes after the image end marker%s. Appended data is invisible when the image "
                              "is viewed." % (len(trailing), (" (looks like %s)" % tmagic) if tmagic else ""),
                              caps=("hidden",), tags=("hidden",)))
            e = Entry(relpath=path + "!/appended-data", size=len(trailing), data=trailing, container=path)
            subs.append(e)
    return findings, units, subs


def svg_html_checks(path: str, text: str) -> List[Finding]:
    out: List[Finding] = []
    low = text.lower()
    is_svg = path.lower().endswith(".svg") or "<svg" in low[:2000] and "<html" not in low[:2000]
    if "<script" in low:
        ext_src = re.findall(r"<script[^>]+src\s*=\s*[\"']?(https?:[^\"'\s>]+)", text, re.I)
        out.append(F("BIN-SVG-HTML-SCRIPT", "Embedded <script> in %s" % ("SVG image" if is_svg else "HTML page"),
                     "high" if is_svg else ("low" if ext_src else "info"), "dynamic-exec", path,
                     "Scripts run when the file is opened in a browser.%s" % (
                         (" Remote scripts: " + ", ".join(visible(u, 120) for u in ext_src[:5])) if ext_src else ""),
                     caps=("execute",) if is_svg else ()))
    n = len(re.findall(r"\son[a-z]{3,20}\s*=\s*[\"']", text, re.I))
    if n and is_svg:
        out.append(F("BIN-SVG-HTML-EVENT-HANDLER", "Inline event handlers in an SVG image", "medium",
                     "dynamic-exec", path, "%d handler(s)." % n, caps=("execute",)))
    if re.search(r"(?:href|src|action)\s*=\s*[\"']\s*javascript:", text, re.I):
        out.append(F("BIN-SVG-HTML-JS-URL", "javascript: URL", "high", "dynamic-exec", path, "", caps=("execute",)))
    if "<foreignobject" in low:
        out.append(F("BIN-SVG-FOREIGNOBJECT", "SVG <foreignObject> (embedded HTML)", "medium", "hidden-content", path,
                     "Can embed arbitrary HTML/forms inside an image."))
    if re.search(r"<meta[^>]+http-equiv\s*=\s*[\"']refresh", text, re.I):
        out.append(F("BIN-HTML-META-REFRESH", "HTML meta refresh redirect", "low", "network", path, ""))
    return out


def rtf_checks(path: str, text: str) -> List[Finding]:
    out = []
    if re.search(r"\\objdata|\\objupdate|\\objemb|\\objlink|\\objautlink", text):
        out.append(F("BIN-RTF-OBJECT", "RTF embeds OLE objects", "high", "binary", path,
                     "Embedded objects in RTF are a classic exploit vector (e.g. CVE-2017-11882).", caps=("execute",)))
    if re.search(r"\\\*\\template\s+https?://", text, re.I):
        out.append(F("BIN-RTF-REMOTE-TEMPLATE", "RTF remote template", "high", "remote-exec", path, "",
                     caps=("download",)))
    return out
