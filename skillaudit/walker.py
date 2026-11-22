"""Filesystem traversal. Never follows symlinks/junctions; records everything.

On Windows also reads file attributes (hidden/system/reparse points) and NTFS
alternate data streams (ADS) via the Win32 API (ctypes, stdlib only).
"""
from __future__ import annotations

import hashlib
import os
import stat
import sys
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Tuple

IS_WINDOWS = sys.platform == "win32"
FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003
IO_REPARSE_TAG_SYMLINK = 0xA000000C


@dataclass
class Entry:
    relpath: str
    abspath: str = ""
    is_dir: bool = False
    is_link: bool = False
    is_junction: bool = False
    reparse_tag: int = 0
    link_target: str = ""
    size: int = 0
    mode: int = 0
    mtime: float = 0.0
    nlink: int = 1
    win_attrs: int = 0
    st_flags: int = 0
    special: str = ""
    ads: List[Tuple[str, int]] = field(default_factory=list)
    data: Optional[bytes] = None
    container: str = ""
    depth: int = 0
    meta: dict = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.relpath.rsplit("/", 1)[-1].rsplit("!/", 1)[-1]

    def read(self, limit: int) -> bytes:
        if self.data is not None:
            return self.data[:limit]
        with open(self.abspath, "rb") as fh:
            return fh.read(limit)

    def read_tail(self, n: int) -> bytes:
        if self.data is not None:
            return self.data[-n:]
        with open(self.abspath, "rb") as fh:
            try:
                fh.seek(-n, os.SEEK_END)
            except OSError:
                fh.seek(0)
            return fh.read(n)

    def sha256(self, cap: int = 1 << 31) -> str:
        h = hashlib.sha256()
        if self.data is not None:
            h.update(self.data)
            return h.hexdigest()
        read = 0
        with open(self.abspath, "rb") as fh:
            while read < cap:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                h.update(chunk)
                read += len(chunk)
        return h.hexdigest()


# ---------------------------------------------------------------- Windows ADS

def list_ads(path: str) -> List[Tuple[str, int]]:
    """Return [(stream_name, size)] excluding the default ::$DATA stream."""
    if not IS_WINDOWS:
        return []
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:
        return []

    class WIN32_FIND_STREAM_DATA(ctypes.Structure):
        _fields_ = [("StreamSize", ctypes.c_longlong), ("cStreamName", ctypes.c_wchar * 296)]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    find_first = k32.FindFirstStreamW
    find_first.argtypes = [wintypes.LPCWSTR, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    find_first.restype = wintypes.HANDLE
    find_next = k32.FindNextStreamW
    find_next.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    find_next.restype = wintypes.BOOL
    find_close = k32.FindClose
    find_close.argtypes = [wintypes.HANDLE]
    invalid = wintypes.HANDLE(-1).value

    data = WIN32_FIND_STREAM_DATA()
    p = path if len(path) < 250 or path.startswith("\\\\?\\") else "\\\\?\\" + os.path.abspath(path)
    handle = find_first(p, 0, ctypes.byref(data), 0)
    if handle in (invalid, None, 0):
        return []
    out = []
    try:
        while True:
            name = data.cStreamName
            if name and name != "::$DATA":
                stream = name[1:].rsplit(":$DATA", 1)[0] if name.endswith(":$DATA") else name[1:]
                out.append((stream, int(data.StreamSize)))
            if not find_next(handle, ctypes.byref(data)):
                break
    finally:
        find_close(handle)
    return out


def read_ads(path: str, stream: str, limit: int) -> bytes:
    with open("%s:%s" % (path, stream), "rb") as fh:
        return fh.read(limit)


# ---------------------------------------------------------------- walking

def _make_entry(abspath: str, relpath: str, st: os.stat_result, depth: int) -> Entry:
    e = Entry(relpath=relpath, abspath=abspath, size=st.st_size, mode=st.st_mode, mtime=st.st_mtime,
              nlink=getattr(st, "st_nlink", 1) or 1, depth=depth)
    e.win_attrs = getattr(st, "st_file_attributes", 0) or 0
    e.st_flags = getattr(st, "st_flags", 0) or 0
    e.reparse_tag = getattr(st, "st_reparse_tag", 0) or 0
    if stat.S_ISLNK(st.st_mode) or e.reparse_tag == IO_REPARSE_TAG_SYMLINK:
        e.is_link = True
    elif e.reparse_tag == IO_REPARSE_TAG_MOUNT_POINT:
        e.is_junction = True
    if e.is_link or e.is_junction:
        try:
            e.link_target = os.readlink(abspath)
        except (OSError, ValueError, NotImplementedError):
            e.link_target = "?"
    elif stat.S_ISDIR(st.st_mode):
        e.is_dir = True
    elif stat.S_ISREG(st.st_mode):
        pass
    elif stat.S_ISFIFO(st.st_mode):
        e.special = "fifo"
    elif stat.S_ISSOCK(st.st_mode):
        e.special = "socket"
    elif stat.S_ISCHR(st.st_mode):
        e.special = "char-device"
    elif stat.S_ISBLK(st.st_mode):
        e.special = "block-device"
    if IS_WINDOWS and not (e.is_link or e.is_junction):
        try:
            e.ads = list_ads(abspath)
        except Exception:
            e.ads = []
    return e


def walk(root: str, max_files: int = 50000, max_depth: int = 64, errors: Optional[list] = None) -> Iterator[Entry]:
    """Yield an Entry for root's contents (or root itself when it is a file)."""
    errors = errors if errors is not None else []
    root = os.path.abspath(root)
    try:
        st = os.lstat(root)
    except OSError as exc:
        errors.append("cannot stat %s: %s" % (root, exc))
        return
    if not stat.S_ISDIR(st.st_mode):
        yield _make_entry(root, os.path.basename(root), st, 0)
        return
    # ADS on the root directory itself
    if IS_WINDOWS:
        try:
            ads = list_ads(root)
            if ads:
                e = _make_entry(root, ".", st, 0)
                yield e
        except Exception:
            pass
    count = 0
    stack = [(root, "", 0)]
    while stack:
        absdir, rel, depth = stack.pop()
        if depth > max_depth:
            errors.append("max depth reached at %s" % (rel or "."))
            continue
        try:
            with os.scandir(absdir) as it:
                items = sorted(it, key=lambda d: d.name)
        except OSError as exc:
            errors.append("cannot list %s: %s" % (rel or ".", exc))
            continue
        subdirs = []
        for de in items:
            relpath = (rel + "/" + de.name) if rel else de.name
            try:
                st = de.stat(follow_symlinks=False)
            except OSError as exc:
                errors.append("cannot stat %s: %s" % (relpath, exc))
                continue
            entry = _make_entry(de.path, relpath, st, depth + 1)
            count += 1
            if count > max_files:
                errors.append("file limit (%d) reached; remaining files not scanned" % max_files)
                return
            yield entry
            if entry.is_dir:
                subdirs.append((de.path, relpath, depth + 1))
        for sd in reversed(subdirs):
            stack.append(sd)
