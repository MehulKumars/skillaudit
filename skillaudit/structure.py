"""Filesystem / structural anomaly checks and special-file content checks."""
from __future__ import annotations

import json
import os
import re
import stat
import sys
import unicodedata
from collections import defaultdict
from typing import Dict, List, Optional

from .charclass import classify
from .model import Finding
from .rules import CATEGORY_INFO
from .sanitize import visible
from .walker import FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM, Entry

IS_WINDOWS = sys.platform == "win32"

SENSITIVE_TARGET = re.compile(
    r"\.ssh|\.aws|\.gnupg|\.kube|\.docker|\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.env\b|credentials|"
    r"Keychains|Login Data|Cookies|wallet|/etc/shadow|/etc/passwd|\.claude|\.codex|\.openclaw|\.config|"
    r"AppData|Application Support|id_rsa|id_ed25519|\.bash_history|\.zsh_history", re.I)
WIN_RESERVED = re.compile(r"^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$", re.I)
DOUBLE_EXT = re.compile(
    r"\.(?:pdf|docx?|xlsx?|pptx?|txt|md|png|jpe?g|gif|mp4|mp3|zip|csv|json|html?)\.(?:exe|scr|com|bat|cmd|ps1|vbs|"
    r"js|jse|hta|lnk|sh|app|command|py|msi|jar|dll|cpl|pif)$", re.I)
EXEC_EXT = re.compile(r"\.(?:sh|bash|zsh|py|pl|rb|js|command|tool|run|bin|elf|out|appimage)$", re.I)

SPECIAL_NAMES = [
    # (regex on relpath, rule id, severity, category, title, message)
    (r"(?:^|/)\.envrc$", "AUTORUN-DIRENV", "high", "autorun", "direnv .envrc (auto-executes on cd)",
     "direnv runs .envrc automatically when a shell enters the directory."),
    (r"(?:^|/)\.vscode/tasks\.json$", "AUTORUN-VSCODE-TASKS", "medium", "autorun", "VS Code tasks file",
     "tasks.json can run commands automatically on folder open (runOn: folderOpen)."),
    (r"(?:^|/)\.vscode/(?:settings|mcp|launch)\.json$", "AGENT-BUNDLED-VSCODE-CONFIG", "medium", "agent-tampering",
     "Bundled VS Code workspace configuration",
     "Workspace settings can auto-approve agent tools (CVE-2025-53773) or register MCP servers."),
    (r"(?:^|/)\.claude/settings(?:\.local)?\.json$", "AGENT-BUNDLED-CLAUDE-SETTINGS", "high", "agent-tampering",
     "Bundled Claude Code settings", "Project settings can define hooks, permission allow-rules, env vars "
     "(ANTHROPIC_BASE_URL) and auto-enable MCP servers (Check Point CVE-2025-59536 research)."),
    (r"(?:^|/)\.claude/(?:commands|agents|hooks|skills)/", "AGENT-BUNDLED-CLAUDE-DIR", "medium", "agent-tampering",
     "Bundled .claude/ commands, agents, hooks or nested skills", "Nested agent configuration inside a skill."),
    (r"(?:^|/)(?:\.mcp\.json|mcp\.json|claude_desktop_config\.json)$", "AGENT-BUNDLED-MCP-CONFIG", "medium",
     "agent-tampering", "Bundled MCP server configuration", "Defines MCP servers (commands that will be executed)."),
    (r"(?:^|/)\.(?:cursor/rules/.+|cursorrules|windsurfrules|clinerules|github/copilot-instructions\.md|"
     r"cursor/mcp\.json|cursor/cli\.json|gemini/settings\.json|codex/config\.toml)$",
     "AGENT-BUNDLED-RULES-FILE", "medium", "agent-tampering", "Bundled AI-assistant rules / config file",
     "Rules files are loaded silently into other assistants (Pillar 'Rules File Backdoor', Miasma worm)."),
    (r"(?:^|/)(?:MEMORY|SOUL|IDENTITY|HEARTBEAT|BOOTSTRAP|USER|TOOLS)\.md$", "AGENT-BUNDLED-MEMORY-FILE", "high",
     "agent-tampering", "Bundled agent memory / identity file",
     "OpenClaw-style memory/identity files persist instructions across sessions (ClawHavoc, HiddenLayer C2)."),
    (r"(?:^|/)(?:CLAUDE|AGENTS|AGENTS\.override|GEMINI)\.md$", "AGENT-BUNDLED-INSTRUCTIONS-FILE", "low",
     "agent-tampering", "Bundled agent instruction file", "Loaded automatically by agents working in this folder."),
    (r"(?:^|/)\.git/hooks/(?!.*\.sample$)[^/]+$", "AUTORUN-GIT-HOOK", "high", "autorun", "Active git hook",
     "Git hooks execute automatically on git operations."),
    (r"(?:^|/)\.git/config$", "FS-GIT-CONFIG", "info", "filesystem", "Embedded git config",
     "Checked for hooksPath / fsmonitor / sshCommand / filters."),
    (r"\.pth$", "AUTORUN-PTH-FILE", "medium", "autorun", "Python .pth file",
     "Lines starting with 'import' in .pth files run at every interpreter start."),
    (r"(?:^|/)(?:sitecustomize|usercustomize)\.py$", "AUTORUN-PY-STARTUP", "high", "autorun",
     "Python startup customisation module", "Executed automatically by every Python interpreter that sees it."),
    (r"(?:^|/)conftest\.py$", "AUTORUN-CONFTEST", "low", "autorun", "pytest conftest.py",
     "Executed automatically by pytest."),
    (r"(?:^|/)setup\.py$", "SUPPLY-SETUP-PY", "low", "supply-chain", "setup.py (runs code at install time)",
     "Arbitrary code runs during pip install."),
    (r"\.(?:lnk|url|scf|library-ms|searchconnector-ms|website|appref-ms)$", "BIN-WINDOWS-SHORTCUT", "high", "binary",
     "Windows shortcut / shell link file", "Can launch arbitrary commands or leak NTLM hashes when browsed."),
    (r"\.reg$", "BIN-REGISTRY-FILE", "high", "persistence", "Windows registry import file",
     "Double-clicking merges keys into the registry (persistence, policy changes)."),
    (r"\.desktop$", "AUTORUN-DESKTOP-ENTRY", "medium", "autorun", "Linux .desktop entry", "Contains an Exec= command."),
    (r"\.(?:service|timer|socket)$", "PERSIST-SYSTEMD-UNIT", "medium", "persistence", "systemd unit file",
     "Defines a service that can run persistently."),
    (r"\.(?:hta|chm|scr|pif|cpl|msc|jse|vbe|wsf|wsh|gadget|application|xbap|sct|ws|msp|mst|inf|ins|isp|workflow|"
     r"jar|apk|ipa|xll|wll|ppam|xlam|com)$", "BIN-DANGEROUS-EXTENSION", "high", "binary",
     "Dangerous executable file type", "This extension is directly executable on at least one OS."),
    (r"\.(?:scpt|scptd)$", "BIN-COMPILED-APPLESCRIPT", "high", "binary", "Compiled AppleScript",
     "Compiled scripts cannot be reviewed as text."),
    (r"(?:^|/)(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)$|\.(?:pem|key|p12|pfx|ppk|jks|keystore|kdbx|ovpn|gpg|asc)$",
     "SECRET-KEY-FILE", "high", "secrets", "Private key / keystore / vault file bundled",
     "A skill should not ship keys; it may also be stolen data."),
    (r"(?:^|/)\.env(?:\.(?!example|sample|template|dist)[\w-]+)?$", "SECRET-DOTENV-FILE", "medium", "secrets",
     ".env file bundled", "Often contains real credentials."),
    (r"(?:^|/)(?:\.git-credentials|\.netrc|_netrc|\.npmrc|\.pypirc|\.htpasswd|wallet\.dat|Login Data|Cookies|"
     r"Local State|key[34]\.db|logins\.json|credentials(?:\.json)?|token\.json|service[-_]account.*\.json)$",
     "SECRET-CREDENTIAL-FILE", "high", "secrets", "Credential store file bundled",
     "Credential files inside a skill are either leaked secrets or exfiltrated data."),
    (r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$", "SUPPLY-CI-WORKFLOW", "info", "supply-chain",
     "GitHub Actions workflow", "Reviewed for pull_request_target and secret exposure."),
    (r"(?:^|/)\.devcontainer/devcontainer\.json$", "AUTORUN-DEVCONTAINER", "medium", "autorun",
     "Dev-container definition", "initializeCommand runs on the host; postCreate/postStart run in the container."),
    (r"(?:^|/)(?:\.DS_Store|\._[^/]+)$", "FS-MAC-METADATA", "low", "filesystem", "macOS metadata file",
     "Leaks file names / extended attributes; resource-fork files can hide data."),
    (r"(?:^|/)(?:Thumbs\.db|desktop\.ini)$", "FS-WINDOWS-METADATA", "low", "filesystem", "Windows folder metadata",
     "desktop.ini can point Explorer at remote icons/CLSIDs."),
    (r"(?:^|/)\.gitmodules$", "SUPPLY-GIT-SUBMODULES", "low", "supply-chain", "Git submodules",
     "Pulls additional repositories at checkout."),
    (r"(?:^|/)(?:\.yarnrc(?:\.yml)?|pip\.conf|pip\.ini|\.condarc|bunfig\.toml)$", "SUPPLY-PACKAGE-MANAGER-CONFIG",
     "medium", "supply-chain", "Package-manager configuration", "Can redirect package installs to another registry."),
    (r"\.(?:pyc|pyo)$", "BIN-PYTHON-BYTECODE", "high", "binary", "Compiled Python bytecode",
     "Bytecode can differ from the shipped .py source (Trail of Bits 'simple-formatter', PyCache Trap)."),
    (r"\.(?:so|dylib|dll|node|o|a|ko|sys|drv|ocx|exe|bin|elf|out|wasm|class)$", "BIN-NATIVE-CODE-EXT",
     "medium", "binary", "Native / compiled code file", "Compiled code cannot be reviewed as text."),
]
SPECIAL_COMPILED = [(re.compile(p, re.I), rid, sev, cat, title, msg) for p, rid, sev, cat, title, msg in SPECIAL_NAMES]

VENDORED_DIRS = {"node_modules": "Vendored node_modules", ".venv": "Bundled Python virtualenv",
                 "venv": "Bundled Python virtualenv", "site-packages": "Bundled site-packages",
                 "vendor": "Vendored third-party code", "__pycache__": "Python bytecode cache"}


def _refs(cat):
    return list(CATEGORY_INFO.get(cat, ("", []))[1])


def F(rid, title, sev, cat, path, message, evidence=(), conf="high", caps=(), tags=()) -> Finding:
    return Finding(rule_id=rid, title=title, severity=sev, category=cat, path=path, confidence=conf, message=message,
                   evidence=list(evidence), origin="structure", references=_refs(cat), capabilities=list(caps),
                   tags=list(tags))


def _resolve_target(root: str, entry: Entry) -> str:
    tgt = entry.link_target
    if not tgt or tgt == "?":
        return ""
    if tgt.startswith("\\\\?\\"):
        tgt = tgt[4:]
    base = os.path.dirname(entry.abspath)
    return os.path.normpath(tgt if os.path.isabs(tgt) else os.path.join(base, tgt))


def _inside(root: str, path: str) -> bool:
    try:
        return os.path.commonpath([os.path.abspath(root), os.path.abspath(path)]) == os.path.abspath(root)
    except ValueError:
        return False


def check_entry(entry: Entry, root: str) -> List[Finding]:
    """Per-entry structural checks (names, attributes, links, specials)."""
    out: List[Finding] = []
    p = entry.relpath
    name = entry.name

    # ---- links -------------------------------------------------------------------
    if entry.is_link or entry.is_junction:
        kind = "junction" if entry.is_junction else "symlink"
        target = _resolve_target(root, entry) if not entry.container else entry.link_target
        raw = entry.link_target
        if SENSITIVE_TARGET.search(raw or "") or SENSITIVE_TARGET.search(target or ""):
            out.append(F("FS-LINK-TO-SENSITIVE", "%s points at a sensitive location" % kind.capitalize(), "critical",
                         "credential-access", p, "Target: %s. An agent that 'reads a reference file' would read this "
                         "secret instead." % visible(raw, 300), caps=("read-secrets",)))
        elif entry.container or not target or not _inside(root, target):
            out.append(F("FS-LINK-ESCAPES-ROOT", "%s points outside the skill folder" % kind.capitalize(), "high",
                         "filesystem", p, "Target: %s" % visible(raw, 300), caps=("read-secrets",)))
        else:
            out.append(F("FS-LINK-INTERNAL", "%s inside the skill" % kind.capitalize(), "low", "filesystem", p,
                         "Target: %s (inside the skill; not followed by the scanner)." % visible(raw, 300)))
    if entry.special:
        out.append(F("FS-SPECIAL-FILE", "Special file (%s)" % entry.special, "high", "filesystem", p,
                     "Device nodes, FIFOs and sockets have no place in a skill package."))

    # ---- names ---------------------------------------------------------------------
    bad_chars = [c for c in name if classify(ord(c)) in ("bidi", "zero-width", "tag", "control", "escape",
                                                          "variation-selector", "blank-glyph", "bidi-mark")]
    if bad_chars or "\n" in name or "\r" in name:
        out.append(F("FS-NAME-HIDDEN-CHARS", "File name contains invisible / bidi / control characters", "critical",
                     "filesystem", visible(p), "Name rendered: %s. RTLO and zero-width tricks disguise the real "
                     "extension (e.g. 'invoice[U+202E]txt.exe' is displayed as 'invoiceexe.txt')." % visible(name), caps=("hidden",)))
    if not name.isascii():
        scripts = set()
        for c in name:
            if c.isalpha():
                try:
                    scripts.add(unicodedata.name(c).split(" ", 1)[0])
                except ValueError:
                    pass
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE"}:
            sev = "critical" if re.sub(r"[^a-z.]", "", unicodedata.normalize("NFKC", name).lower()) in ("skill.md", "kill.md") else "high"
            out.append(F("FS-NAME-HOMOGLYPH", "File name mixes Latin with look-alike letters", sev, "filesystem",
                         visible(p), "'%s' may impersonate an ASCII name." % visible(name), caps=("hidden",)))
    if name != name.rstrip(" .") and name not in (".", ".."):
        out.append(F("FS-NAME-TRAILING-DOT-SPACE", "File name ends with a space or dot", "high", "filesystem",
                     visible(p), "Windows tools cannot open such files normally; used to hide content."))
    if name.startswith("-") and len(name) > 1:
        out.append(F("FS-NAME-LEADING-DASH", "File name starts with '-'", "medium", "filesystem", visible(p),
                     "Names like '-rf' or '--checkpoint-action=...' become options when passed to shell commands "
                     "via wildcards (argument injection)."))
    if WIN_RESERVED.match(name):
        out.append(F("FS-NAME-RESERVED", "Windows reserved device name", "medium", "filesystem", visible(p),
                     "Names like CON/NUL/COM1 behave as devices on Windows."))
    if DOUBLE_EXT.search(name):
        out.append(F("FS-NAME-DOUBLE-EXTENSION", "Deceptive double extension", "high", "filesystem", visible(p),
                     "An executable disguised as a document."))
    if len(name) > 200:
        out.append(F("FS-NAME-VERY-LONG", "Extremely long file name", "low", "filesystem", visible(p[:120]) + "...",
                     "%d characters." % len(name)))

    # ---- attributes ----------------------------------------------------------------------
    if entry.win_attrs & FILE_ATTRIBUTE_HIDDEN and not name.startswith("."):
        out.append(F("FS-WINDOWS-HIDDEN-ATTRIBUTE", "Hidden via the Windows 'hidden' attribute", "high", "filesystem", p,
                     "Invisible in Explorer and 'dir' by default.", caps=("hidden",), tags=("hidden",)))
    if entry.win_attrs & FILE_ATTRIBUTE_SYSTEM:
        out.append(F("FS-WINDOWS-SYSTEM-ATTRIBUTE", "Marked as a Windows system file", "high", "filesystem", p,
                     "System+hidden files are hidden even when 'show hidden files' is on.", caps=("hidden",),
                     tags=("hidden",)))
    if entry.st_flags & 0x8000:  # UF_HIDDEN (macOS chflags hidden)
        out.append(F("FS-MACOS-HIDDEN-FLAG", "Hidden via macOS chflags", "high", "filesystem", p,
                     "Invisible in Finder.", caps=("hidden",), tags=("hidden",)))
    if not IS_WINDOWS and not entry.container and not entry.is_link and entry.mode:
        if entry.mode & (stat.S_ISUID | stat.S_ISGID):
            out.append(F("FS-SETUID-BIT", "setuid / setgid bit set", "high", "privilege-escalation", p,
                         "mode %s" % oct(entry.mode & 0o7777)))
        if not entry.is_dir and entry.mode & 0o111 and not EXEC_EXT.search(name) and "." in name:
            out.append(F("FS-UNEXPECTED-EXEC-BIT", "Executable bit on a non-script file", "medium", "filesystem", p,
                         "mode %s" % oct(entry.mode & 0o7777)))
        if entry.mode & 0o002 and not entry.is_dir:
            out.append(F("FS-WORLD-WRITABLE", "World-writable file", "low", "filesystem", p, oct(entry.mode & 0o7777)))
    if entry.container and entry.meta.get("unix_mode"):
        mode = entry.meta["unix_mode"]
        if mode & (stat.S_ISUID | stat.S_ISGID):
            out.append(F("FS-SETUID-BIT", "setuid / setgid bit set (archive member)", "high", "privilege-escalation", p,
                         "mode %s" % oct(mode & 0o7777)))
    if not entry.is_dir and entry.nlink > 1 and not entry.container and not IS_WINDOWS:
        out.append(F("FS-HARDLINK", "Hard-linked file", "medium", "filesystem", p,
                     "%d links. A hard link can expose a file from elsewhere on the system." % entry.nlink))

    # ---- hidden names ------------------------------------------------------------------------
    if name.startswith(".") and name not in (".", "..", ".gitignore", ".gitattributes", ".editorconfig", ".prettierrc",
                                             ".eslintrc", ".npmignore", ".github", ".vscode", ".git") and not entry.is_dir:
        out.append(F("FS-DOTFILE", "Hidden dot-file", "info", "filesystem", p, "Hidden from default listings.",
                     tags=("hidden",)))
    if entry.is_dir and name.startswith(".") and name not in (".", "..", ".github", ".vscode", ".git", ".claude",
                                                              ".devcontainer", ".cursor"):
        out.append(F("FS-HIDDEN-DIRECTORY", "Hidden directory", "low", "filesystem", p,
                     "Hidden directories are skipped by casual review and by some scanners (SkillCloak).",
                     tags=("hidden",)))
    if entry.is_dir and name in VENDORED_DIRS:
        out.append(F("FS-VENDORED-DIR", VENDORED_DIRS[name], "medium" if name != "__pycache__" else "low",
                     "supply-chain", p, "Third-party or generated code bundled in the skill; review or remove it."))
    if entry.is_dir and name == ".git":
        out.append(F("FS-EMBEDDED-GIT", "Embedded .git repository", "medium", "filesystem", p,
                     "History can contain code that is not in the working tree. Loose objects are scanned; review "
                     "'git log -p' for packed history."))

    # ---- ADS --------------------------------------------------------------------------------------
    for stream, size in entry.ads:
        if stream.lower() == "zone.identifier":
            continue  # handled with its content (mark-of-the-web) by the scanner
        out.append(F("FS-ALTERNATE-DATA-STREAM", "NTFS alternate data stream (hidden data)", "high", "hidden-content",
                     p, "Stream '%s' (%d bytes) is invisible to Explorer, dir and most tools. Its content is scanned "
                     "as '%s:%s'." % (visible(stream), size, p, visible(stream)), caps=("hidden",), tags=("hidden",)))

    # ---- special file names ------------------------------------------------------------------------
    if not entry.is_dir:
        for rx, rid, sev, cat, title, msg in SPECIAL_COMPILED:
            if rx.search(p):
                if rid == "SECRET-KEY-FILE" and name.endswith(".pub"):
                    continue
                out.append(F(rid, title, sev, cat, p, msg))
    return out


def check_tree(entries: List[Entry], root: str) -> List[Finding]:
    out: List[Finding] = []
    by_dir: Dict[str, List[str]] = defaultdict(list)
    files = [e for e in entries if not e.is_dir]
    for e in entries:
        parent = e.relpath.rsplit("/", 1)[0] if "/" in e.relpath else ""
        by_dir[parent].append(e.name)
    for d, names in by_dir.items():
        seen: Dict[str, str] = {}
        for n in names:
            key = unicodedata.normalize("NFC", n).casefold()
            if key in seen and seen[key] != n:
                sev = "high" if key == "skill.md" else "medium"
                out.append(F("FS-CASE-COLLISION", "Names differing only by case / normalisation", sev, "filesystem",
                             (d + "/" if d else "") + n, "'%s' vs '%s' - which one an agent loads depends on the OS."
                             % (visible(seen[key]), visible(n))))
            seen[key] = n
    # pyc without (or with) matching source
    sources = {e.relpath for e in files if e.relpath.endswith(".py")}
    for e in files:
        if e.relpath.endswith((".pyc", ".pyo")):
            base = re.sub(r"(?:__pycache__/)?([^/]+?)(?:\.cpython-\d+|\.pypy\d*)?(?:\.opt-\d)?\.py[co]$", r"\1.py",
                          e.relpath)
            if base not in sources:
                out.append(F("BIN-PYC-WITHOUT-SOURCE", "Python bytecode with no matching source file", "high", "binary",
                             e.relpath, "The behaviour of this file cannot be reviewed. Expected source: %s" % base,
                             caps=("obfuscation",)))
            else:
                out.append(F("BIN-PYC-SHADOWS-SOURCE", "Bytecode shipped next to its source", "medium", "binary",
                             e.relpath, "Python may run the .pyc instead of %s; the two can differ (PyCache Trap)." % base))
    depth = max((e.relpath.count("/") for e in entries), default=0)
    if depth > 12:
        out.append(F("FS-DEEP-NESTING", "Very deep directory nesting", "low", "filesystem", "",
                     "Depth %d. Deep trees hide files from casual review." % depth))
    total = sum(e.size for e in files if not e.container)
    if len(files) > 1000:
        out.append(F("FS-MANY-FILES", "Unusually many files for a skill", "low", "filesystem", "",
                     "%d files." % len(files)))
    if total > 100 * 1024 * 1024:
        out.append(F("FS-LARGE-PACKAGE", "Unusually large skill package", "medium", "filesystem", "",
                     "%.1f MB on disk." % (total / 1e6)))
    return out


# ------------------------------------------------------------------ content checks for special files

def special_content_checks(relpath: str, text: str) -> List[Finding]:
    out: List[Finding] = []
    base = relpath.rsplit("/", 1)[-1].lower()
    low = text.lower()
    if base == "package.json":
        try:
            doc = json.loads(text)
        except ValueError:
            doc = None
        if isinstance(doc, dict):
            scripts = doc.get("scripts") or {}
            if isinstance(scripts, dict):
                for hook in ("preinstall", "install", "postinstall", "prepare", "prepublish", "preuninstall",
                             "postuninstall"):
                    if hook in scripts:
                        out.append(F("SUPPLY-NPM-INSTALL-SCRIPT", "npm lifecycle script runs at install", "high",
                                     "supply-chain", relpath, "%s: %s" % (hook, visible(str(scripts[hook]), 300)),
                                     caps=("execute",)))
            for sect in ("dependencies", "devDependencies", "optionalDependencies"):
                deps = doc.get(sect) or {}
                if isinstance(deps, dict):
                    for name, spec in deps.items():
                        s = str(spec)
                        if re.match(r"(?:https?:|git\+|git:|github:|file:|link:|[\w-]+/[\w.-]+(?:#|$))", s):
                            out.append(F("SUPPLY-NPM-NONREGISTRY-DEP", "Dependency from a URL / git / local path",
                                         "medium", "supply-chain", relpath, "%s: %s" % (visible(name), visible(s, 200))))
                        elif s in ("*", "latest", ""):
                            out.append(F("SUPPLY-NPM-UNPINNED", "Unpinned dependency", "low", "supply-chain", relpath,
                                         "%s: %s" % (visible(name), visible(s or "(empty)"))))
    elif base == "setup.py":
        if re.search(r"cmdclass\s*=|class\s+\w+\((?:install|develop|egg_info|build_py)\)", text):
            out.append(F("SUPPLY-SETUP-PY-CMDCLASS", "setup.py overrides install commands", "high", "supply-chain",
                         relpath, "Custom install/develop commands run arbitrary code during pip install.",
                         caps=("execute",)))
    elif base == "tasks.json" and "/.vscode/" in "/" + relpath.lower():
        if re.search(r"\"runOn\"\s*:\s*\"folderOpen\"", text):
            out.append(F("AUTORUN-VSCODE-FOLDEROPEN", "VS Code task runs automatically on folder open", "high", "autorun",
                         relpath, "A task with runOptions.runOn = folderOpen executes when the folder is opened.",
                         caps=("execute",)))
    elif base.endswith(".pth"):
        lines = [l for l in text.splitlines() if l.strip().startswith(("import ", "import\t"))]
        if lines:
            out.append(F("AUTORUN-PTH-IMPORT", ".pth file executes code at interpreter start", "high", "autorun",
                         relpath, visible(lines[0], 300), caps=("execute", "persist")))
    elif base.endswith(".plist"):
        if "runatload" in low or "programarguments" in low or "startinterval" in low or "keepalive" in low:
            out.append(F("PERSIST-LAUNCHD-PLIST", "launchd job definition (RunAtLoad / ProgramArguments)", "high",
                         "persistence", relpath, "A LaunchAgent/Daemon plist runs a program at login or on a schedule.",
                         caps=("persist", "execute")))
    elif base == "config" and "/.git/" in "/" + relpath.lower():
        m = re.search(r"^[ \t]*(hookspath|fsmonitor|sshcommand|pager|editor|askpass|gpgprogram|textconv|"
                      r"\[filter[^\]]*\])\s*=?.*$", text, re.I | re.M)
        if m:
            out.append(F("AUTORUN-GIT-CONFIG-EXEC", "Git config entry that executes commands", "high", "autorun",
                         relpath, visible(m.group(0).strip(), 300), caps=("execute",)))
    elif base == "devcontainer.json":
        m = re.search(r"\"(initializeCommand|postCreateCommand|postStartCommand|postAttachCommand|onCreateCommand|"
                      r"updateContentCommand)\"\s*:\s*(.{0,200})", text)
        if m:
            sev = "high" if m.group(1) == "initializeCommand" else "medium"
            out.append(F("AUTORUN-DEVCONTAINER-COMMAND", "Dev-container lifecycle command", sev, "autorun", relpath,
                         "%s: %s" % (m.group(1), visible(m.group(2), 200)), caps=("execute",)))
    elif base.endswith(".desktop"):
        m = re.search(r"^[ \t]*Exec\s*=\s*(.+)$", text, re.M)
        if m:
            out.append(F("AUTORUN-DESKTOP-EXEC", ".desktop Exec command", "medium", "autorun", relpath,
                         visible(m.group(1), 300), caps=("execute",)))
    elif base.endswith((".yml", ".yaml")) and "/.github/workflows/" in "/" + relpath.lower():
        if "pull_request_target" in low:
            out.append(F("SUPPLY-CI-PR-TARGET", "Workflow uses pull_request_target", "medium", "supply-chain", relpath,
                         "Runs with secrets on untrusted pull requests if it checks out PR code."))
    elif base in (".npmrc", ".yarnrc", ".yarnrc.yml", "pip.conf", "pip.ini", "bunfig.toml"):
        m = re.search(r"^[ \t]*(?:@[\w-]+:)?(?:registry|npmRegistryServer|index-url|extra-index-url)\s*[=:]\s*(\S+)",
                      text, re.I | re.M)
        if m and not re.search(r"registry\.npmjs\.org|registry\.yarnpkg\.com|pypi\.org", m.group(1)):
            out.append(F("SUPPLY-REGISTRY-CONFIG", "Package-manager config points at a non-default registry", "high",
                         "supply-chain", relpath, visible(m.group(0).strip(), 300), caps=("install-packages",)))
        if re.search(r"_auth(?:Token)?\s*=\s*\S{8,}", text):
            out.append(F("SECRET-REGISTRY-TOKEN", "Registry auth token in config", "high", "secrets", relpath,
                         "An npm/yarn auth token is stored in this file."))
    return out
