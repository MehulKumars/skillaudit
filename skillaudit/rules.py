"""Regex rule catalog.

Every rule is data: id, title, category, severity, regex, optional kind filter,
capability tags (used by the correlation engine), references and remediation.
Custom rules can be loaded from JSON with the same fields (see load_custom_rules).

Regexes are written with bounded quantifiers ([^\\n]{0,N}) to avoid
catastrophic backtracking on hostile input.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence, Set, Tuple

# --------------------------------------------------------------------------
# Categories and their default references
# --------------------------------------------------------------------------

CATEGORY_INFO = {
    "remote-exec": ("Remote code download & execution",
                    ["ATT&CK T1105", "ATT&CK T1059", "OWASP ASI05", "OWASP AST01", "ATLAS AML.T0050"]),
    "dynamic-exec": ("Dynamic / shell code execution", ["ATT&CK T1059", "OWASP ASI05"]),
    "obfuscation": ("Obfuscated or encoded payloads", ["ATT&CK T1027", "ATT&CK T1140"]),
    "exfiltration": ("Data exfiltration", ["ATT&CK T1041", "ATT&CK T1567", "OWASP LLM02", "ATLAS AML.T0086"]),
    "network": ("Network activity", ["ATT&CK T1071"]),
    "credential-access": ("Credential & secret access", ["ATT&CK T1552", "ATT&CK T1555", "OWASP ASI03", "ATLAS AML.T0083"]),
    "persistence": ("Persistence mechanisms", ["ATT&CK T1547", "ATT&CK T1053", "ATT&CK T1546.004", "ATT&CK T1543"]),
    "agent-tampering": ("AI-agent config / memory tampering", ["OWASP ASI06", "OWASP AST01", "ATLAS AML.T0080", "ATLAS AML.T0081"]),
    "prompt-injection": ("Prompt injection / instruction override", ["OWASP LLM01", "OWASP ASI01", "ATLAS AML.T0051", "ATLAS AML.T0110"]),
    "concealment": ("Concealment from the user", ["OWASP ASI09", "OWASP LLM01"]),
    "social-engineering": ("Social engineering of the user", ["ATT&CK T1204", "ATT&CK T1056.002", "OWASP ASI09"]),
    "destructive": ("Destructive actions", ["ATT&CK T1485", "ATT&CK T1490"]),
    "defense-evasion": ("Defense evasion / anti-forensics", ["ATT&CK T1562", "ATT&CK T1070", "ATT&CK T1553.001"]),
    "privilege-escalation": ("Privilege escalation", ["ATT&CK T1548", "ATT&CK T1611"]),
    "reverse-shell": ("Reverse shells & remote access", ["ATT&CK T1219", "ATT&CK T1572", "ATLAS AML.T0072"]),
    "cryptomining": ("Cryptomining", ["ATT&CK T1496"]),
    "crypto-theft": ("Cryptocurrency theft", ["ATT&CK T1005", "ATT&CK T1115"]),
    "recon": ("Reconnaissance / host profiling", ["ATT&CK T1082", "ATT&CK T1033", "ATT&CK T1016", "ATT&CK T1083"]),
    "sandbox-evasion": ("Sandbox / analysis evasion", ["ATT&CK T1497", "ATLAS AML.T0094"]),
    "supply-chain": ("Dependency & supply-chain risk", ["ATT&CK T1195", "OWASP LLM03", "OWASP ASI04", "OWASP AST02", "ATLAS AML.T0010.005"]),
    "secrets": ("Hard-coded secrets", ["ATT&CK T1552.001", "OWASP LLM02"]),
    "hidden-content": ("Hidden content", ["ATT&CK T1564", "OWASP LLM01"]),
    "unicode": ("Deceptive Unicode", ["ATLAS AML.T0068", "OWASP AST04", "OWASP LLM01", "CVE-2021-42574"]),
    "filesystem": ("Filesystem anomalies", ["ATT&CK T1564.001", "ATT&CK T1036"]),
    "binary": ("Opaque / binary content", ["ATT&CK T1027.009", "OWASP ASI04"]),
    "archive": ("Archive anomalies", ["ATT&CK T1027", "ATT&CK T1560"]),
    "manifest": ("SKILL.md manifest issues", ["OWASP AST04", "OWASP ASI04"]),
    "excessive-agency": ("Excessive agency / permissions", ["OWASP LLM06", "OWASP ASI02", "OWASP AST03"]),
    "autorun": ("Auto-executing files", ["ATT&CK T1546", "OWASP ASI05"]),
    "known-ioc": ("Known malicious indicators", ["OWASP AST01"]),
    "financial": ("Financial manipulation", ["OWASP ASI09"]),
    "correlation": ("Correlated attack chains", []),
}

# Kind groups
DOCS = {"markdown", "text"}
CODE = {
    "python", "javascript", "shell", "powershell", "batch", "vbscript", "ruby", "perl", "php", "go", "rust", "lua",
    "java", "c-family", "applescript", "makefile", "dockerfile", "notebook", "html", "svg", "r", "julia", "elixir",
}
PY = {"python", "notebook", "markdown", "text", "decoded"}
JS = {"javascript", "html", "svg", "markdown", "text", "decoded", "json"}
PS = {"powershell", "batch", "markdown", "text", "decoded", "json", "yaml"}

SEC_FLAGS = 0  # case-sensitive (secret formats)


@dataclass
class Rule:
    id: str
    title: str
    category: str
    severity: str
    pattern: str
    confidence: str = "medium"
    flags: int = re.I
    kinds: Optional[Set[str]] = None          # None -> all text kinds
    skip_kinds: Optional[Set[str]] = None
    caps: Tuple[str, ...] = ()
    description: str = ""
    remediation: str = ""
    refs: Tuple[str, ...] = ()
    hints: Tuple[str, ...] = ()               # lowercase substrings; rule skipped if none present
    max_hits: int = 8
    min_count: int = 1                        # report only if at least this many matches in the unit
    redact: bool = False
    validator: Optional[Callable[[re.Match, str], bool]] = None
    custom: bool = False
    regex: "re.Pattern" = field(init=False, repr=False)

    def __post_init__(self):
        self.regex = re.compile(self.pattern, self.flags)

    @property
    def references(self) -> List[str]:
        base = list(self.refs) if self.refs else []
        for r in CATEGORY_INFO.get(self.category, ("", []))[1]:
            if r not in base:
                base.append(r)
        return base

    def applies_to(self, kind: str) -> bool:
        if self.skip_kinds and kind in self.skip_kinds:
            return False
        if self.kinds is None:
            return True
        return kind in self.kinds or kind in ("decoded", "hidden")


RULES: List[Rule] = []


def R(id, title, category, severity, pattern, **kw) -> Rule:
    rule = Rule(id=id, title=title, category=category, severity=severity, pattern=pattern, **kw)
    RULES.append(rule)
    return rule


# Reusable fragments ---------------------------------------------------------

DL = r"(?:curl|wget|fetch|iwr|irm|invoke-webrequest|invoke-restmethod|aria2c|lwp-download|http(?:ie)?\s+get)"
INTERP = (r"(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+)?(?:/usr/(?:local/)?bin/|/bin/)?"
          r"(?:(?:ba|z|k|da|a|fi|tc)?sh|python[0-9.]*|perl|ruby|node|php|iex|invoke-expression|pwsh|"
          r"powershell(?:\.exe)?|osascript|source|bun|deno)\b")


def write_near(target: str) -> str:
    """Regex: a write/append/copy operation aimed at `target` on the same line."""
    return (
        r"(?:(?:>>|>)\s*[\"']?[^\s\"'<>|;&]{0,120}" + target +
        r"|(?:\btee\b|\bAdd-Content\b|\bSet-Content\b|\bOut-File\b|\bappendFile(?:Sync)?\b|\bwriteFile(?:Sync)?\b"
        r"|\bfs\.(?:append|write)File(?:Sync)?\b|\bcp\b|\bmv\b|\bln\s+-s\w*|\bCopy-Item\b|\bMove-Item\b"
        r"|\bshutil\.(?:copy\w*|move)\b|\bsed\s+-i\b|\binstall\s+-[mD])[^\n]{0,160}" + target +
        r"|" + target + r"[^\n]{0,120}(?:['\"][aw]\+?b?['\"]|\.write(?:_text|_bytes|lines)?\s*\(|>>|\bAdd-Content\b"
        r"|\bSet-Content\b|\bappendFile\b|\bwriteFile\b|\bmode\s*=\s*['\"][aw]))"
    )


SHELL_RC = (r"(?:\.bashrc|\.bash_profile|\.bash_login|\.zshrc|\.zprofile|\.zshenv|\.zlogin|(?<![\w.])\.profile\b|"
            r"config\.fish|/etc/profile(?:\.d)?|/etc/bash\.bashrc|/etc/environment|\$PROFILE\b|"
            r"Microsoft\.PowerShell_profile\.ps1|profile\.ps1)")

AGENT_FILES = (
    r"(?:\.claude[/\\](?:settings(?:\.local)?\.json|commands|agents|skills|hooks|plugins|CLAUDE\.md|keybindings\.json)"
    r"|CLAUDE(?:\.local)?\.md|AGENTS\.md|GEMINI\.md|MEMORY\.md|SOUL\.md|IDENTITY\.md|HEARTBEAT\.md|BOOTSTRAP\.md"
    r"|\.cursorrules|\.cursor[/\\](?:rules|mcp\.json)|\.windsurfrules|\.windsurf[/\\]|\.clinerules|\.roo[/\\]"
    r"|copilot-instructions\.md|\.github[/\\]instructions|\.mcp\.json|claude_desktop_config\.json"
    r"|\.codex[/\\](?:config\.toml|AGENTS\.md|instructions\.md)|\.gemini[/\\](?:settings\.json|GEMINI\.md)"
    r"|\.openclaw[/\\]|\.clawdbot[/\\]|\.moltbot[/\\]|\.continue[/\\]config|\.aider\.conf|\.vscode[/\\](?:settings|mcp)\.json"
    r"|\.zed[/\\]settings\.json|opencode\.json)"
)

# ==========================================================================
# 1. Remote code download & execution
# ==========================================================================

R("EXEC-PIPE-TO-SHELL", "Download piped straight into a shell/interpreter", "remote-exec", "critical",
  r"\b" + DL + r"\b[^\n|]{0,400}\|\s*" + INTERP,
  confidence="high", caps=("download", "execute"),
  hints=("curl", "wget", "fetch", "iwr", "irm", "invoke-", "aria2c", "lwp-", "http"),
  description="Remote content is executed without being saved or reviewed (curl | bash). This is the most common "
              "delivery mechanism in malicious skills (e.g. ClawHavoc / AMOS campaigns).",
  remediation="Never pipe network content into an interpreter. Vendor the script into the skill and pin its hash.")

R("EXEC-PROCESS-SUBST", "Shell executes a downloaded script via process substitution", "remote-exec", "critical",
  r"\b(?:(?:ba|z|k)?sh|source|\.)\s+(?:-\S+\s+)*<\(\s*(?:curl|wget)\b",
  confidence="high", caps=("download", "execute"), hints=("<(",))

R("EXEC-SUBSHELL-DOWNLOAD", "eval / -c of a command substitution that downloads code", "remote-exec", "critical",
  r"(?:\beval|\b(?:ba|z)?sh\s+-c|\bpython[0-9.]*\s+-c|\bperl\s+-e|\bnode\s+-e|\bruby\s+-e)\s+[\"']?(?:\$\(|`)\s*(?:curl|wget)\b",
  confidence="high", caps=("download", "execute"), hints=("curl", "wget"))

R("EXEC-PS-DOWNLOAD-IEX", "PowerShell downloads and executes code (IEX + DownloadString/IWR)", "remote-exec", "critical",
  r"(?:\biex\b|invoke-expression)[^\n]{0,250}(?:downloadstring|downloaddata|invoke-webrequest|\biwr\b|\birm\b|"
  r"invoke-restmethod|net\.webclient|start-bitstransfer)|(?:downloadstring|net\.webclient|invoke-restmethod|\birm\b)"
  r"[^\n]{0,250}(?:\|\s*iex\b|invoke-expression)",
  confidence="high", caps=("download", "execute"), hints=("iex", "invoke-expression"))

R("EXEC-PY-REMOTE-EXEC", "Python exec/eval of content fetched from the network", "remote-exec", "critical",
  r"\b(?:exec|eval)\s*\([^\n]{0,120}(?:requests\.(?:get|post)|httpx\.(?:get|post)|urlopen|urllib\.request|urllib2|"
  r"http\.client|socket\.|\.recv\()",
  confidence="high", caps=("download", "execute"), hints=("exec", "eval"))

R("EXEC-JS-REMOTE-EXEC", "JavaScript eval/Function of content fetched from the network", "remote-exec", "critical",
  r"\b(?:eval|Function)\s*\([^\n]{0,120}(?:await\s+)?(?:fetch\s*\(|axios|https?\.get|\.text\(\)|responseText)",
  confidence="high", caps=("download", "execute"), hints=("eval", "function"))

R("EXEC-DOWNLOAD-CHMOD", "Downloads a file and makes it executable", "remote-exec", "high",
  r"\b(?:curl|wget)\b[^\n]{0,300}(?:\s-o|\s-O|--output|>)\s*\S+[^\n]{0,200}(?:&&|;|\|\|)\s*(?:sudo\s+)?chmod\s+"
  r"(?:\+x|[0-7]*[1357][0-7]*\b|[ugoa]+\+x)",
  confidence="high", caps=("download", "execute"), hints=("chmod",))

R("EXEC-DOWNLOAD-EXECUTABLE", "Downloads an executable / script / archive from a URL", "remote-exec", "high",
  r"(?:\b" + DL + r"\b|downloadfile|urlretrieve|start-bitstransfer|requests\.get|urlopen)[^\n]{0,300}"
  r"https?://[^\s'\"<>]+\.(?:exe|dll|scr|msi|bat|cmd|ps1|vbs|hta|sh|bash|command|py|jar|apk|dmg|pkg|app|zip|7z|rar|"
  r"tar\.gz|tgz|bin|elf|so|dylib|deb|rpm|appimage)\b",
  confidence="medium", caps=("download",))

R("EXEC-LOLBIN-CERTUTIL", "certutil used to download or decode (LOLBin)", "remote-exec", "high",
  r"\bcertutil(?:\.exe)?\s+[^\n]{0,80}-(?:urlcache|verifyctl|decode|decodehex)\b", caps=("download", "decode"),
  hints=("certutil",))
R("EXEC-LOLBIN-BITSADMIN", "bitsadmin file transfer (LOLBin)", "remote-exec", "high",
  r"\bbitsadmin(?:\.exe)?\s+[^\n]{0,80}/transfer\b", caps=("download",), hints=("bitsadmin",))
R("EXEC-LOLBIN-MSHTA", "mshta executing remote or inline script", "remote-exec", "critical",
  r"\bmshta(?:\.exe)?\s+[^\n]{0,20}(?:https?:|javascript:|vbscript:|\\\\)", confidence="high",
  caps=("download", "execute"), hints=("mshta",))
R("EXEC-LOLBIN-REGSVR32", "regsvr32 scriptlet execution (Squiblydoo)", "remote-exec", "critical",
  r"\bregsvr32(?:\.exe)?\s+[^\n]{0,80}/i:\s*https?:", confidence="high", caps=("download", "execute"),
  hints=("regsvr32",))
R("EXEC-LOLBIN-RUNDLL32", "rundll32 proxy execution", "remote-exec", "high",
  r"\brundll32(?:\.exe)?\s+[^\n]{0,120}(?:javascript:|url\.dll|shell32\.dll,\s*ShellExec_RunDLL|advpack|ieadvpack|"
  r"zipfldr|pcwutl|,\s*#\d+|\\\\)", caps=("execute",), hints=("rundll32",))
R("EXEC-LOLBIN-MSIEXEC", "msiexec installing a package from a URL", "remote-exec", "high",
  r"\bmsiexec(?:\.exe)?\s+[^\n]{0,80}/(?:i|package)\s*https?:", caps=("download", "execute"), hints=("msiexec",))
R("EXEC-LOLBIN-WMIC", "wmic process creation", "dynamic-exec", "high",
  r"\bwmic(?:\.exe)?\s+[^\n]{0,80}process\s+call\s+create", caps=("execute",), hints=("wmic",))
R("EXEC-LOLBIN-PROXY", "Signed-binary proxy execution tool (LOLBin)", "dynamic-exec", "medium",
  r"\b(?:cmstp|installutil|regasm|regsvcs|msbuild|odbcconf|forfiles|pcalua|mavinject|msxsl|wscript|cscript|"
  r"syncappvpublishingserver|presentationhost|ieexec|hh)(?:\.exe)?\s+\S", confidence="low", caps=("execute",),
  refs=("ATT&CK T1218",))
R("EXEC-NET-WEBCLIENT", ".NET WebClient / BITS download", "remote-exec", "medium",
  r"(?:New-Object\s+(?:System\.)?Net\.WebClient|\[System\.Net\.WebClient\])[^\n]{0,120}\.Download(?:File|String|Data)"
  r"|\bStart-BitsTransfer\b", caps=("download",), hints=("webclient", "bitstransfer"))

# ==========================================================================
# 2. Dynamic execution
# ==========================================================================

R("EXEC-EVAL", "Dynamic code evaluation (eval/exec)", "dynamic-exec", "medium",
  r"(?<![\w.$])(?:exec|eval)\s*\(", confidence="low", caps=("execute",),
  kinds=CODE | {"decoded", "json"}, hints=("exec", "eval"), max_hits=5,
  description="Dynamic evaluation is how obfuscated payloads are usually run. Check what is passed in.")
R("EXEC-EVAL-DOC", "eval/exec mentioned in documentation", "dynamic-exec", "low",
  r"(?<![\w.$])(?:exec|eval)\s*\(", confidence="low", caps=("execute",), kinds={"markdown", "text"},
  hints=("exec", "eval"), max_hits=3)
R("EXEC-PY-COMPILE", "Python compile() of code for exec", "dynamic-exec", "medium",
  r"\bcompile\s*\([^\n]{0,160}['\"]exec['\"]", caps=("execute",), kinds=PY, hints=("compile",))
R("EXEC-PY-DYNAMIC-IMPORT", "Dynamic import of a module name", "dynamic-exec", "low",
  r"\b__import__\s*\(|\bimportlib\.import_module\s*\(\s*(?![\"'])", caps=("execute",), kinds=PY,
  hints=("__import__", "import_module"))
R("EXEC-PY-OS-SYSTEM", "os.system / os.popen / os.exec* shell command", "dynamic-exec", "medium",
  r"\bos\.(?:system|popen|exec[lv]p?e?|spawn[lv]p?e?|posix_spawnp?)\s*\(", caps=("execute",), kinds=PY,
  hints=("os.",))
R("EXEC-PY-SUBPROCESS-SHELL", "subprocess call with shell=True", "dynamic-exec", "medium",
  r"\bsubprocess\.\w+\([^\n]{0,300}shell\s*=\s*True", caps=("execute",), kinds=PY, hints=("shell",))
R("EXEC-PY-SUBPROCESS", "subprocess usage (runs external commands)", "dynamic-exec", "info",
  r"\bsubprocess\.(?:run|call|check_call|check_output|Popen|getoutput|getstatusoutput)\s*\(", confidence="high",
  caps=("execute",), kinds=PY, hints=("subprocess",), max_hits=3)
R("EXEC-PY-PTY", "pty.spawn (interactive shell spawning)", "dynamic-exec", "high",
  r"\bpty\.spawn\s*\(", caps=("execute", "remote-control"), kinds=PY, hints=("pty",))
R("EXEC-PY-MARSHAL", "marshal.loads of code objects", "obfuscation", "high",
  r"\bmarshal\.loads\s*\(", caps=("decode", "execute"), kinds=PY, hints=("marshal",))
R("EXEC-DESERIALIZE", "Unsafe deserialisation (pickle/dill/joblib/shelve)", "dynamic-exec", "medium",
  r"\b(?:pickle|cPickle|_pickle|dill|joblib|shelve|cloudpickle)\.(?:loads?|Unpickler|open)\s*\(|\btorch\.load\s*\("
  r"(?![^\n]*weights_only\s*=\s*True)", caps=("execute",), kinds=PY, hints=("pickle", "dill", "joblib", "shelve", "torch"))
R("EXEC-PY-YAML-UNSAFE", "yaml.load without SafeLoader", "dynamic-exec", "medium",
  r"\byaml\.(?:load|unsafe_load|full_load|load_all)\s*\((?![^\n]*Safe)", caps=("execute",), kinds=PY, hints=("yaml",))
R("EXEC-MEMORY-INJECTION", "Executable-memory / process-injection API", "dynamic-exec", "high",
  r"\b(?:VirtualAlloc(?:Ex)?|VirtualProtect(?:Ex)?|RtlMoveMemory|CreateRemoteThread|WriteProcessMemory|"
  r"NtCreateThreadEx|QueueUserAPC|NtMapViewOfSection|PAGE_EXECUTE_READWRITE|PROT_EXEC|SetThreadContext)\b",
  caps=("execute",), refs=("ATT&CK T1055",),
  description="APIs used by shellcode loaders and process injection. Skills have no legitimate need for them.")
R("EXEC-JS-FUNCTION", "new Function / vm.run* dynamic JavaScript", "dynamic-exec", "medium",
  r"\bnew\s+Function\s*\(|\bvm\.(?:runInNewContext|runInThisContext|runInContext|compileFunction)\b|\bnew\s+vm\.Script\b",
  confidence="low", caps=("execute",), kinds=JS, hints=("function", "vm."))
R("EXEC-JS-CHILD-PROCESS", "Node child_process usage", "dynamic-exec", "low",
  r"require\(\s*['\"](?:node:)?child_process['\"]\s*\)|from\s+['\"](?:node:)?child_process['\"]|"
  r"\b(?:execSync|spawnSync|execFileSync)\s*\(|\bshell\s*:\s*true\b",
  caps=("execute",), kinds=JS, hints=("child_process", "sync(", "shell"), max_hits=3)
R("EXEC-SHELL-EVAL", "Shell eval of a variable or substitution", "dynamic-exec", "low",
  r"(?:^|[;&|][ \t]*)eval\s+[\"']?\$", flags=re.I | re.M, caps=("execute",),
  kinds={"shell", "markdown", "text", "makefile", "dockerfile", "decoded"}, hints=("eval",))
R("EXEC-PS-IEX", "PowerShell Invoke-Expression", "dynamic-exec", "high",
  r"\binvoke-expression\b|\|\s*iex\b|(?<![\w$.-])iex\s*[\(\$\"'{]", caps=("execute",), kinds=PS | CODE,
  hints=("iex", "invoke-expression"))
R("EXEC-PS-ENCODED", "PowerShell -EncodedCommand (base64 hidden command)", "obfuscation", "high",
  r"(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,160}\s[-/](?:e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s+"
  r"[A-Za-z0-9+/=]{16,}", confidence="high", caps=("decode", "execute", "obfuscation"),
  hints=("powershell", "pwsh"))
R("EXEC-PS-POLICY-BYPASS", "PowerShell execution-policy bypass", "defense-evasion", "medium",
  r"-(?:ep|exec|executionpolicy)\s+(?:bypass|unrestricted)\b|set-executionpolicy\s+(?:-\w+\s+)*(?:bypass|unrestricted)",
  caps=("evasion",), hints=("bypass", "unrestricted"))
R("EXEC-PS-HIDDEN-WINDOW", "PowerShell launched with a hidden window", "concealment", "high",
  r"(?:powershell|pwsh)[^\n]{0,200}\s-w(?:indowstyle|in|indow)?\s+(?:hidden|h\b|1\b)|"
  r"Start-Process[^\n]{0,160}-WindowStyle\s+Hidden", caps=("conceal", "execute"), hints=("hidden", " -w"))
R("EXEC-PS-REFLECTION", "Reflective .NET assembly loading", "dynamic-exec", "high",
  r"\[(?:System\.)?Reflection\.Assembly\]::(?:Load|LoadFile|LoadFrom|UnsafeLoadFrom)\s*\(", caps=("execute",),
  hints=("reflection",))
R("EXEC-PS-DLLIMPORT", "P/Invoke of native Windows APIs from script", "dynamic-exec", "medium",
  r"DllImport\s*\(\s*[\"'](?:kernel32|ntdll|user32|advapi32|amsi)", caps=("execute",), hints=("dllimport",))
R("EXEC-WSH-OBJECTS", "Windows Script Host shell / download objects", "dynamic-exec", "medium",
  r"CreateObject\(\s*[\"'](?:WScript\.Shell|Shell\.Application|MSXML2\.(?:Server)?XMLHTTP|ADODB\.Stream|"
  r"WinHttp\.WinHttpRequest)", caps=("execute",), hints=("createobject",))
R("EXEC-APPLESCRIPT-ADMIN", "AppleScript shell command with administrator privileges", "privilege-escalation", "high",
  r"do\s+shell\s+script[^\n]{0,300}with\s+administrator\s+privileges", caps=("execute", "privesc"),
  hints=("administrator",))
R("EXEC-OSASCRIPT", "osascript command execution", "dynamic-exec", "low",
  r"\bosascript\s+(?:-l\s+\w+\s+)?-e\b", caps=("execute",), hints=("osascript",))

# ==========================================================================
# 3. Obfuscation
# ==========================================================================

R("OBF-DECODE-EXEC", "Decode-then-execute (base64/atob/FromBase64String into exec)", "obfuscation", "critical",
  r"(?:\bexec|\beval|\bFunction|\biex|invoke-expression|\bsh|\bbash|\bpython[0-9.]*|\bnode)\b[^\n]{0,120}"
  r"(?:b64decode|base64\.(?:decodebytes|decodestring|standard_b64decode|urlsafe_b64decode)|base64\s+-{1,2}d(?:ecode)?\b|"
  r"\batob\s*\(|Buffer\.from\([^\n]{0,200}['\"]base64['\"]|FromBase64String|codecs\.decode)"
  r"|(?:base64\s+(?:-d|--decode|-D)\b|b64decode|\batob\s*\(|FromBase64String)[^\n]{0,200}"
  r"(?:\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\|\s*python|\bexec\b|\beval\b|\|\s*iex\b|invoke-expression)",
  confidence="high", caps=("decode", "execute", "obfuscation"),
  hints=("b64decode", "base64", "atob", "frombase64string", "codecs.decode"))
R("OBF-DECOMPRESS-EXEC", "exec/eval of decompressed data", "obfuscation", "critical",
  r"\b(?:exec|eval)\s*\([^\n]{0,120}(?:zlib|gzip|bz2|lzma)\.decompress", confidence="high",
  caps=("decode", "execute", "obfuscation"), hints=("decompress",))
R("OBF-ROT13", "ROT13 decoding of strings", "obfuscation", "high",
  r"codecs\.(?:decode|encode)\([^\n]{0,200}['\"]rot[_-]?13['\"]|\btr\s+['\"]?A-Za-z['\"]?\s+['\"]?N-ZA-Mn-za-m",
  caps=("decode", "obfuscation"), hints=("rot", "n-za-m"))
R("OBF-CHARCODE-JS", "String built from char codes (String.fromCharCode)", "obfuscation", "medium",
  r"String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){6,}", caps=("decode", "obfuscation"), hints=("fromcharcode",))
R("OBF-CHARCODE-PY", "String built from chr() chains", "obfuscation", "medium",
  r"(?:chr\(\s*\d+\s*\)\s*\+\s*){6,}", caps=("decode", "obfuscation"), hints=("chr(",))
R("OBF-CHARCODE-PS", "String built from [char] casts", "obfuscation", "medium",
  r"(?:\[char\]\s*0?x?[0-9a-f]+\s*[+,]\s*){6,}", caps=("decode", "obfuscation"), hints=("[char]",))
R("OBF-HEX-ESCAPES", "Long run of \\x hex escapes", "obfuscation", "medium",
  r"(?:\\x[0-9a-fA-F]{2}){16,}", caps=("decode", "obfuscation"), hints=("\\x",))
R("OBF-UNICODE-ESCAPES", "Long run of \\u escapes", "obfuscation", "medium",
  r"(?:\\u00[0-9a-fA-F]{2}){12,}", caps=("decode", "obfuscation"), hints=("\\u00",))
R("OBF-JS-OBFUSCATOR", "javascript-obfuscator style identifiers (_0x...)", "obfuscation", "high",
  r"\b_0x[0-9a-f]{4,6}\b", min_count=10, caps=("obfuscation",), hints=("_0x",),
  description="Many _0xNNNN identifiers indicate machine obfuscation designed to defeat review.")
R("OBF-JSFUCK", "JSFuck / symbol-only JavaScript", "obfuscation", "high",
  r"[\[\]\(\)!+]{80,}", caps=("obfuscation",), kinds=JS | {"decoded"})
R("OBF-PS-TICKS", "PowerShell backtick-obfuscated keyword", "obfuscation", "medium",
  r"\b(?:[A-Za-z]`){3,}[A-Za-z]", caps=("obfuscation",), kinds=PS, hints=("`",))
R("OBF-STRING-CONCAT", "Keyword split into many concatenated fragments", "obfuscation", "low",
  r"\(\s*['\"][\w.-]{1,5}['\"]\s*\+\s*['\"][\w.-]{1,5}['\"]\s*(?:\+\s*['\"][\w.-]{1,5}['\"]\s*){2,}\)",
  caps=("obfuscation",))
R("OBF-STRING-REVERSE", "Reversed string literal (decoded by the scanner)", "obfuscation", "medium",
  r"[\"'][^\"'\n]{8,}[\"']\s*\[\s*::\s*-1\s*\]|\.split\(\s*['\"]{2}\s*\)\.reverse\(\)\.join\(|"
  r"-join\s*\(?\s*\$\w+\[\s*-1\s*\.\.", caps=("obfuscation",), hints=("::-1", "reverse", "-join"))
R("OBF-IFS", "Shell $IFS word-splitting obfuscation", "obfuscation", "medium",
  r"\$\{IFS\}|\$IFS\$\d", caps=("obfuscation",), hints=("ifs",))
R("OBF-BASE64-DECODE", "Base64 decoding at runtime", "obfuscation", "low",
  r"\bbase64\s+(?:-d|--decode|-D)\b|\bb64decode\s*\(|\batob\s*\(|FromBase64String|"
  r"Buffer\.from\([^\n]{0,200}['\"]base64['\"]", caps=("decode",),
  hints=("base64", "b64decode", "atob"), max_hits=4)
R("OBF-SHELLCODE-ARRAY", "Large numeric byte array (possible shellcode)", "obfuscation", "medium",
  r"(?:0x[0-9a-fA-F]{2}\s*,\s*){64,}", caps=("obfuscation",), hints=("0x",))

# ==========================================================================
# 4. Network / exfiltration
# ==========================================================================

R("NET-HTTP-POST-PY", "Python HTTP POST/PUT (outbound data)", "network", "low",
  r"\b(?:requests|httpx|session|client)\.(?:post|put|patch)\s*\(|urllib\.request\.Request\([^\n]{0,200}data\s*=",
  caps=("network", "network-send"), kinds=PY, hints=("post", "put", "patch", "data"), max_hits=4)
R("NET-HTTP-POST-JS", "JavaScript HTTP POST/PUT / sendBeacon", "network", "low",
  r"\bfetch\s*\([^\n]{0,300}method\s*:\s*['\"](?:POST|PUT|PATCH)|\baxios\.(?:post|put|patch)\s*\(|"
  r"\.sendBeacon\s*\(|XMLHttpRequest[^\n]{0,200}\.send\(", caps=("network", "network-send"), kinds=JS,
  hints=("post", "put", "patch", "beacon", "xmlhttprequest"), max_hits=4)
R("NET-CURL-UPLOAD", "curl/wget uploading data or files", "network", "medium",
  r"\bcurl\b[^\n]{0,300}\s(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file|-X\s*(?:POST|PUT))\b|"
  r"\bwget\b[^\n]{0,300}--post-(?:data|file)", caps=("network", "network-send"), hints=("curl", "wget"))
R("NET-PS-UPLOAD", "PowerShell / .NET upload", "network", "medium",
  r"invoke-(?:webrequest|restmethod)[^\n]{0,300}-method\s+(?:post|put)|\.Upload(?:String|File|Data)\s*\(",
  caps=("network", "network-send"), hints=("invoke-", "upload"))
R("NET-HTTP-CLIENT", "Outbound HTTP request", "network", "info",
  r"\brequests\.(?:get|request)\s*\(|\burlopen\s*\(|\burlretrieve\s*\(|\bhttpx\.(?:get|AsyncClient|Client)\b|"
  r"\bfetch\s*\(\s*[`'\"]https?:|\baxios\.get\s*\(|\bhttps?\.(?:get|request)\s*\(|\bcurl\s+[^\n]{0,80}https?://|"
  r"\bwget\s+[^\n]{0,80}https?://|\binvoke-(?:webrequest|restmethod)\b|\biwr\s+|\birm\s+https?:",
  confidence="high", caps=("network", "download"), max_hits=4,
  hints=("requests", "urlopen", "urlretrieve", "httpx", "fetch", "axios", "http", "curl", "wget", "invoke-", "iwr", "irm"))
R("NET-RAW-SOCKET", "Raw socket / WebSocket connection", "network", "low",
  r"\bsocket\.socket\s*\(|\bsocket\.create_connection\s*\(|\bnet\.(?:connect|createConnection)\s*\(|"
  r"\bnew\s+net\.Socket\b|\bnew\s+WebSocket\s*\(|Net\.Sockets\.(?:TcpClient|UdpClient|Socket)",
  caps=("network",), hints=("socket", "net."))
R("NET-DNS-EXFIL", "DNS lookup built from data (DNS exfiltration)", "exfiltration", "high",
  r"(?:^|[;&|`(]\s*|\$\(\s*)(?:nslookup|dig|host|ping)(?:\s+-[\w.-]+(?:\s+\d+)?)*\s+[^\s;|&]*(?:\$\(|\$\{|\$[A-Za-z_])"
  r"[^\s;|&]*|\bgethostbyname\s*\([^\n]{0,80}(?:\+|f[\"']|\.format\(|%)", flags=re.I | re.M,
  caps=("network", "network-send"), hints=("nslookup", "dig", "host", "ping", "gethostbyname"),
  description="Data smuggled in a hostname leaks via DNS even when HTTP egress is blocked (CVE-2025-55284).")
R("NET-EMAIL-SEND", "Sends e-mail (possible exfiltration channel)", "exfiltration", "medium",
  r"\bsmtplib\.SMTP(?:_SSL)?\s*\(|\bnodemailer\b|\bSend-MailMessage\b|\bsendmail\s+-|\bmail\s+-s\s",
  caps=("network", "network-send"), hints=("smtp", "nodemailer", "mail"))
R("NET-REMOTE-COPY", "scp/rsync/sftp/ftp transfer to a remote host", "exfiltration", "medium",
  r"\b(?:scp|rsync|sftp)\b[^\n]{0,200}\s\S+@[\w.-]+:|\bftplib\.FTP\s*\(|\bftp\s+-[inv]+\s",
  caps=("network", "network-send"), hints=("scp", "rsync", "sftp", "ftp"))
R("NET-NETCAT", "netcat connection", "network", "medium",
  r"\b(?:nc|ncat|netcat)(?:\.exe)?\s+(?:-[a-zA-Z]+\s+)*(?:\d{1,3}\.){3}\d{1,3}\s+\d{2,5}\b|"
  r"\|\s*(?:nc|ncat|netcat)\s+[\w.-]+\s+\d{2,5}\b", caps=("network", "network-send"), hints=("nc", "netcat"))
R("NET-MD-IMAGE-EXFIL", "Markdown image URL with templated query (render-time exfiltration)", "exfiltration", "high",
  r"!\[[^\]\n]{0,200}\]\(\s*https?://[^)\s]{0,300}[?&][^)\s=]{1,40}=[^)\s]{0,60}(?:\{|\$\{|%7B|<[A-Za-z_]|\[[A-Z_]{3,})",
  caps=("network-send",), kinds={"markdown", "text", "html", "decoded"}, hints=("!["),
  description="Images are fetched automatically when markdown is rendered; templated query strings leak data.")
R("NET-IP-LOOKUP", "Public-IP / geolocation lookup service", "recon", "medium",
  r"\b(?:api\.ipify\.org|ipinfo\.io|ifconfig\.me|icanhazip\.com|ip-api\.com|checkip\.amazonaws\.com|ipecho\.net|"
  r"myexternalip\.com|wtfismyip\.com|ident\.me|ipapi\.co|ifconfig\.co|geoplugin\.net)\b", caps=("recon", "network"))

# ==========================================================================
# 5. Credential & secret access
# ==========================================================================

R("CRED-SSH", "Access to SSH keys / config", "credential-access", "high",
  r"[/\\]\.ssh[/\\](?:id_|identity|config\b|authorized_keys|known_hosts|\*)|\bid_(?:rsa|dsa|ecdsa|ed25519)\b(?!\.pub)|"
  r"~[/\\]\.ssh\b|\$HOME[/\\]\.ssh\b|expanduser\(\s*['\"]~[/\\]\.ssh", caps=("read-secrets",),
  hints=(".ssh", "id_"))
R("CRED-CLOUD", "Access to cloud provider credentials", "credential-access", "high",
  r"[/\\]\.aws[/\\](?:credentials|config)\b|[/\\]\.azure[/\\]|[/\\]\.config[/\\]gcloud\b|"
  r"application_default_credentials\.json|[/\\]\.kube[/\\]config\b|[/\\]\.docker[/\\]config\.json|"
  r"[/\\]\.terraform\.d[/\\]credentials|[/\\]\.oci[/\\]config|[/\\]\.config[/\\]doctl|[/\\]\.boto\b",
  caps=("read-secrets",), hints=(".aws", ".azure", "gcloud", "application_default", ".kube", ".docker", ".terraform", ".oci", "doctl", ".boto"))
R("CRED-DEV-TOKENS", "Access to developer token files (.npmrc, .pypirc, .netrc, git-credentials)", "credential-access",
  "high",
  r"[/\\]\.npmrc\b|[/\\]\.pypirc\b|[/\\]_?\.?netrc\b|[/\\]\.git-credentials\b|[/\\]\.config[/\\]gh[/\\]hosts\.yml|"
  r"[/\\]\.gem[/\\]credentials|[/\\]\.cargo[/\\]credentials|[/\\]\.composer[/\\]auth\.json|[/\\]\.m2[/\\]settings\.xml|"
  r"[/\\]\.gradle[/\\]gradle\.properties|[/\\]\.config[/\\]hub\b", caps=("read-secrets",),
  hints=("npmrc", "pypirc", "netrc", "git-credentials", "hosts.yml", "credentials", "auth.json", "settings.xml", "gradle", "hub"))
R("CRED-AGENT-TOKENS", "Access to AI-agent auth tokens", "credential-access", "critical",
  r"[/\\]\.claude[/\\]\.credentials\.json|[/\\]\.codex[/\\]auth\.json|[/\\]\.(?:openclaw|clawdbot|moltbot)[/\\][^\s'\"]{0,60}"
  r"(?:credential|auth|token|\.env)|[/\\]\.config[/\\](?:github-copilot|openai|anthropic)[/\\]|"
  r"[/\\]\.gemini[/\\](?:oauth_creds|credentials|google_accounts)", confidence="high", caps=("read-secrets",),
  hints=(".claude", ".codex", "openclaw", "clawdbot", "moltbot", "copilot", "openai", "anthropic", ".gemini"))
R("CRED-BROWSER", "Access to browser credential / cookie stores", "credential-access", "critical",
  r"(?:User Data|Default|Profile \d+)[/\\](?:Login Data|Web Data|Cookies|Network[/\\]Cookies)|[/\\]Local State\b|"
  r"\b(?:key[34]\.db|logins\.json|cookies\.sqlite|signons\.sqlite|formhistory\.sqlite)\b|"
  r"(?:Google[/\\]Chrome|Chromium|BraveSoftware[/\\]Brave-Browser|Microsoft[/\\]Edge|Opera Software|Vivaldi|"
  r"Yandex[/\\]YandexBrowser|Arc[/\\]User Data)[/\\]|Firefox[/\\]Profiles|\.mozilla[/\\]firefox|"
  r"Library[/\\]Cookies|Safari[/\\](?:Cookies|LocalStorage)|Cookies\.binarycookies", confidence="high",
  caps=("read-secrets",), refs=("ATT&CK T1555.003", "ATT&CK T1539"),
  description="Infostealers (AMOS, Lumma, RedLine...) target these exact paths.")
R("CRED-KEYCHAIN", "macOS Keychain dumping / password verification", "credential-access", "critical",
  r"\bsecurity\s+(?:find-generic-password|find-internet-password|dump-keychain|export|unlock-keychain)\b|"
  r"Library[/\\]Keychains|login\.keychain(?:-db)?\b|\bdscl\s+\.\s+-authonly|\bchainbreaker\b",
  confidence="high", caps=("read-secrets",), refs=("ATT&CK T1555.001",),
  hints=("security", "keychain", "dscl", "chainbreaker"))
R("CRED-KEYRING", "OS keyring access", "credential-access", "low",
  r"\bkeyring\.get_password\s*\(|\bkeytar\.getPassword\s*\(|\bsecret-tool\s+lookup\b", caps=("read-secrets",),
  hints=("keyring", "keytar", "secret-tool"))
R("CRED-WINDOWS", "Windows credential store / LSASS / SAM access", "credential-access", "critical",
  r"\bcmdkey\s+/list|\bvaultcmd\b|\bCredEnumerate\w*|\bCryptUnprotectData\b|ProtectedData\]::Unprotect|"
  r"\breg(?:\.exe)?\s+save\s+hklm\\(?:sam|system|security)\b|\blsass(?:\.exe|\.dmp)?\b|\bprocdump[^\n]{0,40}lsass|"
  r"\bmimikatz\b|\bsekurlsa\b|comsvcs(?:\.dll)?[^\n]{0,40}minidump|\bNTDS\.dit\b",
  confidence="high", caps=("read-secrets",), refs=("ATT&CK T1003",))
R("CRED-SHADOW", "Access to /etc/shadow or sudoers", "credential-access", "high",
  r"/etc/(?:shadow|gshadow|master\.passwd)\b|/etc/security/opasswd", caps=("read-secrets",),
  hints=("/etc/",))
R("CRED-GPG", "Access to GPG private keys", "credential-access", "high",
  r"[/\\]\.gnupg[/\\]|\bsecring\.gpg\b|private-keys-v1\.d|gpg\s+--export-secret-keys", caps=("read-secrets",),
  hints=("gnupg", "secring", "private-keys", "export-secret"))
R("CRED-WALLETS", "Access to cryptocurrency wallets / wallet extensions", "crypto-theft", "critical",
  r"\bwallet\.dat\b|[/\\](?:Exodus|Electrum|Atomic|Ethereum[/\\]keystore|Bitcoin|Monero|Coinomi|Guarda|Jaxx|"
  r"Ledger Live|Trezor|Wasabi|Zcash|Armory)[/\\]|\.electrum[/\\]wallets|exodus\.wallet|"
  r"nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|hnfanknocfeofbddgcijnmhnfnkdnaad|"
  r"ibnejdfjmmkpcnlpebklmnkoeoihofec|fhbohimaelbohpjbbldcngcnapndodjp|egjidjbpglichdcondbcbdnbeeppgdph|"
  r"aholpfdialjgjfhomihkjbmgjidlcdno|[/\\]\.config[/\\]solana[/\\]id\.json|[/\\]\.foundry[/\\]keystores",
  confidence="high", caps=("read-secrets",), refs=("ATT&CK T1005",),
  description="Wallet files and browser-extension IDs (MetaMask, Phantom, Coinbase, TronLink, Binance, "
              "Trust, Exodus Web3) targeted by crypto stealers.")
R("CRED-SEED-EXFIL", "Seed / recovery phrase collection or transmission", "crypto-theft", "critical",
  r"\b(?:seed|recovery|mnemonic|secret)\s+(?:phrase|words)\b[^\n]{0,80}\b(?:send|post|upload|submit|enter|paste|"
  r"provide|share|forward|collect)\b|\b(?:send|post|upload|submit|enter|paste|provide|share)\b[^\n]{0,60}"
  r"\b(?:seed|recovery|mnemonic)\s+(?:phrase|words)\b", caps=("read-secrets", "social-engineering"),
  hints=("phrase", "words"))
R("CRED-MESSAGING-TOKENS", "Discord / Telegram / Slack session-token theft paths", "credential-access", "critical",
  r"discord(?:canary|ptb)?[/\\]Local Storage[/\\]leveldb|Telegram Desktop[/\\]tdata|Slack[/\\](?:Cookies|storage)|"
  r"\bdiscord[^\n]{0,40}token[^\n]{0,40}(?:leveldb|grab|steal)", confidence="high", caps=("read-secrets",),
  hints=("discord", "telegram", "slack"))
R("CRED-DOTENV-READ", "Reads .env files", "credential-access", "medium",
  r"(?:\bopen|read_text|readFile(?:Sync)?|\bcat|\btype|Get-Content|load_dotenv|dotenv_values|dotenv\.config)\s*\(?"
  r"[^\n]{0,60}['\"\s(][^\s'\"()]{0,80}\.env\b(?![.\w-]*example)", caps=("read-secrets",), hints=(".env",))
R("CRED-ENV-HARVEST", "Serialises / prints / ships the whole environment (API keys live here)", "credential-access",
  "medium",
  r"(?:json\.dumps?|str|repr|print|pprint|yaml\.dump|pickle\.dumps?|\.write|base64\.b64encode|send|post)\s*\(\s*"
  r"(?:dict\(\s*)?os\.environ\b|\bos\.environ\b[^\n]{0,40}\b(?:requests\.|urlopen|\.post\(|\.send\()|"
  r"JSON\.stringify\(\s*process\.env\s*\)|(?:^|[;&|][ \t]*)(?:printenv|env)[ \t]*(?:$|\|\s|>)|\$\(\s*(?:printenv|env)\s*\)|"
  r"Get-ChildItem\s+env:|\bgci\s+env:|\bdir\s+env:|\[Environment\]::GetEnvironmentVariables\(\)|"
  r"(?:^|[;&|][ \t]*)set\s*>\s*\S+|/proc/self/environ",
  flags=re.I | re.M, caps=("read-secrets",), hints=("environ", "process.env", "env", "environment", "set"))
R("CRED-ENV-ITERATE", "Iterates over all environment variables", "credential-access", "info",
  r"\bos\.environ\.(?:items|keys|values)\(\)|Object\.(?:entries|keys|values)\(\s*process\.env\s*\)",
  confidence="low", caps=(), hints=("environ", "process.env"), max_hits=2,
  description="Usually benign (filtering the environment for a subprocess); suspicious only next to network sends.")
R("CRED-API-KEY-ENV", "Reads AI / cloud API-key environment variables", "credential-access", "info",
  r"\b(?:ANTHROPIC|OPENAI|CLAUDE|AWS_SECRET|AWS_SESSION|GITHUB|GH|GITLAB|NPM|PYPI|HF|HUGGINGFACE|HUGGING_FACE|STRIPE|"
  r"SLACK|DISCORD|TELEGRAM|GOOGLE|GEMINI|AZURE|OPENROUTER|GROQ|MISTRAL|COHERE|REPLICATE|VERCEL|CLOUDFLARE)_?"
  r"(?:API_?KEY|TOKEN|SECRET(?:_ACCESS_KEY)?|ACCESS_TOKEN|AUTH_TOKEN)\b", flags=0, confidence="high",
  caps=("secret-env",), max_hits=3)
R("CRED-PATH-JOIN", "Builds a path into a credential directory (pathlib / path.join style)", "credential-access", "high",
  r"(?:Path\.home\(\)|expanduser\([^)\n]{0,40}\)|environ\[[\"'](?:HOME|USERPROFILE|APPDATA)[\"']\]|"
  r"getenv\([\"'](?:HOME|USERPROFILE|APPDATA)[\"']\)|homedir\(\)|\bHOME\b|\$env:USERPROFILE|path\.join\()"
  r"[^\n]{0,120}[\"']\.(?:ssh|aws|azure|gnupg|kube|docker|clawdbot|openclaw|moltbot|codex|git-credentials|npmrc|pypirc|"
  r"netrc|bash_history|zsh_history|electrum|ethereum)[\"']", flags=0, confidence="high", caps=("read-secrets",),
  hints=(".ssh", ".aws", ".azure", ".gnupg", ".kube", ".docker", ".clawdbot", ".openclaw", ".moltbot", ".codex",
         ".git-credentials", ".npmrc", ".pypirc", ".netrc", "history", ".electrum", ".ethereum"),
  description="Credential paths assembled from components evade simple '~/.aws/credentials' string searches.")
R("CRED-PROC-ENVIRON", "Reads /proc/*/environ (other processes' secrets)", "credential-access", "high",
  r"/proc/(?:self|\d+|\*|\$\w+|\{[^}]{1,20}\})/environ\b|/proc/[^\s'\"]{0,20}/(?:mem|maps|cmdline)\b",
  caps=("read-secrets",), hints=("/proc/",))
R("CRED-SHELL-HISTORY", "Reads shell / REPL history files", "credential-access", "high",
  r"[/\\]\.(?:bash|zsh|sh|python|node_repl|psql|mysql|sqlite|rediscli|lesshst)_?history\b|ConsoleHost_history\.txt",
  caps=("read-secrets",), hints=("history",))
R("CRED-PASSWORD-MANAGERS", "Access to password-manager vaults", "credential-access", "critical",
  r"\.kdbx\b|1Password[/\\]|\bop\s+(?:item\s+get|read)\s|Bitwarden[/\\]|\bbw\s+(?:get|export)\b|"
  r"LastPass|KeePass(?:XC)?[/\\]|Dashlane", confidence="low", caps=("read-secrets",),
  hints=("kdbx", "1password", "op ", "bitwarden", "bw ", "lastpass", "keepass", "dashlane"))
R("CRED-FILE-SWEEP", "Sweeps the home directory / filesystem for files", "recon", "high",
  r"os\.walk\s*\(\s*(?:os\.path\.expanduser\(\s*['\"]~['\"]\s*\)|['\"](?:/|~|C:\\\\)['\"]|Path\.home\(\)|"
  r"os\.environ\[['\"](?:HOME|USERPROFILE)['\"]\])|Path\.home\(\)\.r?glob\(|glob\.glob\([^\n]{0,60}"
  r"(?:~|home|Users)[^\n]{0,40}\*\*|\bfind\s+(?:~|/|\$HOME)\s+[^\n]{0,80}-i?name\s+[^\n]{0,40}"
  r"(?:\.pem|\.key|id_rsa|wallet|\.kdbx|\.env|passw|secret|\.doc|\.pdf)|Get-ChildItem\s+[^\n]{0,60}"
  r"(?:\$env:USERPROFILE|~|C:\\)[^\n]{0,60}-Recurse[^\n]{0,80}(?:-Include|-Filter)",
  caps=("read-secrets", "file-sweep"), hints=("walk", "home", "glob", "find", "get-childitem"))
R("CRED-SENSITIVE-GLOB", "Searches for key / certificate / vault file types", "credential-access", "medium",
  r"['\"*]\*?\.(?:kdbx|pem|ppk|p12|pfx|ovpn|rdp|keystore|jks)['\"]", caps=("read-secrets",))

# ==========================================================================
# 6. Persistence
# ==========================================================================

R("PERSIST-SHELL-RC-WRITE", "Writes to shell startup files (.bashrc/.zshrc/profile)", "persistence", "high",
  write_near(SHELL_RC), confidence="high", caps=("persist",),
  hints=("bashrc", "bash_", "zsh", "profile", "config.fish", "environment"))
R("PERSIST-SHELL-RC-REF", "References shell startup files", "persistence", "low",
  SHELL_RC, caps=(), hints=("bashrc", "bash_", "zsh", "profile", "config.fish", "environment"), max_hits=3)
R("PERSIST-CRON", "Installs cron jobs", "persistence", "high",
  r"\|\s*crontab\b|\bcrontab\s+(?:-u\s+\S+\s+)?(?:-\s*$|-\s*<|\S+\.(?:txt|cron)\b)|/etc/cron(?:tab|\.d|\.daily|\.hourly|\.weekly)"
  r"|/var/spool/cron|@reboot\b", flags=re.I | re.M, confidence="high", caps=("persist",),
  hints=("crontab", "cron", "@reboot"))
R("PERSIST-SYSTEMD", "Creates / enables systemd or init services", "persistence", "high",
  r"systemctl\s+(?:--user\s+)?(?:enable|daemon-reload\s*&&\s*systemctl\s+enable)\b|[/\\]\.config[/\\]systemd[/\\]user|"
  r"/etc/systemd/system/\S+\.(?:service|timer)|/etc/init\.d/|/etc/rc\.local|\bupdate-rc\.d\b",
  caps=("persist",), hints=("systemctl", "systemd", "init.d", "rc.local", "update-rc"))
R("PERSIST-LAUNCHD", "macOS LaunchAgent / LaunchDaemon / login item", "persistence", "high",
  r"\blaunchctl\s+(?:load|bootstrap|submit|enable)\b|Library[/\\]Launch(?:Agents|Daemons)|<key>RunAtLoad</key>|"
  r"\bRunAtLoad\b|login\s+items?[^\n]{0,60}(?:osascript|System Events)|make\s+login\s+item",
  caps=("persist",), hints=("launch", "runatload", "login item"))
R("PERSIST-WIN-RUNKEY", "Windows Run keys / Winlogon / startup folder", "persistence", "high",
  r"\\Microsoft\\Windows\\CurrentVersion\\(?:Run|RunOnce|RunServices|Policies\\Explorer\\Run)\b|"
  r"\\Winlogon\\(?:Userinit|Shell)\b|Image File Execution Options|\\AppInit_DLLs|"
  r"Start Menu\\Programs\\Startup|shell:startup|\\Startup\\[^\n]{0,60}\.(?:lnk|bat|cmd|vbs|exe|ps1)",
  confidence="high", caps=("persist",), hints=("currentversion", "winlogon", "image file", "appinit", "startup"))
R("PERSIST-SCHTASKS", "Windows scheduled task creation", "persistence", "high",
  r"\bschtasks(?:\.exe)?\s+/create\b|\bRegister-ScheduledTask\b|\bNew-ScheduledTask(?:Trigger|Action)\b",
  caps=("persist",), hints=("schtasks", "scheduledtask"))
R("PERSIST-WIN-SERVICE", "Windows service creation", "persistence", "high",
  r"\bsc(?:\.exe)?\s+create\s+\S|\bNew-Service\b", caps=("persist",), hints=("sc", "new-service"))
R("PERSIST-WMI", "WMI event subscription persistence", "persistence", "high",
  r"__EventFilter|CommandLineEventConsumer|__FilterToConsumerBinding|\bRegister-WmiEvent\b",
  caps=("persist",), hints=("event", "wmi"))
R("PERSIST-SSH-AUTHKEYS", "Adds a key to authorized_keys (SSH backdoor)", "persistence", "critical",
  write_near(r"authorized_keys"), confidence="high", caps=("persist", "remote-control"), hints=("authorized_keys",))
R("PERSIST-GIT-HOOKS", "Installs git hooks / changes core.hooksPath", "persistence", "high",
  write_near(r"\.git[/\\]hooks[/\\]") + r"|core\.hooksPath(?!\s*=\s*(?:/dev/null|NUL|\"\"|''|\s))|"
  r"\bgit\s+config\s+[^\n]{0,40}core\.fsmonitor(?!\s+(?:false|0))",
  caps=("persist", "execute"), hints=("hooks", "fsmonitor"))
R("PERSIST-INTERPRETER-HOOK", "Interpreter startup hijack (.pth, sitecustomize, NODE_OPTIONS, ld.so.preload)",
  "persistence", "high",
  r"\bsitecustomize\.py\b|\busercustomize\.py\b|site-packages[/\\][^\s'\"]+\.pth\b|\bPYTHONSTARTUP\b|"
  r"NODE_OPTIONS[^\n]{0,40}--(?:require|import|loader)|/etc/ld\.so\.preload",
  caps=("persist", "execute"), hints=("customize", ".pth", "pythonstartup", "node_options", "preload"))
R("PERSIST-LIBRARY-PRELOAD", "Library preloading (LD_PRELOAD / DYLD_INSERT_LIBRARIES)", "defense-evasion", "low",
  r"\bLD_PRELOAD\b|\bDYLD_INSERT_LIBRARIES\b", caps=("execute",), hints=("preload", "dyld"),
  description="Injects a shared library into every process launched with it. Occasionally used legitimately "
              "(e.g. sandbox shims) - verify the library's origin.")
R("PERSIST-GIT-TEMPLATE", "Global git template / hooks hijack", "persistence", "high",
  r"\bgit\s+config\s+--global\s+(?:init\.templateDir|core\.hooksPath|core\.fsmonitor|core\.sshCommand|core\.pager|"
  r"core\.editor|alias\.\w+\s+['\"]?!)|\.git-templates[/\\]hooks", confidence="high", caps=("persist", "execute"),
  hints=("git config", ".git-templates"), description="SANDWORM_MODE planted ~/.git-templates/hooks and set init.templateDir.")
R("PERSIST-ROGUE-MCP-DIR", "Known rogue MCP-server drop locations", "known-ioc", "critical",
  r"[/\\]\.(?:dev-utils|node-analyzer)[/\\]", confidence="medium", caps=("persist", "agent-config"),
  hints=(".dev-utils", ".node-analyzer"), description="Directories used by the SANDWORM_MODE npm worm (CrowdStrike).")
R("PERSIST-BROWSER-EXTENSION", "Force-installs or side-loads browser extensions", "persistence", "high",
  r"--load-extension\b|ExtensionInstallForcelist|ExtensionInstallAllowlist|external_extensions\.json",
  caps=("persist",), hints=("extension",))

# ==========================================================================
# 7. AI agent configuration / memory tampering
# ==========================================================================

R("AGENT-COMMAND-WRITE", "Creates agent slash-commands / sub-agents / skills", "agent-tampering", "medium",
  write_near(r"\.claude[/\\](?:commands|agents|skills)[/\\]"), confidence="medium", caps=("agent-config",),
  hints=(".claude",), description="Adds new agent commands, sub-agents or skills (self-propagation if unexpected).")
R("AGENT-CONFIG-WRITE", "Writes to AI-agent config, rules or memory files", "agent-tampering", "high",
  write_near(AGENT_FILES.replace(r"|commands|agents|skills|hooks|plugins|CLAUDE\.md", r"|hooks|plugins|CLAUDE\.md")),
  confidence="high", caps=("agent-config", "persist"),
  hints=("claude", "agents.md", "gemini", "memory.md", "soul.md", "identity.md", "heartbeat", "bootstrap", "cursor",
         "windsurf", "cline", ".roo", "copilot", "mcp", "codex", "openclaw", "clawdbot", "moltbot", "continue",
         "aider", ".vscode", ".zed", "opencode"),
  description="Modifying agent memory/config makes injected instructions persist into future sessions "
              "(temporal persistence; e.g. ClawHavoc targeting SOUL.md / MEMORY.md).")
R("AGENT-CONFIG-REF", "References AI-agent config, rules or memory files", "agent-tampering", "low",
  AGENT_FILES, caps=(), max_hits=3,
  hints=("claude", "agents.md", "gemini", "memory.md", "soul.md", "identity.md", "heartbeat", "bootstrap", "cursor",
         "windsurf", "cline", ".roo", "copilot", "mcp", "codex", "openclaw", "clawdbot", "moltbot", "continue",
         "aider", ".vscode", ".zed", "opencode"))
R("AGENT-MEMORY-INSTRUCTION", "Instructs the agent to persist instructions into memory / rules", "agent-tampering",
  "high",
  r"\b(?:add|append|write|save|insert|store|put|copy)\s+(?:the\s+following|this|these|it)(?:\s+(?:instructions?|rules?|"
  r"lines?|text|block|section))?\s+(?:permanently\s+)?(?:to|into|in)\s+(?:your\s+|the\s+)?(?:long[- ]term\s+)?"
  r"(?:memory|memories|MEMORY\.md|CLAUDE\.md|AGENTS\.md|SOUL\.md|system\s+prompt|instructions?\s+file|rules?\s+file|"
  r"\.cursorrules|global\s+(?:config|settings|instructions|rules)|user\s+settings)\b|"
  r"\b(?:remember|memori[sz]e)\s+(?:this|the\s+following)\s+(?:for\s+(?:all\s+)?(?:future|later|subsequent)\s+"
  r"(?:sessions?|conversations?|chats?|tasks?)|permanently|forever)",
  caps=("agent-config", "inject"), hints=("memory", "memories", ".md", "prompt", "file", "rules", "settings", "remember", "memori"))
R("AGENT-PERMISSION-BYPASS", "Disables agent permission prompts / sandbox", "agent-tampering", "high",
  r"--dangerously-skip-permissions|dangerouslySkipPermissions|\bbypassPermissions\b|"
  r"[\"']?defaultMode[\"']?\s*[:=]\s*[\"']?(?:bypassPermissions|acceptEdits)|--permission-mode\s+(?:bypassPermissions|acceptEdits)|"
  r"\byolo[_ -]?mode\b|--yolo\b|--full-auto\b|[\"']?autoApprove[\"']?\s*:\s*(?:true|\[)|[\"']?alwaysAllow[\"']?\s*:|"
  r"enableAllProjectMcpServers|--trust-all-tools|approval_policy\s*=\s*[\"']?never|"
  r"sandbox_mode\s*=\s*[\"']?danger-full-access|--dangerously-bypass-approvals-and-sandbox|"
  r"[\"']Bash\(\s*\*?\s*\)[\"']|[\"']Bash\(\*:\*\)[\"']|chat\.tools\.(?:global\.)?autoApprove|"
  r"chat\.permissions\.default|enabledMcpjsonServers|[\"']?skipDangerousModePermissionPrompt[\"']?",
  confidence="high", caps=("agent-config", "evasion"), skip_kinds={"markdown", "text"},
  hints=("dangerously", "bypass", "defaultmode", "permission-mode", "yolo", "full-auto", "autoapprove", "alwaysallow",
         "enableallproject", "trust-all", "approval_policy", "sandbox_mode", "bash(", "chat.", "enabledmcpjson",
         "skipdangerous"),
  description="Seen in real attacks: CVE-2025-53773 (chat.tools.autoApprove), Check Point's Claude Code project-file "
              "research (enableAllProjectMcpServers), and skills invoking --dangerously-skip-permissions.")
R("AGENT-PERMISSION-BYPASS-DOC", "Mentions disabling agent permission prompts / sandbox", "agent-tampering", "medium",
  r"--dangerously-skip-permissions|\bbypassPermissions\b|--yolo\b|--full-auto\b|enableAllProjectMcpServers|"
  r"--dangerously-bypass-approvals-and-sandbox|chat\.tools\.(?:global\.)?autoApprove|skipDangerousModePermissionPrompt",
  confidence="medium", caps=("agent-config",), kinds={"markdown", "text"},
  hints=("dangerously", "bypasspermissions", "yolo", "full-auto", "enableallproject", "autoapprove", "skipdangerous"))
R("AGENT-API-REDIRECT", "Overrides the model API endpoint (traffic / token interception)", "agent-tampering", "high",
  r"\b(?:ANTHROPIC|OPENAI|CLAUDE|GEMINI|AZURE_OPENAI|OPENROUTER)_(?:BASE_URL|API_BASE|API_URL|ENDPOINT)\b\s*[\"']?\s*[:=]"
  r"|\bANTHROPIC_BEDROCK_BASE_URL\b|\bANTHROPIC_VERTEX_BASE_URL\b",
  confidence="medium", caps=("agent-config", "network-send"), hints=("base_url", "api_base", "api_url", "endpoint"),
  refs=("CVE-2025-59536", "CVE-2026-21852", "ATLAS AML.T0083"),
  description="Redirecting the API base URL sends every prompt and the API key to the attacker's proxy.")
R("AGENT-SCHEDULE-TASKS", "Schedules agent tasks / wakeups (agent-level persistence)", "agent-tampering", "medium",
  r"\b(?:CronCreate|ScheduleWakeup|RemoteTrigger|create_scheduled_task)\b|\bschedule\s+(?:a\s+)?(?:recurring|cron|"
  r"daily|hourly)\s+(?:agent|task|job|routine)\b", caps=("persist", "agent-config"),
  hints=("croncreate", "schedulewakeup", "remotetrigger", "scheduled_task", "schedule"))
R("AGENT-HOOKS-DEFINITION", "Defines agent lifecycle hooks (auto-run commands)", "autorun", "medium",
  r"[\"'](?:PreToolUse|PostToolUse|UserPromptSubmit|SessionStart|SessionEnd|Stop|SubagentStop|PreCompact|"
  r"Notification|PermissionRequest)[\"']\s*:|^[ \t]*(?:PreToolUse|PostToolUse|UserPromptSubmit|SessionStart|SessionEnd|"
  r"SubagentStop|PreCompact|PermissionRequest)\s*:", flags=re.M, confidence="high", caps=("agent-config", "execute"),
  kinds={"json", "yaml", "toml", "config", "decoded", "hidden"},
  hints=("pretooluse", "posttooluse", "userpromptsubmit", "sessionstart", "sessionend", "stop", "precompact",
         "notification", "permissionrequest"),
  description="Hooks run shell commands automatically on agent events, without the model deciding to.")
R("AGENT-MCP-REGISTER", "Registers MCP servers", "agent-tampering", "low",
  r"\bclaude\s+mcp\s+add\b|\bcodex\s+mcp\s+add\b|\bgemini\s+mcp\s+add\b|[\"']mcpServers[\"']\s*:",
  caps=("agent-config",), hints=("mcp",))
R("AGENT-SPAWN-UNSAFE", "Spawns an agent CLI with approvals disabled", "agent-tampering", "high",
  r"\bclaude\s+(?:-p|--print)\b[^\n]{0,200}(?:--dangerously|--permission-mode\s+bypass)|"
  r"\bcodex\s+exec\b[^\n]{0,200}(?:--full-auto|--dangerously|--yolo)|\bgemini\b[^\n]{0,80}(?:--yolo|\s-y\b)|"
  r"\bcursor-agent\b[^\n]{0,80}--force", caps=("agent-config", "execute"), hints=("claude", "codex", "gemini", "cursor-agent"))

# ==========================================================================
# 8. Prompt injection / concealment (natural-language)
# ==========================================================================

_NEGATION_BEFORE = re.compile(r"\b(?:never|don'?t|do\s+not|must\s+not|mustn'?t|cannot|can'?t|should\s+not|shouldn'?t|"
                              r"no\s+\w+)\b[^.!?\n]*$", re.I)


def _not_double_negative(m: "re.Match", _line: str) -> bool:
    """'Never write X without telling the user' is a transparency rule, not concealment."""
    if not m.group(0).lower().startswith("without"):
        return True
    start = m.string.rfind("\n", 0, m.start()) + 1
    before = re.split(r"[.!?]\s", m.string[start:m.start()])[-1]
    return not _NEGATION_BEFORE.search(before)


R("INJ-IGNORE-INSTRUCTIONS", "Instruction-override phrase (ignore previous instructions)", "prompt-injection", "high",
  r"\b(?:ignore|disregard|forget|override|bypass|skip|abandon)\s+(?:all\s+|any\s+|the\s+|your\s+|every\s+|of\s+)*"
  r"(?:previous|prior|above|earlier|preceding|original|existing|initial|system|developer|safety|security)\s+"
  r"(?:instructions?|prompts?|rules?|directions?|guidelines?|guardrails?|constraints?|messages?|context|"
  r"polic(?:y|ies)|restrictions?|programming|directives?)",
  confidence="high", caps=("inject",), hints=("ignore", "disregard", "forget", "override", "bypass", "skip", "abandon"))
R("INJ-NEW-INSTRUCTIONS", "Announces new / hidden / real instructions", "prompt-injection", "medium",
  r"\b(?:new|updated|real|actual|true|hidden|secret|revised)\s+(?:system\s+)?(?:instructions?|directives?|prompt|orders)"
  r"\s*(?::|-|follow)", caps=("inject",), hints=("instruction", "directive", "prompt", "orders"))
R("INJ-ROLE-HIJACK", "Jailbreak / unrestricted-mode framing (DAN, god mode, no longer bound)", "prompt-injection",
  "high",
  r"\byou\s+are\s+(?:now\s+)?(?:in\s+)?(?:developer|god|admin|jailbreak|DAN|unrestricted|uncensored)\s+mode\b|"
  r"\byou\s+are\s+(?:now\s+)?(?:no\s+longer\s+(?:bound|restricted|limited|required)|free\s+(?:from|of)\s+(?:all\s+|any\s+)?"
  r"(?:rules|restrictions|guidelines|policies|filters))|\bact\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|jailbroken|"
  r"evil|uncensored|DAN)\b|\b(?:god|jailbreak|DAN|unrestricted|uncensored)\s+mode\b|\bdo\s+anything\s+now\b|"
  r"\bjailbr(?:eak|oken)\b", caps=("inject",),
  hints=("you are", "act as", "mode", "anything now", "jailbr"))
R("INJ-ROLE-REASSIGN", "Re-assigns the agent's role ('you are now...', 'from now on you...')", "prompt-injection",
  "low", r"\byou\s+are\s+now\s+(?:a|an|the|my)\b|\bfrom\s+now\s+on,?\s+you\s+(?:are|will|must)\b",
  confidence="low", caps=("inject",), hints=("you are now", "from now on"),
  description="Common in legitimate sub-agent prompts; suspicious in skills that should not change the agent's role.")
R("INJ-CHAT-TEMPLATE-TOKENS", "Fake chat-template / platform delimiter tokens", "prompt-injection", "high",
  r"<\|(?:im_start|im_end|system|user|assistant|endoftext|eot_id|start_header_id|end_header_id)\|>|"
  r"\[/?INST\]|<<\s*/?SYS\s*>>|</?antml:[\w-]+|\bBEGIN\s+(?:SYSTEM|ADMIN)\s+(?:PROMPT|INSTRUCTIONS?|MESSAGE)\b|"
  r"<<<\s*(?:end|start)_[a-z_]+\s*>>>",
  caps=("inject",), hints=("<|", "inst]", "sys", "antml", "begin", "<<<"),
  description="Tokens that imitate system or chat-template boundaries to make text look like it comes from the "
              "platform rather than from the skill (HiddenLayer used OpenClaw's own <<<end_tool_call_result>>>).")
R("INJ-ROLE-TAGS", "System / reasoning / tool-result style tags", "prompt-injection", "medium",
  r"<\s*/?\s*(?:system|system[_-]?prompt|sys_prompt)\s*>|</?\s*(?:think|thinking|tool_result|tool_call|"
  r"function_results|function_calls|tool_response|search_results)\s*>|"
  r"^[ \t]*#{1,6}\s*(?:system\s+(?:prompt|message|override)|new\s+instructions)\b|^[ \t]*(?:SYSTEM|ADMIN)\s*:\s*\S",
  flags=re.M, caps=("inject",), hints=("system", "think", "tool_", "function_", "search_results", "instructions", "admin"),
  description="Can fake a system message, a tool result or the model's own reasoning.")
R("INJ-PSEUDO-TAGS", "Instruction-styled pseudo tags (<IMPORTANT>, <instructions>)", "prompt-injection", "low",
  r"<\s*(?:important|instructions?|admin|developer|critical|secret|hidden)\s*>", caps=("inject",),
  hints=("<",), description="Common in tool-poisoning payloads (<IMPORTANT> ... </IMPORTANT>); also used legitimately.")
R("INJ-CONCEAL-FROM-USER", "Tells the agent to hide information from the user", "concealment", "high",
  r"\b(?:do\s+not|don'?t|never|without)\s+(?:ever\s+)?(?:tell(?:ing)?|inform(?:ing)?|notify(?:ing)?|alert(?:ing)?|"
  r"mention(?:ing)?|reveal(?:ing)?|disclos(?:e|ing)|report(?:ing)?|warn(?:ing)?|show(?:ing)?|explain(?:ing)?)\s+"
  r"(?:this\s+(?:to\s+)?|it\s+(?:to\s+)?|anything\s+(?:to\s+)?)?(?:the\s+|your\s+)?(?:user|human|operator|owner|person|admin|anyone)\b"
  r"(?!\s+to\b|\s+how\b|'s\s+(?:name|question))|"
  r"\b(?:hide|conceal|keep|mask)\b[^\n]{0,60}\bfrom\s+(?:the\s+)?(?:user|human|operator|owner)\b|"
  r"\bthe\s+user\s+(?:must|should)\s+(?:not|never)\s+(?:know|see|find\s+out|be\s+told|notice)\b",
  confidence="high", caps=("conceal",), hints=("user", "human", "operator", "owner", "person", "admin", "anyone"),
  validator=_not_double_negative)
R("INJ-STEALTH-ACTION", "Silent / secret action wording", "concealment", "high",
  r"(?<!\bnot\s)(?<!never\s)(?<!n't\s)(?<!\bno\s)"
  r"\b(?:silently|secretly|covertly|quietly|stealthily|invisibly|discreetly|surreptitiously)\s+(?:\w+\s+){0,2}?"
  r"(?:run|execute|send|upload|post|install|download|exfiltrat\w*|transmit|copy|delete|remove|modify|add|write|read|"
  r"collect|forward|call|fetch|curl|launch|start|open|access)\b",
  caps=("conceal",), hints=("silently", "secretly", "covertly", "quietly", "stealthily", "invisibly", "discreetly", "surreptitiously"))
R("INJ-NO-CONFIRMATION", "Tells the agent to skip permission / confirmation / safety checks", "concealment", "medium",
  r"\b(?:do\s+not|don'?t|never|without|no\s+need\s+to)\s+(?:ask(?:ing)?|wait(?:ing)?|prompt(?:ing)?|request(?:ing)?|"
  r"seek(?:ing)?|get(?:ting)?)\s+(?:for\s+)?(?:the\s+user'?s?\s+|any\s+)?(?:permission|confirmation|approval|consent|"
  r"authori[sz]ation)\b|\b(?:skip|bypass|disable|ignore|circumvent|turn\s+off|suppress)\s+(?:all\s+|any\s+|the\s+)?"
  r"(?:confirmation|approval|permission|safety|security|sandbox)\s*(?:checks?|prompts?|dialogs?|warnings?|"
  r"restrictions?|mechanisms?|features?)\b",
  caps=("no-confirm",), hints=("permission", "confirmation", "approval", "consent", "authori", "safety", "security", "sandbox"),
  validator=_not_double_negative,
  description="Legitimate in fully autonomous workflows; dangerous when combined with risky actions.")
R("INJ-DONT-INSPECT", "Discourages reviewing the bundled code", "concealment", "high",
  r"\b(?:no\s+need\s+to|don'?t|do\s+not|never|you\s+(?:shouldn'?t|should\s+not))\s+(?:read|open|inspect|review|look\s+at|"
  r"examine|check|audit|analy[sz]e|view|print|cat)\s+(?:the\s+|its\s+|this\s+)?(?:script|file|code|source|contents?|"
  r"helper|binary|payload|setup\s+file)s?\b", caps=("conceal",), hints=("read", "open", "inspect", "review", "look", "examine", "check", "audit", "analy", "view", "print", "cat"),
  description="SkillJect-style inducement: the SKILL.md looks clean and steers the agent away from the payload.")
R("INJ-FAKE-AUTHORITY", "Claims pre-authorisation by the vendor / admin", "prompt-injection", "high",
  r"\bthis\s+(?:skill|tool|action|request|command|operation)\s+(?:is|has\s+been)\s+(?:pre-?)?(?:approved|authori[sz]ed|"
  r"whitelisted|allowlisted|verified|sanctioned|cleared)\s+by\b|\b(?:anthropic|openai|claude|the\s+(?:security|it|admin)\s+"
  r"team|your\s+(?:admin(?:istrator)?|developer|operator|owner))\s+(?:has\s+)?(?:explicitly\s+)?(?:authori[sz]ed|approved|"
  r"requires|mandates|instructs|wants)\s+(?:you|this|that)\b",
  caps=("inject",), hints=("approved", "authori", "whitelisted", "allowlisted", "verified", "sanctioned", "cleared", "requires", "mandates", "instructs", "wants"))
R("INJ-PRIORITY-CLAIM", "Claims to override other instructions / take precedence", "prompt-injection", "medium",
  r"\b(?:this\s+(?:instruction|rule|skill|message|section)\s+(?:takes|has)\s+(?:absolute\s+)?(?:precedence|priority)|"
  r"(?:highest|top|absolute|overriding)\s+priority\s+(?:instruction|rule|directive)|supersedes?\s+(?:all|any)\s+"
  r"(?:other|previous|prior))\b", caps=("inject",), hints=("precedence", "priority", "supersede"))
R("INJ-EXFIL-INSTRUCTION", "Natural-language instruction to send data somewhere", "exfiltration", "high",
  r"\b(?:send|post|upload|transmit|forward|exfiltrate|email|leak|share|submit|report)\s+(?:the\s+|all\s+|any\s+|every\s+|"
  r"your\s+|their\s+|its\s+)*(?:full\s+|complete\s+|entire\s+)?(?:contents?|data|files?|credentials?|secrets?|keys?|tokens?|"
  r"passwords?|env(?:ironment)?(?:\s+variables)?|\.env|history|cookies|ssh\s+keys?|api\s+keys?|conversation|"
  r"chat\s+(?:history|log)|codebase|source\s+code|system\s+prompt|output)\b[^\n]{0,80}\b(?:to|at|via|using)\s+"
  r"(?:https?://|the\s+(?:following|server|endpoint|webhook|url|address)|this\s+(?:url|endpoint|webhook|address)|"
  r"(?:our|my)\s+(?:server|endpoint|webhook)|[\w.-]+\.(?:com|net|org|io|site|xyz|app|dev|ru|cn|top)\b)",
  caps=("network-send", "inject"), hints=("send", "post", "upload", "transmit", "forward", "exfiltrate", "email", "leak", "share", "submit", "report"))
R("INJ-TOOL-POISONING", "Tool-poisoning pattern (before using this tool, read/pass ...)", "prompt-injection", "high",
  r"\bbefore\s+(?:using|calling|running|invoking|executing)\s+(?:this|any|the|other)\s+(?:tool|function|skill|command)s?"
  r"[^\n]{0,160}\b(?:read|cat|open|send|include|pass|run|execute|call|fetch|upload)\b|"
  r"\b(?:pass|include|put|add|append|embed)\s+(?:its|the|their|all|your)?\s*(?:full\s+)?(?:contents?|content|data|text|"
  r"values?)\s+(?:of\s+[^\n]{0,60}\s+)?(?:as|in|into|inside)\s+(?:the\s+)?['\"`]?\w+['\"`]?\s+(?:parameter|argument|"
  r"field|query|header|sidenote|notes?)\b", caps=("inject",), hints=("before", "pass", "include", "put", "add", "append", "embed"))
R("INJ-REVIEWER-MANIPULATION", "Text aimed at manipulating scanners / reviewers / LLM judges", "prompt-injection",
  "high",
  r"\b(?:security\s+)?(?:scanners?|auditors?|reviewers?|analy[sz]ers?|llms?|ai|models?|assistants?|graders?|judges?)\b"
  r"[^\n]{0,60}\b(?:should|must|will|shall|are\s+instructed\s+to)\s+(?:mark|report|classify|treat|consider|rate|label|"
  r"flag|score)\s+(?:this|it|the\s+skill)\s+as\s+(?:safe|benign|clean|trusted|approved|harmless|low[- ]risk|passing)|"
  r"\b(?:mark|report|classify|label|rate)\s+(?:this\s+(?:skill|file|package|code)|it)\s+as\s+(?:safe|benign|clean|"
  r"harmless|trusted|low[- ]risk)\b", confidence="high", caps=("inject",),
  hints=("safe", "benign", "clean", "trusted", "approved", "harmless", "risk", "passing"),
  description="Attempts to steer an LLM-based reviewer. Treat as strong evidence of malicious intent.")
R("INJ-ANTI-REFUSAL", "Suppresses refusals / safety warnings / disclaimers", "prompt-injection", "high",
  r"\b(?:security|safety)\s+warnings?\s+(?:are|is)\s+(?:just\s+)?(?:test\s+artifacts?|false\s+positives?|expected|harmless|"
  r"noise)|\b(?:ignore|dismiss|suppress|disregard)\s+(?:any\s+|all\s+)?(?:security|safety|antivirus|av|malware)\s+"
  r"(?:warnings?|alerts?|prompts?|messages?|detections?)|\b(?:never|do\s+not|don'?t)\s+(?:refuse|decline)"
  r"(?:\s+(?:any(?:thing)?|requests?|this|to\s+(?:answer|help|comply|respond|assist|do\s+it)))?\s*(?:[.!;,]|$)|"
  r"\b(?:never|do\s+not|don'?t)\s+add\s+(?:any\s+)?(?:safety\s+)?(?:disclaimers?|caveats?)\b",
  flags=re.I | re.M, caps=("inject", "conceal"),
  hints=("warning", "refuse", "decline", "disclaimer", "alert", "detection"))
R("INJ-COMPLIANCE-FRAMING", "Compliance / audit framing used to force tool use", "prompt-injection", "medium",
  r"\b(?:GDPR|SOC\s?2|HIPAA|PCI[- ]DSS|ISO\s?27001|internal\s+audit(?:ing)?|compliance)\b[^\n]{0,120}\b(?:always|must|"
  r"required|mandatory|first\s+step|before\s+(?:any|every))\b[^\n]{0,80}\b(?:call|use|run|invoke|consult|execute|send|"
  r"prefix)\b|\b(?:ALWAYS|MUST)\s+(?:CONSULT|CALL|USE|RUN|INVOKE)\s+THIS\s+(?:TOOL|SKILL)\b",
  flags=re.M, caps=("inject",), hints=("gdpr", "soc", "hipaa", "pci", "iso", "audit", "compliance", "always", "must"),
  description="Trail of Bits 'line jumping': fake compliance requirements push the agent into attacker actions.")
R("INJ-BAN-USER-QUESTIONS", "Forbids the agent from asking the user (AskUserQuestion ban)", "concealment", "medium",
  r"\b(?:do\s+not|don'?t|never)\s+(?:use|call|invoke)\s+(?:the\s+)?[`'\"]?AskUserQuestion\b|"
  r"\bAskUserQuestion\b[^\n]{0,40}\b(?:forbidden|disabled|not\s+allowed|prohibited|banned)",
  caps=("no-confirm",), hints=("askuserquestion",))
R("INJ-IMPLEMENTATION-DETAIL", "Hides behaviour as an 'implementation detail' / 'would upset the user'",
  "concealment", "high",
  r"\b(?:mere|just\s+an?|only\s+an?)\s+implementation\s+detail\b|\b(?:this|it)\s+(?:could|would|might)\s+(?:even\s+)?"
  r"(?:upset|scare|alarm|confuse|worry)\s+the\s+user\b|\bthere\s+is\s+no\s+need\s+to\s+(?:mention|tell|inform|show)\b",
  caps=("conceal",), hints=("implementation detail", "upset", "scare", "alarm", "confuse", "worry", "no need"),
  description="Wording taken from published MCP tool-poisoning and tool-shadowing payloads (Invariant Labs).")
R("INJ-TOOL-WILL-NOT-WORK", "'Otherwise the tool will not work' coercion", "prompt-injection", "medium",
  r"\botherwise\s+(?:the|this)\s+(?:tool|skill|function|integration)\s+(?:will\s+not|won'?t|cannot|can'?t)\s+"
  r"(?:work|function|run)\b", caps=("inject",), hints=("otherwise",))
R("INJ-TOOL-SHADOWING", "Instruction changes how another tool behaves (tool shadowing)", "prompt-injection", "high",
  r"\b(?:side\s+effect|override|overrides|takes\s+precedence)\s+(?:on|over)\s+(?:the\s+)?(?:also\s+present\s+)?"
  r"[`'\"]?[\w.-]+[`'\"]?\s+tool\b|\bwhen\s+this\s+tool\s+is\s+(?:available|present|loaded)[^\n]{0,80}\b(?:must|should|"
  r"always)\b", caps=("inject",), hints=("side effect", "override", "precedence", "when this tool"))
R("INJ-REMOTE-INSTRUCTIONS", "Loads instructions / tasks from a remote URL at runtime", "prompt-injection", "high",
  r"\b(?:fetch|download|load|retrieve|pull|poll|curl|wget)\b[^\n]{0,40}\b(?:(?:your|the|new|latest|updated|remote)\s+)?"
  r"(?:instructions?|prompts?|directives?|tasks?|todo|commands?|playbook)\b[^\n]{0,40}(?:from\s+)?https?://|"
  r"https?://[^\s'\"<>)]+/(?:instructions?|rules|prompt|todo|tasks?|commands?)(?:\.(?:md|txt|json))?\b[^\n]{0,60}"
  r"\b(?:follow|obey|execute|apply|run)\b", caps=("download", "inject"), hints=("http",),
  description="Instructions fetched at runtime can change after review (unverifiable dependency / rug pull).")
R("INJ-NONTEXT-INSTRUCTIONS", "Delegates instructions to an image / document / archive", "hidden-content", "medium",
  r"\b(?:read|follow|load|open|see|use)\s+(?:the\s+)?(?:full\s+|real\s+|detailed\s+|actual\s+)?(?:instructions?|steps?|"
  r"rules?|guide|procedure|prompt)\s+(?:in|from|inside|contained\s+in)\s+[^\n]{0,60}\.(?:png|jpe?g|gif|webp|bmp|svg|pdf|"
  r"docx?|xlsx?|pptx?|zip|odt)\b", caps=("inject",),
  description="Trail of Bits 'context-loader' (.docx) and SkillCamo (image) hide instructions where text scanners "
              "do not look.")
R("INJ-SAFETY-CLAIM", "Unprompted claims that the content is safe", "prompt-injection", "low",
  r"\bthis\s+(?:skill|file|script|code|package|tool)\s+is\s+(?:100%\s+|completely\s+|totally\s+)?(?:safe|harmless|benign|"
  r"not\s+malicious|verified\s+safe|virus[- ]free|malware[- ]free)\b", caps=(), hints=("safe", "harmless", "benign", "malicious", "free"))
R("INJ-DECEPTIVE-OUTPUT", "Instructs the agent to report false results", "concealment", "medium",
  r"\b(?:always|must|should)\s+(?:respond|reply|answer|say|report|claim|state|tell\s+the\s+user)\s+(?:that\s+)?"
  r"(?:everything\s+(?:is|went)\s+(?:fine|ok|okay|well|safe)|(?:the\s+)?(?:task|scan|tests?|install(?:ation)?|"
  r"check)s?\s+(?:passed|succeeded|completed\s+successfully)|no\s+(?:issues|problems|errors|vulnerabilities)\s+(?:were\s+)?found)",
  caps=("conceal",), hints=("respond", "reply", "answer", "say", "report", "claim", "state", "tell"))

# ==========================================================================
# 9. Social engineering of the user
# ==========================================================================

R("SOC-FAKE-PASSWORD-DIALOG", "Fake system password dialog / password verification", "social-engineering", "critical",
  r"osascript[^\n]{0,300}display\s+dialog[^\n]{0,300}(?:password|passcode|hidden\s+answer)|"
  r"display\s+dialog[^\n]{0,200}with\s+hidden\s+answer|\bdscl\s+\.\s+-authonly|\bzenity\s+--password|"
  r"\bkdialog\s+--password|\bGet-Credential\b[^\n]{0,80}-Message|\$host\.ui\.PromptForCredential|"
  r"CredUIPromptForCredentials", confidence="high", caps=("social-engineering", "read-secrets"),
  hints=("dialog", "dscl", "zenity", "kdialog", "credential"),
  description="AMOS / ClawHavoc-style: a fake prompt harvests the user's login password to unlock the Keychain.")
R("SOC-ASK-FOR-PASSWORD", "Asks the user for a password / seed phrase / private key", "social-engineering", "high",
  r"\b(?:enter|type|provide|input|paste|give|share|send|supply)\s+(?:me\s+|us\s+)?(?:your|the)\s+(?:system\s+|admin(?:istrator)?\s+|"
  r"sudo\s+|root\s+|login\s+|mac(?:os)?\s+|computer\s+|account\s+|wallet\s+|keychain\s+|user\s+)?(?:password|passphrase|"
  r"passcode|seed\s+phrase|recovery\s+phrase|private\s+key|2fa\s+code|otp|mfa\s+code)\b",
  caps=("social-engineering", "read-secrets"), hints=("password", "passphrase", "passcode", "phrase", "private key", "2fa", "otp", "mfa"))
R("SOC-SUDO-PASSWORD-PIPE", "Password piped into sudo -S", "social-engineering", "high",
  r"\becho\s+[^\n|]{1,80}\|\s*sudo\s+-S\b|\bsudo\s+-S\b[^\n]{0,40}<<<", caps=("privesc", "read-secrets"),
  hints=("sudo",))
R("SOC-FAKE-PREREQUISITE", "Install-a-'prerequisite' from a URL lure", "social-engineering", "high",
  r"\b(?:download|install|run|get|grab|execute)\b[^\n]{0,80}\b(?:prerequisite|required\s+(?:component|helper|driver|agent|"
  r"update|plugin|runtime|dependency|tool|binary|package)|helper\s+(?:tool|binary|app|utility)|setup\s+(?:tool|utility|"
  r"helper|binary)|security\s+(?:update|patch|component)|missing\s+(?:component|dependency|driver|runtime)|core\s+"
  r"(?:component|runtime|module))\b[^\n]{0,160}https?://",
  caps=("social-engineering", "download"), hints=("http",),
  description="ClawHavoc skills used 'Prerequisites' sections pointing users at malware downloads.")
R("SOC-ARCHIVE-PASSWORD", "Password-protected archive delivery (AV evasion)", "social-engineering", "critical",
  r"\bunzip\s+(?:-\w+\s+)*-P\s*['\"]?\S+|\b7z[az]?\s+[xe]\b[^\n]{0,120}\s-p\S+|\bunrar\s+[xe]\b[^\n]{0,80}\s-p\S+|"
  r"\b(?:password|passwd|pass|pwd|passcode)\s*(?:is|:|=)\s*['\"`*]{0,2}[\w!@#$%^&*.-]{3,}['\"`*]{0,2}[^\n]{0,100}"
  r"\b(?:zip|archive|rar|7z|7-zip|extract|unzip|installer|unpack)\b|\b(?:zip|archive|rar|7z|7-zip|extract|unzip|"
  r"installer|unpack)\b[^\n]{0,100}\b(?:password|passwd|pwd|passcode)\s*(?:is|:|=)\s*['\"`*]{0,2}[\w!@#$%^&*.-]{3,}",
  confidence="high", caps=("social-engineering", "evasion"), hints=("pass", "pwd", "-p"),
  description="Encrypted archives cannot be scanned by antivirus or marketplace scanners; a classic malware lure.")
R("SOC-GATEKEEPER-BYPASS", "macOS Gatekeeper / quarantine bypass", "defense-evasion", "high",
  r"\bxattr\s+(?:-[a-z]+\s+)*-?[dcr]\w*\s[^\n]{0,60}com\.apple\.quarantine|\bxattr\s+-c[rw]?\s|\bxattr\s+-rc\s|"
  r"\bspctl\s+--(?:master-disable|global-disable|add)|right[- ]click[^\n]{0,60}\bopen\b[^\n]{0,80}"
  r"(?:security|gatekeeper|unidentified|warning|anyway)|\bopen\s+anyway\b|Privacy\s*&\s*Security[^\n]{0,60}"
  r"(?:open|allow)\s+anyway", confidence="high", caps=("evasion", "social-engineering"),
  hints=("xattr", "spctl", "right", "anyway"))
R("SOC-DISABLE-SECURITY", "Disables antivirus / firewall / SIP / SELinux", "defense-evasion", "high",
  r"Set-MpPreference[^\n]{0,80}-Disable\w+\s+\$?(?:true|1)|Add-MpPreference[^\n]{0,60}-Exclusion(?:Path|Process|Extension)|"
  r"\bDisableAntiSpyware\b|\bDisableRealtimeMonitoring\b|\bnetsh\s+(?:adv)?firewall\s+set\s+[^\n]{0,40}state\s+off|"
  r"\bufw\s+disable\b|\bsetenforce\s+0\b|\bcsrutil\s+disable\b|\bsystemctl\s+(?:stop|disable|mask)\s+(?:apparmor|"
  r"firewalld|auditd|falcon|clamav)|\b(?:disable|turn\s+off|uninstall|deactivate)\s+(?:your\s+|the\s+)?(?:antivirus|"
  r"anti-virus|windows\s+defender|defender|firewall|gatekeeper|sip|edr|xprotect|security\s+software)\b",
  confidence="high", caps=("evasion",))
R("SOC-URGENCY-BANNER", "Urgent 'required before using this skill' banner", "social-engineering", "medium",
  r"\b(?:CRITICAL|IMPORTANT|REQUIRED|MANDATORY|ATTENTION|WARNING)\b[^\n]{0,40}\b(?:REQUIREMENT|STEP|SETUP|INSTALL\w*|"
  r"DEPENDENCY|PREREQUISITE)S?\b[^\n]{0,40}\bBEFORE\s+(?:USING|RUNNING|STARTING|PROCEEDING)\b|"
  r"\bmust\s+be\s+installed\s+(?:first|before\s+(?:using|running|proceeding))\b|"
  r"[\u2500-\u257f\u2580-\u259f]{6,}[^\n]{0,20}\b(?:REQUIRED|CRITICAL|IMPORTANT|INSTALL)",
  caps=("social-engineering",), hints=("before", "installed", "required", "critical", "important", "install"),
  description="ClawHavoc skills used box-drawing urgency banners before the fake prerequisite step.")
R("SOC-CLICKFIX", "Asks the user to paste a command into Run / Terminal (ClickFix)", "social-engineering", "medium",
  r"\b(?:copy|paste)\b[^\n]{0,60}\b(?:into|in)\s+(?:your\s+|the\s+)?(?:terminal|command\s+prompt|powershell|run\s+dialog|"
  r"cmd|console)\b|\bWin(?:dows)?\s*(?:key\s*)?\+\s*R\b|\bpress\s+(?:win|windows)\s*\+\s*r\b",
  caps=("social-engineering",), hints=("paste", "copy", "win"))

# ==========================================================================
# 10. Destructive
# ==========================================================================

R("DESTR-RM-ROOT", "Recursive delete of root / home / everything", "destructive", "critical",
  r"\brm\s+(?:-[a-zA-Z]+\s+)*-[a-zA-Z]*[rR][a-zA-Z]*\s+(?:-[a-zA-Z-]+\s+)*(?:--no-preserve-root\s+)?[\"']?"
  r"(?:/|/\*|~|~/|~/\*|\$HOME/?|\$\{HOME\}/?|\*|/(?:etc|usr|var|home|Users|System|bin|boot|lib|opt|root)/?)[\"']?"
  r"(?=\s|$|;|&|\|)|--no-preserve-root", flags=re.M, confidence="high", caps=("destructive",), hints=("rm", "preserve-root"))
R("DESTR-WINDOWS-WIPE", "Recursive delete / format of Windows system or user folders", "destructive", "critical",
  r"\b(?:del|erase)\s+(?:/[a-zA-Z]\s+)*[a-zA-Z]:\\(?:\*|Windows|Users)|\brd\s+/s\s+/q\s+[a-zA-Z]:\\(?:\s|$|Windows|Users)|"
  r"\bformat\s+[a-zA-Z]:(?:\s|$)|Remove-Item\s+[^\n]{0,80}-Recurse[^\n]{0,80}(?:[A-Z]:\\(?:\s|$|\*|Windows|Users)|"
  r"\$env:(?:USERPROFILE|SystemRoot|HOMEDRIVE)\b|~[\\/]?(?:\s|$))|\bcipher\s+/w\b", flags=re.I | re.M,
  confidence="high", caps=("destructive",))
R("DESTR-DISK", "Disk wipe / filesystem format", "destructive", "critical",
  r"\bmkfs(?:\.\w+)?\s|\bdd\s+[^\n]{0,80}of=/dev/(?:sd[a-z]|nvme|disk\d|hd[a-z]|mmcblk|xvd)|\bshred\s+[^\n]{0,40}/dev/|"
  r"\bdiskpart\b|\bwipefs\s|>\s*/dev/sd[a-z]\b|\bdiskutil\s+(?:eraseDisk|zeroDisk|secureErase)", confidence="high",
  caps=("destructive",))
R("DESTR-INHIBIT-RECOVERY", "Deletes shadow copies / backups (ransomware behaviour)", "destructive", "critical",
  r"vssadmin(?:\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit[^\n]{0,60}recoveryenabled\s+no|"
  r"wbadmin\s+delete\s+(?:catalog|backup)|\btmutil\s+(?:delete|disable|deletelocalsnapshots)", confidence="high",
  caps=("destructive",), refs=("ATT&CK T1490",))
R("DESTR-FORK-BOMB", "Fork bomb", "destructive", "critical",
  r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", confidence="high", caps=("destructive",))
R("DESTR-GIT-FORCE", "Destructive git history operations", "destructive", "medium",
  r"\bgit\s+push\s+[^\n]{0,60}(?:--force\b|\s-f\b)[^\n]{0,40}\b(?:main|master)\b|\bgit\s+filter-(?:branch|repo)\b|"
  r"\bgit\s+reflog\s+expire\b[^\n]{0,40}--expire=now", caps=("destructive",), hints=("git",))
R("DESTR-MASS-ENCRYPT", "Encrypts files while walking directories (ransomware pattern)", "destructive", "high",
  r"(?:Fernet|AES\.new|createCipheriv|Cipher\(|\.encrypt\()[^\n]{0,200}(?:os\.walk|\.rglob|listdir|readdirSync)|"
  r"(?:os\.walk|\.rglob|readdirSync)[^\n]{0,200}(?:encrypt|Fernet|AES)", caps=("destructive",))

# ==========================================================================
# 11. Defense evasion / anti-forensics / sandbox evasion
# ==========================================================================

R("EVADE-HISTORY-WIPE", "Clears or disables shell history", "defense-evasion", "high",
  r"\bhistory\s+-[cw]\b|\bunset\s+HISTFILE\b|HISTFILE=/dev/null|\bHISTSIZE=0\b|\bClear-History\b|"
  r"Remove-Item[^\n]{0,60}ConsoleHost_history|\bset\s+\+o\s+history\b", confidence="high", caps=("evasion", "conceal"),
  hints=("history", "histfile", "histsize"))
R("EVADE-LOG-WIPE", "Clears system / event logs", "defense-evasion", "high",
  r"\bwevtutil(?:\.exe)?\s+(?:cl|clear-log)\b|\bClear-EventLog\b|\bauditctl\s+-D\b|>\s*/var/log/\S+|"
  r"\btruncate\s+[^\n]{0,30}/var/log|\brm\s+[^\n]{0,30}/var/log|\bjournalctl\s+--vacuum", caps=("evasion", "conceal"))
R("EVADE-AMSI-ETW", "AMSI / ETW tampering", "defense-evasion", "critical",
  r"amsi\s*(?:init\s*failed|utils|scan\s*buffer|context)|\bEtwEventWrite\b|\bAmsiOpenSession\b",
  confidence="high", caps=("evasion",), hints=("amsi", "etw"))
R("EVADE-TIMESTOMP", "Modifies file timestamps", "defense-evasion", "low",
  r"\btouch\s+-[a-z]*[rtd]\s|\.(?:LastWriteTime|CreationTime|LastAccessTime)\s*=|\bSetFileTime\b", caps=("evasion",))
R("EVADE-DETACHED-PROCESS", "Launches detached / background processes", "defense-evasion", "low",
  r"\bnohup\b|\bdisown\b|\bsetsid\s+\S|CREATE_NO_WINDOW|DETACHED_PROCESS|\bstart\s+/b\s|"
  r"start_new_session\s*=\s*True|\bdetached\s*:\s*true", caps=("background",), max_hits=3,
  hints=("nohup", "disown", "setsid", "no_window", "detached", "start", "new_session"))
R("EVADE-LONG-SLEEP", "Long delay before acting (sandbox evasion / delayed trigger)", "sandbox-evasion", "medium",
  r"\b(?:time\.)?sleep\s*\(\s*(?:[3-9]\d{2,}|\d{4,})(?:\.\d+)?\s*\)|\bsleep\s+(?:[3-9]\d{2,}|\d{4,})\b|"
  r"Start-Sleep\s+(?:-s(?:econds)?\s+)?(?:[3-9]\d{2,}|\d{4,})\b|setTimeout\([^\n]{0,200},\s*\d{7,}\s*\)|"
  r"\btimeout\s+/t\s+(?:[3-9]\d{2,}|\d{4,})", caps=("evasion",), hints=("sleep", "settimeout", "timeout"))
R("EVADE-VM-DETECTION", "Virtual machine / debugger / analysis-tool detection", "sandbox-evasion", "medium",
  r"\b(?:VBoxService|VBoxTray|vmtoolsd|vmwaretray|VirtualBox|qemu-ga|sandboxie|SbieDll|wireshark|procmon|x64dbg|"
  r"ollydbg|IsDebuggerPresent|CheckRemoteDebuggerPresent|hypervisor_present|sysctl\s+-n\s+machdep\.cpu\.features)\b",
  confidence="low", caps=("evasion",))
R("EVADE-CI-AWARE", "Behaviour depends on CI / sandbox environment variables", "sandbox-evasion", "low",
  r"(?:os\.environ|os\.getenv|process\.env|\$env:|\$\{?)[^\n]{0,20}\b(?:CI|GITHUB_ACTIONS|GITLAB_CI|JENKINS_URL|"
  r"BUILDKITE|TRAVIS|CIRCLECI|SANDBOX|VIRUSTOTAL|CUCKOO|ANALYSIS)\b", flags=0, caps=("evasion",))
R("EVADE-TIME-BOMB", "Date-triggered logic (time bomb)", "sandbox-evasion", "medium",
  r"(?:datetime\.(?:now|today|utcnow)\(\)|date\.today\(\)|Date\.now\(\)|new\s+Date\(\)|\bdate\s+\+%s|Get-Date)"
  r"[^\n]{0,80}(?:>|<|>=|<=)[^\n]{0,40}(?:datetime\(\s*20[2-3]\d|['\"]20[2-3]\d-\d\d|\b1[7-9]\d{8}\b)",
  caps=("evasion",), hints=("date", "now", "today"))

# ==========================================================================
# 12. Privilege escalation
# ==========================================================================

R("PRIV-SUDOERS", "Modifies sudoers / grants NOPASSWD", "privilege-escalation", "critical",
  r"\bNOPASSWD\s*:|" + write_near(r"/etc/sudoers") + r"|\bvisudo\b|/etc/sudoers\.d/", confidence="high",
  caps=("privesc", "persist"), hints=("nopasswd", "sudoers", "visudo"))
R("PRIV-SETUID", "Sets setuid/setgid bits", "privilege-escalation", "high",
  r"\bchmod\s+(?:-[a-zA-Z]+\s+)*(?:[ugoa]*\+[rwx]*s[rwx]*|[2-7][0-7]{3})\b", caps=("privesc",), hints=("chmod",))
R("PRIV-WORLD-WRITABLE", "World-writable permissions (chmod 777)", "privilege-escalation", "low",
  r"\bchmod\s+(?:-R\s+)?0?777\b|\bchmod\s+(?:-R\s+)?a\+rwx\b", caps=(), hints=("chmod",))
R("PRIV-UAC-BYPASS", "Windows UAC bypass technique", "privilege-escalation", "high",
  r"\b(?:fodhelper|computerdefaults|sdclt)(?:\.exe)?\b|ms-settings\\shell\\open\\command|mscfile\\shell\\open\\command|"
  r"ConsentPromptBehaviorAdmin|EnableLUA[^\n]{0,30}\b0\b", confidence="high", caps=("privesc",))
R("PRIV-ELEVATE", "Requests elevation (sudo / RunAs / admin)", "privilege-escalation", "low",
  r"(?:^|[;&|`(][ \t]*)sudo\s+(?!-n\b|-l\b|-v\b)\S|-Verb\s+RunAs\b|\brunas\s+/user", flags=re.I | re.M,
  caps=("privesc",), max_hits=3, hints=("sudo", "runas"))
R("PRIV-CONTAINER-ESCAPE", "Container escape / host mount primitives", "privilege-escalation", "high",
  r"/var/run/docker\.sock|\bdocker\s+run\b[^\n]{0,120}(?:--privileged\b|-v\s+/:/|--pid=host)|\bnsenter\s+[^\n]{0,30}-t\s+1\b",
  caps=("privesc",), hints=("docker", "nsenter"))
R("PRIV-CAPABILITIES", "Grants Linux capabilities", "privilege-escalation", "medium",
  r"\bsetcap\s+cap_\w+|\bcap_setuid\b|\bcap_sys_admin\b", caps=("privesc",), hints=("cap",))

# ==========================================================================
# 13. Reverse shells / remote access
# ==========================================================================

R("SHELL-DEV-TCP", "Bash /dev/tcp reverse shell", "reverse-shell", "critical",
  r"/dev/(?:tcp|udp)/[\w.$\{\}-]+/\$?\{?\w+", confidence="high", caps=("remote-control", "network"), hints=("/dev/tcp", "/dev/udp"))
R("SHELL-NETCAT-EXEC", "netcat with -e/-c shell", "reverse-shell", "critical",
  r"\b(?:nc|ncat|netcat|nc\.traditional|nc\.openbsd)(?:\.exe)?\b[^\n]{0,80}\s-[ec]\s+[^\s]*(?:sh|cmd(?:\.exe)?|powershell|bash)\b|"
  r"\bncat\b[^\n]{0,80}--(?:exec|sh-exec)\b", confidence="high", caps=("remote-control", "network"))
R("SHELL-MKFIFO", "Named-pipe reverse shell (mkfifo + nc/openssl)", "reverse-shell", "critical",
  r"\bmkfifo\b[^\n]{0,160}\b(?:nc|ncat|netcat|telnet|openssl\s+s_client)\b|\bmknod\b[^\n]{0,40}\bp\b[^\n]{0,80}\b(?:nc|telnet)\b",
  confidence="high", caps=("remote-control", "network"), hints=("mkfifo", "mknod"))
R("SHELL-SOCAT", "socat exec/system reverse shell", "reverse-shell", "critical",
  r"\bsocat\b[^\n]{0,200}\b(?:exec|system):", confidence="high", caps=("remote-control", "network"), hints=("socat",))
R("SHELL-PYTHON", "Python socket + dup2/pty reverse shell", "reverse-shell", "critical",
  r"socket\.socket\([^\n]{0,400}(?:subprocess|os\.dup2|pty\.spawn)|os\.dup2\s*\(\s*\w+\.fileno\(\)\s*,\s*[012]\s*\)",
  confidence="high", caps=("remote-control", "network", "execute"), hints=("dup2", "socket"))
R("SHELL-POWERSHELL", "PowerShell TCPClient reverse shell", "reverse-shell", "critical",
  r"Net\.Sockets\.TCPClient\s*\([^\n]{0,400}(?:GetStream|iex|Invoke-Expression)|"
  r"\.GetStream\(\)[^\n]{0,300}(?:iex|Invoke-Expression|\|\s*Out-String)", confidence="high",
  caps=("remote-control", "network", "execute"), hints=("tcpclient", "getstream"))
R("SHELL-SCRIPTING-LANGS", "Perl/Ruby/PHP socket reverse shell", "reverse-shell", "critical",
  r"\bperl\s+-e\s+[^\n]{0,200}socket\s*\(|\bruby\s+-rsocket\b|\bphp\s+-r\s+[^\n]{0,200}fsockopen|"
  r"\bfsockopen\s*\([^\n]{0,200}\b(?:exec|shell_exec|system|passthru|proc_open)\b", confidence="high",
  caps=("remote-control", "network", "execute"), hints=("socket", "fsockopen"))
R("SHELL-OPENSSL-TELNET", "openssl/telnet piped to a shell", "reverse-shell", "critical",
  r"\bopenssl\s+s_client\s+[^\n]{0,100}-connect[^\n]{0,100}\|\s*(?:/bin/)?(?:ba)?sh\b|"
  r"\btelnet\s+[\w.-]+\s+\d+\s*\|\s*/bin/(?:ba)?sh", confidence="high", caps=("remote-control", "network"),
  hints=("openssl", "telnet"))
R("SHELL-TUNNEL", "Tunnels / port forwarding to the internet", "reverse-shell", "high",
  r"\bssh\s+[^\n]{0,80}\s-[RD]\s*\d+|\bssh\s+[^\n]{0,80}-o\s+StrictHostKeyChecking=no|\bautossh\b|"
  r"\bngrok\s+(?:tcp|http|tls|start)\b|\bcloudflared\s+(?:tunnel|access)\b|\bchisel\s+(?:client|server)\b|"
  r"\bfrpc\b\s+-c|\blt\s+--port\b|\bbore\s+local\b|\bserveo\.net\b|\bpinggy\.io\b",
  caps=("remote-control", "network"))
R("SHELL-REMOTE-ADMIN-TOOL", "Remote-administration tool", "reverse-shell", "medium",
  r"\b(?:anydesk|teamviewer|rustdesk|meshagent|meshcentral|screenconnect|connectwise|tightvnc|ultravnc|x11vnc|"
  r"atera|splashtop|netsupport)\b", confidence="low", caps=("remote-control",))

# ==========================================================================
# 14. Crypto mining / theft
# ==========================================================================

R("MINER-INDICATORS", "Cryptominer indicators", "cryptomining", "critical",
  r"stratum\+(?:tcp|ssl|tls)://|\bxmrig\b|\bminerd\b|\bcpuminer\b|\bcryptonight\b|\bnicehash\b|--donate-level\b|"
  r"\b(?:minexmr|supportxmr|nanopool|2miners|f2pool|hashvault|moneroocean|herominers|unmineable)\b",
  confidence="high", caps=("execute",))
R("CRYPTO-CLIPBOARD-READ", "Reads the clipboard", "crypto-theft", "low",
  r"\bpbpaste\b|\bGet-Clipboard\b|\bpyperclip\.paste\b|\bxclip\s+[^\n]{0,20}-o\b|\bxsel\s+-[a-z]*o|"
  r"navigator\.clipboard\.readText|\bwl-paste\b|\bGetClipboardData\b|win32clipboard\.GetClipboardData|"
  r"clipboard\.paste\(", caps=("clipboard",), hints=("paste", "clipboard", "xclip", "xsel"))
R("CRYPTO-ADDRESS-SWAP", "Clipboard crypto-address replacement (clipper)", "crypto-theft", "critical",
  r"(?:pbcopy|Set-Clipboard|pyperclip\.copy|xclip|writeText|SetClipboardData)[^\n]{0,200}"
  r"(?:\bbc1[a-z0-9]{25,59}\b|\b0x[a-fA-F0-9]{40}\b|\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\bT[1-9A-HJ-NP-Za-km-z]{33}\b)",
  confidence="high", caps=("clipboard",))

R("FIN-WALLET-TRANSFER", "Transfers funds / signs crypto transactions", "financial", "medium",
  r"\b(?:sendTransaction|signTransaction|sendRawTransaction|transfer(?:From)?\s*\(\s*(?:to|recipient|0x)|"
  r"SystemProgram\.transfer|web3\.eth\.sendTransaction|solana\s+transfer|ethers\.Wallet\s*\()",
  caps=("network-send",), hints=("transaction", "transfer", "wallet"),
  description="Direct money movement by an agent (Snyk W009 'direct financial execution'; Unit 42 letssendit).")
R("FIN-AFFILIATE-STEERING", "Steers the agent to affiliate / referral links", "financial", "low",
  r"\b(?:always|must|only)\s+(?:use|include|recommend|insert|append)\s+(?:the\s+|our\s+|these\s+)?(?:referral|affiliate|"
  r"tracking|partner)\s+(?:links?|codes?|urls?|ids?)\b|\breferralLink\b",
  caps=(), hints=("referral", "affiliate", "tracking", "partner"),
  description="Unit 42 'money-radar': remote referral list + 'always use the referral links'.")
R("NET-MAIL-BCC-INJECT", "Hard-coded Bcc/Cc address in mail-sending code", "exfiltration", "medium",
  r"[\"']?\b[Bb]cc[\"']?\s*[:=]\s*[\"'][^\"'\s@]{1,64}@[\w.-]+\.[a-z]{2,}[\"']|\badd_header\(\s*['\"]Bcc['\"]",
  flags=0, caps=("network-send",), description="The postmark-mcp rug pull added a hidden Bcc to every e-mail.")

# ==========================================================================
# 15. Reconnaissance / surveillance
# ==========================================================================

R("RECON-SYSTEM-INFO", "Host / user profiling commands", "recon", "info",
  r"\b(?:whoami|systeminfo|sw_vers|system_profiler|lsb_release|Get-ComputerInfo)\b|\buname\s+-a\b|\bipconfig\s+/all\b|"
  r"\bwmic\s+(?:os|computersystem|csproduct|bios)\b|Win32_(?:OperatingSystem|ComputerSystem|BIOS)|"
  r"\bplatform\.(?:node|uname)\(\)|\bgetpass\.getuser\(\)|\bos\.getlogin\(\)|\bos\.userInfo\(\)|"
  r"\bos\.networkInterfaces\(\)|\bsocket\.gethostname\(\)", confidence="high", caps=("recon",), max_hits=3)
R("RECON-NETWORK-ENUM", "Network / directory enumeration", "recon", "medium",
  r"\b(?:nmap|masscan|zmap|BloodHound|SharpHound|ldapsearch|nltest|dsquery|Get-ADUser|Get-ADComputer)\b|"
  r"\bnet\s+(?:user|group|localgroup|view|share)\b|\barp\s+-a\b", caps=("recon",))
R("RECON-SCREEN-CAPTURE", "Screen capture", "recon", "medium",
  r"\bscreencapture\b|ImageGrab\.grab|pyautogui\.screenshot|\bmss\.mss\(|CopyFromScreen|gnome-screenshot|"
  r"\bimport\s+-window\s+root", caps=("recon",), confidence="low")
R("RECON-KEYLOGGING", "Keystroke capture", "recon", "high",
  r"pynput\.keyboard|keyboard\.on_press|\bGetAsyncKeyState\b|\bSetWindowsHookEx\w*|\bkeylogger\b|\bCGEventTapCreate\b",
  caps=("recon", "read-secrets"), refs=("ATT&CK T1056.001",))
R("RECON-AV-CAPTURE", "Camera / microphone capture", "recon", "medium",
  r"cv2\.VideoCapture\(\s*0|\bgetUserMedia\b|\bimagesnap\b|\bffmpeg\b[^\n]{0,60}-f\s+(?:avfoundation|dshow|v4l2|pulse|alsa)|"
  r"\bpyaudio\b|\bsounddevice\.rec\b", confidence="low", caps=("recon",))

# ==========================================================================
# 16. Supply chain
# ==========================================================================


def _not_pypi(m: "re.Match", line: str) -> bool:
    return not re.search(r"pypi\.org|files\.pythonhosted\.org", m.group(0), re.I)


R("SUPPLY-PIP-INDEX", "pip pointed at a non-default package index", "supply-chain", "high",
  r"\bpip3?\s+install\b[^\n]{0,200}(?:--index-url|\s-i\s+https?://|--extra-index-url|--trusted-host)[^\n]{0,120}|"
  r"^[ \t]*(?:--index-url|--extra-index-url|--trusted-host|-i\s+https?://)[^\n]{0,120}|\bPIP_(?:EXTRA_)?INDEX_URL\b[^\n]{0,120}",
  flags=re.I | re.M, caps=("install-packages",), validator=_not_pypi, hints=("index", "trusted-host", "-i "),
  description="Extra/alternate indexes enable dependency confusion and typosquat delivery.")
R("SUPPLY-PIP-DIRECT-URL", "pip install from a URL / git / local wheel", "supply-chain", "medium",
  r"\bpip3?\s+install\b[^\n]{0,200}(?:git\+|https?://|\bfile://|\S+\.whl\b|\S+\.tar\.gz\b)",
  caps=("install-packages", "download"), hints=("pip",))
R("SUPPLY-REQUIREMENTS-DIRECT-URL", "requirements.txt dependency from a URL / git", "supply-chain", "medium",
  r"^[ \t]*[\w.-]+\s*@\s*(?:git\+|https?://)\S+|^[ \t]*(?:git\+|https?://)\S+", flags=re.I | re.M,
  caps=("install-packages", "download"), kinds={"requirements"})
R("SUPPLY-NPM-DIRECT-URL", "npm/yarn/pnpm install from a URL / git / tarball", "supply-chain", "medium",
  r"\b(?:npm|yarn|pnpm|bun)\s+(?:i|install|add)\b[^\n]{0,200}(?:https?://|git\+|github:|\S+\.tgz\b)",
  caps=("install-packages", "download"), hints=("npm", "yarn", "pnpm", "bun"))
R("SUPPLY-REGISTRY-REDIRECT", "Redirects the npm/yarn/pip registry", "supply-chain", "high",
  r"^[ \t]*(?:@[\w-]+:)?registry\s*=\s*https?://(?!registry\.npmjs\.org|registry\.yarnpkg\.com)\S+|"
  r"\bnpm\s+config\s+set\s+(?:@[\w-]+:)?registry\b|\byarn\s+config\s+set\s+(?:npm)?[Rr]egistry(?:Server)?\b|"
  r"\bnpmRegistryServer\s*:\s*['\"]?https?://(?!registry\.npmjs\.org|registry\.yarnpkg\.com)|"
  r"\b[A-Z_]*REGISTRY(?:_URL)?\s*=\s*['\"]?https?://(?!registry\.npmjs\.org|registry\.yarnpkg\.com|pypi\.org)\S+|"
  r"\bpip\s+config\s+set\s+global\.(?:extra-)?index-url\b", flags=re.I | re.M, caps=("install-packages",),
  hints=("registry", "index-url"),
  description="Trail of Bits bypassed every skill scanner with a 'corporate registry' redirect; dependency confusion.")
R("SUPPLY-RUNTIME-PACKAGE-EXEC", "Executes a registry package at runtime (npx -y / uvx / pipx run)", "supply-chain", "low",
  r"\b(?:npx|bunx|pnpm\s+dlx|yarn\s+dlx)\s+(?:-y\s+|--yes\s+)\S+|\buvx\s+(?!--version)\S+|\bpipx\s+run\s+\S+",
  caps=("install-packages", "execute"), max_hits=4, hints=("npx", "bunx", "dlx", "uvx", "pipx"))
R("SUPPLY-PACKAGE-INSTALL", "Installs packages", "supply-chain", "info",
  r"\b(?:pip3?|npm|yarn|pnpm|gem|cargo|brew|apt(?:-get)?|yum|dnf|apk|choco|winget|scoop|conda|uv\s+pip)\s+"
  r"(?:install|add|get)\b|\bgo\s+install\b", confidence="high", caps=("install-packages",), max_hits=4)
R("SUPPLY-BREAK-SYSTEM", "pip --break-system-packages / sudo pip", "supply-chain", "low",
  r"--break-system-packages\b|\bsudo\s+(?:-H\s+)?pip3?\s+install\b", caps=("install-packages",),
  hints=("break-system", "pip"))
R("SUPPLY-UNPINNED-LATEST", "Installs @latest / unpinned remote tool", "supply-chain", "low",
  r"\bgo\s+install\s+\S+@latest\b|\b(?:npx|npm\s+i(?:nstall)?\s+-g)\s+[\w@/.-]+@latest\b", caps=("install-packages",),
  hints=("@latest",))

# ==========================================================================
# 17. Hard-coded secrets (case-sensitive, redacted in reports)
# ==========================================================================


def _not_example(m: "re.Match", line: str) -> bool:
    s = m.group(0)
    return "EXAMPLE" not in s and "XXXX" not in s.upper() and "0000000000" not in s


R("SECRET-AWS-KEY-ID", "AWS access key id", "secrets", "high", r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b",
  flags=SEC_FLAGS, redact=True, validator=_not_example, caps=("embedded-secret",))
R("SECRET-AWS-SECRET", "AWS secret access key", "secrets", "high",
  r"aws_?secret_?access_?key[\"']?\s*[=:]\s*[\"']?[A-Za-z0-9/+=]{40}\b", flags=re.I, redact=True,
  validator=_not_example, caps=("embedded-secret",))
R("SECRET-GITHUB", "GitHub token", "secrets", "high", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b",
  flags=SEC_FLAGS, redact=True, caps=("embedded-secret",))
R("SECRET-GITLAB", "GitLab token", "secrets", "high", r"\bglpat-[A-Za-z0-9_-]{20}\b", flags=SEC_FLAGS, redact=True,
  caps=("embedded-secret",))
R("SECRET-SLACK", "Slack token", "secrets", "high", r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b", flags=SEC_FLAGS, redact=True,
  caps=("embedded-secret",))
R("SECRET-OPENAI", "OpenAI API key", "secrets", "high",
  r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{16,}T3BlbkFJ[A-Za-z0-9_-]{16,}\b|\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}\b",
  flags=SEC_FLAGS, redact=True, caps=("embedded-secret",))
R("SECRET-ANTHROPIC", "Anthropic API key", "secrets", "high", r"\bsk-ant-(?:api|admin|oat)\d{2}-[A-Za-z0-9_-]{60,}\b",
  flags=SEC_FLAGS, redact=True, caps=("embedded-secret",))
R("SECRET-GOOGLE-API", "Google API key", "secrets", "medium", r"\bAIza[0-9A-Za-z_-]{35}\b", flags=SEC_FLAGS, redact=True,
  caps=("embedded-secret",))
R("SECRET-STRIPE", "Stripe live secret key", "secrets", "high", r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b", flags=SEC_FLAGS,
  redact=True, caps=("embedded-secret",))
R("SECRET-PRIVATE-KEY", "Private key block", "secrets", "high",
  r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----", flags=SEC_FLAGS,
  caps=("embedded-secret",))
R("SECRET-JWT", "JSON Web Token", "secrets", "medium", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
  flags=SEC_FLAGS, redact=True, caps=("embedded-secret",))
R("SECRET-DISCORD-BOT", "Discord bot token", "secrets", "high",
  r"\b[MNO][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,38}\b", flags=SEC_FLAGS, redact=True,
  caps=("embedded-secret", "c2-token"))
R("SECRET-TELEGRAM-BOT", "Telegram bot token (common stealer C2 channel)", "secrets", "high",
  r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b", flags=SEC_FLAGS, redact=True, caps=("embedded-secret", "c2-token"))
R("SECRET-HUGGINGFACE", "Hugging Face token", "secrets", "high", r"\bhf_[A-Za-z0-9]{34,}\b", flags=SEC_FLAGS, redact=True,
  caps=("embedded-secret",))
R("SECRET-NPM", "npm token", "secrets", "high", r"\bnpm_[A-Za-z0-9]{36}\b", flags=SEC_FLAGS, redact=True,
  caps=("embedded-secret",))
R("SECRET-SENDGRID", "SendGrid key", "secrets", "high", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b", flags=SEC_FLAGS,
  redact=True, caps=("embedded-secret",))
R("SECRET-CONNECTION-STRING", "Credentials embedded in a connection string", "secrets", "medium",
  r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|ftp)://[^\s:@/'\"]{1,64}:[^\s@/'\"]{3,64}@",
  redact=True, caps=("embedded-secret",), validator=lambda m, l: not re.search(r"user(name)?:pass(word)?@|<|\$\{|\{\{", m.group(0), re.I))


def _generic_secret_ok(m: "re.Match", line: str) -> bool:
    v = m.group(0).lower()
    bad = ("your", "xxx", "<", "example", "changeme", "${", "{{", "placeholder", "dummy", "test", "sample", "process.env",
           "os.environ", "getenv", "****", "...", "redacted", "insert", "here", "none", "null", "secret_name", "token_name")
    return not any(b in v for b in bad)


R("SECRET-GENERIC-ASSIGNMENT", "Hard-coded password / token assignment", "secrets", "low",
  r"\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)[\"']?\s*[=:]\s*"
  r"[\"'][^\"'\s]{10,}[\"']", redact=True, validator=_generic_secret_ok, caps=("embedded-secret",), max_hits=4)


# --------------------------------------------------------------------------
# Custom rules
# --------------------------------------------------------------------------

def load_custom_rules(path: str) -> List[Rule]:
    """Load rules from JSON: {"rules": [{"id", "title", "severity", "category", "pattern", ...}]}."""
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    out = []
    for raw in doc.get("rules", []):
        flags = 0
        for f in str(raw.get("flags", "i")):
            flags |= {"i": re.I, "m": re.M, "s": re.S, "x": re.X}.get(f, 0)
        kinds = raw.get("kinds")
        out.append(Rule(
            id=str(raw["id"]), title=str(raw.get("title", raw["id"])), category=str(raw.get("category", "network")),
            severity=str(raw.get("severity", "medium")), pattern=str(raw["pattern"]), flags=flags,
            confidence=str(raw.get("confidence", "medium")), kinds=set(kinds) if kinds else None,
            caps=tuple(raw.get("capabilities", ())), description=str(raw.get("description", "")),
            remediation=str(raw.get("remediation", "")), refs=tuple(raw.get("references", ())),
            max_hits=int(raw.get("max_hits", 8)), min_count=int(raw.get("min_count", 1)),
            redact=bool(raw.get("redact", False)), custom=True,
        ))
    return out


def all_rules(extra: Sequence[Rule] = ()) -> List[Rule]:
    ids = set()
    out = []
    for r in list(RULES) + list(extra):
        if r.id in ids:
            raise ValueError("duplicate rule id: %s" % r.id)
        ids.add(r.id)
        out.append(r)
    return out
