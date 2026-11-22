"""SKILL.md manifest analysis (frontmatter + body structure).

Spec references: agentskills.io specification (name 1-64 [a-z0-9-], no leading /
trailing / double hyphen, equals directory; description 1-1024; compatibility
<= 500; metadata string->string; allowed-tools) plus Claude Code extensions
(model, hooks, user-invocable, disable-model-invocation, context, agent, ...).
"""
from __future__ import annotations

import posixpath
import re
from typing import Dict, List, Optional, Set, Tuple

from . import iocs
from .model import Finding, TextUnit
from .rules import CATEGORY_INFO
from .sanitize import visible

SPEC_KEYS = {"name", "description", "license", "allowed-tools", "metadata", "compatibility"}
VENDOR_KEYS = {"version", "model", "disable-model-invocation", "user-invocable", "argument-hint", "context", "agent",
               "hooks", "when_to_use", "when-to-use", "effort", "tools", "disallowed-tools", "color", "author",
               "tags", "homepage", "repository", "keywords", "category", "icon", "emoji", "requires", "dependencies",
               "platforms", "os", "env", "permissions", "triggers", "examples", "title", "summary", "type"}
RISKY_VENDOR_KEYS = {
    "hooks": ("high", "Frontmatter defines hooks that run shell commands automatically while the skill is active."),
    "user-invocable": ("medium", "user-invocable: false hides the skill from the slash-command menu (HiddenLayer)."),
    "context": ("low", "context: fork runs the skill in a background sub-context (Embrace The Red)."),
    "model": ("low", "Overrides the model (downgrade to dodge refusals or upgrade for cost - denial-of-wallet)."),
    "effort": ("low", "Overrides reasoning effort (cost / refusal manipulation)."),
    "when_to_use": ("low", "Activation text outside the description - hub UIs may not show it to users."),
    "when-to-use": ("low", "Activation text outside the description - hub UIs may not show it to users."),
    "agent": ("low", "Routes the skill to a specific sub-agent."),
    "permissions": ("medium", "Declares permissions for the agent."),
    "env": ("medium", "Declares environment variables (check for *_BASE_URL / API redirects)."),
}

NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
FRONT_RE = re.compile(r"\A(\ufeff?)([ \t]*\r?\n)*?---[ \t]*\r?\n(.*?)\r?\n(?:---|\.\.\.)[ \t]*(?:\r?\n|\Z)", re.S)
_QUALIFIER = (r"(?!\s+(?:involving|related|relating|about|that|which|with|where|when|regarding|concerning|mentioning|"
              r"in\b|on\b|for\b|to\b|using|requiring|from|of|containing|touching|like|such)\b)")
TRIGGER_HIJACK = re.compile(
    r"\b(?:use|invoke|activate|load|trigger|run|call|consult)\s+(?:this\s+(?:skill|tool)\s+)?(?:for|on|in|with|before|during)"
    r"\s+(?:all|every|any|each)\s+(?:single\s+)?(?:task|request|prompt|message|conversation|query|question|interaction|"
    r"turn|situation|operation|response)s?\b" + _QUALIFIER + r"|"
    r"\b(?:before|instead\s+of)\s+(?:any|all|every)\s+other\s+(?:skills?|tools?)\b|"
    r"\bregardless\s+of\s+(?:the\s+)?(?:task|request|topic|context|what\s+the\s+user)\b|"
    r"\b(?:always|must)\s+(?:be\s+)?(?:use[ds]?|invoked?|activated?|loaded|called|consulted)\s+(?:first|for\s+(?:all|every|"
    r"any)\s+(?:task|request|message|prompt)s?\b" + _QUALIFIER + r")|\bALWAYS\s+CONSULT\s+THIS\s+(?:TOOL|SKILL)\b", re.I)
PREREQ_HEADING = re.compile(
    r"^(#{1,6})\s*(?:[^\w\s]{0,4}\s*)?(?:prerequisites?|pre-requisites?|requirements?|required\s+(?:setup|dependenc(?:y|ies)|"
    r"components?|tools?)|setup(?:\s+required)?|installation|install(?:ing)?|before\s+(?:you\s+)?(?:start|use|using|"
    r"begin|running)|getting\s+started|dependencies|first[- ]time\s+setup|quick\s*start)\b", re.I | re.M)
LINK_TEXT_VAGUE = re.compile(r"\[(?:here|this\s+link|click\s+here|link|download|this|this\s+page)\]\((https?://[^)\s]+)\)", re.I)
REF_PATH_RE = re.compile(r"(?<![\w/.$<{-])((?:\./)?(?:scripts?|references?|assets?|bin|helpers?)/[\w./-]+\.[A-Za-z0-9]{1,5})\b")
MD_LOCAL_LINK = re.compile(r"\]\((?!https?:|#|mailto:|data:)([^)\s#?]+)(?:[#?][^)]*)?\)")
EXEC_SCRIPT_RE = re.compile(
    r"(?:\b(?:bash|sh|zsh|python3?|py|node|deno|bun|pwsh|powershell(?:\.exe)?|ruby|perl|php|source|osascript|"
    r"uv\s+run|npx\s+tsx|tsx|ts-node)\s+(?:-[\w-]+\s+)*|(?:^|[\s`'\"(])\.\s+|(?:^|[\s`'\"(]))[\"'`]?"
    r"(\./|\$\{?(?:CLAUDE_[A-Z_]+|SKILL_DIR|BASE_DIR|baseDir)\}?/|\{baseDir\}/|<skill[_-]dir>/)?"
    r"((?:scripts?|bin|helpers?)/[\w./-]+\.(?:sh|bash|py|js|mjs|cjs|ts|ps1|rb|pl|php|command|bat|cmd))",
    re.I | re.M)
BINARY_LINK = re.compile(r"\.(?:zip|7z|rar|dmg|pkg|exe|msi|bat|cmd|ps1|sh|command|app|jar|apk|appimage|deb|rpm|tar\.gz|tgz)"
                         r"(?:\?|#|$)", re.I)


def _refs(cat):
    return list(CATEGORY_INFO.get(cat, ("", []))[1])


def _F(rid, title, sev, cat, path, line, message, evidence=(), conf="high", caps=(), snippet="") -> Finding:
    return Finding(rule_id=rid, title=title, severity=sev, category=cat, path=path, line=line, confidence=conf,
                   message=message, evidence=list(evidence), origin="manifest", references=_refs(cat),
                   capabilities=list(caps), snippet=snippet)


def mini_yaml(lines: List[str], first_line: int):
    """Tiny, forgiving YAML subset parser for frontmatter. Returns (data, duplicates, issues)."""
    data: Dict[str, dict] = {}
    dups: List[Tuple[str, int]] = []
    issues: List[Tuple[str, int, str]] = []
    i = 0
    while i < len(lines):
        ln = lines[i]
        if not ln.strip() or ln.lstrip().startswith("#"):
            i += 1
            continue
        indent = ln[:len(ln) - len(ln.lstrip())]
        if "\t" in indent:
            issues.append(("tab", first_line + i, ln))
        m = re.match(r"^([^\s:#\-][^:]*?|\"[^\"]+\"|'[^']+')\s*:(?:[ \t]+(.*)|[ \t]*)$", ln)
        if m and not indent:
            key = m.group(1).strip().strip("'\"")
            val = (m.group(2) or "").strip()
            block = []
            j = i + 1
            while j < len(lines) and (not lines[j].strip() or lines[j][:1] in (" ", "\t", "-")):
                block.append(lines[j])
                j += 1
            while block and not block[-1].strip():
                block.pop()
            if re.match(r"^[|>][-+0-9]*\s*(?:#.*)?$", val):
                parts = [b.strip() for b in block]
                value = (" " if val.startswith(">") else "\n").join(parts).strip()
            elif not val and block and all(b.lstrip().startswith("-") for b in block if b.strip()):
                value = [b.lstrip()[1:].strip().strip("'\"") for b in block if b.strip()]
            elif not val and block:
                value = {"_raw": "\n".join(block)}
            else:
                value = val
                if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                    value = value[1:-1]
                elif value.startswith("[") and value.endswith("]"):
                    value = [v.strip().strip("'\"") for v in value[1:-1].split(",") if v.strip()]
                elif block:
                    value = value + " " + " ".join(b.strip() for b in block)
            if key in data:
                dups.append((key, first_line + i))
            data[key] = {"value": value, "line": first_line + i}
            i = j
        else:
            issues.append(("unparsed", first_line + i, ln))
            i += 1
    return data, dups, issues


def _as_list(v) -> List[str]:
    if isinstance(v, list):
        return [str(x) for x in v]
    if isinstance(v, dict):
        return [x.strip("- ").strip() for x in v.get("_raw", "").splitlines() if x.strip()]
    s = str(v or "")
    # "Read, Grep, Bash(git:*)" or "Read Grep Bash(git:*)"
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        if depth == 0 and (ch == "," or ch.isspace()):
            if cur.strip():
                out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


RISKY_BASH = {
    "curl": "high", "wget": "high", "rm": "high", "sudo": "high", "ssh": "high", "scp": "high", "nc": "high",
    "ncat": "high", "bash": "high", "sh": "high", "zsh": "high", "eval": "high", "python": "medium", "python3": "medium",
    "node": "medium", "npx": "medium", "pip": "medium", "pip3": "medium", "npm": "medium", "powershell": "high",
    "pwsh": "high", "chmod": "medium", "chown": "medium", "dd": "high", "mkfs": "high", "crontab": "high",
    "launchctl": "high", "systemctl": "high", "osascript": "high", "security": "high", "base64": "medium",
    "git push": "medium", "docker": "medium", "kubectl": "medium", "aws": "medium", "gcloud": "medium", "az": "medium",
    "env": "medium", "printenv": "medium", "cat": "low", "find": "low", "xargs": "medium", "perl": "medium",
    "ruby": "medium", "uvx": "medium", "open": "medium", "xattr": "high", "spctl": "high", "reg": "high",
    "schtasks": "high", "certutil": "high", "mshta": "high", "rundll32": "high",
}


def analyze_skill_md(unit: TextUnit, skill_dir: str, dir_name: str, all_paths: Set[str]) -> Tuple[List[Finding], dict]:
    text = unit.text
    path = unit.path
    out: List[Finding] = []
    meta: dict = {"path": path, "name": "", "description": "", "frontmatter": {}, "allowed_tools": [],
                  "scripts_invoked": [], "referenced_files": [], "missing_references": [], "body_lines": 0}

    m = FRONT_RE.match(text)
    if not m:
        if text.lstrip("\ufeff \t\r\n").startswith("---"):
            out.append(_F("META-FRONTMATTER-MALFORMED", "Frontmatter is not terminated / malformed", "medium",
                          "manifest", path, 1, "Agents may silently drop a skill whose YAML fails to parse while its "
                          "scripts stay on disk (openclaw issue 22134)."))
        else:
            out.append(_F("META-NO-FRONTMATTER", "SKILL.md has no YAML frontmatter", "medium", "manifest", path, 1,
                          "A skill needs 'name' and 'description' frontmatter."))
        meta["body_lines"] = text.count("\n") + 1
        body, body_start = text, 1
        fm = {}
    else:
        if m.group(1) or m.group(2):
            out.append(_F("META-FRONTMATTER-OFFSET", "Frontmatter does not start on the first byte", "low", "manifest",
                          path, 1, "A BOM or blank lines before '---' can make some parsers ignore the frontmatter."))
        fm_text = m.group(3)
        fm_first = text[:m.start(3)].count("\n") + 1
        body = text[m.end():]
        body_start = text[:m.end()].count("\n") + 1
        lines = fm_text.split("\n")
        fm, dups, issues = mini_yaml([l.rstrip("\r") for l in lines], fm_first)
        meta["frontmatter"] = {k: (v["value"] if not isinstance(v["value"], dict) else v["value"]["_raw"])
                               for k, v in fm.items()}
        for key, ln in dups:
            out.append(_F("META-DUPLICATE-KEY", "Duplicate frontmatter key '%s'" % visible(key), "high", "manifest",
                          path, ln, "YAML parsers disagree on which value wins - the description a user/hub sees can "
                          "differ from the one the agent uses."))
        tabs = [i for i in issues if i[0] == "tab"]
        if tabs:
            out.append(_F("META-YAML-TABS", "Tab indentation in frontmatter", "medium", "manifest", path, tabs[0][1],
                          "YAML forbids tabs; strict parsers reject the file and the skill may be silently dropped."))
        unparsed = [i for i in issues if i[0] == "unparsed"]
        if unparsed:
            out.append(_F("META-YAML-UNPARSED", "Frontmatter lines not understood", "low", "manifest", path,
                          unparsed[0][1], "%d line(s) were not valid 'key: value' YAML." % len(unparsed),
                          [visible(u[2], 200) for u in unparsed[:5]], conf="medium"))
        if re.search(r"(?:^|[\s:\[,])&[A-Za-z0-9_-]+|(?:^|[\s:\[,])\*[A-Za-z0-9_-]+(?:\s|$|,|\])", fm_text, re.M):
            out.append(_F("META-YAML-ANCHORS", "YAML anchors / aliases in frontmatter", "medium", "manifest", path,
                          fm_first, "Anchors and aliases are unnecessary in skill metadata and can confuse parsers "
                          "(billion-laughs style expansion)."))
        if re.search(r"!![A-Za-z]|![A-Za-z][\w/]*\s|!<", fm_text):
            sev = "critical" if re.search(r"!!python/|!!ruby/|!!java|!!js/", fm_text) else "high"
            out.append(_F("META-YAML-TAGS", "Explicit YAML type tags in frontmatter", sev, "manifest", path, fm_first,
                          "Tags like !!python/object trigger code execution in unsafe YAML loaders.",
                          [visible(x, 200) for x in re.findall(r"[^\n]*![^\n]*", fm_text)[:3]], caps=("execute",)))
        unknown = [k for k in fm if k not in SPEC_KEYS and k not in VENDOR_KEYS]
        if unknown:
            out.append(_F("META-UNKNOWN-KEYS", "Non-standard frontmatter keys", "low", "manifest", path,
                          fm[unknown[0]]["line"], "Keys outside the Agent Skills spec: %s. Hubs often do not show "
                          "these to users." % ", ".join(visible(k) for k in unknown[:12])))
        for key, (sev, why) in RISKY_VENDOR_KEYS.items():
            if key in fm:
                val = fm[key]["value"]
                if key == "user-invocable" and str(val).lower() not in ("false", "no", "0"):
                    continue
                if key == "context" and str(val).lower() != "fork":
                    continue
                shown = val["_raw"] if isinstance(val, dict) else val
                out.append(_F("META-RISKY-FIELD-%s" % key.upper().replace("_", "-"), "Frontmatter field '%s'" % key,
                              sev, "excessive-agency" if key == "hooks" else "manifest", path, fm[key]["line"], why,
                              ["%s: %s" % (key, visible(str(shown), 600))],
                              caps=("execute", "agent-config") if key == "hooks" else ()))

    # ---- name ------------------------------------------------------------------------
    name = str(fm.get("name", {}).get("value", "")) if fm else ""
    meta["name"] = name
    nline = fm.get("name", {}).get("line", 1) if fm else 1
    if fm and not name:
        out.append(_F("META-NAME-MISSING", "Missing 'name'", "medium", "manifest", path, 1, "Required by the spec."))
    if name:
        if not NAME_RE.match(name) or len(name) > 64:
            out.append(_F("META-NAME-INVALID", "Skill name violates the spec", "medium", "manifest", path, nline,
                          "'%s' - must be 1-64 chars of lowercase a-z, 0-9 and single hyphens." % visible(name)))
        if dir_name and name != dir_name and dir_name not in (".", ""):
            out.append(_F("META-NAME-DIR-MISMATCH", "Skill name does not match its folder name", "low", "manifest",
                          path, nline, "name '%s' vs folder '%s'. Mismatches can hide which skill is really installed."
                          % (visible(name), visible(dir_name))))
        low = name.lower()
        if re.search(r"anthropic|claude|openai|official|verified", low):
            out.append(_F("META-NAME-IMPERSONATION", "Name uses vendor / trust words", "low", "manifest", path, nline,
                          "'%s' - the spec reserves 'anthropic'/'claude'; trust words are used to impersonate official "
                          "skills." % visible(name)))
        if low in iocs.KNOWN_BAD_SKILL_NAMES or low.startswith(iocs.KNOWN_BAD_SKILL_PREFIXES):
            out.append(_F("IOC-KNOWN-BAD-SKILL-NAME", "Skill name matches a known malicious skill", "critical", "known-ioc",
                          path, nline, "'%s' appears in published malicious-skill lists (ClawHavoc / Unit 42)."
                          % visible(name)))
        elif re.search(r"-(?=[a-z0-9]*\d)[a-z0-9]{5}$", low):
            out.append(_F("META-NAME-RANDOM-SUFFIX", "Name ends in a random-looking suffix", "low", "manifest", path,
                          nline, "Mass-published malicious clones used random suffixes (e.g. auto-updater-161ks)."))
        if re.search(r"(?:^|-)(?:security|scanner|antivirus|guard|defender|updater?|auto-?update|installer|setup|"
                     r"authenticator|auth-?tool|wallet|airdrop)(?:-|$)", low):
            out.append(_F("META-NAME-LURE-CATEGORY", "Name belongs to a frequently abused lure category", "info",
                          "manifest", path, nline, "Fake security scanners, updaters, auth tools and wallet "
                          "trackers were the most common malicious skill themes in 2026.", conf="medium"))

    # ---- description -----------------------------------------------------------------------
    desc_v = fm.get("description", {}).get("value", "") if fm else ""
    desc = desc_v["_raw"] if isinstance(desc_v, dict) else (" ".join(desc_v) if isinstance(desc_v, list) else str(desc_v))
    meta["description"] = desc
    dline = fm.get("description", {}).get("line", 1) if fm else 1
    if fm and not desc:
        out.append(_F("META-DESCRIPTION-MISSING", "Missing 'description'", "medium", "manifest", path, 1,
                      "Required by the spec; it is what the agent uses to decide when to load the skill."))
    if desc:
        if len(desc) > 1024:
            out.append(_F("META-DESCRIPTION-TOO-LONG", "Description exceeds 1024 characters", "medium", "manifest", path,
                          dline, "%d chars. Oversized descriptions are used for keyword baiting / trigger abuse."
                          % len(desc)))
        if re.search(r"<\s*/?\s*[A-Za-z][\w:-]*[^>]*>", desc):
            out.append(_F("META-DESCRIPTION-XML", "XML/HTML tags in description", "low", "manifest", path, dline,
                          "The spec forbids XML tags in descriptions; they can impersonate prompt structure."))
        hj = TRIGGER_HIJACK.search(desc)
        if hj:
            out.append(_F("META-TRIGGER-HIJACK", "Description tries to make the skill trigger on everything", "high",
                          "prompt-injection", path, dline, "Overly broad / forced activation ('%s') hijacks skill "
                          "selection (SkillSpector TR1, arXiv 2605.11418)." % visible(hj.group(0), 120),
                          caps=("inject",)))
        if len(desc) < 20:
            out.append(_F("META-DESCRIPTION-VAGUE", "Very short description", "low", "manifest", path, dline,
                          "Hard to judge what the skill is supposed to do."))
        meta["description_capabilities_text"] = desc.lower()

    # ---- allowed-tools ---------------------------------------------------------------------------
    for key in ("allowed-tools", "tools"):
        if fm and key in fm:
            tools = _as_list(fm[key]["value"])
            meta["allowed_tools"] = tools
            tline = fm[key]["line"]
            for t in tools:
                tl = t.strip()
                m2 = re.match(r"^Bash(?:\((.*)\))?$", tl, re.I)
                if tl in ("*", "all") or (m2 and (m2.group(1) is None or m2.group(1).strip() in ("", "*", "*:*", ":*"))):
                    out.append(_F("PERM-UNRESTRICTED-SHELL", "Pre-approves unrestricted shell access", "medium",
                                  "excessive-agency", path, tline, "'%s' lets the agent run any command without a "
                                  "permission prompt while this skill is active. Escalated to HIGH if the skill also "
                                  "contains dangerous behaviour (CHAIN-PREAPPROVED-SHELL-DANGER)." % visible(tl),
                                  caps=("execute", "pre-approved-shell")))
                    continue
                if m2:
                    spec = m2.group(1).strip()
                    cmd = re.split(r"[:\s*]", spec, 1)[0].lower()
                    cmd2 = " ".join(spec.lower().replace(":", " ").split()[:2])
                    sev = RISKY_BASH.get(cmd2) or RISKY_BASH.get(cmd)
                    rest = spec[len(cmd):].strip(" :")
                    if cmd in ("bash", "sh", "zsh", "python", "python3", "node", "pwsh", "powershell", "ruby", "perl") \
                            and re.match(r"[\"']?[\w${}./-]*[/\\][\w.-]+\.(?:sh|py|js|mjs|ps1|rb|pl)[\"']?", rest):
                        sev = "low"  # pre-approves one specific bundled script, not the interpreter in general
                    if sev and sev != "low":
                        out.append(_F("PERM-RISKY-SHELL-COMMAND", "Pre-approves a risky shell command", sev,
                                      "excessive-agency", path, tline, "'%s' is approved without prompting." % visible(tl),
                                      caps=("execute", "pre-approved-shell")))
                    continue
                if re.match(r"^(?:Write|Edit|MultiEdit)\((?:/|~|\*\*|C:)", tl, re.I):
                    out.append(_F("PERM-BROAD-WRITE", "Pre-approves writes to broad paths", "medium", "excessive-agency",
                                  path, tline, visible(tl)))
                elif re.match(r"^(?:WebFetch|WebSearch)\b", tl):
                    out.append(_F("PERM-NETWORK-TOOL", "Pre-approves web access", "low", "excessive-agency", path, tline,
                                  visible(tl), caps=("network",)))
                elif re.match(r"^(?:CronCreate|RemoteTrigger|ScheduleWakeup)\b", tl):
                    out.append(_F("PERM-SCHEDULING-TOOL", "Pre-approves task scheduling", "medium", "excessive-agency",
                                  path, tline, visible(tl), caps=("persist",)))
                elif re.match(r"^mcp__\w*\*|^mcp__.*__\*$", tl):
                    out.append(_F("PERM-MCP-WILDCARD", "Pre-approves all tools of an MCP server", "medium",
                                  "excessive-agency", path, tline, visible(tl)))

    # ---- body ------------------------------------------------------------------------------------------
    meta["body_lines"] = body.count("\n") + 1
    if meta["body_lines"] > 500:
        out.append(_F("META-LONG-BODY", "Very long SKILL.md body", "info", "manifest", path, body_start,
                      "%d lines. Long plausible documentation is used to bury a single malicious step."
                      % meta["body_lines"], conf="medium"))

    refs: Set[str] = set()
    for rx in (REF_PATH_RE, MD_LOCAL_LINK):
        for mm in rx.finditer(body):
            refs.add(mm.group(1))
    invoked: List[str] = []
    plugin_scripts: List[str] = []
    for mm in EXEC_SCRIPT_RE.finditer(body):
        s = mm.group(2)
        if mm.group(1) and "PLUGIN_ROOT" in mm.group(1).upper():
            if s not in plugin_scripts:
                plugin_scripts.append(s)  # lives in the plugin root, outside this skill folder
            continue
        if s not in invoked:
            invoked.append(s)
    meta["plugin_root_scripts"] = plugin_scripts
    if plugin_scripts:
        out.append(_F("META-PLUGIN-ROOT-SCRIPTS", "SKILL.md runs scripts from the plugin root", "info", "manifest",
                      path, 0, "%s - these live outside this skill folder; scan the whole plugin directory to cover "
                      "them." % ", ".join(visible(x) for x in plugin_scripts[:10])))
    present = {p.lower() for p in all_paths}
    missing = []
    resolved_refs = []
    for r in sorted(refs | set(invoked)):
        rr = r[2:] if r.startswith("./") else r
        if rr.startswith("../"):
            out.append(_F("META-REFERENCE-OUTSIDE", "SKILL.md references a path outside the skill", "medium", "manifest",
                          path, 0, visible(r)))
            continue
        full = posixpath.normpath(posixpath.join(skill_dir, rr)) if skill_dir else posixpath.normpath(rr)
        resolved_refs.append(full)
        if full.lower() not in present and not any(p.startswith(full.lower() + "/") for p in present):
            if re.search(r"\.[A-Za-z0-9]{1,5}$", rr):
                missing.append(r)
    meta["referenced_files"] = resolved_refs
    meta["scripts_invoked"] = [posixpath.normpath(posixpath.join(skill_dir, s[2:] if s.startswith("./") else s))
                               if skill_dir else posixpath.normpath(s[2:] if s.startswith("./") else s) for s in invoked]
    meta["missing_references"] = missing
    invoked_set = set(invoked)
    missing_exec = [x for x in missing if x in invoked_set]
    missing_other = [x for x in missing if x not in invoked_set]
    if missing_exec:
        out.append(_F("META-MISSING-INVOKED-SCRIPT", "SKILL.md tells the agent to run a script that is not bundled",
                      "low", "supply-chain", path, 0, "Missing: %s. The script may be fetched at runtime (unreviewable) "
                      "or was removed to pass review." % ", ".join(visible(x) for x in missing_exec[:10])))
    if missing_other:
        out.append(_F("META-MISSING-REFERENCE", "SKILL.md references files that are not in the package", "low",
                      "supply-chain", path, 0, "Missing: %s." % ", ".join(visible(x) for x in missing_other[:10]),
                      conf="medium"))

    # ---- prerequisite / install lures --------------------------------------------------------------------
    for hm in PREREQ_HEADING.finditer(body):
        level = len(hm.group(1))
        start = hm.end()
        nxt = re.compile(r"^#{1,%d}\s" % level, re.M).search(body, start)
        section = body[start: nxt.start() if nxt else min(len(body), start + 4000)]
        sec_line = body_start + body[:hm.start()].count("\n")
        urls = [iocs.clean_url(u.group(0)) for u in iocs.URL_RE.finditer(section)]
        ext = []
        for u in urls:
            host, _, _ = iocs.parse_url(u)
            tags = iocs.classify_host(host, u)
            if iocs.is_known_installer(u) or ("well-known" in tags and not BINARY_LINK.search(u)):
                continue
            ext.append((u, tags))
        lowsec = section.lower()
        has_pw = bool(re.search(r"\bpass(?:word|wd|code)?\b\s*[:=]|\bunzip\s+-P|\s-p\w", section, re.I))
        has_dl = bool(re.search(r"\b(?:download|install|run|execute|curl|wget|paste|terminal|setup|extract|unzip)\b", lowsec))
        bad = [(u, t) for u, t in ext if BINARY_LINK.search(u) or set(t) & {"paste-site", "file-share", "public-ip",
                                                                           "known-bad", "url-shortener", "free-hosting",
                                                                           "github-release-download", "dynamic-dns"}]
        vague = LINK_TEXT_VAGUE.findall(section)
        if (bad and has_dl) or (has_pw and has_dl and ext):
            sev = "critical" if has_pw or any("known-bad" in t or "public-ip" in t or "paste-site" in t for _, t in bad) else "high"
            out.append(_F("META-PREREQUISITE-LURE", "Setup section sends the user/agent to download & run external code",
                          sev, "social-engineering", path, sec_line,
                          "The '%s' section links to: %s%s. This is the ClawHavoc delivery pattern (fake required "
                          "dependency -> password-protected zip / base64 | bash)." %
                          (visible(hm.group(0).strip("# "), 60), ", ".join(visible(u, 120) for u, _ in (bad or ext)[:5]),
                           " and mentions an archive password" if has_pw else ""),
                          caps=("social-engineering", "download")))
        elif ext and has_dl:
            out.append(_F("META-PREREQUISITE-EXTERNAL", "Setup section installs from external sources", "medium",
                          "supply-chain", path, sec_line, "Links: %s" % ", ".join(visible(u, 120) for u, _ in ext[:5]),
                          caps=("download",)))
        if vague:
            out.append(_F("META-VAGUE-LINK-TEXT", "Download links hidden behind vague link text ('here', 'this link')",
                          "medium", "social-engineering", path, sec_line,
                          ", ".join(visible(v, 120) for v in vague[:5])))
    return out, meta
