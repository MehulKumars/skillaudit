"""Cross-finding correlation: attack chains, capability summary, risk score, verdict."""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Dict, List, Sequence, Tuple

from .model import Finding, max_sev, sev_rank
from .rules import CATEGORY_INFO

CAP_LABELS = {
    "download": "Downloads remote content",
    "execute": "Executes commands / code",
    "network": "Uses the network",
    "network-send": "Sends data out over the network",
    "exfil-endpoint": "References an exfiltration / webhook endpoint",
    "read-secrets": "Accesses credentials or secret stores",
    "secret-env": "Reads API-key environment variables",
    "decode": "Decodes encoded data at runtime",
    "obfuscation": "Contains obfuscated / encoded content",
    "persist": "Installs persistence",
    "agent-config": "Touches AI-agent configuration / memory",
    "inject": "Contains prompt-injection language",
    "conceal": "Hides activity from the user",
    "destructive": "Performs destructive operations",
    "recon": "Profiles the host / user",
    "privesc": "Escalates privileges",
    "remote-control": "Opens remote access (shells / tunnels)",
    "evasion": "Evades defenses or analysis",
    "install-packages": "Installs packages / dependencies",
    "clipboard": "Reads or writes the clipboard",
    "file-sweep": "Sweeps the filesystem for files",
    "social-engineering": "Social-engineers the user",
    "pre-approved-shell": "Pre-approves shell commands (allowed-tools)",
    "embedded-secret": "Contains hard-coded secrets",
    "background": "Starts background / detached processes",
    "c2-token": "Contains a bot token (possible C2 channel)",
    "hidden": "Contains content hidden from human view (comments, invisible chars, hidden files)",
}
DANGEROUS_CATS = {"prompt-injection", "concealment", "remote-exec", "exfiltration", "credential-access",
                  "agent-tampering", "social-engineering", "reverse-shell", "destructive"}
ACTION_CATS = {"remote-exec", "dynamic-exec", "exfiltration", "network", "credential-access", "persistence",
               "agent-tampering", "destructive", "reverse-shell", "defense-evasion", "privilege-escalation",
               "cryptomining", "crypto-theft", "obfuscation", "known-ioc", "correlation", "recon", "sandbox-evasion",
               "autorun", "financial", "secrets"}
DOC_EXT = (".md", ".txt", ".rst", ".markdown", ".mdx", ".html", ".htm")
SEND = {"network-send", "exfil-endpoint"}


def _refs(cat):
    return list(CATEGORY_INFO.get(cat, ("", []))[1])


def _ev(fs: Sequence[Finding], caps: set, limit: int = 6) -> List[str]:
    out = []
    for f in fs:
        if set(f.capabilities) & caps:
            out.append("%s [%s] %s:%s - %s" % (f.rule_id, f.severity, f.path, f.line, f.title))
            if len(out) >= limit:
                break
    return out


def _chain(rid, title, sev, path, message, evidence, caps=()) -> Finding:
    return Finding(rule_id=rid, title=title, severity=sev, category="correlation", path=path, confidence="high",
                   message=message, evidence=evidence, origin="correlation", capabilities=list(caps),
                   references=["OWASP AST01", "OWASP ASI05", "ATLAS AML.T0086"] if "EXFIL" in rid else ["OWASP AST01"])


def chains(findings: List[Finding], skills: List[dict]) -> List[Finding]:
    live = [f for f in findings if sev_rank(f.severity) >= sev_rank("info")]
    by_path: Dict[str, List[Finding]] = defaultdict(list)
    for f in live:
        by_path[f.path].append(f)
    out: List[Finding] = []

    for path, fs in by_path.items():
        if not path or path == "(skill)":
            continue
        caps = {c for f in fs for c in f.capabilities}
        meaningful = {c for f in fs if sev_rank(f.severity) >= sev_rank("low") for c in f.capabilities}
        if "read-secrets" in meaningful and caps & SEND:
            out.append(_chain("CHAIN-CREDENTIAL-EXFILTRATION", "Credential access + outbound data in the same file",
                              "critical", path, "This file both reads secrets and sends data out - the classic "
                              "stealer pattern (ToxicSkills, rankaj, AMOS).", _ev(fs, {"read-secrets"} | SEND, 8),
                              ("read-secrets", "network-send")))
        elif "secret-env" in caps and "exfil-endpoint" in caps:
            out.append(_chain("CHAIN-API-KEY-EXFILTRATION", "API-key environment access + exfiltration endpoint",
                              "high", path, "API keys read from the environment in a file that also references a "
                              "webhook / request-capture service.", _ev(fs, {"secret-env", "exfil-endpoint"})))
        if "file-sweep" in caps and caps & SEND:
            out.append(_chain("CHAIN-FILE-SWEEP-EXFILTRATION", "Filesystem sweep + outbound data", "critical", path,
                              "Collects files from the home directory and sends data out.", _ev(fs, {"file-sweep"} | SEND)))
        if "recon" in meaningful and caps & SEND and "read-secrets" not in meaningful:
            out.append(_chain("CHAIN-RECON-EXFILTRATION", "Host profiling + outbound data", "high", path,
                              "Collects host/user details and sends data out (victim fingerprinting).",
                              _ev(fs, {"recon"} | SEND)))
        has_remote_exec = any(f.category == "remote-exec" and sev_rank(f.severity) >= sev_rank("high") for f in fs)
        if "download" in caps and "execute" in meaningful and not has_remote_exec:
            dl = [f for f in fs if "download" in f.capabilities and f.rule_id != "NET-HTTP-CLIENT"]
            if dl:
                out.append(_chain("CHAIN-DOWNLOAD-EXECUTE", "Downloads content and executes code in the same file",
                                  "high", path, "Download and execution primitives co-exist; check whether fetched "
                                  "content reaches an interpreter (dropper pattern).", _ev(fs, {"download", "execute"})))
        has_decode_exec = any(f.rule_id in ("OBF-DECODE-EXEC", "OBF-DECOMPRESS-EXEC", "EXEC-PS-ENCODED") for f in fs)
        if "decode" in caps and "execute" in meaningful and not has_decode_exec:
            obf = any(f.category == "obfuscation" and sev_rank(f.severity) >= sev_rank("medium") for f in fs)
            out.append(_chain("CHAIN-DECODE-EXECUTE", "Runtime decoding + code execution in the same file",
                              "high" if obf else "medium", path, "Encoded data and an execution sink in one file: "
                              "verify the decoded data never reaches exec/eval/a shell.", _ev(fs, {"decode", "execute"})))
        hidden_bad = [f for f in fs if "hidden" in f.tags and f.category in DANGEROUS_CATS
                      and f.origin not in ("structure",)]
        if hidden_bad:
            out.append(_chain("CHAIN-HIDDEN-INSTRUCTIONS", "Dangerous instructions inside hidden content", "critical",
                              path, "Instructions or commands are hidden from human reviewers (comments, invisible "
                              "Unicode, hidden HTML) but are read by the agent.",
                              ["%s [%s] line %s via %s" % (f.rule_id, f.severity, f.line, f.origin) for f in hidden_bad[:8]],
                              ("inject", "conceal")))

    # ---------------------------------------------------------------- skill-level
    all_caps = {c for f in live if sev_rank(f.severity) >= sev_rank("low") for c in f.capabilities}
    serious = [f for f in live if sev_rank(f.severity) >= sev_rank("medium")]
    serious_caps = {c for f in serious for c in f.capabilities}
    if "conceal" in serious_caps and serious_caps & {"execute", "network-send", "read-secrets", "destructive", "persist",
                                                      "download", "exfil-endpoint", "remote-control"}:
        out.append(_chain("CHAIN-CONCEALED-ACTION", "Concealment language combined with dangerous capabilities", "high",
                          "(skill)", "The skill tells the agent to hide things from the user AND contains risky "
                          "actions - 'Do Not Mention This to the User' pattern (arXiv 2602.06547).",
                          _ev(serious, {"conceal"}, 4) + _ev(serious, {"execute", "network-send", "read-secrets",
                                                                      "destructive", "persist", "download"}, 4)))
    agent_write = [f for f in live if f.rule_id in ("AGENT-CONFIG-WRITE", "AGENT-MEMORY-INSTRUCTION",
                                                    "AGENT-BUNDLED-MEMORY-FILE", "AGENT-SCHEDULE-TASKS")]
    if agent_write and "inject" in serious_caps:
        out.append(_chain("CHAIN-MEMORY-POISONING", "Persistent agent-memory poisoning", "critical", "(skill)",
                          "The skill writes to agent memory/config/rules and contains injection language - "
                          "instructions would survive uninstalling the skill (temporal persistence).",
                          ["%s %s:%s" % (f.rule_id, f.path, f.line) for f in agent_write[:4]] + _ev(live, {"inject"}, 4)))
    if "social-engineering" in serious_caps and serious_caps & {"download", "execute"}:
        out.append(_chain("CHAIN-INSTALL-LURE", "Social-engineering lure leading to download / execution", "critical",
                          "(skill)", "The ClawHavoc pattern: convince the user or agent to install a 'required' "
                          "component that is actually malware.",
                          _ev(serious, {"social-engineering"}, 4) + _ev(serious, {"download", "execute"}, 4)))
    if "pre-approved-shell" in all_caps:
        bad = [f for f in live if sev_rank(f.severity) >= sev_rank("high") and f.category in
               DANGEROUS_CATS | {"dynamic-exec", "persistence", "privilege-escalation", "obfuscation"}]
        if bad:
            out.append(_chain("CHAIN-PREAPPROVED-SHELL-DANGER", "Pre-approved shell access + dangerous behaviour", "high",
                              "(skill)", "allowed-tools removes the permission prompt that would otherwise let the user "
                              "stop these actions.", _ev(live, {"pre-approved-shell"}, 2) +
                              ["%s [%s] %s:%s" % (f.rule_id, f.severity, f.path, f.line) for f in bad[:5]]))

    for sk in skills:
        for script in sk.get("scripts_invoked", []):
            fs = [f for f in by_path.get(script, []) if f.origin != "structure" and f.category in ACTION_CATS]
            if not fs:
                continue
            worst = max_sev(*[f.severity for f in fs])
            if sev_rank(worst) >= sev_rank("medium"):
                sev = "critical" if sev_rank(worst) >= sev_rank("high") else "medium"
                out.append(_chain("CHAIN-SKILLJECT", "SKILL.md makes the agent run a bundled script with risky behaviour",
                                  sev, sk.get("path", "(skill)"), "SKILL.md instructs the agent to execute '%s', which "
                                  "has %s-severity findings. A clean-looking SKILL.md that delegates to a payload "
                                  "script is the SkillJect / auxiliary-payload pattern." % (script, worst),
                                  ["%s [%s] line %s - %s" % (f.rule_id, f.severity, f.line, f.title)
                                   for f in sorted(fs, key=lambda x: -sev_rank(x.severity))[:8]], ("execute",)))

    # ---------------------------------------------------------------- undeclared capabilities
    for sk in skills:
        desc = (sk.get("description") or "").lower() + " " + (sk.get("name") or "").lower().replace("-", " ")
        if not desc.strip():
            continue
        checks = (
            (SEND, r"send|upload|post|api|web|http|sync|share|publish|e-?mail|slack|discord|telegram|notify|webhook|"
                   r"cloud|remote|server|online|deploy|integrat|report|submit|github|jira|notion|drive|s3|bucket",
             "CAPABILITY-UNDECLARED-NETWORK-SEND", "Sends data out, but the description does not say so", "medium"),
            ({"read-secrets"}, r"credential|secret|key|token|ssh|aws|password|auth|vault|keychain|wallet|login|"
                               r"\benv\b|environment|cookie|browser|1password|bitwarden|gpg|cert",
             "CAPABILITY-UNDECLARED-CREDENTIAL-ACCESS", "Accesses credentials, but the description does not say so",
             "medium"),
            ({"persist"}, r"startup|schedul|cron|daemon|service|background|persist|login|autostart|boot|launch|"
                          r"hook|monitor|watch",
             "CAPABILITY-UNDECLARED-PERSISTENCE", "Installs persistence, but the description does not say so", "medium"),
            ({"remote-control"}, r"ssh|tunnel|remote|shell|vnc|desktop|ngrok|proxy|port",
             "CAPABILITY-UNDECLARED-REMOTE-ACCESS", "Opens remote access, but the description does not say so", "high"),
        )
        for capset, words, rid, title, sev in checks:
            hits = [f for f in serious if set(f.capabilities) & capset and
                    (not f.path.lower().endswith(DOC_EXT) or f.path.lower().endswith("skill.md"))]
            if hits and not re.search(words, desc):
                out.append(_chain(rid, title, sev, sk.get("path", "(skill)"),
                                  "Description: \"%s\". A mismatch between stated purpose and actual capability is a key "
                                  "malicious-skill signal (e.g. a weather skill that reads .env)." % (sk.get("description")
                                                                                                    or "")[:200],
                                  ["%s [%s] %s:%s" % (f.rule_id, f.severity, f.path, f.line) for f in hits[:5]]))
    return out


def capability_summary(findings: List[Finding]) -> Dict[str, List[str]]:
    caps: Dict[str, set] = defaultdict(set)
    for f in findings:
        for c in f.capabilities:
            caps[c].add(f.path or "(skill)")
    return {c: sorted(v)[:20] for c, v in sorted(caps.items())}


W = {"critical": 0.6, "high": 0.3, "medium": 0.1, "low": 0.025, "info": 0.0}
C = {"high": 1.0, "medium": 0.75, "low": 0.45}


def score_and_verdict(findings: List[Finding]) -> Tuple[int, str, str]:
    best: Dict[Tuple[str, str], float] = {}
    for f in findings:
        w = W.get(f.severity, 0) * C.get(f.confidence, 0.75)
        key = (f.rule_id, f.path)
        best[key] = max(best.get(key, 0.0), w)
    p = 1.0
    for w in best.values():
        p *= (1 - w)
    score = int(round(100 * (1 - p)))
    crit = [f for f in findings if f.severity == "critical" and f.confidence != "low"]
    high = [f for f in findings if (f.severity == "high" and f.confidence != "low") or
            (f.severity == "critical" and f.confidence == "low")]
    med = [f for f in findings if f.severity == "medium"]
    low = [f for f in findings if f.severity == "low"]
    if crit:
        return score, "CRITICAL", "Do not install. Strong indicators of malicious or highly dangerous behaviour."
    if high or score >= 60:
        return score, "HIGH", "Manual security review required before use."
    if med or score >= 20:
        return score, "MEDIUM", "Review the flagged items; may be acceptable with a clear justification."
    if low:
        return score, "LOW", "No significant risks detected by static analysis (not a guarantee of safety)."
    return score, "CLEAN", "No findings. Static analysis cannot prove a skill is safe."
