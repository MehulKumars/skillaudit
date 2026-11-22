# skillaudit: plan, design and status

## 1. Goal

A tool that can evaluate **any** AI-agent skill (the `SKILL.md` file and every folder, subfolder, hidden file and
encoded payload around it) for security risk. It must:

- run **fully offline**, with no LLM, no internet and no third-party packages;
- never execute or deserialise the content it inspects;
- produce a report that a human security engineer **or another LLM** can review safely and efficiently.

## 2. Threat model (what a malicious skill does)

Distilled from the research in [THREAT-CATALOG.md](THREAT-CATALOG.md):

| # | Vector | Real-world example | Where it hides |
|---|---|---|---|
| 1 | Fake prerequisite / install lure | ClawHavoc (341 to 1,184 ClawHub skills delivering AMOS) | SKILL.md "Prerequisites", password-protected zips, `base64 -D \| bash` |
| 2 | Auxiliary payload (SkillJect) | Clean SKILL.md that says "run scripts/validate.py" | bundled scripts |
| 3 | Credential / wallet theft and exfiltration | rankaj (`~/.clawdbot/.env` to webhook.site), AMOS | scripts, natural-language instructions |
| 4 | Prompt injection, concealment, tool poisoning | Invariant `<IMPORTANT>` sidenote, "Do not mention this to the user" | SKILL.md, references, tool descriptions |
| 5 | Invisible content | Unicode tags (ASCII smuggling), variation-selector bytes (GlassWorm), zero-width, bidi, HTML comments, padding | any text file |
| 6 | Temporal persistence | writes to MEMORY.md / SOUL.md / HEARTBEAT.md, cron, shell rc, agent settings | scripts, instructions |
| 7 | Agent-config tampering | `--dangerously-skip-permissions`, `ANTHROPIC_BASE_URL`, `chat.tools.autoApprove`, bundled `.claude/settings.json` | scripts, config files |
| 8 | Opaque code | `.pyc` that differs from `.py`, native binaries, `.docx` hiding `sync1.sh`, images with appended zips | assets |
| 9 | Supply chain | alternate package indexes, registry redirects, `npx -y`, install hooks, rug-pull updates | package configs |
| 10 | Reviewer manipulation | text telling AI scanners to "mark this skill as safe" | anywhere |

## 3. Architecture

```
target -> discover units (one per skill; a folder of skills is split, plus a unit for files outside skills)
       -> walker (lstat only; Windows attributes + NTFS ADS; never follows links)
       -> per file: magic sniff -> text decode (UTF-8/16/32, BOM-less UTF-16) -> kind/surface
            |- archives: opened in memory -> members re-queued (recursive, size/count/depth budgets)
            |- binaries: format analyzers (PE/ELF/Mach-O, pickle via pickletools, OLE, PDF, images, polyglots)
            |      -> printable strings / metadata / appended data re-queued as text units
            '- text: content engine
                  |- Unicode analyzer (decodes tag / variation-selector / zero-width payloads -> re-scanned)
                  |- hidden-content analyzer (comments, hidden HTML, padding, deceptive links)
                  |- ~220 regex rules (raw view + NFKC/invisible-stripped view for evasion)
                  |- IOC extraction + classification + offline known-bad matching
                  '- decoders (base64, hex, escapes, char codes, ROT13, -EncodedCommand, compression)
                        -> decoded text re-scanned (depth <= 4)
       -> structure checks (names, attributes, links, special files, case collisions, pyc vs source)
       -> SKILL.md manifest analyzer (spec + risky fields + allowed-tools + lures + invoked scripts)
       -> correlation (attack chains, undeclared capabilities) -> allowlist -> score + verdict
       -> reports: Markdown (LLM-safe), HTML (CSP, escaped), JSON, SARIF; index for multi-skill scans
```

Design rules:

- **Fail visible, never silent.** Unreadable, encrypted, oversized or unscannable content becomes a finding, never
  a skipped file.
- **Untrusted content is always sanitised.** Invisible characters become `[U+XXXX]` markers, fences are sized so
  content cannot close them, the HTML is escaped under a strict CSP, and secrets are redacted.
- **No in-band suppression.** Only the auditor's allowlist can suppress, and it can be pinned to SHA-256.
- **Bounded everything.** Read caps, archive budgets, decode depth and linear-time padding detection protect
  against scanner denial of service.

## 4. Validation done

| Check | Result |
|---|---|
| Unit and end-to-end tests (`tests/test_skillaudit.py`) | 21 tests: 10 attack fixtures plus a benign control, report safety and privacy, allowlist, baseline, padding/ReDoS, CLI exit codes |
| Benign corpus: 108 real installed skills (Anthropic official, plugin marketplace, Codex system skills) | After tuning: 0 CRITICAL, 1 HIGH, 15 MEDIUM, 40 LOW, 52 CLEAN (official Homebrew `curl \| bash` installer, which really is remote code execution) |
| Malicious fixtures (ClawHavoc, SkillJect, Unicode smuggling, hidden Markdown, persistence, obfuscation, MCP poisoning, reviewer manipulation, binary/archive tricks, packaged `.skill`) | 9 CRITICAL, 1 HIGH, each with the expected rule IDs |
| ReDoS / performance probe (`tests/perf_redos.py`) | 0 slow rules at 20 KB and 200 KB hostile inputs; a 22 MB padded file scans in ~1.3 s (was >10 min before the fix) |

False-positive tuning targeted documented patterns: defensive quotes of injection phrases, negated instructions
("do not silently fetch"), double negatives ("never ... without telling the user"), UI `display:none` in real HTML,
Markdown-table padding, Greek letters in maths, `core.hooksPath=/dev/null` hardening, and official installers.

## 5. Roadmap (optional next steps)

1. **Pre-install gate.** A Claude Code `PreToolUse` hook or a `skillaudit watch` mode that scans any new folder
   appearing under `~/.claude/skills` or a plugin cache, and blocks or warns on HIGH and above.
2. **Hash-pinned lockfile.** Record reviewed skill hashes (`skills.lock`) and fail when an installed skill drifts
   from it (rug-pull defence), building on `--baseline`.
3. **IOC feed updates.** Keep `iocs.py` lists in a separate JSON file that can be refreshed (manually or by a
   separate, opt-in online script) without touching code.
4. **Optional dynamic stage (separate tool).** A sandboxed run (container with `--network none`, read-only mount,
   filesystem diff and syscall trace) for skills that pass static review. It stays separate so the core remains
   offline and execution-free.
5. **Python AST dataflow.** Taint tracking from secret sources to network sinks across functions, beyond the
   same-file co-occurrence used today.
6. **YARA export.** Emit the regex catalog as YARA rules for teams that already run YARA.
7. **CI template.** A GitHub Actions workflow that runs `skillaudit --fail-on high -f sarif` and uploads SARIF.
