# skillaudit benchmark: per-rule numbers (baseline-1.0.0)

> **Limit.** The malicious samples and the rules were written by the same author, so these numbers show that known techniques are covered. They are not a real-world detection rate. The legitimate samples are what was installed on one developer machine, so they over-represent browser automation, design skills and front-end packages.

Tuning samples only. *Legit samples*: legitimate samples the rule fires on. *Labels*: CRITICAL and HIGH findings on legitimate samples (w = wrong match, r = real but normal here, h = needs a human, u = unlabelled). *Malicious*: demo skills it fires on at low or above. *Holds up*: demos whose verdict drops if the rule is removed. Rules that never fired and have no malicious example are listed only if they can report CRITICAL.

| Rule | Severity | Legit samples | Legit hits | Where on legit samples | Labels w/r/h/u | Malicious | Holds up | Status |
|---|---|---|---|---|---|---|---|---|
| `OBF-EMBEDDED-BINARY` | critical | 5 | 17 | own code 14, bundled / third-party 3 | 0/4/0/0 | 0 | 0 | unknown |
| `CRED-BROWSER` | critical | 4 | 49 | bundled / third-party 26, type definitions 16, own code 7 | 49/0/0/0 | 0 | 0 | pattern-tested |
| `UNI-ZERO-WIDTH` | critical | 4 | 11 | own code 8, bundled / third-party 3 | - | 1 | 0 | malicious example |
| `EXEC-JS-REMOTE-EXEC` | critical | 3 | 6 | bundled / third-party 4, own code 2 | 6/0/0/0 | 0 | 0 | pattern-tested |
| `OBF-ENCODED-PAYLOAD` | critical | 3 | 6 | own code 3, bundled / third-party 3 | - | 3 | 0 | malicious example |
| `OBF-DECODE-EXEC` | critical | 2 | 6 | own code 5, bundled / third-party 1 | 6/0/0/0 | 3 | 0 | malicious example |
| `CHAIN-CREDENTIAL-EXFILTRATION` | critical | 1 | 1 | bundled / third-party 1 | 1/0/0/0 | 2 | 0 | malicious example |
| `CHAIN-INSTALL-LURE` | critical | 1 | 1 | whole package 1 | 1/0/0/0 | 3 | 0 | malicious example |
| `CRED-PASSWORD-MANAGERS` | critical | 1 | 28 | own code 26, type definitions 2 | 28/0/0/0 | 0 | 0 | unknown |
| `EXEC-PS-DOWNLOAD-IEX` | critical | 1 | 2 | own code 1, bundled / third-party 1 | 2/0/0/0 | 2 | 0 | malicious example |
| `EXEC-SUBSHELL-DOWNLOAD` | critical | 1 | 1 | SKILL.md 1 | 0/1/0/0 | 0 | 0 | unknown |
| `MINER-INDICATORS` | critical | 1 | 21 | own code 21 | 21/0/0/0 | 0 | 0 | unknown |
| `SHELL-MKFIFO` | critical | 1 | 2 | own code 1, bundled / third-party 1 | 2/0/0/0 | 0 | 0 | unknown |
| `BIN-PDF-LAUNCH` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `BIN-PICKLE-CODE-EXEC` | critical | 0 | 0 | - | - | 1 | 0 | malicious example |
| `CHAIN-FILE-SWEEP-EXFILTRATION` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `CHAIN-HIDDEN-INSTRUCTIONS` | critical | 0 | 0 | - | - | 2 | 0 | malicious example |
| `CHAIN-MEMORY-POISONING` | critical | 0 | 0 | - | - | 1 | 0 | malicious example |
| `CHAIN-SKILLJECT` | critical | 0 | 0 | - | - | 3 | 0 | malicious example |
| `CRED-AGENT-TOKENS` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `CRED-KEYCHAIN` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `CRED-MESSAGING-TOKENS` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `CRED-SEED-EXFIL` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `CRED-WALLETS` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `CRED-WINDOWS` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `CRYPTO-ADDRESS-SWAP` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `DESTR-DISK` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `DESTR-FORK-BOMB` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `DESTR-INHIBIT-RECOVERY` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `DESTR-RM-ROOT` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `DESTR-WINDOWS-WIPE` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `EVADE-AMSI-ETW` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `EXEC-LOLBIN-MSHTA` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `EXEC-LOLBIN-REGSVR32` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `EXEC-PIPE-TO-SHELL` | critical | 0 | 0 | - | - | 7 | 0 | malicious example |
| `EXEC-PROCESS-SUBST` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `EXEC-PY-REMOTE-EXEC` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `FS-LINK-TO-SENSITIVE` | critical | 0 | 0 | - | - | 1 | 0 | malicious example |
| `FS-NAME-HIDDEN-CHARS` | critical | 0 | 0 | - | - | 0 | 0 | pattern-tested |
| `FS-NAME-HOMOGLYPH` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `IOC-KNOWN-BAD` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `IOC-KNOWN-BAD-HASH` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `IOC-KNOWN-BAD-IP` | critical | 0 | 0 | - | - | 1 | 0 | malicious example |
| `IOC-KNOWN-BAD-PACKAGE` | critical | 0 | 0 | - | - | 1 | 1 | malicious example |
| `IOC-KNOWN-BAD-SKILL-NAME` | critical | 0 | 0 | - | - | 2 | 0 | malicious example |
| `IOC-KNOWN-BAD-STRING` | critical | 0 | 0 | - | - | 2 | 0 | malicious example |
| `META-PREREQUISITE-LURE` | critical | 0 | 0 | - | - | 2 | 0 | malicious example |
| `META-YAML-TAGS` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `OBF-DECOMPRESS-EXEC` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `PERSIST-ROGUE-MCP-DIR` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `PERSIST-SSH-AUTHKEYS` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `PRIV-SUDOERS` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `SHELL-DEV-TCP` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `SHELL-NETCAT-EXEC` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `SHELL-OPENSSL-TELNET` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `SHELL-POWERSHELL` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `SHELL-PYTHON` | critical | 0 | 0 | - | - | 1 | 0 | malicious example |
| `SHELL-SCRIPTING-LANGS` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `SHELL-SOCAT` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `SOC-ARCHIVE-PASSWORD` | critical | 0 | 0 | - | - | 2 | 0 | malicious example |
| `SOC-FAKE-PASSWORD-DIALOG` | critical | 0 | 0 | - | - | 0 | 0 | unknown |
| `UNI-TAG-SMUGGLING` | critical | 0 | 0 | - | - | 1 | 0 | malicious example |
| `UNI-VARIATION-SELECTOR-SMUGGLING` | critical | 0 | 0 | - | - | 1 | 0 | malicious example |
| `OBF-MINIFIED-CODE` | high | 21 | 124 | bundled / third-party 65, own code 54, type definitions 5 | 0/92/0/0 | 0 | 0 | unknown |
| `SUPPLY-NPM-INSTALL-SCRIPT` | high | 11 | 11 | own code 11 | 11/0/0/0 | 0 | 0 | unknown |
| `CHAIN-DECODE-EXECUTE` | high | 5 | 17 | own code 11, bundled / third-party 6 | 3/10/0/0 | 0 | 0 | unknown |
| `BIN-COMPILED-CODE` | high | 3 | 3 | own code 3 | 0/3/0/0 | 0 | 0 | unknown |
| `BIN-NATIVE-EXECUTABLE` | high | 3 | 3 | own code 2, bundled / third-party 1 | 0/3/0/0 | 1 | 0 | malicious example |
| `EXEC-DOWNLOAD-EXECUTABLE` | high | 3 | 6 | own code 4, SKILL.md 1, bundled / third-party 1 | 0/5/0/0 | 2 | 0 | malicious example |
| `HIDE-COMMENT-INSTRUCTIONS` | high | 3 | 3 | documentation 3 | - | 1 | 0 | malicious example |
| `INJ-IGNORE-INSTRUCTIONS` | high | 3 | 3 | SKILL.md 3 | - | 3 | 0 | malicious example |
| `UNI-HOMOGLYPH-MIXED-SCRIPT` | high | 3 | 6 | own code 3, bundled / third-party 3 | 6/0/0/0 | 1 | 0 | malicious example |
| `PERSIST-BROWSER-EXTENSION` | high | 2 | 2 | type definitions 1, bundled / third-party 1 | 0/2/0/0 | 0 | 0 | unknown |
| `PERSIST-SHELL-RC-WRITE` | high | 2 | 5 | bundled / third-party 4, own code 1 | 4/1/0/0 | 1 | 0 | malicious example |
| `AGENT-CONFIG-WRITE` | high | 1 | 2 | own code 2 | 0/2/0/0 | 1 | 0 | malicious example |
| `CHAIN-CONCEALED-ACTION` | high | 1 | 1 | whole package 1 | 1/0/0/0 | 5 | 0 | malicious example |
| `CHAIN-DOWNLOAD-EXECUTE` | high | 1 | 1 | documentation 1 | 1/0/0/0 | 0 | 0 | unknown |
| `CRED-CLOUD` | high | 1 | 3 | SKILL.md 3 | 3/0/0/0 | 0 | 0 | unknown |
| `CRED-DEV-TOKENS` | high | 1 | 4 | SKILL.md 4 | 4/0/0/0 | 0 | 0 | unknown |
| `CRED-PROC-ENVIRON` | high | 1 | 1 | own code 1 | 1/0/0/0 | 0 | 0 | unknown |
| `CRED-SSH` | high | 1 | 2 | SKILL.md 2 | 2/0/0/0 | 4 | 0 | malicious example |
| `EXEC-LOLBIN-RUNDLL32` | high | 1 | 1 | own code 1 | 0/1/0/0 | 0 | 0 | unknown |
| `EXEC-PS-IEX` | high | 1 | 2 | own code 1, bundled / third-party 1 | 2/0/0/0 | 2 | 0 | malicious example |
| `HIDE-INVISIBLE-HTML` | high | 1 | 2 | documentation 2 | - | 1 | 0 | malicious example |
| `INJ-CONCEAL-FROM-USER` | high | 1 | 1 | bundled / third-party 1 | 0/1/0/0 | 2 | 0 | malicious example |
| `IOC-FILE-SHARE` | high | 1 | 12 | own code 12 | 0/12/0/0 | 0 | 0 | unknown |
| `IOC-NON-ASCII-HOST` | high | 1 | 1 | bundled / third-party 1 | 1/0/0/0 | 0 | 0 | unknown |
| `IOC-PASTE-SITE` | high | 1 | 3 | own code 3 | 0/3/0/0 | 0 | 0 | unknown |
| `META-RISKY-FIELD-HOOKS` | high | 1 | 1 | SKILL.md 1 | 0/0/1/0 | 1 | 0 | malicious example |
| `PERSIST-CRON` | high | 1 | 2 | own code 1, bundled / third-party 1 | 2/0/0/0 | 1 | 0 | malicious example |
| `PERSIST-INTERPRETER-HOOK` | high | 1 | 1 | bundled / third-party 1 | 1/0/0/0 | 0 | 0 | unknown |
| `SOC-ASK-FOR-PASSWORD` | high | 1 | 1 | type definitions 1 | - | 0 | 0 | unknown |
| `UNI-ANSI-ESCAPE` | high | 1 | 1 | own code 1 | 0/1/0/0 | 0 | 0 | unknown |
| `AGENT-API-REDIRECT` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `AGENT-MEMORY-INSTRUCTION` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `AGENT-PERMISSION-BYPASS` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `AGENT-SPAWN-UNSAFE` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `ARC-ENCRYPTED-MEMBERS` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `ARC-PATH-TRAVERSAL` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `BIN-APPENDED-DATA` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `BIN-POLYGLOT` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `CAPABILITY-UNDECLARED-REMOTE-ACCESS` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `CHAIN-PREAPPROVED-SHELL-DANGER` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `CRED-PATH-JOIN` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `EXEC-PS-ENCODED` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `EXEC-PS-HIDDEN-WINDOW` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `FS-ALTERNATE-DATA-STREAM` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `FS-EXTENSION-MISMATCH` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `FS-NAME-DOUBLE-EXTENSION` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `FS-WINDOWS-HIDDEN-ATTRIBUTE` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `HIDE-MARKDOWN-COMMENT` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `HIDE-VERTICAL-PADDING` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `INJ-DONT-INSPECT` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `INJ-EXFIL-INSTRUCTION` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `INJ-FAKE-AUTHORITY` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `INJ-IMPLEMENTATION-DETAIL` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `INJ-REVIEWER-MANIPULATION` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `INJ-ROLE-HIJACK` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `INJ-STEALTH-ACTION` | high | 0 | 0 | - | - | 2 | 0 | malicious example |
| `INJ-TOOL-POISONING` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `IOC-EXFIL-SERVICE` | high | 0 | 0 | - | - | 3 | 0 | malicious example |
| `META-TRIGGER-HIJACK` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `NET-MD-IMAGE-EXFIL` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `OBF-JS-OBFUSCATOR` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `OBF-ROT13` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `SECRET-ANTHROPIC` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `SECRET-AWS-KEY-ID` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `SOC-GATEKEEPER-BYPASS` | high | 0 | 0 | - | - | 2 | 0 | malicious example |
| `UNI-MULTIPLE-HIDDEN-TYPES` | high | 0 | 0 | - | - | 1 | 0 | malicious example |
| `HIDE-HTML-COMMENTS` | medium | 45 | 62 | documentation 46, SKILL.md 11, own code 3, bundled / third-party 2 | - | 0 | 0 | unknown |
| `CRED-DOTENV-READ` | medium | 7 | 20 | bundled / third-party 13, own code 6, documentation 1 | - | 0 | 0 | unknown |
| `EXEC-EVAL` | medium | 7 | 51 | own code 25, bundled / third-party 25, type definitions 1 | - | 1 | 0 | malicious example |
| `EXEC-JS-FUNCTION` | medium | 7 | 27 | bundled / third-party 17, own code 6, documentation 3, type definitions 1 | - | 0 | 0 | unknown |
| `BIN-NATIVE-CODE-EXT` | medium | 6 | 6 | own code 5, bundled / third-party 1 | - | 1 | 0 | malicious example |
| `META-REFERENCE-OUTSIDE` | medium | 6 | 14 | SKILL.md 14 | - | 0 | 0 | unknown |
| `UNI-CONTROL-CHARS` | medium | 5 | 16 | own code 9, bundled / third-party 7 | - | 0 | 0 | unknown |
| `IOC-RAW-PUBLIC-IP` | medium | 4 | 24 | own code 21, bundled / third-party 3 | - | 0 | 0 | unknown |
| `IOC-URL-CREDENTIALS` | medium | 4 | 8 | bundled / third-party 6, own code 1, documentation 1 | - | 0 | 0 | unknown |
| `AGENT-COMMAND-WRITE` | medium | 3 | 6 | documentation 5, own code 1 | - | 0 | 0 | unknown |
| `AGENT-SCHEDULE-TASKS` | medium | 3 | 12 | SKILL.md 12 | - | 0 | 0 | unknown |
| `EVADE-VM-DETECTION` | medium | 3 | 41 | own code 33, bundled / third-party 8 | - | 0 | 0 | unknown |
| `FS-VENDORED-DIR` | medium | 3 | 3 | bundled / third-party 3 | - | 0 | 0 | unknown |
| `HIDE-DECEPTIVE-LINK` | medium | 3 | 4 | documentation 4 | - | 1 | 0 | malicious example |
| `CAPABILITY-UNDECLARED-PERSISTENCE` | medium | 2 | 2 | SKILL.md 2 | - | 1 | 0 | malicious example |
| `INJ-PRIORITY-CLAIM` | medium | 2 | 2 | type definitions 1, bundled / third-party 1 | - | 1 | 0 | malicious example |
| `NET-IP-LOOKUP` | medium | 2 | 9 | bundled / third-party 6, documentation 3 | - | 0 | 0 | unknown |
| `PERM-UNRESTRICTED-SHELL` | medium | 2 | 2 | SKILL.md 2 | - | 1 | 0 | malicious example |
| `AGENT-HOOKS-DEFINITION` | medium | 1 | 1 | bundled / third-party 1 | - | 0 | 0 | unknown |
| `AGENT-PERMISSION-BYPASS-DOC` | medium | 1 | 1 | SKILL.md 1 | - | 0 | 0 | unknown |
| `CAPABILITY-UNDECLARED-CREDENTIAL-ACCESS` | medium | 1 | 1 | SKILL.md 1 | - | 4 | 0 | malicious example |
| `CRED-ENV-HARVEST` | medium | 1 | 2 | bundled / third-party 2 | - | 0 | 0 | unknown |
| `EXEC-LOLBIN-PROXY` | medium | 1 | 1 | own code 1 | - | 0 | 0 | unknown |
| `EXEC-PY-OS-SYSTEM` | medium | 1 | 1 | own code 1 | - | 1 | 0 | malicious example |
| `INJ-NO-CONFIRMATION` | medium | 1 | 1 | SKILL.md 1 | - | 0 | 0 | unknown |
| `INJ-ROLE-TAGS` | medium | 1 | 1 | bundled / third-party 1 | - | 0 | 0 | unknown |
| `IOC-URL-SHORTENER` | medium | 1 | 1 | bundled / third-party 1 | - | 0 | 0 | unknown |
| `NET-CURL-UPLOAD` | medium | 1 | 1 | documentation 1 | - | 0 | 0 | unknown |
| `NET-PS-UPLOAD` | medium | 1 | 2 | bundled / third-party 1, own code 1 | - | 0 | 0 | unknown |
| `OBF-HEX-ESCAPES` | medium | 1 | 2 | bundled / third-party 2 | - | 0 | 0 | unknown |
| `OBF-IFS` | medium | 1 | 1 | own code 1 | - | 0 | 0 | unknown |
| `OBF-STRING-REVERSE` | medium | 1 | 4 | bundled / third-party 4 | - | 0 | 0 | unknown |
| `PERM-RISKY-SHELL-COMMAND` | medium | 1 | 3 | SKILL.md 3 | - | 0 | 0 | unknown |
| `RECON-AV-CAPTURE` | medium | 1 | 6 | bundled / third-party 6 | - | 0 | 0 | unknown |
| `SECRET-GOOGLE-API` | medium | 1 | 2 | bundled / third-party 1, own code 1 | - | 0 | 0 | unknown |
| `SECRET-JWT` | medium | 1 | 2 | own code 2 | - | 0 | 0 | unknown |
| `SHELL-REMOTE-ADMIN-TOOL` | medium | 1 | 27 | own code 27 | - | 0 | 0 | unknown |
| `SUPPLY-NPM-DIRECT-URL` | medium | 1 | 1 | documentation 1 | - | 0 | 0 | unknown |
| `SUPPLY-NPM-NONREGISTRY-DEP` | medium | 1 | 1 | bundled / third-party 1 | - | 0 | 0 | unknown |
| `UNI-HOMOGLYPH-WHOLE-WORD` | medium | 1 | 1 | bundled / third-party 1 | - | 0 | 0 | unknown |
| `UNI-PRIVATE-USE` | medium | 1 | 3 | own code 3 | - | 0 | 0 | unknown |
| `AGENT-BUNDLED-MCP-CONFIG` | medium | 0 | 0 | - | - | 1 | 0 | malicious example |
| `BIN-IMAGE-METADATA-TEXT` | medium | 0 | 0 | - | - | 1 | 0 | malicious example |
| `CAPABILITY-UNDECLARED-NETWORK-SEND` | medium | 0 | 0 | - | - | 4 | 0 | malicious example |
| `EXEC-NET-WEBCLIENT` | medium | 0 | 0 | - | - | 1 | 0 | malicious example |
| `EXEC-PS-POLICY-BYPASS` | medium | 0 | 0 | - | - | 1 | 0 | malicious example |
| `INJ-TOOL-WILL-NOT-WORK` | medium | 0 | 0 | - | - | 1 | 0 | malicious example |
| `META-RISKY-FIELD-USER-INVOCABLE` | medium | 0 | 0 | - | - | 1 | 0 | malicious example |
| `OBF-CHARCODE-JS` | medium | 0 | 0 | - | - | 1 | 0 | malicious example |
| `SECRET-DOTENV-FILE` | medium | 0 | 0 | - | - | 1 | 0 | malicious example |
| `SOC-CLICKFIX` | medium | 0 | 0 | - | - | 2 | 0 | malicious example |
| `SOC-URGENCY-BANNER` | medium | 0 | 0 | - | - | 2 | 0 | malicious example |
| `UNI-BIDI-CONTROL` | medium | 0 | 0 | - | - | 1 | 0 | malicious example |
| `AGENT-CONFIG-REF` | low | 23 | 83 | documentation 39, SKILL.md 35, own code 7, type definitions 1, bundled / third-party 1 | - | 2 | 0 | malicious example |
| `OBF-BASE64-DECODE` | low | 15 | 97 | own code 70, bundled / third-party 25, documentation 2 | - | 3 | 0 | malicious example |
| `IOC-FREE-HOSTING` | low | 13 | 83 | own code 41, bundled / third-party 25, type definitions 10, documentation 7 | - | 0 | 0 | unknown |
| `EXEC-JS-CHILD-PROCESS` | low | 8 | 35 | own code 22, bundled / third-party 11, documentation 1, type definitions 1 | - | 1 | 0 | malicious example |
| `AGENT-MCP-REGISTER` | low | 7 | 22 | documentation 17, SKILL.md 5 | - | 1 | 0 | malicious example |
| `EVADE-CI-AWARE` | low | 7 | 27 | own code 13, type definitions 8, bundled / third-party 4, documentation 1, SKILL.md 1 | - | 0 | 0 | unknown |
| `META-MISSING-REFERENCE` | low | 7 | 7 | SKILL.md 7 | - | 0 | 0 | unknown |
| `NET-RAW-SOCKET` | low | 6 | 11 | own code 6, bundled / third-party 5 | - | 1 | 0 | malicious example |
| `EVADE-DETACHED-PROCESS` | low | 5 | 17 | own code 8, bundled / third-party 8, SKILL.md 1 | - | 0 | 0 | unknown |
| `INJ-SAFETY-CLAIM` | low | 5 | 5 | documentation 5 | - | 0 | 0 | unknown |
| `META-MISSING-INVOKED-SCRIPT` | low | 4 | 4 | SKILL.md 4 | - | 0 | 0 | unknown |
| `SUPPLY-UNPINNED-LATEST` | low | 4 | 18 | documentation 11, SKILL.md 4, own code 2, bundled / third-party 1 | - | 0 | 0 | unknown |
| `BIN-SVG-HTML-SCRIPT` | low | 3 | 9 | documentation 9 | - | 0 | 0 | unknown |
| `EXEC-EVAL-DOC` | low | 3 | 3 | documentation 1, SKILL.md 1, bundled / third-party 1 | - | 0 | 0 | unknown |
| `META-DESCRIPTION-XML` | low | 3 | 3 | SKILL.md 3 | - | 0 | 0 | unknown |
| `PERSIST-SHELL-RC-REF` | low | 3 | 8 | bundled / third-party 4, own code 3, documentation 1 | - | 1 | 0 | malicious example |
| `PRIV-ELEVATE` | low | 3 | 7 | own code 4, SKILL.md 2, documentation 1 | - | 0 | 0 | unknown |
| `SECRET-GENERIC-ASSIGNMENT` | low | 3 | 3 | type definitions 1, own code 1, bundled / third-party 1 | - | 0 | 0 | unknown |
| `SUPPLY-NPM-UNPINNED` | low | 3 | 3 | own code 3 | - | 0 | 0 | unknown |
| `IOC-SUSPICIOUS-TLD` | low | 2 | 14 | own code 12, bundled / third-party 2 | - | 0 | 0 | unknown |
| `META-NAME-IMPERSONATION` | low | 2 | 2 | SKILL.md 2 | - | 0 | 0 | unknown |
| `OBF-HIGH-ENTROPY-BLOB` | low | 2 | 2 | own code 2 | - | 1 | 0 | malicious example |
| `PERSIST-LIBRARY-PRELOAD` | low | 2 | 4 | own code 4 | - | 0 | 0 | unknown |
| `SUPPLY-RUNTIME-PACKAGE-EXEC` | low | 2 | 2 | SKILL.md 1, bundled / third-party 1 | - | 0 | 0 | unknown |
| `CRYPTO-CLIPBOARD-READ` | low | 1 | 1 | documentation 1 | - | 0 | 0 | unknown |
| `FS-HIDDEN-DIRECTORY` | low | 1 | 1 | bundled / third-party 1 | - | 0 | 0 | unknown |
| `FS-MANY-FILES` | low | 1 | 1 | whole package 1 | - | 0 | 0 | unknown |
| `INJ-PSEUDO-TAGS` | low | 1 | 1 | bundled / third-party 1 | - | 1 | 0 | malicious example |
| `INJ-ROLE-REASSIGN` | low | 1 | 1 | documentation 1 | - | 0 | 0 | unknown |
| `META-NAME-DIR-MISMATCH` | low | 1 | 1 | SKILL.md 1 | - | 0 | 0 | unknown |
| `NET-HTTP-POST-JS` | low | 1 | 1 | documentation 1 | - | 0 | 0 | unknown |
| `OBF-ENCODED-CODE` | low | 1 | 2 | own code 1, bundled / third-party 1 | - | 0 | 0 | unknown |
| `PRIV-WORLD-WRITABLE` | low | 1 | 1 | SKILL.md 1 | - | 0 | 0 | unknown |
| `UNI-STYLED-LETTERS` | low | 1 | 1 | own code 1 | - | 0 | 0 | unknown |
| `IOC-GITHUB-RELEASE-DOWNLOAD` | low | 0 | 0 | - | - | 2 | 0 | malicious example |
| `META-DESCRIPTION-VAGUE` | low | 0 | 0 | - | - | 1 | 0 | malicious example |
| `NET-HTTP-POST-PY` | low | 0 | 0 | - | - | 1 | 0 | malicious example |
| `META-NO-SKILL-MD` | info | 90 | 90 | whole package 90 | - | 0 | 0 | unknown |
| `SUPPLY-PACKAGE-INSTALL` | info | 76 | 126 | documentation 81, own code 22, SKILL.md 14, bundled / third-party 9 | - | 0 | 0 | unknown |
| `META-LONG-BODY` | info | 7 | 7 | SKILL.md 7 | - | 0 | 0 | unknown |
| `NET-HTTP-CLIENT` | info | 7 | 18 | own code 8, documentation 4, type definitions 3, bundled / third-party 2, SKILL.md 1 | - | 0 | 0 | unknown |
| `EXEC-PY-SUBPROCESS` | info | 5 | 18 | own code 17, SKILL.md 1 | - | 0 | 0 | unknown |
| `META-PLUGIN-ROOT-SCRIPTS` | info | 5 | 5 | SKILL.md 5 | - | 0 | 0 | unknown |
| `RECON-SYSTEM-INFO` | info | 5 | 19 | bundled / third-party 7, own code 6, type definitions 5, documentation 1 | - | 0 | 0 | unknown |
| `CRED-API-KEY-ENV` | info | 4 | 5 | documentation 3, own code 2 | - | 0 | 0 | unknown |
| `CRED-ENV-ITERATE` | info | 4 | 10 | own code 8, bundled / third-party 2 | - | 0 | 0 | unknown |
| `FS-DOTFILE` | info | 1 | 1 | own code 1 | - | 0 | 0 | unknown |
| `META-NAME-LURE-CATEGORY` | info | 1 | 1 | SKILL.md 1 | - | 0 | 0 | unknown |
| `SUPPLY-CI-WORKFLOW` | info | 1 | 1 | own code 1 | - | 0 | 0 | unknown |
