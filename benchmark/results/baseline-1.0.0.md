# skillaudit benchmark: baseline-1.0.0

> **Limit.** The malicious samples and the rules were written by the same author, so these numbers show that known techniques are covered. They are not a real-world detection rate. The legitimate samples are what was installed on one developer machine, so they over-represent browser automation, design skills and front-end packages.

Scanner: skillaudit 1.0.0 (source sha256 `2c076ce7ff5df153`), run 2026-11-25T23:22:31+00:00. Nothing scanned was executed.

## Samples

| Side | Group | Split | Samples | Files | Verdicts |
|---|---|---|---|---|---|
| legitimate | installed-skills | holdout | 40 | 410 | HIGH 1, MEDIUM 4, LOW 14, CLEAN 21 |
| legitimate | installed-skills | tune | 56 | 334 | HIGH 2, MEDIUM 12, LOW 16, CLEAN 26 |
| legitimate | named | tune | 24 | 607 | CRITICAL 3, MEDIUM 8, LOW 1, CLEAN 12 |
| legitimate | node-packages | holdout | 99 | 5046 | CRITICAL 10, HIGH 17, MEDIUM 16, LOW 34, CLEAN 22 |
| legitimate | node-packages | tune | 86 | 8854 | CRITICAL 4, HIGH 17, MEDIUM 13, LOW 23, CLEAN 29 |
| legitimate | python-packages | holdout | 1 | 858 | HIGH 1 |
| needs a human | | | 1 | 63 | CRITICAL 1 |
| malicious | demo skills | | 10 | | CRITICAL 9, HIGH 1 |

Held-back samples are reported only as totals and are not used for tuning or labelling.

**Not on disk, so not scanned:**

- `demo:theme-pack/report\u202efdp.exe`: not written on Windows: Windows Security deletes it on sight; FS-NAME-HIDDEN-CHARS is tested in memory instead

## False alarms on legitimate samples

A CRITICAL verdict on a legitimate sample always counts as a false alarm. HIGH is reported separately: CRITICAL and HIGH findings on tuning samples are labelled *wrong match* (the text is not what the rule describes), *real but normal here* (true, and expected for this kind of tool) or *needs a human*.

| Group | Split | Samples | CRITICAL (false alarm) | HIGH | MEDIUM or lower |
|---|---|---|---|---|---|
| installed-skills | holdout | 40 | 0 | 1 | 39 |
| installed-skills | tune | 56 | 0 | 2 | 54 |
| named | tune | 24 | 3 | 0 | 21 |
| node-packages | holdout | 99 | 10 | 17 | 72 |
| node-packages | tune | 86 | 4 | 17 | 65 |
| python-packages | holdout | 1 | 0 | 1 | 0 |

CRITICAL and HIGH findings on tuning samples, by label:

| Severity | wrong match | real but normal here | needs a human | unlabelled |
|---|---|---|---|---|
| critical | 116 | 4 | 0 | 0 |
| high | 42 | 137 | 1 | 0 |

### Named samples

| Sample | Files | Verdict | Score | crit / high / med / low | Rules behind CRITICAL |
|---|---|---|---|---|---|
| npm:playwright@1.66.0-alpha-2026-11-18 | 60 | CRITICAL | 100 | 7 / 5 / 25 / 47 | CHAIN-INSTALL-LURE, CRED-BROWSER |
| npm:@playwright/mcp@0.0.86 | 7 | MEDIUM | 30 | 0 / 0 / 4 / 16 | - |
| skill:accessibility | 3 | MEDIUM | 20 | 0 / 0 / 2 / 2 | - |
| skill:emil-design-eng | 1 | CLEAN | 0 | 0 / 0 / 0 / 0 | - |
| skill:choreograph | 2 | MEDIUM | 5 | 0 / 0 / 1 / 0 | - |
| skill:performance | 3 | MEDIUM | 13 | 0 / 0 / 1 / 2 | - |
| skill:core-web-vitals | 4 | MEDIUM | 13 | 0 / 0 / 3 / 2 | - |
| skill:frontend-design | 2 | CLEAN | 0 | 0 / 0 / 0 / 0 | - |
| skill:animate | 2 | CLEAN | 0 | 0 / 0 / 0 / 0 | - |
| skill:gsap-plugins | 1 | LOW | 2 | 0 / 0 / 0 / 1 | - |
| skill:best-practices | 2 | MEDIUM | 18 | 0 / 0 / 2 / 1 | - |
| skill:review-animations | 2 | CLEAN | 0 | 0 / 0 / 0 / 0 | - |
| skill:gsap-scrolltrigger | 1 | CLEAN | 0 | 0 / 0 / 0 / 0 | - |
| skill:seo | 2 | MEDIUM | 17 | 0 / 0 / 3 / 0 | - |
| skill:mobile-native | 1 | CLEAN | 0 | 0 / 0 / 0 / 0 | - |
| skill:gsap-core | 1 | CLEAN | 0 | 0 / 0 / 0 / 0 | - |
| skill:web-quality-audit | 2 | MEDIUM | 10 | 0 / 0 / 6 / 0 | - |
| skill:animation-performance | 1 | CLEAN | 0 | 0 / 0 / 0 / 0 | - |
| skill:gsap-utils | 1 | CLEAN | 0 | 0 / 0 / 0 / 0 | - |
| skill:gsap-timeline | 1 | CLEAN | 0 | 0 / 0 / 0 / 0 | - |
| skill:gsap-performance | 1 | CLEAN | 0 | 0 / 0 / 0 / 0 | - |
| demo:csv-formatter | 3 | CLEAN | 0 | 0 / 0 / 0 / 0 | - |
| npm:playwright-core@1.66.0-alpha-2026-11-18 | 116 | CRITICAL | 100 | 38 / 24 / 61 / 57 | CRED-BROWSER, EXEC-JS-REMOTE-EXEC, OBF-DECODE-EXEC |
| npm:chrome-devtools-mcp@1.13.0 | 388 | CRITICAL | 100 | 15 / 19 / 61 / 86 | CHAIN-CREDENTIAL-EXFILTRATION, CRED-BROWSER, EXEC-JS-REMOTE-EXEC |
| skill:impeccable *(needs a human)* | 63 | CRITICAL | 95 | 1 / 3 / 8 / 22 | OBF-DECODE-EXEC |

Rules that put legitimate tuning samples at CRITICAL (number of samples; one is enough):

- `CRED-BROWSER`: 4
- `EXEC-JS-REMOTE-EXEC`: 3
- `OBF-DECODE-EXEC`: 2
- `CHAIN-INSTALL-LURE`: 1
- `EXEC-PS-DOWNLOAD-IEX`: 1
- `SHELL-MKFIFO`: 1
- `OBF-EMBEDDED-BINARY`: 1
- `MINER-INDICATORS`: 1
- `CHAIN-CREDENTIAL-EXFILTRATION`: 1

## Malicious demo skills

| Demo | Expected | Verdict | Score | Caught | Without known-bad lists | Rules the verdict depends on |
|---|---|---|---|---|---|---|
| demo:notes-organizer | CRITICAL | CRITICAL | 100 | yes | CRITICAL 100 | none alone |
| demo:markdown-helper | CRITICAL | CRITICAL | 100 | yes | CRITICAL 100 | none alone |
| demo:solana-wallet-tracker | CRITICAL | CRITICAL | 100 | yes | CRITICAL 100 | none alone |
| demo:productivity-booster | CRITICAL | CRITICAL | 100 | yes | CRITICAL 100 | none alone |
| demo:code-reviewer | CRITICAL | CRITICAL | 97 | yes | CRITICAL 97 | none alone |
| demo:pdf-merger | HIGH | HIGH | 47 | yes | HIGH 47 | none alone |
| demo:packaged.skill | CRITICAL | CRITICAL | 100 | yes | CRITICAL 100 | none alone |
| demo:image-resizer | CRITICAL | CRITICAL | 100 | yes | CRITICAL 100 | none alone |
| demo:calculator-mcp | CRITICAL | CRITICAL | 94 | yes | HIGH 84 | IOC-KNOWN-BAD-PACKAGE |
| demo:theme-pack | CRITICAL | CRITICAL | 100 | yes | CRITICAL 100 | none alone |

*Rules the verdict depends on*: removing that one rule (and the chains built on it) drops the verdict below what is expected. *none alone* means several rules each hold it up.

## Size check

The same content, copied more times. A size-independent score would not move.

| Sample | Files | Verdict | Score | crit / high / med / low |
|---|---|---|---|---|
| size:npm:@playwright/mcp@0.0.86 x16 | 112 | HIGH | 100 | 0 / 0 / 64 / 256 |
| size:demo:code-reviewer + 15 copies of npm:@playwright/mcp@0.0.86 | 107 | CRITICAL | 100 | 2 / 5 / 62 / 242 |
| size:npm:@playwright/mcp@0.0.86 x4 | 28 | HIGH | 76 | 0 / 0 / 16 / 64 |
| size:demo:code-reviewer + 3 copies of npm:@playwright/mcp@0.0.86 | 23 | CRITICAL | 99 | 2 / 5 / 14 / 50 |
| size:npm:@playwright/mcp@0.0.86 x1 | 7 | MEDIUM | 30 | 0 / 0 / 4 / 16 |
| size:demo:code-reviewer + 0 copies of npm:@playwright/mcp@0.0.86 | 2 | CRITICAL | 97 | 2 / 5 / 2 / 2 |

## Rule coverage

| Status | All rules | Critical rules |
|---|---|---|
| malicious example | 102 | 21 |
| pattern-tested | 3 | 3 |
| unknown | 218 | 39 |

*unknown*: no malicious sample triggers the rule, so the benchmark cannot show whether a change to it stops real detections. Per-rule numbers are in `baseline-1.0.0-rules.md`.

