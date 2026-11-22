# Security policy

## Reporting a bypass or vulnerability

skillaudit is a detection tool, so two kinds of reports are valuable:

1. **Evasions.** A skill that is clearly malicious but scans as LOW or CLEAN.
2. **Scanner vulnerabilities.** Input that makes skillaudit crash, hang (ReDoS), read outside the target, execute
   anything, or leak raw untrusted content (invisible characters, unescaped HTML, fence breaks) into a report.

Please use **GitHub private vulnerability reporting** (Security tab, then "Report a vulnerability") instead of a
public issue. Include a minimal, defanged reproduction: use `203.0.113.0/24` addresses and `*.example.invalid`
hosts, and never attach live malware.

## Scope notes

- Static analysis has known limits (see the README section "Limitations"). Reports that a runtime-only or purely
  semantic attack is not caught are still welcome, but may become documentation rather than a fix.
- The rule and fixture files in this repository intentionally contain attack patterns. Antivirus tools or
  skillaudit itself may flag them; that is expected.
