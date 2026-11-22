"""ReDoS / performance probe: time every rule and analyzer against hostile inputs.

Usage: python tests/perf_redos.py [size_kb]      (default 20 KB per probe)

At small sizes a quadratic regex already takes ~seconds while linear ones take milliseconds, so offenders stand out.
Anything slower than the threshold is printed as SLOW; the script exits 1 if any were found.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from skillaudit import iocs  # noqa: E402
from skillaudit.decoders import find_encoded  # noqa: E402
from skillaudit.engine import ContentEngine  # noqa: E402
from skillaudit.hidden import scan_hidden  # noqa: E402
from skillaudit.model import TextUnit  # noqa: E402
from skillaudit.rules import all_rules  # noqa: E402
from skillaudit.unicode_checks import normalized_view, scan_unicode  # noqa: E402

n = int(float(sys.argv[1]) * 1000) if len(sys.argv) > 1 else 20000
THRESH = 0.25
probes = {
    "spaces": " " * n + "\nx", "newlines": "\n" * n + "x", "aaaa": "a" * n, "b64": "QUFB" * (n // 4),
    "curl": "curl " * (n // 5), "pipe": "| " * (n // 2), "exec": "exec(" * (n // 5), "slash": "/" * n,
    "tokens": "ignore the previous user silently send http://a.b/c " * (n // 50), "brackets": "[" * n,
    "comment": "<!--" + "x" * n, "pct": "%41" * (n // 3), "ticks": "`" * n, "quotes": "'" * n, "dquotes": '"' * n,
    "dots": "a." * (n // 2), "digits": "1," * (n // 2), "ip": "1.1.1.1 " * (n // 8), "at": "a@" * (n // 2),
    "colon": "a:" * (n // 2), "dollar": "$(" * (n // 2), "lt": "<a " * (n // 3), "bang": "![a](" * (n // 5),
    "hash": "#" * n, "url": "http://" + "a" * n, "hex0x": "0x41," * (n // 5), "dash": "-" * n,
    "pw": 'password = "' + "a" * n, "tab": "\t" * n + "x", "bslash": "\\" * n, "xesc": "\\x41" * (n // 4),
    "chr": "chr(65)+" * (n // 8), "ps": "[char]65+" * (n // 9), "words": "do not tell the user " * (n // 21),
}
rules = all_rules()
slow = []


def report(dt, name, what):
    slow.append((dt, name, what))
    print("SLOW %6.2fs  %-10s %s" % (dt, name, what), flush=True)


for name, text in probes.items():
    for r in rules:
        t0 = time.time()
        for i, _ in enumerate(r.regex.finditer(text)):
            if i > 5000:
                break
        dt = time.time() - t0
        if dt > THRESH:
            report(dt, name, r.id)
    analyzers = (
        ("decoders", lambda: list(find_encoded(text))),
        ("unicode", lambda: scan_unicode(TextUnit("p.md", text, "markdown"))),
        ("hidden", lambda: scan_hidden(TextUnit("p.md", text, "markdown"))),
        ("iocs", lambda: iocs.extract(text)),
        ("normalize", lambda: normalized_view(text)),
        ("engine-md", lambda: ContentEngine(rules).scan(TextUnit("p.md", text, "markdown"))),
        ("engine-py", lambda: ContentEngine(rules).scan(TextUnit("p.py", text, "python"))),
    )
    for label, fn in analyzers:
        t0 = time.time()
        fn()
        dt = time.time() - t0
        if dt > THRESH * (8 if label.startswith("engine") else 1):
            report(dt, name, label)
    print("ok  %-10s" % name, flush=True)

print("\n%d slow item(s)." % len(slow))
sys.exit(1 if slow else 0)
