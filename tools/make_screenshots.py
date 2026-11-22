"""Regenerate the README screenshots from real scans of the demo attack corpus.

    python tools/make_screenshots.py

Needs Microsoft Edge or Google Chrome (used headless, offline, local files only).
Writes docs/images/*.png. Demo skills go to ./demo-skills and reports to ./skillaudit-reports/demo (both gitignored).
"""
import html
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests"))
import fixtures  # noqa: E402

IMG = os.path.join(ROOT, "docs", "images")
DEMO = os.path.join(ROOT, "demo-skills")
REPORTS = os.path.join(ROOT, "skillaudit-reports", "demo")
BROWSERS = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/microsoft-edge",
]

SGR_FG = {"30": "#0c0c0c", "90": "#767676", "91": "#e74856", "93": "#f9f1a5", "94": "#3b78ff", "97": "#f2f2f2"}
SGR_BG = {"41": "#c50f1f", "101": "#e74856", "102": "#16c60c", "103": "#f9f1a5", "104": "#3b78ff"}


def ansi_to_html(text: str) -> str:
    out, fg, bg, bold, dim = [], None, None, False, False
    for part in re.split(r"(\x1b\[[0-9;]*m)", text):
        m = re.match(r"\x1b\[([0-9;]*)m", part)
        if m:
            for code in (m.group(1) or "0").split(";"):
                if code == "0":
                    fg, bg, bold, dim = None, None, False, False
                elif code == "1":
                    bold = True
                elif code == "2":
                    dim = True
                elif code in SGR_FG:
                    fg = SGR_FG[code]
                elif code in SGR_BG:
                    bg = SGR_BG[code]
            continue
        if not part:
            continue
        style = []
        if fg:
            style.append("color:%s" % fg)
        if bg:
            style.append("background:%s" % bg)
        if bold:
            style.append("font-weight:700")
        if dim:
            style.append("opacity:.55")
        esc = html.escape(part)
        out.append('<span style="%s">%s</span>' % (";".join(style), esc) if style else esc)
    return "".join(out)


def run(args):
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    p = subprocess.run([sys.executable, "-m", "skillaudit", *args], cwd=ROOT, capture_output=True, text=True,
                       encoding="utf-8", env=env)
    return p.stdout


def terminal_page(blocks) -> str:
    body = []
    for cmd, output in blocks:
        body.append('<span style="color:#16c60c">PS skill-audit&gt;</span> <span style="color:#f2f2f2">%s</span>\n'
                    % html.escape(cmd))
        body.append(ansi_to_html(output.rstrip("\n")) + "\n\n")
    return """<!doctype html><html><head><meta charset="utf-8"><style>
body{margin:0;background:#1e1e2e;padding:28px;font-family:'Cascadia Mono','Cascadia Code',Consolas,Menlo,monospace}
.win{background:#0c0c0c;border-radius:10px;box-shadow:0 12px 40px rgba(0,0,0,.45);overflow:hidden;display:inline-block;min-width:1180px}
.bar{background:#2b2b2b;height:34px;display:flex;align-items:center;padding:0 14px;gap:8px;color:#bbb;font:13px system-ui}
.dot{width:12px;height:12px;border-radius:50%%;display:inline-block}
pre{margin:0;padding:16px 20px 20px;color:#cccccc;font-size:14px;line-height:1.45;white-space:pre}
</style></head><body><div class="win"><div class="bar"><span class="dot" style="background:#ff5f57"></span>
<span class="dot" style="background:#febc2e"></span><span class="dot" style="background:#28c840"></span>
<span style="margin-left:10px">Windows PowerShell - skillaudit</span></div><pre>%s</pre></div></body></html>""" % "".join(body)


def find_browser() -> str:
    for b in BROWSERS:
        if os.path.exists(b):
            return b
    for name in ("msedge", "chrome", "google-chrome", "chromium"):
        p = shutil.which(name)
        if p:
            return p
    sys.exit("No Edge/Chrome found for headless screenshots.")


def shoot(browser, url, out, w, h, dark=False, scale=1.5):
    profile = tempfile.mkdtemp(prefix="skillaudit-shot-")
    args = [browser, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run",
            "--no-default-browser-check", "--disable-extensions", "--user-data-dir=" + profile,
            "--window-size=%d,%d" % (w, h), "--force-device-scale-factor=%s" % scale, "--screenshot=" + out,
            "--blink-settings=preferredColorScheme=%d" % (0 if dark else 1)]
    if dark:
        args.append("--force-dark-mode")
    args.append(url)
    subprocess.run(args, capture_output=True, timeout=120)
    shutil.rmtree(profile, ignore_errors=True)
    print("  %s (%s)" % (os.path.relpath(out, ROOT), "ok" if os.path.exists(out) else "FAILED"))


def file_url(path: str, frag: str = "") -> str:
    return "file:///" + os.path.abspath(path).replace("\\", "/") + (("#" + frag) if frag else "")


def excerpt(report_html: str, start_marker: str, end_marker: str, out_path: str, title: str) -> str:
    """Cut one real section out of a generated report (same CSS) for a focused screenshot."""
    with open(report_html, encoding="utf-8") as fh:
        page = fh.read()
    head = page.split("<body>", 1)[0]
    a = page.index(start_marker)
    b = page.index(end_marker, a + len(start_marker)) + (len(end_marker) if end_marker.startswith("</") else 0)
    section = page[a:b].replace("<details class='f", "<details open class='f", 1)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(head + "<body><main><h1>%s</h1>%s</main></body></html>" % (html.escape(title), section))
    return out_path


def main():
    os.makedirs(IMG, exist_ok=True)
    shutil.rmtree(DEMO, ignore_errors=True)
    shutil.rmtree(REPORTS, ignore_errors=True)
    fixtures.build_all(DEMO)

    single = run(["demo-skills/solana-wallet-tracker", "-o", "skillaudit-reports/demo/solana-wallet-tracker",
                  "--color", "always", "--fail-on", "none"])
    many = run(["demo-skills", "-o", "skillaudit-reports/demo", "--color", "always", "--fail-on", "none", "-q"])
    term = os.path.join(IMG, "_terminal.html")
    with open(term, "w", encoding="utf-8") as fh:
        fh.write(terminal_page([("python -m skillaudit demo-skills/solana-wallet-tracker", single),
                                ("python -m skillaudit demo-skills -q", many)]))
    lines = (single + many).count("\n") + 3
    browser = find_browser()
    print("Screenshots with", browser)
    shoot(browser, file_url(term), os.path.join(IMG, "terminal.png"), 1260, 80 + lines * 21)
    os.remove(term)

    r = os.path.join(REPORTS, "solana-wallet-tracker", "report.html")
    shoot(browser, file_url(r), os.path.join(IMG, "report-light.png"), 1280, 1150)
    shoot(browser, file_url(r), os.path.join(IMG, "report-dark.png"), 1280, 1150, dark=True)
    shoot(browser, file_url(os.path.join(REPORTS, "index.html")), os.path.join(IMG, "summary.png"), 1280, 600)

    tmp = []
    tmp.append(excerpt(os.path.join(REPORTS, "markdown-helper", "report.html"), "<details class='f critical' data-sev='critical' id='UNI-TAG-SMUGGLING'",
                       "</details>", os.path.join(IMG, "_unicode.html"),
                       "markdown-helper: invisible text decoded"))
    shoot(browser, file_url(tmp[-1]), os.path.join(IMG, "unicode-smuggling.png"), 1280, 370)
    tmp.append(excerpt(os.path.join(REPORTS, "code-reviewer", "report.html"), "<h2 id='chains'>",
                       "<h2 id='capabilities'>", os.path.join(IMG, "_chains.html"),
                       "code-reviewer: correlated attack chains"))
    shoot(browser, file_url(tmp[-1]), os.path.join(IMG, "skillject-chain.png"), 1280, 930)
    for t in tmp:
        os.remove(t)


if __name__ == "__main__":
    main()
