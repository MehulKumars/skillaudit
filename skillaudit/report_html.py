"""Self-contained HTML report (no external resources, strict CSP, everything escaped)."""
from __future__ import annotations

from typing import List

from .correlate import CAP_LABELS
from .model import ScanResult, sev_rank
from .rules import CATEGORY_INFO
from .sanitize import h, visible

CSS = """
:root{--bg:#f6f7f9;--panel:#fff;--text:#1d2129;--muted:#5b6472;--border:#dfe3e8;--code:#f0f2f5;
--critical:#b3261e;--high:#d9480f;--medium:#b7791f;--low:#2f6fb3;--info:#6b7280;--ok:#2e7d32;--link:#0b5cad}
@media (prefers-color-scheme: dark){:root{--bg:#111418;--panel:#1a1f25;--text:#e6e9ee;--muted:#9aa4b2;
--border:#2b323b;--code:#0f1317;--critical:#ff6b61;--high:#ff9248;--medium:#f2c14e;--low:#6aa9ff;--info:#9aa4b2;--ok:#6fcf73;--link:#8ab4ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1180px;margin:0 auto;padding:24px 16px 80px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px;border-bottom:1px solid var(--border);padding-bottom:6px}
.muted{color:var(--muted)}.panel{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:16px;margin:12px 0}
.verdict{display:flex;flex-wrap:wrap;gap:16px;align-items:center}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600;color:#fff;background:var(--info)}
.b-critical{background:var(--critical)}.b-high{background:var(--high)}.b-medium{background:var(--medium);color:#111}
.b-low{background:var(--low)}.b-info{background:var(--info)}.b-clean{background:var(--ok)}
.big{font-size:28px;font-weight:700}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:10px;text-align:center}
.card .n{font-size:22px;font-weight:700}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0}
.toolbar button{border:1px solid var(--border);background:var(--panel);color:var(--text);border-radius:6px;padding:4px 10px;cursor:pointer}
.toolbar button.on{outline:2px solid var(--low)}input[type=search]{flex:1;min-width:180px;padding:6px 10px;border-radius:6px;
border:1px solid var(--border);background:var(--panel);color:var(--text)}
details.f{background:var(--panel);border:1px solid var(--border);border-left:4px solid var(--info);border-radius:8px;margin:8px 0;padding:8px 12px}
details.f.critical{border-left-color:var(--critical)}details.f.high{border-left-color:var(--high)}
details.f.medium{border-left-color:var(--medium)}details.f.low{border-left-color:var(--low)}
details.f summary{cursor:pointer;display:flex;gap:8px;flex-wrap:wrap;align-items:baseline}
.rid{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px;color:var(--muted)}
.loc{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px;word-break:break-all}
pre{background:var(--code);border:1px solid var(--border);border-radius:6px;padding:10px;overflow-x:auto;
white-space:pre-wrap;word-break:break-word;font:12px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--border);
vertical-align:top}th{color:var(--muted);font-weight:600}td code{word-break:break-all}
.warn{border-left:4px solid var(--high)}.tablewrap{overflow-x:auto}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
"""

JS = """
(function(){var active=new Set(['critical','high','medium','low','info']);
function apply(){var q=(document.getElementById('q').value||'').toLowerCase();
document.querySelectorAll('details.f').forEach(function(d){var ok=active.has(d.dataset.sev)&&(!q||d.textContent.toLowerCase().indexOf(q)>=0);
d.style.display=ok?'':'none';});}
document.querySelectorAll('[data-filter]').forEach(function(b){b.addEventListener('click',function(){var s=b.dataset.filter;
if(active.has(s)){active.delete(s);b.classList.remove('on');}else{active.add(s);b.classList.add('on');}apply();});});
document.getElementById('q').addEventListener('input',apply);
document.getElementById('expand').addEventListener('click',function(){document.querySelectorAll('details.f').forEach(function(d){d.open=true;});});
document.getElementById('collapse').addEventListener('click',function(){document.querySelectorAll('details.f').forEach(function(d){d.open=false;});});
})();
"""


def _badge(sev: str) -> str:
    return '<span class="badge b-%s">%s</span>' % (h(sev.lower()), h(sev.upper()))


def render(res: ScanResult) -> str:
    s = res.stats.get("by_severity", {})
    P: List[str] = []
    P.append("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    P.append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    P.append("<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; "
             "script-src 'unsafe-inline'; img-src data:\">")
    P.append("<meta name='referrer' content='no-referrer'>")
    P.append("<title>Skill audit: %s</title><style>%s</style></head><body><main>" % (h(visible(res.unit_name)), CSS))
    P.append("<h1>Skill security audit: %s</h1>" % h(visible(res.unit_name)))
    P.append("<div class='muted'>%s %s &middot; %s &middot; target <code>%s</code></div>" % (
        h(res.tool), h(res.version), h(res.started), h(visible(res.target))))
    vcls = res.verdict.lower() if res.verdict != "CLEAN" else "clean"
    P.append("<div class='panel verdict'><div><div class='muted'>Verdict</div><div class='big'>%s</div></div>"
             "<div><div class='muted'>Risk score</div><div class='big'>%d<span class='muted'>/100</span></div></div>"
             "<div style='flex:1;min-width:220px'>%s</div></div>" % (_badge(vcls) .replace(vcls.upper(), h(res.verdict)),
                                                                     res.risk_score, h(res.verdict_detail)))
    P.append("<div class='cards'>")
    for sev in ("critical", "high", "medium", "low", "info"):
        P.append("<div class='card'><div class='n' style='color:var(--%s)'>%d</div><div class='muted'>%s</div></div>"
                 % (sev, s.get(sev, 0), sev))
    P.append("<div class='card'><div class='n'>%d</div><div class='muted'>files</div></div></div>" % res.coverage.get("files", 0))
    P.append("<div class='panel warn'><strong>Untrusted content.</strong> Snippets and sources below are copied from the "
             "scanned skill and may contain text crafted to mislead reviewers or AI models. Invisible characters are "
             "shown as markers like <code>[U+202E RLO]</code>.</div>")

    for m in res.skill.get("manifests", []):
        P.append("<h2>Skill manifest <span class='loc'>%s</span></h2><div class='panel tablewrap'><table>" % h(visible(m.get("path", ""))))
        for k, v in (("name", m.get("name", "")), ("description", m.get("description", "")),
                     ("allowed-tools", ", ".join(m.get("allowed_tools", [])) or "(none)"),
                     ("scripts invoked", ", ".join(m.get("scripts_invoked", [])) or "(none detected)")):
            P.append("<tr><th>%s</th><td><code>%s</code></td></tr>" % (h(k), h(visible(str(v), 1500))))
        P.append("</table></div>")

    chains = [f for f in res.findings if f.category == "correlation"]
    P.append("<h2 id='chains'>Correlated attack chains (%d)</h2>" % len(chains))
    if not chains:
        P.append("<p class='muted'>None identified.</p>")
    for f in chains:
        P.append("<div class='panel'>%s <strong>%s</strong> <span class='loc'>%s</span><p>%s</p>%s</div>" % (
            _badge(f.severity), h(f.title), h(visible(f.path)), h(f.message),
            ("<pre>%s</pre>" % h("\n".join(f.evidence))) if f.evidence else ""))

    P.append("<h2 id='capabilities'>Capabilities</h2><div class='panel tablewrap'><table><tr><th>Capability</th><th>Where</th></tr>")
    for cap, paths in res.capabilities.items():
        P.append("<tr><td>%s</td><td class='loc'>%s</td></tr>" % (h(CAP_LABELS.get(cap, cap)),
                                                                 h(", ".join(visible(p) for p in paths[:10]))))
    P.append("</table></div>")

    P.append("<h2 id='findings'>Findings (%d)</h2>" % len([f for f in res.findings if f.category != "correlation"]))
    P.append("<div class='toolbar'>%s<input id='q' type='search' placeholder='Filter findings (rule, path, text)'>"
             "<button id='expand'>Expand all</button><button id='collapse'>Collapse all</button></div>"
             % "".join("<button class='on' data-filter='%s'>%s (%d)</button>" % (x, x, s.get(x, 0))
                       for x in ("critical", "high", "medium", "low", "info")))
    anchored = set()
    for f in res.findings:
        if f.category == "correlation":
            continue
        cat = CATEGORY_INFO.get(f.category, (f.category,))[0]
        anchor = "" if f.rule_id in anchored else " id='%s'" % h(f.rule_id)
        anchored.add(f.rule_id)
        open_attr = " open" if sev_rank(f.severity) >= sev_rank("critical") else ""
        P.append("<details class='f %s' data-sev='%s'%s%s><summary>%s <strong>%s</strong> <span class='loc'>%s%s</span> "
                 "<span class='rid'>%s</span></summary>" % (h(f.severity), h(f.severity), anchor, open_attr, _badge(f.severity),
                                                             h(f.title), h(visible(f.path) or "(package)"),
                                                             h(":%d" % f.line if f.line else ""), h(f.rule_id)))
        P.append("<p class='muted'>%s &middot; confidence %s &middot; origin %s%s</p>" % (
            h(cat), h(f.confidence), h(f.origin), (" &middot; tags " + h(", ".join(f.tags))) if f.tags else ""))
        if f.message:
            P.append("<p>%s</p>" % h(f.message))
        if f.snippet:
            P.append("<pre>%s</pre>" % h(f.snippet))
        if f.evidence:
            P.append("<pre>%s</pre>" % h("\n".join(f.evidence)))
        if f.remediation:
            P.append("<p><strong>Remediation:</strong> %s</p>" % h(f.remediation))
        if f.references:
            P.append("<p class='muted'>%s</p>" % h(", ".join(f.references)))
        P.append("</details>")

    P.append("<h2 id='indicators'>Indicators</h2>")
    any_ioc = False
    for kind in ("urls", "domains", "ips", "emails", "wallets"):
        items = res.iocs.get(kind, [])
        if not items:
            continue
        any_ioc = True
        P.append("<div class='panel tablewrap'><strong>%s (%d)</strong><table><tr><th>Value</th><th>Tags</th><th>Seen at</th></tr>"
                 % (h(kind), len(items)))
        for r in items[:500]:
            P.append("<tr><td><code>%s</code></td><td>%s</td><td class='loc'>%s</td></tr>" % (
                h(visible(r["value"], 300)), h(", ".join(r["tags"])), h(", ".join(visible(x) for x in r["locations"][:3]))))
        P.append("</table></div>")
    if not any_ioc:
        P.append("<p class='muted'>None.</p>")

    P.append("<h2>File inventory (%d)</h2><div class='panel tablewrap'><table><tr><th>Path</th><th>Kind</th><th>Size</th>"
             "<th>SHA-256</th><th>Flags</th><th>Max</th></tr>" % len(res.files))
    for r in sorted(res.files, key=lambda r: r.path)[:3000]:
        P.append("<tr><td class='loc'>%s</td><td>%s</td><td>%s</td><td class='loc'>%s</td><td>%s</td><td>%s</td></tr>" % (
            h(visible(r.path, 300)), h(r.kind), h(format(r.size, ",")), h(r.sha256), h(", ".join(r.flags)),
            _badge(r.max_severity) if r.max_severity else ""))
    P.append("</table></div>")

    if res.baseline:
        b = res.baseline
        P.append("<h2>Changes since baseline</h2><div class='panel'><pre>%s</pre></div>" % h(
            "added: %s\nremoved: %s\nchanged: %s\nnew findings: %d\nresolved findings: %d" % (
                ", ".join(b["added_files"]) or "-", ", ".join(b["removed_files"]) or "-",
                ", ".join(b["changed_files"]) or "-", len(b["new_findings"]), len(b["resolved_findings"]))))

    if res.sources:
        P.append("<h2>Embedded source (untrusted)</h2>")
        for src in res.sources:
            P.append("<details class='f info' data-sev='info'><summary><span class='loc'>%s</span> %s</summary>%s</details>" % (
                h(visible(src["path"])), _badge(src["max_severity"]) if src.get("max_severity") else "",
                "<p class='muted'>omitted (size budget)</p>" if src.get("omitted") else "<pre>%s</pre>" % h(src["content"])))

    P.append("<h2>Limitations</h2><div class='panel'><ul>%s</ul></div>" % "".join(
        "<li>%s</li>" % h(x) for x in res.coverage.get("limitations", [])))
    P.append("<p class='muted'>Generated offline by %s %s in %.2f s. No data left this machine.</p>" % (
        h(res.tool), h(res.version), res.duration_s))
    P.append("<script>%s</script></main></body></html>" % JS)
    return "".join(P)


def render_index(results: List[ScanResult], tool: str, version: str) -> str:
    rows = []
    for r in sorted(results, key=lambda x: (-x.risk_score, x.unit_name)):
        s = r.stats.get("by_severity", {})
        folder = r.options.get("_folder", "")
        rows.append("<tr><td class='loc'><a href='%s/report.html'>%s</a></td><td>%s</td><td>%d</td><td>%d</td><td>%d</td>"
                    "<td>%d</td><td>%d</td></tr>" % (h(folder), h(visible(r.unit_name)),
                                                     _badge(r.verdict.lower() if r.verdict != "CLEAN" else "clean")
                                                     .replace(">CLEAN<", ">CLEAN<"), r.risk_score, s.get("critical", 0),
                                                     s.get("high", 0), s.get("medium", 0), s.get("low", 0)))
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, "
            "initial-scale=1'><meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src "
            "'unsafe-inline'\"><title>Skill audit summary</title><style>%s</style></head><body><main><h1>Skill audit "
            "summary</h1><p class='muted'>%s %s &middot; %d unit(s)</p><div class='panel tablewrap'><table><tr><th>Unit</th>"
            "<th>Verdict</th><th>Score</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr>%s</table></div>"
            "</main></body></html>" % (CSS, h(tool), h(version), len(results), "".join(rows)))
