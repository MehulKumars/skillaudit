"""JSON and SARIF 2.1.0 output."""
from __future__ import annotations

import json
from typing import Dict, List

from .model import ScanResult
from .rules import CATEGORY_INFO, all_rules

SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}


def to_json(res: ScanResult) -> str:
    doc = res.to_dict()
    doc["schema"] = "skillaudit-report/1"
    doc["options"] = {k: v for k, v in doc.get("options", {}).items() if not k.startswith("_")}
    return json.dumps(doc, indent=2, ensure_ascii=False)


def to_sarif(res: ScanResult) -> str:
    rules_meta: Dict[str, dict] = {}
    known = {r.id: r for r in all_rules()}
    results: List[dict] = []
    for f in res.findings:
        if f.rule_id not in rules_meta:
            r = known.get(f.rule_id)
            desc = (r.description if r and r.description else f.title)
            rules_meta[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id.replace("-", ""),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": desc},
                "help": {"text": (r.remediation if r and r.remediation else desc)},
                "properties": {"tags": ["security", f.category] + f.references[:4],
                               "security-severity": SECURITY_SEVERITY.get(f.severity, "5.0"),
                               "precision": {"high": "high", "medium": "medium", "low": "low"}.get(f.confidence, "medium")},
            }
        uri = (f.path or res.unit_name).replace("\\", "/")
        loc = {"physicalLocation": {"artifactLocation": {"uri": uri}}}
        if f.line:
            loc["physicalLocation"]["region"] = {"startLine": max(1, f.line)}
            if f.column:
                loc["physicalLocation"]["region"]["startColumn"] = max(1, f.column)
        text = f.title + (" - " + f.message if f.message else "")
        results.append({
            "ruleId": f.rule_id,
            "level": SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": text[:2000]},
            "locations": [loc],
            "partialFingerprints": {"skillauditFingerprint/v1": f.fingerprint},
            "properties": {"severity": f.severity, "confidence": f.confidence, "category": f.category,
                           "origin": f.origin, "snippet": f.snippet[:500], "tags": f.tags},
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": res.tool, "version": res.version,
                                "informationUri": "https://example.invalid/skillaudit",
                                "rules": list(rules_meta.values())}},
            "results": results,
            "properties": {"verdict": res.verdict, "riskScore": res.risk_score, "unit": res.unit_name},
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)
