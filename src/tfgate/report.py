"""Output formats: a human table, JSON for other tools, SARIF for GitHub code scanning."""

from __future__ import annotations

import json

from . import __version__
from .rules import RULES, Severity
from .scanner import Result

SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def table(result: Result, threshold: Severity) -> str:
    lines = [f"Scanned {result.resources_scanned} resource change(s)."]
    for w in result.expired_waivers:
        lines.append(f"EXPIRED WAIVER  {w.rule_id} on {w.address} (expired {w.expires})")
    if not result.findings:
        lines.append("No findings.")
        return "\n".join(lines)
    lines.append("")
    lines.append(f"{'SEVERITY':<9} {'RULE':<11} {'CONTROLS':<14} {'RESOURCE':<45} DETAIL")
    for f in result.findings:
        sev = f.rule.severity.name + ("*" if f.waived else "")
        controls = ",".join(f.rule.controls)
        lines.append(f"{sev:<9} {f.rule.id:<11} {controls:<14} {f.address:<45} {f.message}")
    waived = sum(f.waived for f in result.findings)
    failing = len(result.failing(threshold))
    lines.append("")
    lines.append(
        f"{len(result.findings)} finding(s), {waived} waived (*), {failing} at or above {threshold.name}."
    )
    return "\n".join(lines)


def as_json(result: Result, threshold: Severity) -> str:
    return json.dumps(
        {
            "resources_scanned": result.resources_scanned,
            "threshold": threshold.name,
            "passed": not result.failing(threshold) and not result.expired_waivers,
            "expired_waivers": [
                {"rule_id": w.rule_id, "address": w.address, "expires": w.expires.isoformat()}
                for w in result.expired_waivers
            ],
            "findings": [
                {
                    "rule_id": f.rule.id,
                    "title": f.rule.title,
                    "severity": f.rule.severity.name,
                    "controls": list(f.rule.controls),
                    "address": f.address,
                    "message": f.message,
                    "remediation": f.rule.remediation,
                    "waived": f.waived,
                    "waiver_reason": f.waived_by.reason if f.waived_by else None,
                }
                for f in result.findings
            ],
        },
        indent=2,
    )


def as_sarif(result: Result, plan_path: str) -> str:
    rules = [
        {
            "id": r.id,
            "name": r.id.replace("-", ""),
            "shortDescription": {"text": r.title},
            "help": {"text": r.remediation},
            "properties": {"tags": ["security", *(f"NIST-800-53/{c}" for c in r.controls)]},
            "defaultConfiguration": {"level": SARIF_LEVEL[r.severity]},
        }
        for r in RULES
    ]
    results = [
        {
            "ruleId": f.rule.id,
            "level": SARIF_LEVEL[f.rule.severity],
            "message": {"text": f"{f.address}: {f.message}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": plan_path}}}],
            **(
                {"suppressions": [{"kind": "external", "justification": f.waived_by.reason}]}
                if f.waived_by
                else {}
            ),
        }
        for f in result.findings
    ]
    return json.dumps(
        {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "tfgate",
                            "version": __version__,
                            "informationUri": "https://github.com/speakwithuche-create/tf-compliance-gate",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        },
        indent=2,
    )
