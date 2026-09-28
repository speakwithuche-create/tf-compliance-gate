"""Scan a Terraform plan (``terraform show -json plan.out``) against the rules."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from .rules import RULES, Rule, Severity

SCANNED_ACTIONS = {"create", "update"}


@dataclass(frozen=True)
class Finding:
    rule: Rule
    address: str
    message: str
    waived_by: Waiver | None = None

    @property
    def waived(self) -> bool:
        return self.waived_by is not None


@dataclass(frozen=True)
class Waiver:
    """An approved, time-boxed exception (a POA&M item in FedRAMP terms)."""

    rule_id: str
    address: str
    reason: str
    approved_by: str
    expires: date

    def matches(self, rule_id: str, address: str) -> bool:
        return self.rule_id == rule_id and self.address == address


@dataclass
class Result:
    findings: list[Finding] = field(default_factory=list)
    resources_scanned: int = 0
    expired_waivers: list[Waiver] = field(default_factory=list)

    def failing(self, threshold: Severity) -> list[Finding]:
        return [f for f in self.findings if not f.waived and f.rule.severity >= threshold]


def load_plan(path: str | Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        plan = json.load(fh)
    if "resource_changes" not in plan:
        raise ValueError(
            f"{path} is not a Terraform JSON plan (run: terraform show -json plan.out > plan.json)"
        )
    return plan


def load_waivers(path: str | Path | None, today: date) -> tuple[list[Waiver], list[Waiver]]:
    """Return (active, expired) waivers. Every waiver must name who approved
    it, why, and when it expires: an exception without an end date is just
    a permanent hole."""
    if path is None:
        return [], []
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    active, expired = [], []
    for i, w in enumerate(raw.get("waivers", [])):
        missing = [k for k in ("rule_id", "address", "reason", "approved_by", "expires") if not w.get(k)]
        if missing:
            raise ValueError(f"waiver #{i} is missing {', '.join(missing)}")
        waiver = Waiver(
            rule_id=w["rule_id"],
            address=w["address"],
            reason=w["reason"],
            approved_by=w["approved_by"],
            expires=date.fromisoformat(w["expires"]),
        )
        (active if waiver.expires >= today else expired).append(waiver)
    return active, expired


def scan(
    plan: dict[str, Any],
    waivers: list[Waiver] | None = None,
    rules: list[Rule] | None = None,
) -> Result:
    rules = RULES if rules is None else rules
    waivers = waivers or []
    result = Result()

    for rc in plan.get("resource_changes", []):
        change = rc.get("change") or {}
        if not SCANNED_ACTIONS & set(change.get("actions", [])):
            continue  # deletes and no-ops can't introduce a violation
        after = change.get("after") or {}
        result.resources_scanned += 1
        for r in rules:
            if rc.get("type") not in r.resource_types:
                continue
            for message in r.check(after):
                waiver = next((w for w in waivers if w.matches(r.id, rc["address"])), None)
                result.findings.append(Finding(r, rc["address"], message, waiver))

    result.findings.sort(key=lambda f: (-f.rule.severity, f.rule.id, f.address))
    return result
