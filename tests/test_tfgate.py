import json
from datetime import date
from pathlib import Path

import pytest

from tfgate import rules
from tfgate.cli import main
from tfgate.rules import RULES, Severity
from tfgate.scanner import load_plan, load_waivers, scan

FIX = Path(__file__).parent / "fixtures"
GOOD = FIX / "compliant.plan.json"
BAD = FIX / "noncompliant.plan.json"


def ids(result):
    return {(f.rule.id, f.address) for f in result.findings}


# --- end to end --------------------------------------------------------------


def test_compliant_plan_has_no_findings():
    assert scan(load_plan(GOOD)).findings == []


def test_noncompliant_plan_flags_every_expected_violation():
    got = ids(scan(load_plan(BAD)))
    assert got == {
        ("TAG-001", "azurerm_resource_group.main"),
        ("AZ-STG-001", "azurerm_storage_account.public"),
        ("AZ-STG-002", "azurerm_storage_account.public"),
        ("AZ-STG-003", "azurerm_storage_account.public"),
        ("AZ-STG-003", "azurerm_storage_account.public"),
        ("AZ-KV-001", "azurerm_key_vault.weak"),
        ("AZ-KV-002", "azurerm_key_vault.weak"),
        ("AZ-NSG-001", "azurerm_network_security_group.web"),
        ("AZ-SQL-001", "azurerm_mssql_server.db"),
        ("AZ-AKS-001", "azurerm_kubernetes_cluster.aks"),
        ("AWS-SG-001", "aws_security_group.bastion"),
        ("AWS-S3-001", "aws_s3_bucket_public_access_block.data"),
    }


def test_deleted_resources_are_not_scanned():
    assert not any(f.address == "azurerm_storage_account.old" for f in scan(load_plan(BAD)).findings)


def test_findings_sorted_most_severe_first():
    sev = [f.rule.severity for f in scan(load_plan(BAD)).findings]
    assert sev == sorted(sev, reverse=True)


def test_every_rule_maps_to_a_control_and_has_remediation():
    assert len({r.id for r in RULES}) == len(RULES), "duplicate rule IDs"
    for r in RULES:
        assert r.controls and all(c[:2].isalpha() and "-" in c for c in r.controls), r.id
        assert r.remediation, r.id


# --- individual rules: the security behavior, not just the happy path -------


@pytest.mark.parametrize(
    "rule_fn, attrs, violates",
    [
        (rules.storage_min_tls, {"min_tls_version": "TLS1_2"}, False),
        (rules.storage_min_tls, {"min_tls_version": "TLS1_1"}, True),
        (rules.storage_min_tls, {}, True),  # unset is not compliant
        (rules.storage_https_only, {"enable_https_traffic_only": True}, False),  # azurerm 3.x name
        (rules.storage_https_only, {"https_traffic_only_enabled": None}, True),
        (
            rules.nsg_admin_ports,
            {
                "direction": "Inbound",
                "access": "Allow",
                "source_address_prefix": "*",
                "destination_port_range": "20-25",
            },
            True,
        ),
        (
            rules.nsg_admin_ports,
            {
                "direction": "Inbound",
                "access": "Allow",
                "source_address_prefix": "0.0.0.0/0",
                "destination_port_range": "*",
            },
            True,
        ),
        (
            rules.nsg_admin_ports,
            {
                "direction": "Inbound",
                "access": "Deny",
                "source_address_prefix": "*",
                "destination_port_range": "22",
            },
            False,
        ),
        (
            rules.nsg_admin_ports,
            {
                "direction": "Outbound",
                "access": "Allow",
                "source_address_prefix": "*",
                "destination_port_range": "22",
            },
            False,
        ),
        (
            rules.nsg_admin_ports,
            {
                "direction": "Inbound",
                "access": "Allow",
                "source_address_prefixes": ["10.0.0.0/8", "Internet"],
                "destination_port_ranges": ["443", "3389"],
            },
            True,
        ),
        (rules.aws_sg_admin_ports, {"ingress": [{"protocol": "-1", "cidr_blocks": ["0.0.0.0/0"]}]}, True),
        (
            rules.aws_sg_admin_ports,
            {
                "ingress": [
                    {
                        "from_port": 22,
                        "to_port": 22,
                        "protocol": "tcp",
                        "cidr_blocks": [],
                        "ipv6_cidr_blocks": ["::/0"],
                    }
                ]
            },
            True,
        ),
        (
            rules.aws_sg_admin_ports,
            {"cidr_ipv4": "0.0.0.0/0", "from_port": 443, "to_port": 443, "ip_protocol": "tcp"},
            False,
        ),
        (rules.required_tags, {"tags": {"owner": "a", "environment": "b", "data_classification": ""}}, True),
        (rules.required_tags, {"tags": None}, True),
    ],
)
def test_rule_behavior(rule_fn, attrs, violates):
    assert bool(rule_fn(attrs)) is violates


# --- waivers ------------------------------------------------------------------


def write_waivers(tmp_path, expires, **overrides):
    w = {
        "rule_id": "AZ-SQL-001",
        "address": "azurerm_mssql_server.db",
        "reason": "migration in progress",
        "approved_by": "isso@example.com",
        "expires": expires,
    }
    w.update(overrides)
    p = tmp_path / "waivers.json"
    p.write_text(json.dumps({"waivers": [w]}))
    return p


def test_active_waiver_suppresses_only_its_finding(tmp_path):
    active, _ = load_waivers(write_waivers(tmp_path, "2030-01-01"), date(2026, 1, 1))
    result = scan(load_plan(BAD), active)
    waived = [f for f in result.findings if f.waived]
    assert {(f.rule.id, f.address) for f in waived} == {("AZ-SQL-001", "azurerm_mssql_server.db")}


def test_expired_waiver_fails_the_gate(tmp_path):
    waivers = write_waivers(tmp_path, "2025-01-01")
    plan_with_only_sql = tmp_path / "plan.json"
    plan = load_plan(BAD)
    plan["resource_changes"] = [r for r in plan["resource_changes"] if r["type"] == "azurerm_mssql_server"]
    plan_with_only_sql.write_text(json.dumps(plan))
    code = main(["scan", str(plan_with_only_sql), "--waivers", str(waivers)], today=date(2026, 1, 1))
    assert code == 1


def test_waiver_without_approver_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="approved_by"):
        load_waivers(write_waivers(tmp_path, "2030-01-01", approved_by=""), date(2026, 1, 1))


# --- CLI ------------------------------------------------------------------------


def test_cli_exit_codes(tmp_path, capsys):
    assert main(["scan", str(GOOD)]) == 0
    assert main(["scan", str(BAD)]) == 1
    assert main(["scan", str(tmp_path / "missing.json")]) == 2
    not_a_plan = tmp_path / "x.json"
    not_a_plan.write_text("{}")
    assert main(["scan", str(not_a_plan)]) == 2


def test_fail_on_threshold(tmp_path):
    only_tags = tmp_path / "tags.json"
    plan = load_plan(BAD)
    plan["resource_changes"] = [r for r in plan["resource_changes"] if r["type"] == "azurerm_resource_group"]
    only_tags.write_text(json.dumps(plan))
    assert main(["scan", str(only_tags), "--fail-on", "high"]) == 0  # LOW finding only
    assert main(["scan", str(only_tags), "--fail-on", "low"]) == 1


def test_json_and_sarif_output_are_valid(tmp_path, capsys):
    main(["scan", str(BAD), "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["passed"] is False and data["findings"][0]["severity"] == "CRITICAL"

    out = tmp_path / "results.sarif"
    main(["scan", str(BAD), "--format", "sarif", "-o", str(out)])
    sarif = json.loads(out.read_text())
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert all(r["ruleId"] in rule_ids for r in run["results"])


def test_severity_parse():
    assert Severity.parse("critical") is Severity.CRITICAL
    with pytest.raises(ValueError):
        Severity.parse("urgent")
