"""Compliance rules.

Each rule inspects the planned ("after") attributes of one Terraform resource
and returns a list of problems. Rules are plain functions registered with the
@rule decorator, so adding a control is a few lines plus a test.

Control IDs refer to NIST SP 800-53 Rev. 5, the catalog FedRAMP baselines
are built from.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.upper()]
        except KeyError:
            raise ValueError(f"unknown severity {value!r}") from None


Check = Callable[[dict[str, Any]], list[str]]


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    controls: tuple[str, ...]
    resource_types: tuple[str, ...]
    check: Check
    remediation: str


RULES: list[Rule] = []

REQUIRED_TAGS = ("owner", "environment", "data_classification")
ADMIN_PORTS = {22, 3389}
OPEN_SOURCES = {"*", "0.0.0.0/0", "::/0", "internet", "any"}


def rule(
    id: str,
    title: str,
    severity: Severity,
    controls: tuple[str, ...],
    resource_types: tuple[str, ...],
    remediation: str,
) -> Callable[[Check], Check]:
    def register(fn: Check) -> Check:
        RULES.append(Rule(id, title, severity, controls, resource_types, fn, remediation))
        return fn

    return register


# --- helpers ---------------------------------------------------------------


def _ports(spec: Any) -> set[int]:
    """Expand '22', '20-25', '*', 22 into a set of ports (capped for '*')."""
    if spec is None:
        return set()
    if isinstance(spec, int):
        return {spec}
    spec = str(spec).strip()
    if spec in ("*", "-1", ""):
        return set(range(0, 65536))
    if "-" in spec:
        lo, hi = spec.split("-", 1)
        return set(range(int(lo), int(hi) + 1))
    return {int(spec)}


def _open(sources: Any) -> bool:
    if sources is None:
        return False
    if isinstance(sources, str):
        sources = [sources]
    return any(str(s).strip().lower() in OPEN_SOURCES for s in sources)


# --- Azure -----------------------------------------------------------------


@rule(
    "AZ-STG-001",
    "Storage account must require TLS 1.2 or higher",
    Severity.HIGH,
    ("SC-8", "SC-13"),
    ("azurerm_storage_account",),
    'Set min_tls_version = "TLS1_2".',
)
def storage_min_tls(a: dict[str, Any]) -> list[str]:
    v = a.get("min_tls_version")
    return [] if v in ("TLS1_2", "TLS1_3") else [f"min_tls_version is {v!r}"]


@rule(
    "AZ-STG-002",
    "Storage account must only accept HTTPS traffic",
    Severity.HIGH,
    ("SC-8",),
    ("azurerm_storage_account",),
    "Set https_traffic_only_enabled = true.",
)
def storage_https_only(a: dict[str, Any]) -> list[str]:
    # Attribute was renamed in azurerm 4.x; accept either name.
    v = a.get("https_traffic_only_enabled", a.get("enable_https_traffic_only"))
    return [] if v is True else ["HTTPS-only traffic is not enforced"]


@rule(
    "AZ-STG-003",
    "Storage account must not allow public access",
    Severity.CRITICAL,
    ("AC-3", "SC-7"),
    ("azurerm_storage_account",),
    "Set public_network_access_enabled = false and allow_nested_items_to_be_public = false.",
)
def storage_no_public(a: dict[str, Any]) -> list[str]:
    problems = []
    if a.get("public_network_access_enabled") is not False:
        problems.append("public network access is enabled")
    if a.get("allow_nested_items_to_be_public") is not False:
        problems.append("blobs can be made public")
    return problems


@rule(
    "AZ-KV-001",
    "Key Vault must have purge protection and soft delete",
    Severity.HIGH,
    ("SC-12", "CP-9"),
    ("azurerm_key_vault",),
    "Set purge_protection_enabled = true and soft_delete_retention_days >= 7.",
)
def key_vault_protection(a: dict[str, Any]) -> list[str]:
    problems = []
    if a.get("purge_protection_enabled") is not True:
        problems.append("purge protection is disabled")
    if (a.get("soft_delete_retention_days") or 0) < 7:
        problems.append("soft delete retention is under 7 days")
    return problems


@rule(
    "AZ-KV-002",
    "Key Vault must use RBAC and deny public network access",
    Severity.MEDIUM,
    ("AC-3", "AC-6"),
    ("azurerm_key_vault",),
    "Set enable_rbac_authorization = true and public_network_access_enabled = false.",
)
def key_vault_access(a: dict[str, Any]) -> list[str]:
    problems = []
    rbac = a.get("rbac_authorization_enabled", a.get("enable_rbac_authorization"))
    if rbac is not True:
        problems.append("RBAC authorization is disabled (legacy access policies)")
    if a.get("public_network_access_enabled") is not False:
        problems.append("public network access is enabled")
    return problems


@rule(
    "AZ-NSG-001",
    "No inbound SSH/RDP from the internet",
    Severity.CRITICAL,
    ("SC-7", "AC-17"),
    ("azurerm_network_security_rule", "azurerm_network_security_group"),
    "Restrict source_address_prefix to a management range or use Azure Bastion.",
)
def nsg_admin_ports(a: dict[str, Any]) -> list[str]:
    # A standalone rule resource, or inline rules on an NSG.
    rules = a.get("security_rule") if "security_rule" in a else [a]
    problems = []
    for r in rules or []:
        if str(r.get("direction", "")).lower() != "inbound":
            continue
        if str(r.get("access", "")).lower() != "allow":
            continue
        sources = r.get("source_address_prefixes") or r.get("source_address_prefix")
        ports = _ports(r.get("destination_port_range"))
        for p in r.get("destination_port_ranges") or []:
            ports |= _ports(p)
        exposed = sorted(ports & ADMIN_PORTS)
        if _open(sources) and exposed:
            name = r.get("name", "rule")
            problems.append(f"{name} allows port(s) {exposed} from the internet")
    return problems


@rule(
    "AZ-SQL-001",
    "SQL server must require TLS 1.2 and disable public access",
    Severity.HIGH,
    ("SC-8", "SC-7"),
    ("azurerm_mssql_server",),
    'Set minimum_tls_version = "1.2" and public_network_access_enabled = false.',
)
def sql_server(a: dict[str, Any]) -> list[str]:
    problems = []
    if a.get("minimum_tls_version") not in ("1.2", "1.3"):
        problems.append(f"minimum_tls_version is {a.get('minimum_tls_version')!r}")
    if a.get("public_network_access_enabled") is not False:
        problems.append("public network access is enabled")
    return problems


@rule(
    "AZ-AKS-001",
    "AKS must use Entra ID RBAC with local accounts disabled",
    Severity.HIGH,
    ("AC-2", "IA-2"),
    ("azurerm_kubernetes_cluster",),
    "Set local_account_disabled = true and configure azure_active_directory_role_based_access_control.",
)
def aks_identity(a: dict[str, Any]) -> list[str]:
    problems = []
    if a.get("local_account_disabled") is not True:
        problems.append("local (shared) admin account is enabled")
    if not a.get("azure_active_directory_role_based_access_control"):
        problems.append("Entra ID RBAC is not configured")
    return problems


TAGGABLE = (
    "azurerm_resource_group",
    "azurerm_storage_account",
    "azurerm_key_vault",
    "azurerm_kubernetes_cluster",
    "azurerm_mssql_server",
    "azurerm_virtual_network",
    "aws_s3_bucket",
    "aws_instance",
)


@rule(
    "TAG-001",
    "Resources must carry ownership and classification tags",
    Severity.LOW,
    ("CM-8", "RA-2"),
    TAGGABLE,
    f"Add tags: {', '.join(REQUIRED_TAGS)}.",
)
def required_tags(a: dict[str, Any]) -> list[str]:
    tags = a.get("tags") or {}
    missing = [t for t in REQUIRED_TAGS if not tags.get(t)]
    return [f"missing tags: {', '.join(missing)}"] if missing else []


# --- AWS -------------------------------------------------------------------


@rule(
    "AWS-S3-001",
    "S3 public access block must be fully enabled",
    Severity.CRITICAL,
    ("AC-3", "SC-7"),
    ("aws_s3_bucket_public_access_block",),
    "Set all four block_* / ignore_* / restrict_* arguments to true.",
)
def s3_public_access_block(a: dict[str, Any]) -> list[str]:
    keys = (
        "block_public_acls",
        "block_public_policy",
        "ignore_public_acls",
        "restrict_public_buckets",
    )
    off = [k for k in keys if a.get(k) is not True]
    return [f"not enabled: {', '.join(off)}"] if off else []


@rule(
    "AWS-SG-001",
    "No inbound SSH/RDP from the internet",
    Severity.CRITICAL,
    ("SC-7", "AC-17"),
    ("aws_security_group", "aws_vpc_security_group_ingress_rule"),
    "Restrict cidr_blocks to a management range or use SSM Session Manager.",
)
def aws_sg_admin_ports(a: dict[str, Any]) -> list[str]:
    ingress = a.get("ingress") if "ingress" in a else [a]
    problems = []
    for r in ingress or []:
        sources = (r.get("cidr_blocks") or []) + (r.get("ipv6_cidr_blocks") or [])
        if r.get("cidr_ipv4"):
            sources.append(r["cidr_ipv4"])
        if r.get("cidr_ipv6"):
            sources.append(r["cidr_ipv6"])
        proto = str(r.get("protocol", r.get("ip_protocol", ""))).lower()
        if proto in ("-1", "all"):
            ports = set(range(0, 65536))
        else:
            lo, hi = r.get("from_port"), r.get("to_port")
            ports = set(range(int(lo), int(hi) + 1)) if lo is not None and hi is not None else set()
        exposed = sorted(ports & ADMIN_PORTS)
        if _open(sources) and exposed:
            problems.append(f"ingress allows port(s) {exposed} from the internet")
    return problems
