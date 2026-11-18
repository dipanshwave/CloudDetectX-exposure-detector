"""Azure subscription-wide checks and RBAC analysis (read-only, via Azure Resource Manager).

Collectors call the API; evaluate_* functions are pure so they can be tested with sample data.
"""

from __future__ import annotations

from clouddetectx.checks import OPEN_CIDRS, risky_ports, short_list
from clouddetectx.models import Finding, Severity

ADMIN_ROLES = {"Owner", "User Access Administrator"}
BROAD_ROLES = {"Owner", "Contributor", "User Access Administrator"}
STORAGE_DATA_ROLES = {"Storage Blob Data Owner": "s3_full", "Storage Blob Data Contributor": "write_all",
                      "Storage Account Contributor": "can_expose", "Storage Blob Data Reader": "read_all"}
MAX_OWNERS = 3


def _port_list(rule: dict) -> list[str]:
    p = rule.get("properties", rule)
    ranges = ([p["destinationPortRange"]] if p.get("destinationPortRange") else []) + (p.get("destinationPortRanges") or [])
    out = []
    for r in ranges:
        if r == "*":
            return ["all ports"]
        lo, _, hi = str(r).partition("-")
        out += risky_ports(int(lo), int(hi or lo))
    return sorted(set(out))


def evaluate_nsgs(nsgs: list[dict]) -> list[dict]:
    """Inbound Allow rules from the internet to sensitive ports, on NSGs attached to NICs or subnets."""
    out = []
    for nsg in nsgs:
        props = nsg.get("properties", {})
        if not (props.get("networkInterfaces") or props.get("subnets")):
            continue
        for rule in props.get("securityRules", []):
            rp = rule.get("properties", {})
            if rp.get("direction") != "Inbound" or rp.get("access") != "Allow":
                continue
            sources = ([rp["sourceAddressPrefix"]] if rp.get("sourceAddressPrefix") else []) + (rp.get("sourceAddressPrefixes") or [])
            if not any(s in OPEN_CIDRS for s in sources):
                continue
            ports = _port_list(rule)
            if ports:
                out.append({"nsg": nsg.get("name"), "rule": rule.get("name"), "ports": ports})
    return out


def evaluate_sql(servers: list[dict], firewall: dict[str, list[dict]]) -> list[dict]:
    out = []
    for srv in servers:
        if (srv.get("properties", {}).get("publicNetworkAccess") or "Enabled") != "Enabled":
            continue
        for rule in firewall.get(srv["id"], []):
            rp = rule.get("properties", {})
            if rp.get("startIpAddress") == "0.0.0.0" and rp.get("endIpAddress") == "255.255.255.255":
                out.append({"server": srv.get("name"), "rule": rule.get("name")})
    return out


def evaluate_aks(clusters: list[dict]) -> list[dict]:
    out = []
    for c in clusters:
        access = c.get("properties", {}).get("apiServerAccessProfile") or {}
        if not access.get("enablePrivateCluster") and not access.get("authorizedIPRanges"):
            out.append({"cluster": c.get("name")})
    return out


def run(provider) -> tuple[list[Finding], list[str], dict[str, str]]:
    from clouddetectx.checks.rest import ArmClient, RestError

    arm = ArmClient(provider.credential)
    sub = f"/subscriptions/{provider.subscription_id}"
    findings, notes, errors = [], [], {}

    def guard(area, fn):
        try:
            return fn()
        except RestError as exc:
            errors[area] = str(exc)
            return None

    nsgs = guard("network security groups", lambda: arm.list(f"{sub}/providers/Microsoft.Network/networkSecurityGroups", "2023-09-01"))
    open_rules = evaluate_nsgs(nsgs or [])
    if open_rules:
        findings.append(Finding(
            "AZ-ACCT-001", "Network security groups expose admin or database ports to the internet", Severity.HIGH,
            f"{len(open_rules)} inbound rule(s) allow Internet/Any on sensitive ports: "
            + short_list([f"{r['nsg']}/{r['rule']}: {', '.join(r['ports'])}" for r in open_rules], 6) + ".",
            "Limit the source to your own IP ranges, or use Azure Bastion / Just-in-time VM access / private endpoints.",
            evidence={"rules": open_rules[:200]}))

    servers = guard("SQL servers", lambda: arm.list(f"{sub}/providers/Microsoft.Sql/servers", "2021-11-01")) or []
    firewall = {}
    for srv in servers[:200]:
        rules = guard("SQL firewall", lambda s=srv: arm.list(f"{s['id']}/firewallRules", "2021-11-01"))
        firewall[srv["id"]] = rules or []
    open_sql = evaluate_sql(servers, firewall)
    if open_sql:
        findings.append(Finding(
            "AZ-ACCT-002", "SQL servers accept connections from any IP address", Severity.HIGH,
            f"{len(open_sql)} SQL server firewall rule(s) allow 0.0.0.0-255.255.255.255: "
            + short_list([f"{x['server']}/{x['rule']}" for x in open_sql]) + ".",
            "Delete the allow-all rule; use private endpoints or specific client IP ranges.",
            evidence={"servers": open_sql}))

    clusters = guard("AKS", lambda: arm.list(f"{sub}/providers/Microsoft.ContainerService/managedClusters", "2024-02-01"))
    open_aks = evaluate_aks(clusters or [])
    if open_aks:
        findings.append(Finding(
            "AZ-ACCT-003", "Kubernetes API servers are open to the internet", Severity.HIGH,
            f"{len(open_aks)} AKS cluster(s) have a public API server with no authorized IP ranges: "
            + short_list([c["cluster"] for c in open_aks]) + ".",
            "Use a private cluster or set authorized IP ranges on the API server.", evidence={"clusters": open_aks}))

    diag = guard("activity log export", lambda: arm.list(f"{sub}/providers/Microsoft.Insights/diagnosticSettings", "2021-05-01-preview"))
    if diag is not None and not diag:
        findings.append(Finding(
            "AZ-ACCT-004", "Activity Log is not exported", Severity.MEDIUM,
            "No diagnostic setting sends the subscription Activity Log anywhere, so control-plane history "
            "(who changed what) is kept for only 90 days.",
            "Add a subscription diagnostic setting sending the Activity Log to Log Analytics or a storage account."))

    if errors:
        notes.append("Some Azure account checks were skipped: " + ", ".join(f"{k} ({v[:80]})" for k, v in sorted(errors.items())) + ".")
    return findings, notes, errors


# --------------------------------------------------------------------------- RBAC

def evaluate_rbac(subscription_id: str, assignments: list[dict], definitions: dict[str, dict]):
    """Returns (principals, findings) from role assignments and role definitions."""
    from clouddetectx.iam import Principal

    sub_scope = f"/subscriptions/{subscription_id}".lower()
    by_principal: dict[str, Principal] = {}
    owners, storage_broad = [], []
    for a in assignments:
        ap = a.get("properties", {})
        role = definitions.get((ap.get("roleDefinitionId") or "").lower(), {})
        role_name = role.get("roleName", "custom role")
        scope = (ap.get("scope") or "").lower()
        pid = ap.get("principalId", "?")
        kind = (ap.get("principalType") or "principal").lower()
        p = by_principal.setdefault(pid, Principal(kind, pid, f"{ap.get('principalType', '')} {pid}".strip()))
        p.statements = []
        broad_scope = scope == sub_scope or ("/resourcegroups/" in scope and scope.count("/") <= 4)
        if role_name in BROAD_ROLES and scope == sub_scope:
            p.capabilities["admin"] = "yes"
            if role_name in ADMIN_ROLES:
                owners.append(p)
        elif role_name in STORAGE_DATA_ROLES and broad_scope:
            cap = STORAGE_DATA_ROLES[role_name]
            p.capabilities.setdefault(cap, "yes")
            if cap != "read_all":
                storage_broad.append((p, role_name, scope))
    principals = list(by_principal.values())

    findings = []
    owners = list({p.name: p for p in owners}.values())
    if len(owners) > MAX_OWNERS:
        findings.append(Finding(
            "AZ-IAM-001", f"More than {MAX_OWNERS} subscription owners", Severity.MEDIUM,
            f"{len(owners)} principals have Owner or User Access Administrator on the whole subscription.",
            "Keep 2-3 owners, assign them through Privileged Identity Management, and use narrower roles otherwise.",
            evidence={"principals": [p.arn for p in owners][:100]}))
    if storage_broad:
        findings.append(Finding(
            "AZ-IAM-002", "Broad storage data access at subscription or resource-group scope", Severity.MEDIUM,
            f"{len(storage_broad)} assignment(s) give data-plane write/admin access to every storage account in scope: "
            + short_list([f"{role} for {p.arn}" for p, role, _ in storage_broad], 5) + ".",
            "Assign storage data roles on individual storage accounts or containers.",
            evidence={"assignments": [{"principal": p.arn, "role": r, "scope": s} for p, r, s in storage_broad][:100]}))
    custom_admin = [d for d in definitions.values()
                    if d.get("type") == "CustomRole" and any("*" in (perm.get("actions") or []) for perm in d.get("permissions", []))]
    if custom_admin:
        findings.append(Finding(
            "AZ-IAM-003", "Custom roles grant all actions", Severity.HIGH,
            f"{len(custom_admin)} custom role(s) allow '*' actions: " + short_list([d.get("roleName") for d in custom_admin]) + ".",
            "Replace '*' with the specific actions the role needs.", evidence={"roles": [d.get("roleName") for d in custom_admin]}))
    return principals, findings


def analyze_identity(provider):
    from clouddetectx.checks.rest import ArmClient, RestError
    from clouddetectx.iam import IamReport
    from clouddetectx.providers.base import ProviderError

    arm = ArmClient(provider.credential)
    sub = f"/subscriptions/{provider.subscription_id}"
    try:
        defs = arm.list(f"{sub}/providers/Microsoft.Authorization/roleDefinitions", "2022-04-01")
        assignments = arm.list(f"{sub}/providers/Microsoft.Authorization/roleAssignments", "2022-04-01")
    except RestError as exc:
        raise ProviderError(f"RBAC analysis needs Microsoft.Authorization/*/read (Reader role): {exc}") from exc
    definitions = {d["id"].lower(): {**d.get("properties", {})} for d in defs}
    principals, findings = evaluate_rbac(provider.subscription_id, assignments, definitions)
    notes = ["Azure RBAC role assignments at subscription and resource-group scope. Principals are shown by object ID "
             "(display names need Microsoft Graph access); deny assignments and PIM eligibility are not evaluated."]
    return IamReport(provider.subscription_id, principals, findings, notes)
