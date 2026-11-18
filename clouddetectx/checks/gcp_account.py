"""Google Cloud project-wide checks and IAM analysis (read-only REST)."""

from __future__ import annotations

from datetime import datetime, timezone

from clouddetectx.checks import risky_ports, short_list
from clouddetectx.models import Finding, Severity

KEY_MAX_AGE_DAYS = 90
PUBLIC = {"allUsers", "allAuthenticatedUsers"}
ROLE_CAPS = {"roles/owner": "admin", "roles/editor": "s3_full", "roles/storage.admin": "s3_full",
             "roles/storage.objectAdmin": "write_all", "roles/storage.objectCreator": "write_all",
             "roles/storage.objectViewer": "read_all"}


def _age_days(ts: str | None) -> int | None:
    if not ts:
        return None
    try:
        return (datetime.now(timezone.utc) - datetime.fromisoformat(ts.replace("Z", "+00:00"))).days
    except ValueError:
        return None


def evaluate_firewalls(rules: list[dict]) -> list[dict]:
    out = []
    for r in rules:
        if r.get("direction", "INGRESS") != "INGRESS" or r.get("disabled"):
            continue
        if not set(r.get("sourceRanges") or []) & {"0.0.0.0/0", "::/0"}:
            continue
        ports = []
        for allow in r.get("allowed", []):
            if allow.get("IPProtocol") == "all":
                ports = ["all ports"]
                break
            for pr in allow.get("ports") or ["0-65535"]:
                lo, _, hi = str(pr).partition("-")
                ports += risky_ports(int(lo), int(hi or lo))
        if ports:
            out.append({"rule": r.get("name"), "network": (r.get("network") or "").rsplit("/", 1)[-1], "ports": sorted(set(ports))})
    return out


def evaluate_sql(instances: list[dict]) -> list[dict]:
    out = []
    for i in instances:
        ipc = (i.get("settings") or {}).get("ipConfiguration") or {}
        nets = [n.get("value") for n in ipc.get("authorizedNetworks") or []]
        if ipc.get("ipv4Enabled") and "0.0.0.0/0" in nets:
            out.append({"instance": i.get("name"), "region": i.get("region")})
    return out


def evaluate_gke(clusters: list[dict]) -> list[dict]:
    out = []
    for c in clusters:
        private = (c.get("privateClusterConfig") or {}).get("enablePrivateEndpoint")
        authorized = (c.get("masterAuthorizedNetworksConfig") or {}).get("enabled")
        if not private and not authorized:
            out.append({"cluster": c.get("name"), "location": c.get("location")})
    return out


def data_access_logged(policy: dict) -> bool:
    for cfg in policy.get("auditConfigs", []) or []:
        if cfg.get("service") in ("allServices", "storage.googleapis.com"):
            if any(lc.get("logType") == "DATA_READ" for lc in cfg.get("auditLogConfigs", [])):
                return True
    return False


def run(provider) -> tuple[list[Finding], list[str], dict[str, str]]:
    from clouddetectx.checks.rest import GcpRest, RestError

    rest = GcpRest()
    project = provider.project
    findings, notes, errors = [], [], {}

    def guard(area, fn):
        try:
            return fn()
        except RestError as exc:
            errors[area] = str(exc)
            return None

    fw = guard("firewall rules", lambda: rest.list(f"https://compute.googleapis.com/compute/v1/projects/{project}/global/firewalls", "items"))
    open_fw = evaluate_firewalls(fw or [])
    if open_fw:
        findings.append(Finding(
            "GCP-ACCT-001", "Firewall rules expose admin or database ports to the internet", Severity.HIGH,
            f"{len(open_fw)} ingress rule(s) allow 0.0.0.0/0 on sensitive ports: "
            + short_list([f"{r['rule']}: {', '.join(r['ports'])}" for r in open_fw], 6) + ".",
            "Restrict source ranges, or use Identity-Aware Proxy TCP forwarding instead of public SSH/RDP.",
            evidence={"rules": open_fw[:200]}))

    sql = guard("Cloud SQL", lambda: rest.list(f"https://sqladmin.googleapis.com/v1/projects/{project}/instances", "items"))
    open_sql = evaluate_sql(sql or [])
    if open_sql:
        findings.append(Finding(
            "GCP-ACCT-002", "Cloud SQL instances accept connections from any IP address", Severity.HIGH,
            f"{len(open_sql)} instance(s) have a public IP with authorized network 0.0.0.0/0: "
            + short_list([i["instance"] for i in open_sql]) + ".",
            "Remove 0.0.0.0/0, use private IP or the Cloud SQL Auth Proxy.", evidence={"instances": open_sql}))

    policy = guard("project IAM policy", lambda: rest.post(
        f"https://cloudresourcemanager.googleapis.com/v1/projects/{project}:getIamPolicy",
        {"options": {"requestedPolicyVersion": 3}}))
    if policy is not None and not data_access_logged(policy):
        findings.append(Finding(
            "GCP-ACCT-003", "Data Access audit logs are off for Cloud Storage", Severity.MEDIUM,
            "Reads of Cloud Storage objects by authenticated users are not logged, so data access can't be investigated.",
            "Enable DATA_READ and DATA_WRITE audit logs for storage.googleapis.com (or allServices)."))

    gke = guard("GKE", lambda: rest.list(f"https://container.googleapis.com/v1/projects/{project}/locations/-/clusters", "clusters"))
    open_gke = evaluate_gke(gke or [])
    if open_gke:
        findings.append(Finding(
            "GCP-ACCT-004", "Kubernetes control planes are open to the internet", Severity.HIGH,
            f"{len(open_gke)} GKE cluster(s) have a public endpoint without authorized networks: "
            + short_list([c["cluster"] for c in open_gke]) + ".",
            "Enable control plane authorized networks or a private endpoint.", evidence={"clusters": open_gke}))

    try:
        stale = []
        for key in provider.client.list_hmac_keys(project_id=project):
            age = (datetime.now(timezone.utc) - key.time_created).days if key.time_created else None
            if key.state == "ACTIVE" and age is not None and age > KEY_MAX_AGE_DAYS:
                stale.append({"access_id": key.access_id[-4:], "service_account": key.service_account_email, "age_days": age})
        if stale:
            findings.append(Finding(
                "GCP-GCS-008", f"Cloud Storage HMAC keys older than {KEY_MAX_AGE_DAYS} days", Severity.MEDIUM,
                f"{len(stale)} active HMAC key(s) have not been rotated: "
                + short_list([f"…{k['access_id']} ({k['service_account']}, {k['age_days']}d)" for k in stale]) + ".",
                "Rotate or delete HMAC keys; prefer OAuth / workload identity.", evidence={"keys": stale}))
    except Exception as exc:  # noqa: BLE001 - keep going without HMAC data
        errors["HMAC keys"] = f"{type(exc).__name__}: {str(exc)[:120]}"

    provider._project_policy = policy
    if errors:
        notes.append("Some GCP project checks were skipped (API disabled or no permission): "
                     + ", ".join(f"{k} ({v[:80]})" for k, v in sorted(errors.items())) + ".")
    return findings, notes, errors


# --------------------------------------------------------------------------- IAM

def evaluate_iam(project: str, policy: dict, sa_keys: dict[str, list[dict]]):
    from clouddetectx.iam import Principal

    by_member: dict[str, Principal] = {}
    basic, storage_admin, public = [], [], []
    for b in policy.get("bindings", []):
        role = b.get("role", "")
        for m in b.get("members", []):
            if m in PUBLIC:
                public.append((m, role))
                continue
            kind, _, name = m.partition(":")
            p = by_member.setdefault(m, Principal(kind or "member", name or m, m))
            cap = ROLE_CAPS.get(role)
            if cap and not (cap == "admin" and "admin" in p.capabilities):
                p.capabilities.setdefault(cap, "conditional" if b.get("condition") else "yes")
            if role in ("roles/owner", "roles/editor"):
                basic.append((p, role))
            elif role in ("roles/storage.admin", "roles/storage.objectAdmin"):
                storage_admin.append((p, role))
    for email, keys in sa_keys.items():
        p = by_member.setdefault(f"serviceAccount:{email}", Principal("serviceAccount", email, f"serviceAccount:{email}"))
        p.keys = [{"id_suffix": k["name"].rsplit("/", 1)[-1][-4:], "status": "Active",
                   "age_days": _age_days(k.get("validAfterTime")) or 0} for k in keys]
    principals = list(by_member.values())

    findings = []
    if public:
        findings.append(Finding(
            "GCP-IAM-004", "Project IAM grants roles to everyone", Severity.CRITICAL,
            "The project IAM policy grants " + short_list([f"{r} to {m}" for m, r in public]) + ".",
            "Remove allUsers / allAuthenticatedUsers from the project IAM policy.", exposes_data=True,
            evidence={"bindings": [{"member": m, "role": r} for m, r in public]}))
    if basic:
        sas = [p for p, _ in basic if p.kind == "serviceAccount"]
        findings.append(Finding(
            "GCP-IAM-001", "Basic Owner/Editor roles are granted", Severity.HIGH if sas else Severity.MEDIUM,
            f"{len(basic)} member(s) hold roles/owner or roles/editor on project {project}"
            + (f", including {len(sas)} service account(s)" if sas else "") + ": "
            + short_list([f"{p.arn} ({r.split('/')[-1]})" for p, r in basic], 6) + ".",
            "Replace basic roles with predefined roles scoped to what each member needs.",
            evidence={"members": [{"member": p.arn, "role": r} for p, r in basic][:100]}))
    if storage_admin:
        findings.append(Finding(
            "GCP-IAM-002", "Storage admin roles at project level", Severity.MEDIUM,
            f"{len(storage_admin)} member(s) can administer or write every bucket in the project: "
            + short_list([f"{p.arn} ({r.split('/')[-1]})" for p, r in storage_admin], 6) + ".",
            "Grant storage roles on individual buckets instead of the whole project.",
            evidence={"members": [{"member": p.arn, "role": r} for p, r in storage_admin][:100]}))
    stale = [(p, k) for p in principals for k in p.keys if k["age_days"] > KEY_MAX_AGE_DAYS]
    if stale:
        findings.append(Finding(
            "GCP-IAM-003", f"Service account keys older than {KEY_MAX_AGE_DAYS} days", Severity.HIGH,
            f"{len(stale)} user-managed key(s) have not been rotated: "
            + short_list([f"{p.name} (…{k['id_suffix']}, {k['age_days']}d)" for p, k in stale]) + ".",
            "Rotate or delete service account keys; prefer workload identity federation or attached service accounts.",
            evidence={"keys": [{"service_account": p.name, "key": k["id_suffix"], "age_days": k["age_days"]} for p, k in stale]}))
    return principals, findings


def analyze_identity(provider):
    from clouddetectx.checks.rest import GcpRest, RestError
    from clouddetectx.iam import IamReport
    from clouddetectx.providers.base import ProviderError

    rest = GcpRest()
    project = provider.project
    try:
        policy = getattr(provider, "_project_policy", None) or rest.post(
            f"https://cloudresourcemanager.googleapis.com/v1/projects/{project}:getIamPolicy",
            {"options": {"requestedPolicyVersion": 3}})
    except RestError as exc:
        raise ProviderError(f"IAM analysis needs resourcemanager.projects.getIamPolicy: {exc}") from exc
    sa_keys, notes = {}, []
    try:
        for sa in rest.list(f"https://iam.googleapis.com/v1/projects/{project}/serviceAccounts", "accounts", limit=500):
            keys = rest.get(f"https://iam.googleapis.com/v1/{sa['name']}/keys", {"keyTypes": "USER_MANAGED"}).get("keys", [])
            if keys:
                sa_keys[sa["email"]] = keys
    except RestError as exc:
        notes.append(f"Service account keys not checked: {exc}")
    principals, findings = evaluate_iam(project, policy, sa_keys)
    notes.append("Project-level IAM bindings and user-managed service account keys. Folder/organization policies, "
                 "IAM deny policies and bucket-level bindings (checked per bucket) are not combined here.")
    return IamReport(project, principals, findings, notes)
