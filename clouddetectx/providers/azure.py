"""Microsoft Azure Blob Storage provider.

The scanned resource is a storage account. Public exposure happens when the
account allows anonymous blob access AND a container's access level is
"Blob" or "Container".

Authentication uses DefaultAzureCredential: `az login`, environment variables
(AZURE_CLIENT_ID / AZURE_TENANT_ID / AZURE_CLIENT_SECRET), managed identity, etc.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from clouddetectx.config import Settings
from clouddetectx.models import AccessEvent, ChangeEvent, Finding, Posture, RemediationAction, Resource, Severity
from clouddetectx.providers.base import ProviderError, StorageProvider

BLOB_OPERATIONS = {
    "GetBlob": "GetObject",
    "GetBlobProperties": "HeadObject",
    "ListBlobs": "ListBucket",
    "PutBlob": "PutObject",
    "PutBlock": "PutObject",
    "PutBlockList": "PutObject",
    "CopyBlob": "PutObject",
    "DeleteBlob": "DeleteObject",
}

STORAGE_BLOB_LOGS_QUERY = """
StorageBlobLogs
| where AccountName =~ '{account}'
| project TimeGenerated, OperationName, AuthenticationType, RequesterUpn, RequesterObjectId,
          CallerIpAddress, StatusCode, ResponseBodySize, UserAgentHeader, ObjectKey
| order by TimeGenerated asc
| take 50000
"""


def _resource_group(resource_id: str) -> str:
    parts = resource_id.split("/")
    return parts[parts.index("resourceGroups") + 1]


def _enum(value: Any) -> str | None:
    return None if value is None else str(getattr(value, "value", value))


class AzureProvider(StorageProvider):
    name = "azure"
    display_name = "Microsoft Azure (Blob Storage)"

    def __init__(self, settings: Settings):
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.storage import StorageManagementClient
        except ImportError as exc:  # pragma: no cover
            raise ProviderError("Azure SDK is not installed. Run: pip install -r requirements.txt") from exc

        if not settings.azure_subscription_id:
            raise ProviderError(
                "AZURE_SUBSCRIPTION_ID is not set. Find it with `az account show --query id -o tsv` "
                "and add it to .env."
            )
        import logging

        # The SDK logs verbose credential-chain warnings; we surface a clear error ourselves.
        logging.getLogger("azure").setLevel(logging.ERROR)
        self.settings = settings
        self.subscription_id = settings.azure_subscription_id
        self.credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
        self.storage = StorageManagementClient(self.credential, self.subscription_id)
        self._accounts: dict[str, Any] | None = None

    def _call(self, fn, what: str):
        from azure.core.exceptions import AzureError, ClientAuthenticationError

        try:
            return fn()
        except ClientAuthenticationError as exc:
            raise ProviderError(f"Azure authentication failed ({what}). Run `az login`. {exc.message}") from exc
        except AzureError as exc:
            raise ProviderError(f"Azure API error ({what}): {exc}") from exc

    def account_label(self) -> str:
        self._load_accounts()
        return f"Azure subscription {self.subscription_id}"

    # -- discovery ---------------------------------------------------------------
    def _load_accounts(self) -> dict[str, Any]:
        if self._accounts is None:
            accounts = self._call(lambda: list(self.storage.storage_accounts.list()), "list storage accounts")
            self._accounts = {a.name: a for a in accounts}
        return self._accounts

    def _resource(self, account) -> Resource:
        return Resource(
            provider="azure",
            name=account.name,
            resource_id=account.id,
            location=account.location,
            kind="storage-account",
            extra={"resource_group": _resource_group(account.id)},
        )

    def list_resources(self) -> list[Resource]:
        return [self._resource(a) for a in self._load_accounts().values()]

    def get_resource(self, name: str) -> Resource:
        account = self._load_accounts().get(name)
        if not account:
            raise ProviderError(f"Storage account '{name}' not found in subscription {self.subscription_id}.")
        return self._resource(account)

    # -- posture -------------------------------------------------------------------
    def collect_posture(self, resource: Resource) -> Posture:
        from azure.core.exceptions import AzureError

        rg = resource.extra["resource_group"]
        posture = Posture(resource=resource)
        cfg = posture.config
        try:
            acct = self.storage.storage_accounts.get_properties(rg, resource.name)
        except AzureError as exc:
            posture.errors["account"] = str(exc)
            return posture

        rules = acct.network_rule_set
        cfg.update({
            # None on older accounts means the legacy default: anonymous access permitted.
            "allow_blob_public_access": acct.allow_blob_public_access,
            "public_network_access": _enum(acct.public_network_access),
            "network_default_action": _enum(rules.default_action) if rules else None,
            "ip_rules": [r.ip_address_or_range for r in (rules.ip_rules or [])] if rules else [],
            "https_only": acct.enable_https_traffic_only,
            "minimum_tls_version": _enum(acct.minimum_tls_version),
            "allow_shared_key_access": acct.allow_shared_key_access,
        })

        containers = []
        try:
            for c in self.storage.blob_containers.list(rg, resource.name):
                containers.append({"name": c.name, "public_access": _enum(c.public_access) or "None"})
        except AzureError as exc:
            posture.errors["containers"] = str(exc)
        cfg["containers"] = containers

        try:
            props = self.storage.blob_services.get_service_properties(rg, resource.name)
            cfg["versioning"] = bool(props.is_versioning_enabled)
            cfg["soft_delete"] = bool(props.delete_retention_policy and props.delete_retention_policy.enabled)
        except AzureError as exc:
            posture.errors["blob_service"] = str(exc)

        cfg["diagnostic_settings"] = self._blob_diagnostic_settings(resource, posture)
        return posture

    def _blob_diagnostic_settings(self, resource: Resource, posture: Posture) -> list[dict]:
        from azure.core.exceptions import AzureError
        from azure.mgmt.monitor import MonitorManagementClient

        try:
            monitor = MonitorManagementClient(self.credential, self.subscription_id)
            settings = monitor.diagnostic_settings.list(f"{resource.resource_id}/blobServices/default")
            out = []
            for s in settings:
                logs_on = [lg.category or lg.category_group for lg in (s.logs or []) if lg.enabled]
                out.append({"name": s.name, "workspace_id": s.workspace_id,
                            "storage_account_id": s.storage_account_id, "log_categories": logs_on})
            return out
        except AzureError as exc:
            posture.errors["diagnostic_settings"] = str(exc)
            return []

    # -- evaluation ------------------------------------------------------------------
    def evaluate(self, posture: Posture) -> list[Finding]:
        cfg = posture.config
        findings: list[Finding] = []
        if "account" in posture.errors:
            return [Finding("AZ-ST-000", "Could not read storage account", Severity.INFO,
                            posture.errors["account"], "Grant the scanner the Reader role.")]

        account_allows = cfg.get("allow_blob_public_access") is not False
        public = [c for c in cfg.get("containers", []) if c["public_access"] in ("Blob", "Container")]

        if public:
            listable = [c["name"] for c in public if c["public_access"] == "Container"]
            findings.append(Finding(
                check_id="AZ-ST-001",
                title="Containers allow anonymous public read access",
                severity=Severity.CRITICAL if account_allows else Severity.LOW,
                description=(
                    f"{len(public)} container(s) have a public access level: "
                    + ", ".join(f"{c['name']} ({c['public_access']})" for c in public)
                    + (". 'Container' level also lets anyone enumerate every blob." if listable else ".")
                    + ("" if account_allows else " Currently neutralised because the account disallows anonymous access.")
                ),
                recommendation="Set the containers to Private and disable 'Allow Blob anonymous access' on the account.",
                exposes_data=account_allows,
                evidence={"containers": public},
            ))

        if account_allows:
            findings.append(Finding(
                check_id="AZ-ST-002",
                title="Storage account permits anonymous blob access",
                severity=Severity.MEDIUM,
                description="AllowBlobPublicAccess is enabled (or unset on a legacy account), so any container can be made public.",
                recommendation="Set allowBlobPublicAccess=false (Azure Policy: 'Storage account public access should be disallowed').",
                evidence={"allow_blob_public_access": cfg.get("allow_blob_public_access")},
            ))

        if cfg.get("public_network_access") != "Disabled" and cfg.get("network_default_action") == "Allow":
            findings.append(Finding(
                check_id="AZ-ST-003",
                title="Storage account is reachable from all networks",
                severity=Severity.MEDIUM,
                description="The firewall default action is Allow, so the endpoint accepts traffic from any IP address.",
                recommendation="Set the default action to Deny and allow only required VNets/IPs or private endpoints.",
                evidence={"public_network_access": cfg.get("public_network_access"),
                          "default_action": cfg.get("network_default_action")},
            ))

        if cfg.get("allow_shared_key_access") is not False:
            findings.append(Finding(
                check_id="AZ-ST-004",
                title="Shared key (account key) authorization is allowed",
                severity=Severity.LOW,
                description="Leaked account keys or account-key SAS tokens give full data access and are hard to audit.",
                recommendation="Disable shared key access and use Microsoft Entra ID authorization.",
            ))

        if cfg.get("https_only") is False:
            findings.append(Finding("AZ-ST-005", "HTTP (unencrypted) traffic is allowed", Severity.MEDIUM,
                                    "Secure transfer required is disabled.", "Enable 'Secure transfer required'."))

        if cfg.get("minimum_tls_version") not in (None, "TLS1_2", "TLS1_3"):
            findings.append(Finding("AZ-ST-006", "Outdated minimum TLS version", Severity.LOW,
                                    f"Minimum TLS version is {cfg.get('minimum_tls_version')}.",
                                    "Set minimum TLS version to TLS1_2."))

        if not any(d.get("log_categories") for d in cfg.get("diagnostic_settings", [])):
            findings.append(Finding(
                check_id="AZ-ST-007",
                title="Blob diagnostic logging is not enabled",
                severity=Severity.MEDIUM,
                description="Without StorageRead logs you cannot prove whether exposed blobs were downloaded.",
                recommendation="Add a diagnostic setting on blobServices/default sending StorageRead/Write/Delete to Log Analytics.",
            ))

        if cfg.get("versioning") is False and cfg.get("soft_delete") is False:
            findings.append(Finding("AZ-ST-008", "Blob versioning and soft delete are disabled", Severity.LOW,
                                    "Deleted or overwritten blobs cannot be recovered.",
                                    "Enable blob soft delete and versioning."))

        for label, err in posture.errors.items():
            findings.append(Finding("AZ-ST-000", f"Could not read {label}", Severity.INFO, err[:300],
                                    "Grant the scanner Reader + Monitoring Reader roles."))
        return findings

    # -- investigation ------------------------------------------------------------------
    def collect_access_events(self, posture: Posture, since: datetime):
        from azure.core.exceptions import AzureError
        from azure.monitor.query import LogsQueryClient, LogsQueryStatus

        notes: list[str] = []
        diag = [d for d in posture.config.get("diagnostic_settings", []) if d.get("workspace_id") and d.get("log_categories")]
        if not diag:
            notes.append("No diagnostic setting sends blob logs to a Log Analytics workspace; access cannot be reconstructed.")
            return [], [], notes

        client = LogsQueryClient(self.credential)
        query = STORAGE_BLOB_LOGS_QUERY.format(account=posture.resource.name.replace("'", ""))
        try:
            resp = client.query_resource(posture.resource.resource_id, query,
                                         timespan=(since, datetime.now(timezone.utc)))
        except AzureError as exc:
            notes.append(f"Log Analytics query failed: {exc}")
            return [], [], notes
        if resp.status == LogsQueryStatus.PARTIAL:
            notes.append(f"Log Analytics returned partial results: {resp.partial_error}")
            tables = resp.partial_data
        else:
            tables = resp.tables

        events: list[AccessEvent] = []
        for table in tables:
            cols = list(table.columns)
            for row in table.rows:
                r = dict(zip(cols, row))
                auth = r.get("AuthenticationType") or ""
                principal = {
                    "Anonymous": "anonymous",
                    "AccountKey": "account key",
                    "SAS": "SAS token",
                }.get(auth, r.get("RequesterUpn") or r.get("RequesterObjectId") or auth)
                ip = (r.get("CallerIpAddress") or "")
                ip = ip.rsplit(":", 1)[0] if ip.count(":") == 1 else ip  # strip ":port" from IPv4
                key = r.get("ObjectKey") or ""
                key = "/".join(key.split("/")[2:]) or None  # "/account/container/blob" -> "container/blob"
                ts = r["TimeGenerated"]
                events.append(AccessEvent(
                    timestamp=ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc),
                    operation=BLOB_OPERATIONS.get(r.get("OperationName"), r.get("OperationName") or ""),
                    key=key,
                    source_ip=ip or None,
                    principal=principal,
                    status=int(r["StatusCode"]) if r.get("StatusCode") not in (None, "") else None,
                    bytes_sent=int(r.get("ResponseBodySize") or 0),
                    user_agent=r.get("UserAgentHeader"),
                    source="azure-storage-blob-logs",
                ))
        return events, ["Log Analytics: StorageBlobLogs"], notes

    def collect_change_events(self, posture: Posture, since: datetime):
        from azure.core.exceptions import AzureError
        from azure.mgmt.monitor import MonitorManagementClient

        notes: list[str] = []
        changes: list[ChangeEvent] = []
        rg = posture.resource.extra["resource_group"]
        flt = f"eventTimestamp ge '{since.strftime('%Y-%m-%dT%H:%M:%SZ')}' and resourceGroupName eq '{rg}'"
        try:
            monitor = MonitorManagementClient(self.credential, self.subscription_id)
            account_id = posture.resource.resource_id.lower()
            for ev in monitor.activity_logs.list(filter=flt):
                if not (ev.resource_id or "").lower().startswith(account_id):
                    continue
                op = ev.operation_name.value if ev.operation_name else ""
                if not (op.endswith("/write") or op.endswith("/delete")):
                    continue
                if ev.status and ev.status.value not in ("Succeeded",):
                    continue
                changes.append(ChangeEvent(
                    timestamp=ev.event_timestamp,
                    action=op,
                    actor=ev.caller,
                    source_ip=ev.http_request.client_ip_address if ev.http_request else None,
                    detail=ev.resource_id or "",
                ))
        except AzureError as exc:
            notes.append(f"Activity Log lookup failed: {exc}")
        changes.sort(key=lambda c: c.timestamp)
        return changes, notes

    # -- data discovery & external verification ------------------------------------------
    def _account_url(self, posture: Posture) -> str:
        return f"https://{posture.resource.name}.blob.core.windows.net"

    def _container_client(self, posture: Posture, container: str, anonymous: bool):
        from azure.storage.blob import ContainerClient

        return ContainerClient(self._account_url(posture), container,
                               credential=None if anonymous else self.credential)

    def sample_objects(self, posture: Posture, limit: int):
        from azure.core.exceptions import AzureError

        from clouddetectx.sensitive import ObjectRef

        out: list[ObjectRef] = []
        notes: list[str] = []
        self._anonymous_containers: set[str] = set()
        containers = posture.config.get("containers", [])
        # Public containers first: they are what an attacker sees.
        containers = sorted(containers, key=lambda c: c["public_access"] == "None")
        for c in containers:
            if len(out) >= limit:
                break
            name = c["name"]
            for anonymous in (False, True):
                if anonymous and c["public_access"] == "None":
                    break
                try:
                    client = self._container_client(posture, name, anonymous)
                    for blob in client.list_blobs(results_per_page=min(1000, limit)):
                        out.append(ObjectRef(blob.name, blob.size, name))
                        if len(out) >= limit:
                            break
                    if anonymous:
                        self._anonymous_containers.add(name)
                        notes.append(f"Read container '{name}' anonymously (no 'Storage Blob Data Reader' role).")
                    break
                except AzureError as exc:
                    if anonymous or c["public_access"] == "None":
                        notes.append(f"Cannot list container '{name}': {type(exc).__name__}. "
                                     "Grant the 'Storage Blob Data Reader' role to inspect it.")
        return out, notes

    def read_object(self, posture: Posture, obj, max_bytes: int) -> bytes:
        anonymous = obj.container in getattr(self, "_anonymous_containers", set())
        blob = self._container_client(posture, obj.container, anonymous).get_blob_client(obj.key)
        return blob.download_blob(offset=0, length=max_bytes).readall()

    def probe_targets(self, posture: Posture, sample: list):
        from urllib.parse import quote

        from clouddetectx.probe import ProbeTarget

        base = self._account_url(posture)
        targets = [ProbeTarget("anonymous-list", f"Container '{c['name']}'",
                               f"{base}/{quote(c['name'])}?restype=container&comp=list&maxresults=5")
                   for c in posture.config.get("containers", [])[:10]]
        targets += [ProbeTarget("anonymous-read", obj.display, f"{base}/{quote(obj.container)}/{quote(obj.key)}", "HEAD")
                    for obj in sample]
        return targets

    # -- remediation -------------------------------------------------------------------
    def remediate(self, posture: Posture, findings: list[Finding], dry_run: bool, harden: bool):
        from azure.core.exceptions import AzureError
        from azure.mgmt.storage.models import BlobContainer, StorageAccountUpdateParameters

        cfg = posture.config
        rg = posture.resource.extra["resource_group"]
        account = posture.resource.name
        actions: list[RemediationAction] = []

        def run(action: str, detail: str, before: Any, fn):
            if dry_run:
                actions.append(RemediationAction(action, "planned", detail, before))
                return
            try:
                fn()
                actions.append(RemediationAction(action, "applied", detail, before))
            except AzureError as exc:
                actions.append(RemediationAction(action, "failed", f"{detail} -> {exc}", before))

        # 1. Containment: disallowing anonymous access at the account overrides every container instantly.
        if cfg.get("allow_blob_public_access") is not False:
            run("Disable anonymous blob access on the storage account",
                f"allowBlobPublicAccess=false on {account}",
                {"allow_blob_public_access": cfg.get("allow_blob_public_access")},
                lambda: self.storage.storage_accounts.update(
                    rg, account, StorageAccountUpdateParameters(allow_blob_public_access=False)))

        # 2. Make each public container private so the exposure doesn't return if the account flag is flipped back.
        for c in cfg.get("containers", []):
            if c["public_access"] in ("Blob", "Container"):
                run(f"Set container '{c['name']}' to Private",
                    f"publicAccess None (was {c['public_access']})",
                    {"public_access": c["public_access"]},
                    lambda name=c["name"]: self.storage.blob_containers.update(
                        rg, account, name, BlobContainer(public_access="None")))

        if harden:
            if cfg.get("https_only") is False or cfg.get("minimum_tls_version") not in (None, "TLS1_2", "TLS1_3"):
                run("Require HTTPS and TLS 1.2", "enableHttpsTrafficOnly=true, minimumTlsVersion=TLS1_2",
                    {"https_only": cfg.get("https_only"), "minimum_tls_version": cfg.get("minimum_tls_version")},
                    lambda: self.storage.storage_accounts.update(
                        rg, account, StorageAccountUpdateParameters(
                            enable_https_traffic_only=True, minimum_tls_version="TLS1_2")))

        if not actions:
            actions.append(RemediationAction("No change required", "skipped", "No anonymous access to remove."))
        return actions
