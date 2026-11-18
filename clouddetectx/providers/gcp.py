"""Google Cloud Storage provider.

Authentication uses Application Default Credentials:
`gcloud auth application-default login`, GOOGLE_APPLICATION_CREDENTIALS, or the
attached service account on GCE/Cloud Run/GKE.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from typing import Any

from clouddetectx.config import Settings
from clouddetectx.models import AccessEvent, ChangeEvent, Finding, Posture, RemediationAction, Resource, Severity
from clouddetectx.providers.base import ProviderError, StorageProvider

PUBLIC_MEMBERS = {"allUsers": "allUsers (anyone on the internet)",
                  "allAuthenticatedUsers": "allAuthenticatedUsers (any Google account)"}

WRITE_ROLES = ("objectAdmin", "objectCreator", "admin", "legacyBucketWriter", "legacyBucketOwner", "objectUser")

AUDIT_METHODS = {
    "storage.objects.get": "GetObject",
    "storage.objects.list": "ListBucket",
    "storage.objects.create": "PutObject",
    "storage.objects.update": "PutObject",
    "storage.objects.delete": "DeleteObject",
}


def _usage_operation(method: str, operation: str, has_object: bool) -> str:
    op = (operation or "").lower()
    if "list" in op or (method == "GET" and not has_object):
        return "ListBucket"
    return {"GET": "GetObject", "HEAD": "HeadObject", "PUT": "PutObject", "POST": "PutObject",
            "DELETE": "DeleteObject"}.get(method, operation or method)


def parse_usage_log(text: str) -> list[dict]:
    """Parse a Cloud Storage usage log (CSV with a header row)."""
    return list(csv.DictReader(io.StringIO(text)))


def _public_bindings(bindings: list[dict]) -> list[dict]:
    out = []
    for b in bindings:
        members = [m for m in b.get("members", []) if m in PUBLIC_MEMBERS]
        if members:
            out.append({"role": b["role"], "members": members, "condition": b.get("condition")})
    return out


class GCPProvider(StorageProvider):
    name = "gcp"
    display_name = "Google Cloud (Cloud Storage)"

    def __init__(self, settings: Settings, project: str | None = None):
        try:
            from google.auth.exceptions import DefaultCredentialsError
            from google.cloud import storage
        except ImportError as exc:  # pragma: no cover
            raise ProviderError("Google Cloud SDK is not installed. Run: pip install -r requirements.txt") from exc
        self.settings = settings
        try:
            self.client = storage.Client(project=project or settings.gcp_project)
        except DefaultCredentialsError as exc:
            raise ProviderError(
                "No Google Cloud credentials found. Run `gcloud auth application-default login` "
                "or set GOOGLE_APPLICATION_CREDENTIALS."
            ) from exc
        if not self.client.project:
            raise ProviderError("GCP project unknown. Set GOOGLE_CLOUD_PROJECT in .env.")
        self.project = self.client.project
        self._logging = None

    def _logging_client(self):
        if self._logging is None:
            from google.cloud import logging as gcl

            self._logging = gcl.Client(project=self.project)
        return self._logging

    def _call(self, fn, what: str):
        from google.api_core.exceptions import GoogleAPIError
        from google.auth.exceptions import GoogleAuthError

        try:
            return fn()
        except GoogleAuthError as exc:
            raise ProviderError(f"GCP authentication failed ({what}): {exc}") from exc
        except GoogleAPIError as exc:
            raise ProviderError(f"GCP API error ({what}): {exc}") from exc

    def account_label(self) -> str:
        return f"GCP project {self.project}"

    def account_id(self) -> str:
        return self.project

    def list_accounts(self) -> list[dict]:
        from clouddetectx.checks.rest import GcpRest, RestError

        try:
            projects = GcpRest().list("https://cloudresourcemanager.googleapis.com/v1/projects", "projects",
                                      {"filter": "lifecycleState:ACTIVE"})
        except RestError as exc:
            raise ProviderError(f"Cannot list GCP projects: {exc}") from exc
        return [{"id": p["projectId"], "name": p.get("name") or p["projectId"]} for p in projects]

    def for_account(self, account_id: str) -> "GCPProvider":
        if account_id == self.project:
            return self
        return GCPProvider(self.settings, project=account_id)

    def account_checks(self):
        from clouddetectx.checks import gcp_account

        return gcp_account.run(self)

    def analyze_identity(self):
        from clouddetectx.checks import gcp_account

        return gcp_account.analyze_identity(self)

    # -- discovery ----------------------------------------------------------------
    def _resource(self, bucket) -> Resource:
        return Resource(provider="gcp", name=bucket.name, resource_id=f"gs://{bucket.name}",
                        location=(bucket.location or "").lower() or None, account=self.project)

    def list_resources(self) -> list[Resource]:
        return [self._resource(b) for b in self._call(lambda: list(self.client.list_buckets()), "list buckets")]

    def get_resource(self, name: str) -> Resource:
        return self._resource(self._call(lambda: self.client.get_bucket(name), f"get bucket {name}"))

    # -- posture ---------------------------------------------------------------------
    def collect_posture(self, resource: Resource) -> Posture:
        from google.api_core.exceptions import GoogleAPIError

        posture = Posture(resource=resource)
        cfg = posture.config
        try:
            bucket = self.client.get_bucket(resource.name)
        except GoogleAPIError as exc:
            posture.errors["bucket"] = str(exc)
            return posture

        iam_cfg = bucket.iam_configuration
        cfg["public_access_prevention"] = iam_cfg.public_access_prevention
        cfg["uniform_bucket_level_access"] = bool(iam_cfg.uniform_bucket_level_access_enabled)
        cfg["versioning"] = bool(bucket.versioning_enabled)
        cfg["logging"] = bucket.get_logging()
        cfg["retention_policy"] = bool(bucket.retention_period)
        cfg["retention_locked"] = bool(getattr(bucket, "retention_policy_locked", False))
        cfg["default_kms_key"] = bucket.default_kms_key_name
        cfg["encryption_summary"] = {
            "at_rest": "Customer-managed key (Cloud KMS)" if bucket.default_kms_key_name else "Google-managed keys",
            "kms_key": bucket.default_kms_key_name, "bucket_key": None,
            "in_transit_enforced": True,          # the Cloud Storage JSON/XML APIs are HTTPS-only
            "object_lock": cfg["retention_locked"],
        }

        try:
            policy = bucket.get_iam_policy(requested_policy_version=3)
            cfg["iam_bindings"] = [
                {"role": b["role"], "members": sorted(b["members"]), **({"condition": b["condition"]} if b.get("condition") else {})}
                for b in policy.bindings
            ]
            cfg["iam_etag"] = policy.etag
        except GoogleAPIError as exc:
            posture.errors["iam_policy"] = str(exc)
            cfg["iam_bindings"] = []

        cfg["public_acl_entries"] = []
        cfg["public_objects"] = []
        cfg["objects_inspected"] = 0
        if not cfg["uniform_bucket_level_access"]:
            try:
                bucket.acl.reload()
                cfg["public_acl_entries"] = [e for e in bucket.acl if e.get("entity") in PUBLIC_MEMBERS]
            except GoogleAPIError as exc:
                posture.errors["bucket_acl"] = str(exc)
            limit = self.settings.max_objects_to_inspect
            if limit > 0:
                try:
                    for blob in self.client.list_blobs(bucket, max_results=limit, projection="full"):
                        cfg["objects_inspected"] += 1
                        entries = [e for e in (blob.acl or []) if e.get("entity") in PUBLIC_MEMBERS] if blob.acl else []
                        if not entries:
                            blob.acl.reload()
                            entries = [e for e in blob.acl if e.get("entity") in PUBLIC_MEMBERS]
                        if entries:
                            cfg["public_objects"].append({"key": blob.name, "entries": entries})
                except GoogleAPIError as exc:
                    posture.errors["object_acls"] = str(exc)
        return posture

    # -- evaluation ------------------------------------------------------------------------
    def evaluate(self, posture: Posture) -> list[Finding]:
        cfg = posture.config
        findings: list[Finding] = []
        if "bucket" in posture.errors:
            return [Finding("GCP-GCS-000", "Could not read bucket", Severity.INFO, posture.errors["bucket"],
                            "Grant the scanner roles/storage.admin or a custom read role.")]

        pap_enforced = cfg.get("public_access_prevention") == "enforced"
        public_bindings = _public_bindings(cfg.get("iam_bindings", []))
        if public_bindings:
            roles = sorted({b["role"] for b in public_bindings})
            writes = any(any(w in r for w in WRITE_ROLES) for r in roles)
            findings.append(Finding(
                check_id="GCP-GCS-001",
                title="Bucket IAM policy grants public access",
                severity=(Severity.CRITICAL if not pap_enforced else Severity.LOW),
                description=(
                    "IAM grants " + "; ".join(
                        f"{b['role']} to {', '.join(PUBLIC_MEMBERS[m] for m in b['members'])}" for b in public_bindings)
                    + (". Includes write access - anyone can upload or overwrite data." if writes else ".")
                    + (" Currently neutralised by Public Access Prevention." if pap_enforced else "")
                ),
                recommendation="Remove allUsers/allAuthenticatedUsers bindings and enforce Public Access Prevention.",
                exposes_data=not pap_enforced,
                evidence={"bindings": public_bindings},
            ))

        if cfg.get("public_acl_entries"):
            findings.append(Finding(
                check_id="GCP-GCS-002",
                title="Bucket ACL grants public access",
                severity=Severity.HIGH if not pap_enforced else Severity.LOW,
                description=f"Legacy ACL entries: {cfg['public_acl_entries']}.",
                recommendation="Enable uniform bucket-level access, which disables ACLs entirely.",
                exposes_data=not pap_enforced,
                evidence={"entries": cfg["public_acl_entries"]},
            ))

        if cfg.get("public_objects"):
            findings.append(Finding(
                check_id="GCP-GCS-003",
                title="Objects are publicly readable via object ACLs",
                severity=Severity.CRITICAL if not pap_enforced else Severity.LOW,
                description=f"{len(cfg['public_objects'])} of {cfg.get('objects_inspected', 0)} sampled objects have public ACLs.",
                recommendation="Enforce Public Access Prevention and enable uniform bucket-level access.",
                exposes_data=not pap_enforced,
                evidence={"objects": [o["key"] for o in cfg["public_objects"][:50]]},
            ))

        if not pap_enforced:
            findings.append(Finding(
                check_id="GCP-GCS-004",
                title="Public Access Prevention is not enforced",
                severity=Severity.MEDIUM,
                description=(f"publicAccessPrevention is '{cfg.get('public_access_prevention')}'. 'inherited' is only "
                             "safe if the organization policy constraints/storage.publicAccessPrevention is enforced."),
                recommendation="Set publicAccessPrevention=enforced on the bucket or enforce the org policy constraint.",
            ))

        if not cfg.get("uniform_bucket_level_access"):
            findings.append(Finding(
                check_id="GCP-GCS-005",
                title="Uniform bucket-level access is disabled",
                severity=Severity.LOW,
                description="Fine-grained ACLs are active, so individual objects can be made public without IAM changes.",
                recommendation="Enable uniform bucket-level access.",
            ))

        if not cfg.get("logging"):
            findings.append(Finding(
                check_id="GCP-GCS-006",
                title="Usage logging is disabled",
                severity=Severity.MEDIUM,
                description=("Cloud Audit Logs do not record anonymous access to public objects, so without usage "
                             "logs downloads by the public cannot be detected."),
                recommendation="Enable usage logs: gcloud storage buckets update gs://BUCKET --log-bucket=gs://LOG_BUCKET",
            ))

        if not cfg.get("retention_policy"):
            findings.append(Finding("GCP-GCS-009", "No retention policy", Severity.INFO,
                                    "Objects can be deleted at any time by anyone with delete permission.",
                                    "For backups and audit data, set (and optionally lock) a retention policy."))

        if not cfg.get("versioning") and not cfg.get("retention_policy"):
            findings.append(Finding("GCP-GCS-007", "Object versioning is disabled", Severity.LOW,
                                    "Deleted or overwritten objects cannot be recovered.",
                                    "Enable object versioning or soft delete retention."))

        for label, err in posture.errors.items():
            findings.append(Finding("GCP-GCS-000", f"Could not read {label}", Severity.INFO, err[:300],
                                    "Grant the scanner storage.buckets.getIamPolicy and storage.objects.list."))
        return findings

    # -- investigation -------------------------------------------------------------------------
    def collect_access_events(self, posture: Posture, since: datetime):
        events: list[AccessEvent] = []
        sources: list[str] = []
        notes: list[str] = []
        bucket_name = posture.resource.name

        log_cfg = posture.config.get("logging")
        if log_cfg:
            log_bucket = log_cfg["logBucket"]
            prefix = (log_cfg.get("logObjectPrefix") or bucket_name) + "_usage_"
            try:
                files = 0
                for blob in self.client.list_blobs(log_bucket, prefix=prefix):
                    if blob.updated and blob.updated < since:
                        continue
                    if files >= self.settings.max_log_objects:
                        notes.append(f"Stopped after {files} usage log files (CLOUDDETECTX_MAX_LOG_OBJECTS).")
                        break
                    files += 1
                    for row in parse_usage_log(blob.download_as_text()):
                        if row.get("cs_bucket") and row["cs_bucket"] != bucket_name:
                            continue
                        ts = datetime.fromtimestamp(int(row["time_micros"]) / 1_000_000, tz=timezone.utc)
                        if ts < since:
                            continue
                        method = row.get("cs_method", "")
                        events.append(AccessEvent(
                            timestamp=ts,
                            operation=_usage_operation(method, row.get("cs_operation", ""), bool(row.get("cs_object"))),
                            key=row.get("cs_object") or None,
                            source_ip=row.get("c_ip") or None,
                            principal="unknown (usage logs carry no identity)",
                            status=int(row["sc_status"]) if row.get("sc_status", "").isdigit() else None,
                            bytes_sent=int(row.get("sc_bytes") or 0),
                            user_agent=row.get("cs_user_agent") or None,
                            source="gcs-usage-log",
                        ))
                sources.append(f"Usage logs: gs://{log_bucket}/{prefix}* ({files} files)")
            except Exception as exc:  # noqa: BLE001
                notes.append(f"Could not read usage logs from gs://{log_bucket}: {exc}")
        else:
            notes.append("Usage logging is not enabled; anonymous downloads of public objects are not recorded anywhere.")

        # Data Access audit logs: authenticated reads/writes (only if DATA_READ auditing is enabled).
        flt = (
            f'logName="projects/{self.project}/logs/cloudaudit.googleapis.com%2Fdata_access" '
            f'AND resource.type="gcs_bucket" AND resource.labels.bucket_name="{bucket_name}" '
            f'AND timestamp>="{since.strftime("%Y-%m-%dT%H:%M:%SZ")}"'
        )
        try:
            from google.cloud.logging import ASCENDING

            count = 0
            for entry in self._logging_client().list_entries(filter_=flt, order_by=ASCENDING, max_results=50000):
                pp = entry.to_api_repr().get("protoPayload", {})
                method = pp.get("methodName", "")
                meta = pp.get("requestMetadata", {})
                code = (pp.get("status") or {}).get("code", 0)
                resource_name = pp.get("resourceName", "")
                events.append(AccessEvent(
                    timestamp=entry.timestamp,
                    operation=AUDIT_METHODS.get(method, method),
                    key=resource_name.split("/objects/", 1)[1] if "/objects/" in resource_name else None,
                    source_ip=meta.get("callerIp"),
                    principal=(pp.get("authenticationInfo") or {}).get("principalEmail") or "anonymous",
                    status=200 if not code else (403 if code == 7 else 400),
                    user_agent=meta.get("callerSuppliedUserAgent"),
                    source="gcp-data-access-audit-log",
                ))
                count += 1
            sources.append(f"Cloud Audit Logs (Data Access): {count} entries")
            if not count:
                notes.append("No Data Access audit log entries found (DATA_READ auditing may be disabled for Cloud Storage).")
        except Exception as exc:  # noqa: BLE001
            notes.append(f"Could not query Data Access audit logs: {exc}")

        events.sort(key=lambda e: e.timestamp)
        return events, sources, notes

    def collect_change_events(self, posture: Posture, since: datetime):
        notes: list[str] = []
        changes: list[ChangeEvent] = []
        flt = (
            f'logName="projects/{self.project}/logs/cloudaudit.googleapis.com%2Factivity" '
            f'AND resource.type="gcs_bucket" AND resource.labels.bucket_name="{posture.resource.name}" '
            f'AND timestamp>="{since.strftime("%Y-%m-%dT%H:%M:%SZ")}"'
        )
        try:
            from google.cloud.logging import ASCENDING

            for entry in self._logging_client().list_entries(filter_=flt, order_by=ASCENDING, max_results=5000):
                pp = entry.to_api_repr().get("protoPayload", {})
                delta = (pp.get("serviceData") or {}).get("policyDelta") or pp.get("metadata") or {}
                changes.append(ChangeEvent(
                    timestamp=entry.timestamp,
                    action=pp.get("methodName", ""),
                    actor=(pp.get("authenticationInfo") or {}).get("principalEmail"),
                    source_ip=(pp.get("requestMetadata") or {}).get("callerIp"),
                    detail=str(delta)[:500],
                ))
        except Exception as exc:  # noqa: BLE001
            notes.append(f"Could not query Admin Activity audit logs: {exc}")
        return changes, notes

    # -- data discovery & external verification ---------------------------------------------------
    def sample_objects(self, posture: Posture, limit: int):
        from google.api_core.exceptions import GoogleAPIError

        from clouddetectx.sensitive import ObjectRef

        try:
            blobs = self.client.list_blobs(posture.resource.name, max_results=limit)
            return [ObjectRef(b.name, b.size) for b in blobs], []
        except GoogleAPIError as exc:
            raise ProviderError(f"Cannot list objects in {posture.resource.name}: {exc}") from exc

    def read_object(self, posture: Posture, obj, max_bytes: int) -> bytes:
        blob = self.client.bucket(posture.resource.name).blob(obj.key)
        return blob.download_as_bytes(start=0, end=max_bytes - 1)

    def probe_targets(self, posture: Posture, sample: list):
        from urllib.parse import quote

        from clouddetectx.probe import ProbeTarget

        bucket = quote(posture.resource.name)
        targets = [ProbeTarget("anonymous-list", "List bucket contents",
                               f"https://storage.googleapis.com/storage/v1/b/{bucket}/o?maxResults=5")]
        targets += [ProbeTarget("anonymous-read", obj.key, f"https://storage.googleapis.com/{bucket}/{quote(obj.key)}", "HEAD")
                    for obj in sample]
        return targets

    # -- remediation -----------------------------------------------------------------------------
    def remediate(self, posture: Posture, findings: list[Finding], dry_run: bool, harden: bool):
        from google.api_core.exceptions import GoogleAPIError

        cfg = posture.config
        actions: list[RemediationAction] = []
        bucket = self.client.bucket(posture.resource.name)

        def run(action: str, detail: str, before: Any, fn, op: str = "", target: str = ""):
            if dry_run:
                actions.append(RemediationAction(action, "planned", detail, before, op, target))
                return
            try:
                fn()
                actions.append(RemediationAction(action, "applied", detail, before, op, target))
            except GoogleAPIError as exc:
                actions.append(RemediationAction(action, "failed", f"{detail} -> {exc}", before, op, target))

        # 1. Containment: enforced Public Access Prevention blocks allUsers/allAuthenticatedUsers everywhere.
        if cfg.get("public_access_prevention") != "enforced":
            def enforce_pap():
                bucket.reload()
                bucket.iam_configuration.public_access_prevention = "enforced"
                bucket.patch()
            run("Enforce Public Access Prevention", "publicAccessPrevention=enforced",
                {"public_access_prevention": cfg.get("public_access_prevention")}, enforce_pap, "gcs.pap")

        # 2. Remove public members from IAM bindings.
        if _public_bindings(cfg.get("iam_bindings", [])):
            def strip_iam():
                policy = bucket.get_iam_policy(requested_policy_version=3)
                for b in policy.bindings:
                    b["members"] = {m for m in b["members"] if m not in PUBLIC_MEMBERS}
                policy.bindings = [b for b in policy.bindings if b["members"]]
                bucket.set_iam_policy(policy)
            run("Remove allUsers/allAuthenticatedUsers from bucket IAM",
                "storage.buckets.setIamPolicy", cfg.get("iam_bindings"), strip_iam, "gcs.iam")

        # 3. Remove public ACL entries (bucket + sampled objects).
        def revoke(acl):
            acl.reload()
            for entity in (acl.all(), acl.all_authenticated()):
                entity.revoke_read()
                entity.revoke_write()
                entity.revoke_owner()
            acl.save()

        if cfg.get("public_acl_entries"):
            run("Remove public entries from the bucket ACL", "bucket ACL save",
                cfg["public_acl_entries"], lambda: revoke(bucket.acl), "gcs.bucket_acl")
        for obj in cfg.get("public_objects", []):
            run(f"Remove public entries from object ACL: {obj['key']}", "object ACL save",
                obj["entries"], lambda k=obj["key"]: revoke(bucket.blob(k).acl), "gcs.object_acl", obj["key"])

        if harden:
            if not cfg.get("uniform_bucket_level_access"):
                def enable_ubla():
                    bucket.reload()
                    bucket.iam_configuration.uniform_bucket_level_access_enabled = True
                    bucket.patch()
                run("Enable uniform bucket-level access", "Disables all ACLs on the bucket", False, enable_ubla, "gcs.ubla")
            if not cfg.get("versioning"):
                def enable_versioning():
                    bucket.reload()
                    bucket.versioning_enabled = True
                    bucket.patch()
                run("Enable object versioning", "versioning.enabled=true", False, enable_versioning, "gcs.versioning")

        if not actions:
            actions.append(RemediationAction("No change required", "skipped", "No public access to remove."))
        return actions

    def rollback(self, resource: Resource, applied: list[dict], dry_run: bool):
        from google.api_core.exceptions import GoogleAPIError

        bucket = self.client.bucket(resource.name)
        out: list[RemediationAction] = []

        def set_pap(value):
            bucket.reload()
            bucket.iam_configuration.public_access_prevention = value or "inherited"
            bucket.patch()

        def set_iam(bindings):
            policy = bucket.get_iam_policy(requested_policy_version=3)
            policy.bindings = [{"role": b["role"], "members": set(b["members"]),
                                **({"condition": b["condition"]} if b.get("condition") else {})} for b in bindings or []]
            bucket.set_iam_policy(policy)

        def restore_acl(acl, entries):
            acl.reload()
            for e in entries or []:
                entity = acl.all() if e.get("entity") == "allUsers" else acl.all_authenticated()
                {"READER": entity.grant_read, "WRITER": entity.grant_write, "OWNER": entity.grant_owner}.get(
                    e.get("role"), entity.grant_read)()
            acl.save()

        def set_flag(attr, value):
            bucket.reload()
            if attr == "ubla":
                bucket.iam_configuration.uniform_bucket_level_access_enabled = value
            else:
                bucket.versioning_enabled = value
            bucket.patch()

        for a in applied:
            op, before, target = a.get("op"), a.get("before"), a.get("target") or ""
            title = f"Undo: {a.get('action')}"
            fns = {
                "gcs.pap": (lambda b=before: set_pap((b or {}).get("public_access_prevention")), "Restore Public Access Prevention"),
                "gcs.iam": (lambda b=before: set_iam(b), "Restore previous bucket IAM bindings"),
                "gcs.bucket_acl": (lambda b=before: restore_acl(bucket.acl, b), "Restore public bucket ACL entries"),
                "gcs.object_acl": (lambda b=before, k=target: restore_acl(bucket.blob(k).acl, b), f"Restore ACL on {target}"),
                "gcs.ubla": (lambda: set_flag("ubla", False), "Disable uniform bucket-level access (possible for 90 days)"),
                "gcs.versioning": (lambda: set_flag("versioning", False), "Disable object versioning"),
            }
            if op not in fns:
                out.append(RemediationAction(title, "skipped", "No automatic undo for this action.", before, op or "", target))
                continue
            fn, detail = fns[op]
            if dry_run:
                out.append(RemediationAction(title, "planned", detail, before, op, target))
                continue
            try:
                fn()
                out.append(RemediationAction(title, "applied", detail, before, op, target))
            except GoogleAPIError as exc:
                out.append(RemediationAction(title, "failed", f"{detail} -> {exc}", before, op, target))
        return out
