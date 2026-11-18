"""Amazon S3 provider.

Uses the standard boto3 credential chain (environment variables, ~/.aws profiles,
SSO, instance/role credentials). Nothing here is LocalStack-specific.
"""

from __future__ import annotations

import copy
import gzip
import json
import re
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

from clouddetectx.config import Settings
from clouddetectx.models import (
    AccessEvent,
    ChangeEvent,
    Finding,
    Posture,
    RemediationAction,
    Resource,
    Severity,
)
from clouddetectx.providers.base import ProviderError, StorageProvider

ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTHENTICATED_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
PUBLIC_GROUPS = {ALL_USERS: "AllUsers (anyone on the internet)", AUTHENTICATED_USERS: "AuthenticatedUsers (any AWS account)"}

PAB_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")

# Policy condition keys that limit a "Principal: *" statement to a known network or identity.
RESTRICTING_CONDITION_KEYS = {
    "aws:sourceip", "aws:sourcevpc", "aws:sourcevpce", "aws:principalorgid", "aws:principalorgpaths",
    "aws:principalaccount", "aws:principalarn", "aws:sourceaccount", "aws:sourcearn", "aws:sourceorgid",
    "aws:sourceorgpaths", "aws:userid", "aws:username",
}

S3_LOG_OPERATIONS = {
    "REST.GET.OBJECT": "GetObject",
    "REST.HEAD.OBJECT": "HeadObject",
    "REST.GET.BUCKET": "ListBucket",
    "REST.PUT.OBJECT": "PutObject",
    "REST.POST.UPLOAD": "PutObject",
    "REST.COPY.OBJECT": "PutObject",
    "REST.DELETE.OBJECT": "DeleteObject",
    "REST.POST.MULTI_OBJECT_DELETE": "DeleteObject",
    "REST.GET.ACL": "GetBucketAcl",
    "REST.GET.OBJECT_ACL": "GetObjectAcl",
    "REST.GET.BUCKETPOLICY": "GetBucketPolicy",
}

CLOUDTRAIL_DATA_EVENTS = {
    "GetObject", "HeadObject", "ListObjects", "ListObjectsV2", "PutObject", "DeleteObject",
    "DeleteObjects", "CopyObject", "GetObjectAcl", "PutObjectAcl", "CompleteMultipartUpload",
}

CHANGE_EVENT_NAMES = {
    "CreateBucket", "PutBucketAcl", "PutBucketPolicy", "DeleteBucketPolicy",
    "PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock",
    "PutBucketOwnershipControls", "DeleteBucketOwnershipControls",
    "PutBucketLogging", "PutBucketEncryption", "DeleteBucketEncryption",
}

_LOG_TOKEN = re.compile(r'\[[^\]]*\]|"(?:[^"\\]|\\.)*"|\S+')


def _error_code(exc: Exception) -> str:
    return getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)


# --------------------------------------------------------------------------- policy helpers

def _as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _principal_is_public(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return "*" in _as_list(principal.get("AWS"))
    return False


def _has_restricting_condition(statement: dict) -> bool:
    for operator_block in (statement.get("Condition") or {}).values():
        if isinstance(operator_block, dict):
            if any(key.lower() in RESTRICTING_CONDITION_KEYS for key in operator_block):
                return True
    return False


def public_policy_statements(policy: dict | None) -> list[dict]:
    """Allow statements that grant access to everyone without a narrowing condition."""
    if not policy:
        return []
    public = []
    for stmt in _as_list(policy.get("Statement")):
        if stmt.get("Effect") != "Allow":
            continue
        open_principal = _principal_is_public(stmt.get("Principal")) or "NotPrincipal" in stmt
        if open_principal and not _has_restricting_condition(stmt):
            public.append(stmt)
    return public


def tls_enforced(policy: dict | None) -> bool:
    """True if the policy denies requests made without TLS (aws:SecureTransport = false)."""
    for stmt in _as_list((policy or {}).get("Statement")):
        if stmt.get("Effect") != "Deny":
            continue
        for operator, block in (stmt.get("Condition") or {}).items():
            if not operator.lower().startswith("bool") or not isinstance(block, dict):
                continue
            for key, value in block.items():
                if key.lower() == "aws:securetransport" and str(_as_list(value)[0]).lower() == "false":
                    return True
    return False


_ACCOUNT_IN_ARN = re.compile(r"^arn:aws[\w-]*:(?:iam|sts)::(\d{12}):")


def _principal_accounts(principal: Any) -> set[str]:
    """12-digit account IDs named by an AWS principal (plain IDs or IAM/STS ARNs)."""
    out = set()
    if isinstance(principal, dict):
        for value in _as_list(principal.get("AWS")):
            value = str(value)
            if re.fullmatch(r"\d{12}", value):
                out.add(value)
            elif m := _ACCOUNT_IN_ARN.match(value):
                out.add(m.group(1))
    return out


def cross_account_statements(policy: dict | None, own_account: str | None) -> list[dict]:
    """Allow statements that grant access to other AWS accounts without an organisation condition."""
    if not policy or not own_account:
        return []
    out = []
    for stmt in _as_list(policy.get("Statement")):
        if stmt.get("Effect") != "Allow" or _has_restricting_condition(stmt):
            continue
        others = sorted(_principal_accounts(stmt.get("Principal")) - {own_account})
        if others:
            out.append({"accounts": others, "actions": _as_list(stmt.get("Action")), "sid": stmt.get("Sid")})
    return out


ENCRYPTION_NAMES = {"AES256": "SSE-S3 (S3-managed keys)", "aws:kms": "SSE-KMS", "aws:kms:dsse": "DSSE-KMS"}


def encryption_summary(cfg: dict) -> dict:
    rule = (cfg.get("encryption") or [{}])[0]
    default = rule.get("ApplyServerSideEncryptionByDefault") or {}
    algo = default.get("SSEAlgorithm")
    return {
        "at_rest": ENCRYPTION_NAMES.get(algo, algo) if algo else None,
        "kms_key": default.get("KMSMasterKeyID"),
        "bucket_key": rule.get("BucketKeyEnabled"),
        "in_transit_enforced": tls_enforced(cfg.get("policy")),
        "object_lock": cfg.get("object_lock"),
        "mfa_delete": cfg.get("mfa_delete"),
    }


def _public_grants(grants: list[dict]) -> list[dict]:
    return [g for g in grants or [] if g.get("Grantee", {}).get("URI") in PUBLIC_GROUPS]


# --------------------------------------------------------------------------- log parsers

def parse_s3_access_log_line(line: str) -> dict | None:
    """Parse one S3 server access log record (documented space-delimited format)."""
    tokens = _LOG_TOKEN.findall(line.strip())
    if len(tokens) < 18:
        return None
    try:
        ts = datetime.strptime(tokens[2].strip("[]"), "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None

    def val(i: int) -> str | None:
        v = tokens[i].strip('"') if i < len(tokens) else "-"
        return None if v == "-" else v

    def num(i: int) -> int | None:
        v = val(i)
        return int(v) if v and v.isdigit() else None

    return {
        "timestamp": ts,
        "bucket": val(1),
        "remote_ip": val(3),
        "requester": val(4),
        "operation": val(6) or "",
        "key": val(7),
        "status": num(9),
        "bytes_sent": num(11) or 0,
        "user_agent": val(16),
    }


def _access_event_from_s3_log(rec: dict) -> AccessEvent:
    op = rec["operation"]
    return AccessEvent(
        timestamp=rec["timestamp"],
        operation=S3_LOG_OPERATIONS.get(op, op),
        key=rec["key"],
        source_ip=rec["remote_ip"],
        principal=rec["requester"] or "anonymous",
        status=rec["status"],
        bytes_sent=rec["bytes_sent"],
        user_agent=rec["user_agent"],
        source="s3-server-access-log",
    )


def _access_event_from_cloudtrail(rec: dict) -> AccessEvent:
    identity = rec.get("userIdentity") or {}
    anonymous = identity.get("accountId") == "ANONYMOUS_PRINCIPAL" or identity.get("type") == "AnonymousUser"
    name = rec.get("eventName", "")
    status = 200 if not rec.get("errorCode") else (403 if "AccessDenied" in rec.get("errorCode", "") else 400)
    extra = rec.get("additionalEventData") or {}
    return AccessEvent(
        timestamp=datetime.fromisoformat(rec["eventTime"].replace("Z", "+00:00")),
        operation={"ListObjects": "ListBucket", "ListObjectsV2": "ListBucket"}.get(name, name),
        key=(rec.get("requestParameters") or {}).get("key"),
        source_ip=rec.get("sourceIPAddress"),
        principal="anonymous" if anonymous else (identity.get("arn") or identity.get("principalId")),
        status=status,
        bytes_sent=int(extra.get("bytesTransferredOut") or 0),
        user_agent=rec.get("userAgent"),
        source="cloudtrail-data-events",
    )


# --------------------------------------------------------------------------- provider

class AWSProvider(StorageProvider):
    name = "aws"
    display_name = "Amazon Web Services (S3)"

    def __init__(self, settings: Settings, session=None):
        try:
            import boto3
            from botocore.config import Config
        except ImportError as exc:  # pragma: no cover
            raise ProviderError("boto3 is not installed. Run: pip install -r requirements.txt") from exc

        self.settings = settings
        self._boto_config = Config(retries={"max_attempts": 8, "mode": "adaptive"}, connect_timeout=10, read_timeout=60,
                                   max_pool_connections=max(10, settings.scan_workers * 2))
        from botocore.exceptions import ProfileNotFound

        try:
            self.session = session or boto3.session.Session(profile_name=settings.aws_profile, region_name=settings.aws_region)
        except ProfileNotFound as exc:
            raise ProviderError(f"{exc}. Check AWS_PROFILE in .env or run `aws configure list-profiles`.") from exc
        self._clients: dict[tuple[str, str], Any] = {}
        self._client_lock = threading.Lock()
        self._identity: dict | None = None
        self._account_pab: dict | None | bool = False  # False = not fetched yet
        self._cloudfront: list | None = None

    # -- clients -------------------------------------------------------------
    def _client(self, service: str, region: str | None = None):
        region = region or self.session.region_name or "us-east-1"
        key = (service, region)
        with self._client_lock:     # boto3 sessions are not thread-safe; clients are
            if key not in self._clients:
                self._clients[key] = self.session.client(service, region_name=region, config=self._boto_config)
            return self._clients[key]

    def _identity_info(self) -> dict:
        if self._identity is None:
            from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

            try:
                self._identity = self._client("sts").get_caller_identity()
            except NoCredentialsError as exc:
                raise ProviderError(
                    "No AWS credentials found. Run `aws configure` or `aws sso login`, "
                    "or set AWS_PROFILE in .env."
                ) from exc
            except (ClientError, BotoCoreError) as exc:
                raise ProviderError(f"AWS authentication failed: {exc}") from exc
        return self._identity

    def account_label(self) -> str:
        ident = self._identity_info()
        return f"AWS account {ident['Account']} as {ident['Arn']}"

    def account_id(self) -> str:
        return self._identity_info()["Account"]

    # -- multi-account (AWS Organizations) ------------------------------------------
    def list_accounts(self) -> list[dict]:
        from botocore.exceptions import BotoCoreError, ClientError

        try:
            out = []
            for page in self._client("organizations", "us-east-1").get_paginator("list_accounts").paginate():
                out += [{"id": a["Id"], "name": a.get("Name") or a["Id"]} for a in page.get("Accounts", [])
                        if a.get("Status", "ACTIVE") == "ACTIVE"]
            return out
        except (ClientError, BotoCoreError) as exc:
            raise ProviderError(
                f"Cannot list AWS Organizations accounts ({_error_code(exc)}). Run from the management account or a "
                "delegated administrator with organizations:ListAccounts.") from exc

    def for_account(self, account_id: str) -> "AWSProvider":
        if account_id == self.account_id():
            return self
        role = self.settings.aws_org_role
        if not role:
            raise ProviderError("Set 'Member-account role' (Settings > AWS) to scan other accounts, e.g. a read-only "
                                "role named CloudDetectXAudit with the SecurityAudit policy in every member account.")
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError

        try:
            creds = self._client("sts").assume_role(
                RoleArn=f"arn:aws:iam::{account_id}:role/{role}", RoleSessionName="clouddetectx",
                DurationSeconds=3600)["Credentials"]
        except (ClientError, BotoCoreError) as exc:
            raise ProviderError(f"Cannot assume role {role} in account {account_id}: {_error_code(exc)}") from exc
        session = boto3.session.Session(aws_access_key_id=creds["AccessKeyId"],
                                        aws_secret_access_key=creds["SecretAccessKey"],
                                        aws_session_token=creds["SessionToken"],
                                        region_name=self.session.region_name)
        return AWSProvider(self.settings, session=session)

    def account_checks(self):
        from clouddetectx.checks import aws_account

        return aws_account.run(self)

    # -- identity (IAM) -------------------------------------------------------------
    def analyze_identity(self):
        from botocore.exceptions import BotoCoreError, ClientError

        from clouddetectx.iam import IamReport, build_principals, evaluate

        account = self._identity_info()["Account"]
        iam = self._client("iam", "us-east-1")
        details: dict[str, list] = {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
        try:
            for page in iam.get_paginator("get_account_authorization_details").paginate(
                    Filter=["User", "Group", "Role", "LocalManagedPolicy", "AWSManagedPolicy"]):
                for key in details:
                    details[key] += page.get(key, [])
        except (ClientError, BotoCoreError) as exc:
            raise ProviderError(
                "IAM analysis needs iam:GetAccountAuthorizationDetails (part of the SecurityAudit policy): "
                f"{_error_code(exc)}") from exc

        principals, skipped = build_principals(details)
        notes: list[str] = []
        now = datetime.now(timezone.utc)
        for p in [x for x in principals if x.kind == "user"][:1000]:
            try:
                keys = iam.list_access_keys(UserName=p.name).get("AccessKeyMetadata", [])
                p.keys = [{"id_suffix": k["AccessKeyId"][-4:], "status": k["Status"],
                           "age_days": (now - k["CreateDate"]).days} for k in keys]
                p.mfa = bool(iam.list_mfa_devices(UserName=p.name).get("MFADevices"))
                try:
                    iam.get_login_profile(UserName=p.name)
                    p.console = True
                except ClientError as exc:
                    if _error_code(exc) != "NoSuchEntity":
                        raise
                    p.console = False
            except (ClientError, BotoCoreError) as exc:
                notes.append(f"Could not read credentials for user {p.name}: {_error_code(exc)}")
        notes.append("Static analysis of identity policies: permission boundaries, SCPs, session policies and "
                     "condition values are not evaluated. Resource policies are checked per bucket.")
        return IamReport(account, principals, evaluate(principals), notes, skipped)

    # -- discovery -------------------------------------------------------------
    def _bucket_region(self, bucket: str) -> str:
        loc = self._client("s3", "us-east-1").get_bucket_location(Bucket=bucket).get("LocationConstraint")
        return {None: "us-east-1", "": "us-east-1", "EU": "eu-west-1"}.get(loc, loc)

    def _resource(self, bucket: str, region: str | None) -> Resource:
        return Resource(provider="aws", name=bucket, resource_id=f"arn:aws:s3:::{bucket}", location=region,
                        account=self._identity_info()["Account"])

    def list_resources(self) -> list[Resource]:
        self._identity_info()
        s3 = self._client("s3", "us-east-1")
        resources = []
        for page in s3.get_paginator("list_buckets").paginate():
            for b in page.get("Buckets", []):
                resources.append(self._resource(b["Name"], b.get("BucketRegion")))
        return resources

    def get_resource(self, name: str) -> Resource:
        self._identity_info()
        from botocore.exceptions import ClientError

        try:
            return self._resource(name, self._bucket_region(name))
        except ClientError as exc:
            raise ProviderError(f"Cannot access bucket '{name}': {_error_code(exc)}") from exc

    # -- posture ---------------------------------------------------------------
    def _account_public_access_block(self) -> dict | None:
        if self._account_pab is False:
            from botocore.exceptions import BotoCoreError, ClientError

            try:
                resp = self._client("s3control").get_public_access_block(AccountId=self._identity_info()["Account"])
                self._account_pab = resp["PublicAccessBlockConfiguration"]
            except (ClientError, BotoCoreError):
                self._account_pab = None
        return self._account_pab  # type: ignore[return-value]

    def collect_posture(self, resource: Resource) -> Posture:
        from botocore.exceptions import ClientError

        bucket = resource.name
        posture = Posture(resource=resource)
        cfg = posture.config
        try:
            if not resource.location:
                resource.location = self._bucket_region(bucket)
        except ClientError as exc:
            posture.errors["location"] = _error_code(exc)
        s3 = self._client("s3", resource.location)

        def fetch(label: str, fn, missing_codes: tuple[str, ...] = ()):
            try:
                return fn()
            except ClientError as exc:
                code = _error_code(exc)
                if code not in missing_codes:
                    posture.errors[label] = code
                return None

        acl = fetch("acl", lambda: s3.get_bucket_acl(Bucket=bucket))
        cfg["acl_owner"] = (acl or {}).get("Owner")
        cfg["acl_grants"] = (acl or {}).get("Grants", [])

        policy = fetch("policy", lambda: s3.get_bucket_policy(Bucket=bucket), ("NoSuchBucketPolicy",))
        cfg["policy"] = json.loads(policy["Policy"]) if policy else None
        cfg["account_id"] = self._identity_info()["Account"]

        status = fetch("policy_status", lambda: s3.get_bucket_policy_status(Bucket=bucket), ("NoSuchBucketPolicy",))
        cfg["policy_is_public"] = (status or {}).get("PolicyStatus", {}).get("IsPublic")

        pab = fetch("public_access_block", lambda: s3.get_public_access_block(Bucket=bucket),
                    ("NoSuchPublicAccessBlockConfiguration",))
        cfg["public_access_block"] = (pab or {}).get("PublicAccessBlockConfiguration")
        cfg["account_public_access_block"] = self._account_public_access_block()

        own = fetch("ownership", lambda: s3.get_bucket_ownership_controls(Bucket=bucket),
                    ("OwnershipControlsNotFoundError",))
        rules = (own or {}).get("OwnershipControls", {}).get("Rules", [])
        cfg["object_ownership"] = rules[0]["ObjectOwnership"] if rules else None

        enc = fetch("encryption", lambda: s3.get_bucket_encryption(Bucket=bucket),
                    ("ServerSideEncryptionConfigurationNotFoundError",))
        cfg["encryption"] = (enc or {}).get("ServerSideEncryptionConfiguration", {}).get("Rules")

        ver = fetch("versioning", lambda: s3.get_bucket_versioning(Bucket=bucket))
        cfg["versioning"] = (ver or {}).get("Status", "Disabled")

        log = fetch("logging", lambda: s3.get_bucket_logging(Bucket=bucket))
        cfg["logging"] = (log or {}).get("LoggingEnabled")
        cfg["mfa_delete"] = (ver or {}).get("MFADelete") == "Enabled"

        lock = fetch("object_lock", lambda: s3.get_object_lock_configuration(Bucket=bucket),
                     ("ObjectLockConfigurationNotFoundError", "NoSuchObjectLockConfiguration"))
        cfg["object_lock"] = ((lock or {}).get("ObjectLockConfiguration") or {}).get("ObjectLockEnabled") == "Enabled"
        cfg["access_points"] = self._access_points(bucket, resource.location, posture)
        cfg["cloudfront"] = self._cloudfront_origins(bucket, posture)
        cfg["encryption_summary"] = encryption_summary(cfg)

        cfg["public_objects"] = []
        cfg["objects_inspected"] = 0
        limit = self.settings.max_objects_to_inspect
        if limit > 0 and cfg["object_ownership"] != "BucketOwnerEnforced":
            listing = fetch("list_objects", lambda: s3.list_objects_v2(Bucket=bucket, MaxKeys=limit))
            for obj in (listing or {}).get("Contents", []):
                cfg["objects_inspected"] += 1
                oacl = fetch(f"object_acl:{obj['Key']}", lambda k=obj["Key"]: s3.get_object_acl(Bucket=bucket, Key=k))
                if oacl and _public_grants(oacl.get("Grants", [])):
                    cfg["public_objects"].append({"key": obj["Key"], "owner": oacl.get("Owner"), "grants": oacl["Grants"]})
            cfg["objects_truncated"] = bool((listing or {}).get("IsTruncated"))
        return posture

    def _access_points(self, bucket: str, region: str | None, posture: Posture) -> list[dict]:
        from botocore.exceptions import BotoCoreError, ClientError

        out = []
        try:
            ctl = self._client("s3control", region)
            account = self.account_id()
            for ap in ctl.list_access_points(AccountId=account, Bucket=bucket).get("AccessPointList", []):
                status = {}
                try:
                    status = ctl.get_access_point_policy_status(AccountId=account, Name=ap["Name"]).get("PolicyStatus", {})
                except ClientError as exc:
                    if _error_code(exc) not in ("NoSuchAccessPointPolicy",):
                        raise
                detail = ctl.get_access_point(AccountId=account, Name=ap["Name"])
                out.append({"name": ap["Name"], "network_origin": ap.get("NetworkOrigin"),
                            "policy_is_public": bool(status.get("IsPublic")),
                            "block_public_access": detail.get("PublicAccessBlockConfiguration") or {}})
        except (ClientError, BotoCoreError) as exc:
            posture.errors["access_points"] = _error_code(exc)
        return out

    def _cloudfront_origins(self, bucket: str, posture: Posture) -> list[dict]:
        """CloudFront distributions whose origin is this bucket, and whether they use OAC/OAI."""
        from botocore.exceptions import BotoCoreError, ClientError

        if self._cloudfront is None:
            dists = []
            try:
                for page in self._client("cloudfront", "us-east-1").get_paginator("list_distributions").paginate():
                    dists += (page.get("DistributionList") or {}).get("Items", []) or []
            except (ClientError, BotoCoreError) as exc:
                posture.errors["cloudfront"] = _error_code(exc)
            self._cloudfront = dists
        out = []
        prefixes = (f"{bucket}.s3.", f"{bucket}.s3-")
        for d in self._cloudfront:
            for o in (d.get("Origins") or {}).get("Items", []) or []:
                domain = (o.get("DomainName") or "").lower()
                if not domain.startswith(prefixes):
                    continue
                oai = ((o.get("S3OriginConfig") or {}).get("OriginAccessIdentity") or "").strip()
                out.append({"distribution": d.get("Id"), "domain": d.get("DomainName"), "origin": domain,
                            "protected": bool(o.get("OriginAccessControlId") or oai),
                            "website_endpoint": "s3-website" in domain})
        return out

    # -- evaluation --------------------------------------------------------------
    @staticmethod
    def _pab(cfg: dict, flag: str) -> bool:
        return bool((cfg.get("public_access_block") or {}).get(flag)) or bool(
            (cfg.get("account_public_access_block") or {}).get(flag)
        )

    def evaluate(self, posture: Posture) -> list[Finding]:
        cfg = posture.config
        findings: list[Finding] = []
        ignore_acls = self._pab(cfg, "IgnorePublicAcls")
        restrict_policy = self._pab(cfg, "RestrictPublicBuckets")
        acls_disabled = cfg.get("object_ownership") == "BucketOwnerEnforced"

        # Bucket ACL
        public_grants = _public_grants(cfg.get("acl_grants", []))
        if public_grants:
            perms = sorted({g["Permission"] for g in public_grants})
            groups = sorted({PUBLIC_GROUPS[g["Grantee"]["URI"]] for g in public_grants})
            effective = not ignore_acls and not acls_disabled
            writes = any(p in ("WRITE", "WRITE_ACP", "FULL_CONTROL") for p in perms)
            findings.append(Finding(
                check_id="AWS-S3-001",
                title="Bucket ACL grants public access",
                severity=(Severity.CRITICAL if writes else Severity.HIGH) if effective else Severity.LOW,
                description=(
                    f"The bucket ACL grants {', '.join(perms)} to {', '.join(groups)}. "
                    + ("READ lets anyone list every object name in the bucket." if "READ" in perms else "")
                    + ("" if effective else " Currently neutralised by Block Public Access / disabled ACLs.")
                ),
                recommendation="Remove AllUsers/AuthenticatedUsers grants and set Object Ownership to BucketOwnerEnforced.",
                exposes_data=effective,
                evidence={"grants": public_grants},
            ))

        # Object ACLs
        public_objects = cfg.get("public_objects", [])
        if public_objects:
            effective = not ignore_acls and not acls_disabled
            findings.append(Finding(
                check_id="AWS-S3-002",
                title="Objects are publicly readable via object ACLs",
                severity=Severity.CRITICAL if effective else Severity.LOW,
                description=(
                    f"{len(public_objects)} of {cfg.get('objects_inspected', 0)} inspected objects have a public ACL"
                    + (" (only the first objects were sampled)." if cfg.get("objects_truncated") else ".")
                ),
                recommendation="Enable Block Public Access (IgnorePublicAcls) and reset object ACLs to private.",
                exposes_data=effective,
                evidence={"objects": [o["key"] for o in public_objects[:50]]},
            ))

        # Bucket policy
        stmts = public_policy_statements(cfg.get("policy"))
        if stmts or cfg.get("policy_is_public"):
            effective = not restrict_policy
            actions = sorted({a for s in stmts for a in _as_list(s.get("Action"))})
            findings.append(Finding(
                check_id="AWS-S3-003",
                title="Bucket policy allows public access",
                severity=Severity.CRITICAL if effective else Severity.LOW,
                description=(
                    f"The bucket policy grants {', '.join(actions) or 'access'} to Principal '*' with no "
                    "IP/VPC/organisation condition." + ("" if effective else " Currently neutralised by RestrictPublicBuckets.")
                ),
                recommendation="Remove the public statements or restrict them with aws:SourceVpce / aws:PrincipalOrgID conditions.",
                exposes_data=effective,
                evidence={"statements": stmts, "aws_policy_status_is_public": cfg.get("policy_is_public")},
            ))

        # Block Public Access
        missing = [f for f in PAB_FLAGS if not self._pab(cfg, f)]
        if missing:
            findings.append(Finding(
                check_id="AWS-S3-004",
                title="S3 Block Public Access is not fully enabled",
                severity=Severity.MEDIUM,
                description=f"Disabled at both bucket and account level: {', '.join(missing)}.",
                recommendation="Enable all four Block Public Access settings on the bucket and, ideally, the whole account.",
                evidence={"bucket": cfg.get("public_access_block"), "account": cfg.get("account_public_access_block")},
            ))

        if not cfg.get("logging"):
            findings.append(Finding(
                check_id="AWS-S3-005",
                title="Server access logging is disabled",
                severity=Severity.MEDIUM,
                description="Without access logs (or CloudTrail S3 data events) you cannot prove whether exposed data was downloaded.",
                recommendation="Enable S3 server access logging or CloudTrail data events for this bucket.",
            ))

        if not cfg.get("encryption") and "encryption" not in posture.errors:
            findings.append(Finding(
                check_id="AWS-S3-006",
                title="Default encryption not configured",
                severity=Severity.LOW,
                description="No default server-side encryption configuration was returned.",
                recommendation="Enable SSE-S3 or SSE-KMS default encryption.",
            ))

        if "policy" not in posture.errors and not tls_enforced(cfg.get("policy")):
            findings.append(Finding(
                check_id="AWS-S3-008",
                title="Encryption in transit (HTTPS) is not enforced",
                severity=Severity.LOW,
                description="The bucket policy has no statement denying requests where aws:SecureTransport is false, "
                            "so clients can read and write data over plain HTTP.",
                recommendation="Add a Deny statement for s3:* on the bucket and its objects with the condition "
                               '{"Bool": {"aws:SecureTransport": "false"}} (applied by remediation with --harden).',
            ))

        cross = cross_account_statements(cfg.get("policy"), cfg.get("account_id"))
        if cross:
            accounts = sorted({a for c in cross for a in c["accounts"]})
            actions = sorted({a for c in cross for a in c["actions"]})
            writes = any(a in ("*", "s3:*") or a.startswith(("s3:Put", "s3:Delete")) for a in actions)
            findings.append(Finding(
                check_id="AWS-S3-009",
                title="Bucket policy grants access to other AWS accounts",
                severity=Severity.HIGH if writes else Severity.MEDIUM,
                description=f"{len(accounts)} external account(s) ({', '.join(accounts[:5])}"
                            f"{'...' if len(accounts) > 5 else ''}) are granted {', '.join(actions[:6]) or 'access'} "
                            "with no organisation condition.",
                recommendation="Confirm each external account is a trusted partner. Otherwise remove it, or limit the "
                               "statement with aws:PrincipalOrgID and the narrowest actions possible.",
                evidence={"statements": cross},
            ))

        public_aps = [a for a in cfg.get("access_points", [])
                      if a["policy_is_public"] and a.get("network_origin") == "Internet"
                      and not (a.get("block_public_access") or {}).get("RestrictPublicBuckets")]
        if public_aps:
            effective = not restrict_policy
            findings.append(Finding(
                check_id="AWS-S3-010",
                title="Access point policy allows public access",
                severity=Severity.CRITICAL if effective else Severity.LOW,
                description=f"{len(public_aps)} internet-facing access point(s) have a public policy: "
                            + ", ".join(a["name"] for a in public_aps[:5])
                            + ("." if effective else ". Currently neutralised by RestrictPublicBuckets."),
                recommendation="Restrict the access point policy, set its Block Public Access, or make it VPC-only.",
                exposes_data=effective,
                evidence={"access_points": public_aps},
            ))

        unprotected = [c for c in cfg.get("cloudfront", []) if not c["protected"]]
        if unprotected:
            findings.append(Finding(
                check_id="AWS-S3-011",
                title="Served through CloudFront without origin access control",
                severity=Severity.MEDIUM,
                description=f"{len(unprotected)} CloudFront distribution(s) read this bucket without OAC/OAI, which "
                            "only works if the bucket itself is public, so the CDN can be bypassed: "
                            + ", ".join(c["distribution"] or "?" for c in unprotected[:5]) + ".",
                recommendation="Add an Origin Access Control to the distribution, allow only it in the bucket policy, "
                               "and turn Block Public Access back on.",
                evidence={"distributions": unprotected},
            ))

        if not cfg.get("object_lock") and not cfg.get("mfa_delete"):
            findings.append(Finding(
                check_id="AWS-S3-012",
                title="No Object Lock or MFA Delete",
                severity=Severity.INFO,
                description="Someone with write access (or stolen credentials) can permanently delete objects and versions.",
                recommendation="For backups and audit data, enable Object Lock (new buckets) or MFA Delete.",
            ))

        if cfg.get("versioning") != "Enabled":
            findings.append(Finding(
                check_id="AWS-S3-007",
                title="Versioning is not enabled",
                severity=Severity.LOW,
                description="Objects overwritten or deleted by an attacker with write access cannot be recovered.",
                recommendation="Enable bucket versioning (and consider MFA delete / Object Lock).",
            ))

        for label, code in posture.errors.items():
            if not label.startswith("object_acl:"):
                findings.append(Finding(
                    check_id="AWS-S3-000",
                    title=f"Could not read {label}",
                    severity=Severity.INFO,
                    description=f"API returned {code}; this check was skipped.",
                    recommendation="Grant the scanner s3:Get* permissions on this bucket.",
                ))
        return findings

    # -- investigation -------------------------------------------------------------
    def collect_access_events(self, posture: Posture, since: datetime):
        events: list[AccessEvent] = []
        sources: list[str] = []
        notes: list[str] = []
        bucket = posture.resource.name

        logging_cfg = posture.config.get("logging")
        if logging_cfg:
            target, prefix = logging_cfg["TargetBucket"], logging_cfg.get("TargetPrefix", "")
            try:
                found, files = self._read_server_access_logs(bucket, target, prefix, since, logging_cfg)
                events.extend(found)
                sources.append(f"S3 server access logs: s3://{target}/{prefix} ({files} files)")
            except Exception as exc:  # noqa: BLE001 - surface any read failure as a note
                notes.append(f"Could not read server access logs from s3://{target}/{prefix}: {_error_code(exc)}")
        else:
            notes.append("Server access logging is not enabled on this bucket.")

        if self.settings.aws_cloudtrail_bucket:
            try:
                found, files = self._read_cloudtrail_data_events(bucket, since)
                events.extend(found)
                sources.append(f"CloudTrail data events: s3://{self.settings.aws_cloudtrail_bucket} ({files} files)")
            except Exception as exc:  # noqa: BLE001
                notes.append(f"Could not read CloudTrail logs: {_error_code(exc)}")
        else:
            notes.append("CLOUDDETECTX_AWS_CLOUDTRAIL_BUCKET not set; CloudTrail S3 data events were not searched.")

        events.sort(key=lambda e: e.timestamp)
        return events, sources, notes

    def _read_server_access_logs(self, bucket, target, prefix, since, logging_cfg):
        s3 = self._client("s3", self._bucket_region(target))
        kwargs: dict[str, Any] = {"Bucket": target, "Prefix": prefix}
        if "PartitionedPrefix" not in (logging_cfg.get("TargetObjectKeyFormat") or {}):
            # SimplePrefix keys are "<prefix>YYYY-mm-dd-HH-MM-SS-<id>", so we can skip older files.
            kwargs["StartAfter"] = prefix + since.strftime("%Y-%m-%d")
        events, files = [], 0
        for page in s3.get_paginator("list_objects_v2").paginate(**kwargs):
            for obj in page.get("Contents", []):
                if obj["LastModified"] < since:
                    continue
                if files >= self.settings.max_log_objects:
                    return events, files
                files += 1
                body = s3.get_object(Bucket=target, Key=obj["Key"])["Body"].read().decode("utf-8", "replace")
                for line in body.splitlines():
                    rec = parse_s3_access_log_line(line)
                    if rec and rec["bucket"] == bucket and rec["timestamp"] >= since:
                        events.append(_access_event_from_s3_log(rec))
        return events, files

    def _read_cloudtrail_data_events(self, bucket, since):
        trail_bucket = self.settings.aws_cloudtrail_bucket
        s3 = self._client("s3", self._bucket_region(trail_bucket))
        base = self.settings.aws_cloudtrail_prefix
        if base and not base.endswith("/"):
            base += "/"
        base += f"AWSLogs/{self._identity_info()['Account']}/CloudTrail/"
        regions = [
            p["Prefix"]
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=trail_bucket, Prefix=base, Delimiter="/")
            for p in page.get("CommonPrefixes", [])
        ]
        events, files = [], 0
        day = since.date()
        today = datetime.now(timezone.utc).date()
        while day <= today:
            for region_prefix in regions:
                day_prefix = f"{region_prefix}{day:%Y/%m/%d}/"
                for page in s3.get_paginator("list_objects_v2").paginate(Bucket=trail_bucket, Prefix=day_prefix):
                    for obj in page.get("Contents", []):
                        if files >= self.settings.max_log_objects:
                            return events, files
                        files += 1
                        raw = s3.get_object(Bucket=trail_bucket, Key=obj["Key"])["Body"].read()
                        if obj["Key"].endswith(".gz"):
                            raw = gzip.decompress(raw)
                        for rec in json.loads(raw).get("Records", []):
                            if (
                                rec.get("eventSource") == "s3.amazonaws.com"
                                and rec.get("eventName") in CLOUDTRAIL_DATA_EVENTS
                                and (rec.get("requestParameters") or {}).get("bucketName") == bucket
                            ):
                                ev = _access_event_from_cloudtrail(rec)
                                if ev.timestamp >= since:
                                    events.append(ev)
            day += timedelta(days=1)
        return events, files

    def collect_change_events(self, posture: Posture, since: datetime):
        from botocore.exceptions import BotoCoreError, ClientError

        notes: list[str] = []
        changes: list[ChangeEvent] = []
        # CloudTrail event history keeps 90 days of management events, without needing a trail.
        start = max(since, datetime.now(timezone.utc) - timedelta(days=90))
        regions = {posture.resource.location or "us-east-1", "us-east-1"}
        seen = set()
        for region in regions:
            try:
                ct = self._client("cloudtrail", region)
                pages = ct.get_paginator("lookup_events").paginate(
                    LookupAttributes=[{"AttributeKey": "ResourceName", "AttributeValue": posture.resource.name}],
                    StartTime=start,
                )
                for page in pages:
                    for ev in page.get("Events", []):
                        if ev["EventName"] not in CHANGE_EVENT_NAMES or ev["EventId"] in seen:
                            continue
                        seen.add(ev["EventId"])
                        detail = json.loads(ev.get("CloudTrailEvent", "{}"))
                        changes.append(ChangeEvent(
                            timestamp=ev["EventTime"],
                            action=ev["EventName"],
                            actor=(detail.get("userIdentity") or {}).get("arn") or ev.get("Username"),
                            source_ip=detail.get("sourceIPAddress"),
                            detail=json.dumps(detail.get("requestParameters") or {}, default=str)[:500],
                        ))
            except (ClientError, BotoCoreError) as exc:
                notes.append(f"CloudTrail event history lookup failed in {region}: {_error_code(exc)}")
            except Exception as exc:  # noqa: BLE001 - never let change history abort an investigation
                notes.append(f"CloudTrail event history unavailable in {region}: {exc}")
        changes.sort(key=lambda c: c.timestamp)
        return changes, notes

    # -- data discovery & external verification ----------------------------------------
    def sample_objects(self, posture: Posture, limit: int):
        from botocore.exceptions import ClientError

        from clouddetectx.sensitive import ObjectRef

        s3 = self._client("s3", posture.resource.location)
        out: list[ObjectRef] = []
        try:
            for page in s3.get_paginator("list_objects_v2").paginate(
                    Bucket=posture.resource.name, PaginationConfig={"PageSize": min(1000, limit)}):
                for obj in page.get("Contents", []):
                    out.append(ObjectRef(obj["Key"], obj.get("Size")))
                    if len(out) >= limit:
                        return out, []
        except ClientError as exc:
            raise ProviderError(f"Cannot list objects in {posture.resource.name}: {_error_code(exc)}") from exc
        return out, []

    def read_object(self, posture: Posture, obj, max_bytes: int) -> bytes:
        s3 = self._client("s3", posture.resource.location)
        resp = s3.get_object(Bucket=posture.resource.name, Key=obj.key, Range=f"bytes=0-{max_bytes - 1}")
        return resp["Body"].read(max_bytes)

    def probe_targets(self, posture: Posture, sample: list):
        from urllib.parse import quote

        from clouddetectx.probe import ProbeTarget

        region = posture.resource.location or "us-east-1"
        # Path-style URL: works for bucket names containing dots (virtual-host TLS would fail).
        base = f"https://s3.{region}.amazonaws.com/{quote(posture.resource.name)}"
        targets = [ProbeTarget("anonymous-list", "List bucket contents", f"{base}?list-type=2&max-keys=5")]
        targets += [ProbeTarget("anonymous-read", obj.key, f"{base}/{quote(obj.key)}", "HEAD") for obj in sample]
        return targets

    # -- remediation ---------------------------------------------------------------
    def remediate(self, posture: Posture, findings: list[Finding], dry_run: bool, harden: bool):
        from botocore.exceptions import ClientError

        bucket = posture.resource.name
        cfg = posture.config
        s3 = self._client("s3", posture.resource.location)
        actions: list[RemediationAction] = []

        def run(action: str, detail: str, before: Any, fn, op: str = "", target: str = ""):
            if dry_run:
                actions.append(RemediationAction(action, "planned", detail, before, op, target))
                return
            try:
                fn()
                actions.append(RemediationAction(action, "applied", detail, before, op, target))
            except ClientError as exc:
                actions.append(RemediationAction(action, "failed", f"{detail} -> {_error_code(exc)}: {exc}", before, op, target))

        # 1. Containment first: Block Public Access overrides public ACLs and policies immediately.
        current_pab = cfg.get("public_access_block") or {}
        if not all(current_pab.get(f) for f in PAB_FLAGS):
            run(
                "Enable S3 Block Public Access (all four settings) on the bucket",
                f"s3:PutPublicAccessBlock on {bucket}",
                current_pab or None,
                lambda: s3.put_public_access_block(
                    Bucket=bucket, PublicAccessBlockConfiguration={f: True for f in PAB_FLAGS}
                ),
                "s3.public_access_block",
            )

        acls_disabled = cfg.get("object_ownership") == "BucketOwnerEnforced"

        # 2. Strip public grants from the bucket ACL, keeping every other grant.
        public_grants = _public_grants(cfg.get("acl_grants", []))
        if public_grants and not acls_disabled:
            kept = [g for g in cfg["acl_grants"] if g not in public_grants]
            run(
                "Remove public grants from the bucket ACL",
                f"Removed {len(public_grants)} grant(s) to AllUsers/AuthenticatedUsers",
                {"Owner": cfg.get("acl_owner"), "Grants": cfg["acl_grants"]},
                lambda: s3.put_bucket_acl(
                    Bucket=bucket, AccessControlPolicy={"Owner": cfg["acl_owner"], "Grants": kept}
                ),
                "s3.bucket_acl",
            )

        # 3. Strip public statements from the bucket policy (and, with --harden, require HTTPS).
        policy = cfg.get("policy")
        public_stmts = public_policy_statements(policy)
        add_tls = harden and "policy" not in posture.errors and not tls_enforced(policy)
        if public_stmts or add_tls:
            new_policy = copy.deepcopy(policy) if policy else {"Version": "2012-10-17", "Statement": []}
            new_policy["Statement"] = [s for s in _as_list(new_policy.get("Statement")) if s not in public_stmts]
            changes = [f"removed {len(public_stmts)} public statement(s)"] if public_stmts else []
            if add_tls:
                new_policy["Statement"].append({
                    "Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                })
                changes.append("added a statement denying non-HTTPS requests")
            if new_policy["Statement"]:
                title = ("Remove public statements from the bucket policy" if public_stmts else
                         "Require HTTPS in the bucket policy")
                if public_stmts and add_tls:
                    title += " and require HTTPS"
                run(title, "; ".join(changes).capitalize() + f" ({len(new_policy['Statement'])} statement(s) after)",
                    policy, lambda: s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(new_policy)), "s3.bucket_policy")
            else:
                run("Delete the bucket policy", "Every statement in the policy was public",
                    policy, lambda: s3.delete_bucket_policy(Bucket=bucket), "s3.bucket_policy")

        # 4. Reset public object ACLs.
        if not acls_disabled:
            for obj in cfg.get("public_objects", []):
                kept = [g for g in obj["grants"] if g not in _public_grants(obj["grants"])]
                run(
                    f"Remove public grants from object ACL: {obj['key']}",
                    f"s3:PutObjectAcl on s3://{bucket}/{obj['key']}",
                    {"Owner": obj["owner"], "Grants": obj["grants"]},
                    lambda o=obj, k=kept: s3.put_object_acl(
                        Bucket=bucket, Key=o["key"], AccessControlPolicy={"Owner": o["owner"], "Grants": k}
                    ),
                    "s3.object_acl", obj["key"],
                )

        # 5. Optional hardening.
        if harden:
            if not cfg.get("encryption"):
                run("Enable default encryption (SSE-S3)", "s3:PutBucketEncryption AES256", None,
                    lambda: s3.put_bucket_encryption(
                        Bucket=bucket,
                        ServerSideEncryptionConfiguration={
                            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
                        },
                    ), "s3.encryption")
            if cfg.get("versioning") != "Enabled":
                run("Enable bucket versioning", "s3:PutBucketVersioning Enabled", cfg.get("versioning"),
                    lambda: s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"}),
                    "s3.versioning")

        if not actions:
            actions.append(RemediationAction("No change required", "skipped", "Bucket has no public exposure to remove."))
        return actions

    def rollback(self, resource: Resource, applied: list[dict], dry_run: bool):
        """Restore the configuration saved in a report's applied actions (given newest first)."""
        from botocore.exceptions import ClientError

        bucket = resource.name
        s3 = self._client("s3", resource.location)
        out: list[RemediationAction] = []
        for a in applied:
            op, before, target = a.get("op"), a.get("before"), a.get("target") or ""
            title = f"Undo: {a.get('action')}"
            if op == "s3.public_access_block":
                fn = ((lambda b=before: s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration=b))
                      if before else (lambda: s3.delete_public_access_block(Bucket=bucket)))
                detail = "Restore previous bucket Block Public Access" if before else "Remove bucket Block Public Access"
            elif op == "s3.bucket_acl":
                fn, detail = (lambda b=before: s3.put_bucket_acl(Bucket=bucket, AccessControlPolicy=b)), "Restore previous bucket ACL"
            elif op == "s3.bucket_policy":
                fn = ((lambda b=before: s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(b)))
                      if before else (lambda: s3.delete_bucket_policy(Bucket=bucket)))
                detail = "Restore previous bucket policy" if before else "Delete the bucket policy (there was none)"
            elif op == "s3.object_acl":
                fn = lambda b=before, k=target: s3.put_object_acl(Bucket=bucket, Key=k, AccessControlPolicy=b)  # noqa: E731
                detail = f"Restore previous ACL on {target}"
            elif op == "s3.encryption":
                fn, detail = (lambda: s3.delete_bucket_encryption(Bucket=bucket)), "Remove default encryption setting (S3 still encrypts with SSE-S3)"
            elif op == "s3.versioning":
                fn = lambda: s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Suspended"})  # noqa: E731
                detail = "Suspend versioning (S3 can't return a bucket to 'never enabled')"
            else:
                out.append(RemediationAction(title, "skipped", "No automatic undo for this action; restore it manually from the saved configuration.", before, op or "", target))
                continue
            if dry_run:
                out.append(RemediationAction(title, "planned", detail, before, op, target))
                continue
            try:
                fn()
                out.append(RemediationAction(title, "applied", detail, before, op, target))
            except ClientError as exc:
                out.append(RemediationAction(title, "failed", f"{detail} -> {_error_code(exc)}", before, op, target))
        return out
