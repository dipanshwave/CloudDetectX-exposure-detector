"""AWS account-wide checks: CloudTrail, root account, password policy, security groups, public
databases and snapshots, KMS key rotation, EBS default encryption, EKS endpoints, account-level
S3 Block Public Access. Read-only; every check degrades to a note when a permission is missing.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from clouddetectx.checks import risky_ports, short_list
from clouddetectx.models import Finding, Severity

PAB_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
MAX_PER_REGION = 500


def _code(exc) -> str:
    return getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)


def run(provider) -> tuple[list[Finding], list[str], dict[str, str]]:
    from botocore.exceptions import BotoCoreError, ClientError

    findings: list[Finding] = []
    notes: list[str] = []
    errors: dict[str, str] = {}
    home = provider.session.region_name or "us-east-1"

    def guard(area: str, fn):
        try:
            return fn()
        except (ClientError, BotoCoreError) as exc:
            errors[area] = _code(exc)
            return None

    wanted = [r.strip() for r in (provider.settings.aws_check_regions or "").split(",") if r.strip()]
    regions = wanted or guard("regions", lambda: [r["RegionName"] for r in provider._client("ec2", home).describe_regions()["Regions"]]) or [home]

    # ---- global checks
    findings += guard("cloudtrail", lambda: cloudtrail(provider, home)) or []
    findings += guard("root account", lambda: root_account(provider)) or []
    findings += guard("password policy", lambda: password_policy(provider)) or []
    findings += guard("account Block Public Access", lambda: account_bpa(provider)) or []

    # ---- regional checks, in parallel
    def regional(region):
        out = {}
        for area, fn in (("security groups", open_security_groups), ("RDS", public_rds),
                         ("snapshots", public_snapshots), ("KMS", kms_rotation),
                         ("EBS encryption", ebs_default_encryption), ("EKS", eks_endpoints)):
            try:
                out[area] = fn(provider, region)
            except (ClientError, BotoCoreError) as exc:
                code = _code(exc)
                if code not in ("OptInRequired", "AuthFailure", "UnrecognizedClientException", "InvalidClientTokenId"):
                    errors.setdefault(area, f"{code} ({region})")
                out[area] = []
        return out

    with ThreadPoolExecutor(max_workers=min(8, len(regions)), thread_name_prefix="clouddetectx-region") as pool:
        per_region = dict(zip(regions, pool.map(regional, regions)))

    def gather(area):
        return [dict(item, region=region) for region, data in per_region.items() for item in data.get(area, [])]

    sgs = gather("security groups")
    if sgs:
        findings.append(Finding(
            "AWS-ACCT-005", "Security groups expose admin or database ports to the internet", Severity.HIGH,
            f"{len(sgs)} security group rule(s) attached to running resources allow 0.0.0.0/0 or ::/0 on "
            f"sensitive ports: " + short_list([f"{g['group']} ({g['region']}): {', '.join(g['ports'])}" for g in sgs], 6) + ".",
            "Restrict these rules to your own IP ranges, or use SSM Session Manager / a VPN / private endpoints instead.",
            evidence={"rules": sgs[:200]}))
    rds = gather("RDS")
    if rds:
        findings.append(Finding(
            "AWS-ACCT-006", "Databases are publicly accessible", Severity.HIGH,
            f"{len(rds)} RDS instance(s) have PubliclyAccessible=true: "
            + short_list([f"{d['id']} ({d['region']})" for d in rds]) + ".",
            "Set PubliclyAccessible=false and reach databases from inside the VPC.",
            evidence={"instances": rds[:200]}))
    snaps = gather("snapshots")
    if snaps:
        findings.append(Finding(
            "AWS-ACCT-007", "Snapshots are shared publicly", Severity.CRITICAL,
            f"{len(snaps)} snapshot(s) can be restored by ANY AWS account: "
            + short_list([f"{x['type']} {x['id']} ({x['region']})" for x in snaps]) + ". Anyone can copy the full disk or database.",
            "Remove the public 'all' restore / createVolumePermission, and enable EBS snapshot Block Public Access.",
            exposes_data=True, evidence={"snapshots": snaps[:200]}))
    keys = gather("KMS")
    if keys:
        findings.append(Finding(
            "AWS-ACCT-008", "KMS key rotation is disabled", Severity.MEDIUM,
            f"{len(keys)} customer-managed symmetric key(s) do not rotate automatically: "
            + short_list([f"{k['id']} ({k['region']})" for k in keys]) + ".",
            "Enable automatic key rotation on customer-managed KMS keys.", evidence={"keys": keys[:200]}))
    ebs = [r for r, d in per_region.items() if d.get("EBS encryption")]
    if ebs:
        findings.append(Finding(
            "AWS-ACCT-009", "EBS encryption by default is off", Severity.LOW,
            f"New EBS volumes are not encrypted by default in {len(ebs)} region(s): {short_list(sorted(ebs))}.",
            "Enable EBS encryption by default in every region you use.", evidence={"regions": sorted(ebs)}))
    eks = gather("EKS")
    if eks:
        findings.append(Finding(
            "AWS-ACCT-010", "Kubernetes API endpoints are open to the internet", Severity.HIGH,
            f"{len(eks)} EKS cluster(s) expose the API endpoint to 0.0.0.0/0: "
            + short_list([f"{c['name']} ({c['region']})" for c in eks]) + ".",
            "Make the endpoint private, or restrict publicAccessCidrs to your own networks.",
            evidence={"clusters": eks[:200]}))
    if errors:
        notes.append("Some account checks were skipped for missing permissions: "
                     + ", ".join(f"{k} ({v})" for k, v in sorted(errors.items())) + ".")
    return findings, notes, errors


# --------------------------------------------------------------------------- global

def cloudtrail(provider, home) -> list[Finding]:
    ct = provider._client("cloudtrail", home)
    trails = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
    logging_multi = []
    for t in trails:
        if not t.get("IsMultiRegionTrail"):
            continue
        status = ct.get_trail_status(Name=t["TrailARN"])
        if status.get("IsLogging"):
            logging_multi.append(t["Name"])
    if logging_multi:
        return []
    return [Finding(
        "AWS-ACCT-001", "No multi-region CloudTrail trail is logging", Severity.HIGH,
        f"{len(trails)} trail(s) found, but none is multi-region and logging. API activity (including who made a bucket "
        "public) is only kept for 90 days in event history and is not delivered anywhere.",
        "Create a multi-region trail with log file validation, delivered to a locked-down S3 bucket.",
        evidence={"trails": [t.get("Name") for t in trails]})]


def root_account(provider) -> list[Finding]:
    summary = provider._client("iam", "us-east-1").get_account_summary()["SummaryMap"]
    out = []
    if not summary.get("AccountMFAEnabled"):
        out.append(Finding(
            "AWS-ACCT-002", "Root account has no MFA", Severity.CRITICAL,
            "The root user can do anything in the account, including deleting every bucket, and is protected only by a password.",
            "Enable a hardware or virtual MFA device on the root user and stop using it for daily work."))
    if summary.get("AccountAccessKeysPresent"):
        out.append(Finding(
            "AWS-ACCT-003", "Root account has access keys", Severity.CRITICAL,
            "Root access keys give unrestricted, unscoped API access and can't be limited by IAM policies.",
            "Delete the root access keys and use IAM roles instead."))
    return out


def password_policy(provider) -> list[Finding]:
    from botocore.exceptions import ClientError

    iam = provider._client("iam", "us-east-1")
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
    except ClientError as exc:
        if _code(exc) != "NoSuchEntity":
            raise
        return [Finding("AWS-ACCT-004", "No IAM password policy", Severity.MEDIUM,
                        "IAM users can set short, simple passwords that never expire.",
                        "Set a password policy: at least 14 characters and prevent reuse of the last 24.")]
    weak = []
    if policy.get("MinimumPasswordLength", 0) < 14:
        weak.append(f"minimum length {policy.get('MinimumPasswordLength', 0)} (< 14)")
    if not policy.get("PasswordReusePrevention"):
        weak.append("password reuse allowed")
    if weak:
        return [Finding("AWS-ACCT-004", "Weak IAM password policy", Severity.MEDIUM, "Password policy: " + "; ".join(weak) + ".",
                        "Require at least 14 characters and prevent reuse of the last 24 passwords.",
                        evidence={"policy": policy})]
    return []


def account_bpa(provider) -> list[Finding]:
    from botocore.exceptions import ClientError

    try:
        cfg = provider._client("s3control").get_public_access_block(AccountId=provider.account_id())["PublicAccessBlockConfiguration"]
    except ClientError as exc:
        if _code(exc) != "NoSuchPublicAccessBlockConfiguration":
            raise
        cfg = {}
    missing = [f for f in PAB_FLAGS if not cfg.get(f)]
    if not missing:
        return []
    return [Finding("AWS-ACCT-011", "Account-level S3 Block Public Access is not fully on", Severity.MEDIUM,
                    f"Off at account level: {', '.join(missing)}. Any bucket without its own Block Public Access can be made public.",
                    "Turn on all four Block Public Access settings for the account (S3 console > Block Public Access settings for this account).",
                    evidence={"account": cfg})]


# --------------------------------------------------------------------------- regional

def open_security_groups(provider, region) -> list[dict]:
    ec2 = provider._client("ec2", region)
    in_use = set()
    for page in ec2.get_paginator("describe_network_interfaces").paginate():
        for eni in page.get("NetworkInterfaces", []):
            in_use.update(g["GroupId"] for g in eni.get("Groups", []))
    out = []
    for page in ec2.get_paginator("describe_security_groups").paginate():
        for sg in page.get("SecurityGroups", []):
            if sg["GroupId"] not in in_use:
                continue
            for perm in sg.get("IpPermissions", []):
                open_v4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
                open_v6 = any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
                if not (open_v4 or open_v6):
                    continue
                ports = risky_ports(perm.get("FromPort"), perm.get("ToPort"), perm.get("IpProtocol") == "-1")
                if ports:
                    out.append({"group": f"{sg.get('GroupName')} ({sg['GroupId']})", "group_id": sg["GroupId"],
                                "ports": ports, "cidr": "0.0.0.0/0" if open_v4 else "::/0"})
            if len(out) >= MAX_PER_REGION:
                return out
    return out


def public_rds(provider, region) -> list[dict]:
    rds = provider._client("rds", region)
    out = []
    for page in rds.get_paginator("describe_db_instances").paginate():
        for db in page.get("DBInstances", []):
            if db.get("PubliclyAccessible"):
                out.append({"id": db["DBInstanceIdentifier"], "engine": db.get("Engine")})
    return out


def public_snapshots(provider, region) -> list[dict]:
    out = []
    ec2 = provider._client("ec2", region)
    for page in ec2.get_paginator("describe_snapshots").paginate(OwnerIds=["self"], RestorableByUserIds=["all"]):
        own = provider.account_id()      # only this account's snapshots (never AWS's own public ones)
        out += [{"type": "EBS", "id": s["SnapshotId"]} for s in page.get("Snapshots", []) if s.get("OwnerId") in (None, own)]
    rds = provider._client("rds", region)
    checked = 0
    for page in rds.get_paginator("describe_db_snapshots").paginate(SnapshotType="manual"):
        for snap in page.get("DBSnapshots", []):
            checked += 1
            if checked > MAX_PER_REGION:
                return out
            attrs = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=snap["DBSnapshotIdentifier"])
            for a in attrs["DBSnapshotAttributesResult"].get("DBSnapshotAttributes", []):
                if a.get("AttributeName") == "restore" and "all" in (a.get("AttributeValues") or []):
                    out.append({"type": "RDS", "id": snap["DBSnapshotIdentifier"]})
    return out


def kms_rotation(provider, region) -> list[dict]:
    kms = provider._client("kms", region)
    out = []
    for page in kms.get_paginator("list_keys").paginate():
        for k in page.get("Keys", [])[:MAX_PER_REGION]:
            meta = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
            if (meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled"
                    or meta.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT" or meta.get("Origin") != "AWS_KMS"):
                continue
            if not kms.get_key_rotation_status(KeyId=k["KeyId"]).get("KeyRotationEnabled"):
                out.append({"id": k["KeyId"]})
    return out


def ebs_default_encryption(provider, region) -> list[dict]:
    enabled = provider._client("ec2", region).get_ebs_encryption_by_default().get("EbsEncryptionByDefault")
    return [] if enabled else [{"region": region}]


def eks_endpoints(provider, region) -> list[dict]:
    eks = provider._client("eks", region)
    out = []
    for page in eks.get_paginator("list_clusters").paginate():
        for name in page.get("clusters", []):
            vpc = eks.describe_cluster(name=name)["cluster"].get("resourcesVpcConfig", {})
            if vpc.get("endpointPublicAccess") and "0.0.0.0/0" in (vpc.get("publicAccessCidrs") or ["0.0.0.0/0"]):
                out.append({"name": name})
    return out
