"""Storage-focused IAM permission analysis (AWS).

Works on the output of iam:GetAccountAuthorizationDetails (one paginated, read-only call
covered by the SecurityAudit policy) plus per-user MFA / access-key metadata.

This is a static approximation of IAM evaluation: Allow statements from identity policies
(inline, attached managed, and group policies for users) minus unconditional Deny
statements. It does not evaluate permission boundaries, SCPs, session policies or
condition values, so results are marked "conditional" where a condition applies.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from urllib.parse import unquote

from clouddetectx.models import Finding, Severity

KEY_MAX_AGE_DAYS = 90

# Probe ARNs: if a resource pattern matches these random names it covers every bucket.
_ANY_BUCKET = "arn:aws:s3:::cdx-any-bucket-7f3a9c"
_ANY_OBJECT = _ANY_BUCKET + "/cdx-any-key"

READ = ("s3:GetObject",)
LIST = ("s3:ListBucket",)
WRITE = ("s3:PutObject", "s3:DeleteObject")
EXPOSE = ("s3:PutBucketPolicy", "s3:PutBucketAcl", "s3:PutObjectAcl", "s3:PutBucketPublicAccessBlock")
ACCOUNT_EXPOSE = ("s3:PutAccountPublicAccessBlock",)
ADMIN_PROBES = ("iam:PutUserPolicy", "iam:CreateAccessKey", "s3:GetObject", "ec2:RunInstances", "kms:Decrypt")

CAPABILITY_LABELS = {
    "admin": "Full administrator",
    "s3_full": "Full S3 access",
    "read_all": "Read every bucket",
    "write_all": "Write/delete in every bucket",
    "can_expose": "Can make buckets public",
}


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _doc(document) -> dict:
    """Policy documents arrive as dicts (boto3) or URL-encoded JSON strings."""
    if isinstance(document, dict):
        return document
    if isinstance(document, str):
        try:
            return json.loads(unquote(document))
        except ValueError:
            return {}
    return {}


def _match(patterns: list, value: str) -> bool:
    v = value.lower()
    return any(fnmatchcase(v, str(p).lower()) for p in patterns)


@dataclass
class Statement:
    effect: str
    actions: list
    not_actions: list
    resources: list
    not_resources: list
    conditional: bool
    source: str

    @classmethod
    def parse(cls, raw: dict, source: str) -> "Statement":
        return cls(
            effect=raw.get("Effect", "Allow"),
            actions=_as_list(raw.get("Action")),
            not_actions=_as_list(raw.get("NotAction")),
            resources=_as_list(raw.get("Resource")),
            not_resources=_as_list(raw.get("NotResource")),
            conditional=bool(raw.get("Condition")),
            source=source,
        )

    def allows_action(self, action: str) -> bool:
        if self.not_actions:
            return not _match(self.not_actions, action)
        return _match(self.actions, action)

    def covers(self, arn: str) -> bool:
        if self.not_resources:
            return not _match(self.not_resources, arn)
        return _match(self.resources, arn)


@dataclass
class Principal:
    kind: str                      # user | role | group
    name: str
    arn: str
    statements: list[Statement] = field(default_factory=list, repr=False)
    console: bool | None = None    # users: has a console password
    mfa: bool | None = None        # users: has an MFA device
    keys: list[dict] = field(default_factory=list)   # users: [{id_suffix, status, age_days}]
    capabilities: dict[str, str] = field(default_factory=dict)   # capability -> "yes" | "conditional"

    def can(self, action: str, arn: str) -> str | None:
        """'yes', 'conditional' or None for one action on one resource ARN."""
        denied = any(s.effect == "Deny" and not s.conditional and s.allows_action(action) and s.covers(arn)
                     for s in self.statements)
        if denied:
            return None
        best = None
        for s in self.statements:
            if s.effect == "Allow" and s.allows_action(action) and s.covers(arn):
                if not s.conditional:
                    return "yes"
                best = "conditional"
        return best

    def can_any(self, actions: tuple, arns: tuple) -> str | None:
        results = {self.can(a, r) for a in actions for r in arns}
        return "yes" if "yes" in results else "conditional" if "conditional" in results else None

    def sources(self, actions: tuple, arns: tuple) -> list[str]:
        return sorted({s.source for s in self.statements if s.effect == "Allow"
                       and any(s.allows_action(a) and s.covers(r) for a in actions for r in arns)})

    @property
    def old_keys(self) -> list[dict]:
        return [k for k in self.keys if k["status"] == "Active" and k["age_days"] > KEY_MAX_AGE_DAYS]

    @property
    def risky(self) -> bool:
        return bool(self.capabilities) or bool(self.old_keys) or (self.console is True and self.mfa is False)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind, "name": self.name, "arn": self.arn,
            "capabilities": [{"key": k, "label": CAPABILITY_LABELS[k], "level": v} for k, v in self.capabilities.items()],
            "console": self.console, "mfa": self.mfa, "keys": self.keys,
            "old_keys": len(self.old_keys), "risky": self.risky,
            "policies": sorted({s.source for s in self.statements}),
        }


@dataclass
class IamReport:
    account_id: str
    principals: list[Principal]
    findings: list[Finding]
    notes: list[str]
    skipped_service_roles: int = 0
    analyzed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def counts(self) -> dict:
        p = self.principals
        return {
            "principals": len(p),
            "users": sum(x.kind == "user" for x in p),
            "roles": sum(x.kind == "role" for x in p),
            "risky": sum(x.risky for x in p),
            **{k: sum(k in x.capabilities for x in p) for k in CAPABILITY_LABELS},
            "no_mfa": sum(bool(x.console) and x.mfa is False for x in p),
            "old_keys": sum(len(x.old_keys) for x in p),
        }

    def bucket_access(self, bucket: str) -> list[dict]:
        """Who can read / list / write / manage one bucket through identity policies."""
        bucket_arn, object_arn = f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/cdx-any-key"
        rows = []
        for p in self.principals:
            access = {
                "read": p.can_any(READ, (object_arn,)),
                "list": p.can_any(LIST, (bucket_arn,)),
                "write": p.can_any(WRITE, (object_arn,)),
                "manage": p.can_any(EXPOSE, (bucket_arn, object_arn)),
            }
            if any(access.values()):
                rows.append({"kind": p.kind, "name": p.name, "arn": p.arn, **access,
                             "admin": "admin" in p.capabilities,
                             "via": p.sources(READ + LIST + WRITE + EXPOSE, (bucket_arn, object_arn))})
        order = {"yes": 0, "conditional": 1, None: 2}
        return sorted(rows, key=lambda r: (order[r["manage"]], order[r["write"]], order[r["read"]], r["name"]))

    def to_dict(self) -> dict:
        return {
            "account_id": self.account_id,
            "analyzed_at": self.analyzed_at.isoformat(),
            "counts": self.counts(),
            "principals": [p.to_dict() for p in sorted(self.principals, key=_risk_order)],
            "findings": [f.to_dict() for f in self.findings],
            "notes": self.notes,
            "skipped_service_roles": self.skipped_service_roles,
        }


def _risk_order(p: Principal):
    weight = {"admin": 0, "s3_full": 1, "can_expose": 2, "write_all": 3, "read_all": 4}
    first = min((weight[k] for k in p.capabilities), default=9)
    return (not p.risky, first, p.kind, p.name.lower())


# --------------------------------------------------------------------------- building the report

def build_principals(details: dict) -> tuple[list[Principal], int]:
    """details: merged GetAccountAuthorizationDetails pages. Returns (principals, skipped service roles)."""
    managed: dict[str, list[dict]] = {}
    for pol in details.get("Policies", []):
        default = next((v for v in pol.get("PolicyVersionList", []) if v.get("IsDefaultVersion")), None)
        if default:
            managed[pol["Arn"]] = _as_list(_doc(default.get("Document")).get("Statement"))

    def from_managed(attached: list[dict]) -> list[Statement]:
        out = []
        for a in attached or []:
            for raw in managed.get(a.get("PolicyArn"), []):
                out.append(Statement.parse(raw, a.get("PolicyName") or a.get("PolicyArn", "").rsplit("/", 1)[-1]))
        return out

    def from_inline(inline: list[dict]) -> list[Statement]:
        return [Statement.parse(raw, f"{p.get('PolicyName')} (inline)")
                for p in inline or [] for raw in _as_list(_doc(p.get("PolicyDocument")).get("Statement"))]

    groups: dict[str, list[Statement]] = {}
    for g in details.get("GroupDetailList", []):
        stmts = from_inline(g.get("GroupPolicyList")) + from_managed(g.get("AttachedManagedPolicies"))
        for s in stmts:
            s.source = f"{s.source} via group {g['GroupName']}"
        groups[g["GroupName"]] = stmts

    principals: list[Principal] = []
    for u in details.get("UserDetailList", []):
        stmts = from_inline(u.get("UserPolicyList")) + from_managed(u.get("AttachedManagedPolicies"))
        for gname in u.get("GroupList", []):
            stmts += groups.get(gname, [])
        principals.append(Principal("user", u["UserName"], u["Arn"], stmts))

    skipped = 0
    for r in details.get("RoleDetailList", []):
        if (r.get("Path") or "").startswith("/aws-service-role/"):
            skipped += 1     # service-linked roles are managed by AWS and can't be changed
            continue
        stmts = from_inline(r.get("RolePolicyList")) + from_managed(r.get("AttachedManagedPolicies"))
        principals.append(Principal("role", r["RoleName"], r["Arn"], stmts))

    for p in principals:
        p.capabilities = capabilities(p)
    return principals, skipped


def capabilities(p: Principal) -> dict[str, str]:
    caps: dict[str, str] = {}
    admin = [p.can(a, "*") for a in ADMIN_PROBES]
    if all(admin):
        caps["admin"] = "conditional" if "conditional" in admin else "yes"
        return caps                     # admin implies everything below
    every = (_ANY_BUCKET, _ANY_OBJECT)
    full = [p.can_any((a,), every) for a in ("s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:PutBucketPolicy")]
    if all(full):
        caps["s3_full"] = "conditional" if "conditional" in full else "yes"
        return caps
    for key, actions in (("read_all", READ), ("write_all", WRITE), ("can_expose", EXPOSE + ACCOUNT_EXPOSE)):
        level = p.can_any(actions, every + ("*",))
        if level:
            caps[key] = level
    return caps


def _names(principals: list[Principal], limit: int = 12) -> str:
    names = [f"{p.kind} {p.name}" for p in principals[:limit]]
    return ", ".join(names) + (f" and {len(principals) - limit} more" if len(principals) > limit else "")


def evaluate(principals: list[Principal]) -> list[Finding]:
    findings: list[Finding] = []

    def evidence(ps: list[Principal], extra=None) -> dict:
        return {"principals": [{"kind": p.kind, "name": p.name, "arn": p.arn,
                                "capabilities": p.capabilities, **(extra(p) if extra else {})} for p in ps[:100]]}

    admins = [p for p in principals if "admin" in p.capabilities]
    if admins:
        users = [p for p in admins if p.kind == "user"]
        findings.append(Finding(
            "AWS-IAM-001", "IAM principals with full administrator access",
            Severity.HIGH if users else Severity.MEDIUM,
            f"{len(admins)} principal(s) can perform any action on any resource, including reading every bucket and "
            f"making any bucket public: {_names(admins)}.",
            "Grant administrator access only to a few roles assumed with MFA. Replace user-attached admin policies "
            "with scoped roles.",
            evidence=evidence(admins),
        ))

    s3_full = [p for p in principals if "s3_full" in p.capabilities]
    if s3_full:
        findings.append(Finding(
            "AWS-IAM-002", "IAM principals with unrestricted S3 access",
            Severity.HIGH if any(p.kind == "user" and p.keys for p in s3_full) else Severity.MEDIUM,
            f"{len(s3_full)} principal(s) have s3:* (or equivalent) on every bucket: {_names(s3_full)}. "
            "One leaked credential exposes all storage.",
            "Scope S3 permissions to the specific buckets and actions each workload needs.",
            evidence=evidence(s3_full),
        ))

    exposers = [p for p in principals if "can_expose" in p.capabilities]
    if exposers:
        findings.append(Finding(
            "AWS-IAM-003", "Principals can make any bucket public",
            Severity.MEDIUM,
            f"{len(exposers)} principal(s) can change bucket policies, ACLs or Block Public Access on every bucket "
            f"without being administrators: {_names(exposers)}.",
            "Remove s3:PutBucketPolicy / s3:PutBucketAcl / s3:PutBucketPublicAccessBlock from broad policies, and "
            "keep account-level Block Public Access on so these permissions can't expose data.",
            evidence=evidence(exposers),
        ))

    no_mfa = [p for p in principals if p.kind == "user" and p.console and p.mfa is False]
    if no_mfa:
        privileged = [p for p in no_mfa if p.capabilities]
        findings.append(Finding(
            "AWS-IAM-004", "Console users without MFA",
            Severity.HIGH if privileged else Severity.MEDIUM,
            f"{len(no_mfa)} IAM user(s) can sign in to the console with only a password: {_names(no_mfa)}."
            + (f" {len(privileged)} of them have broad storage permissions." if privileged else ""),
            "Require MFA for every console user, or move people to IAM Identity Center (SSO).",
            evidence=evidence(no_mfa),
        ))

    stale = [p for p in principals if p.old_keys]
    if stale:
        findings.append(Finding(
            "AWS-IAM-005", f"Active access keys older than {KEY_MAX_AGE_DAYS} days",
            Severity.HIGH if any(p.capabilities for p in stale) else Severity.MEDIUM,
            f"{sum(len(p.old_keys) for p in stale)} active key(s) on {len(stale)} user(s) have not been rotated in "
            f"{KEY_MAX_AGE_DAYS}+ days: {_names(stale)}. Long-lived keys are the most common way storage gets breached.",
            "Rotate the keys (create new, deploy, deactivate old, delete), or replace them with roles / short-lived credentials.",
            evidence=evidence(stale, lambda p: {"old_keys": p.old_keys}),
        ))
    return findings
