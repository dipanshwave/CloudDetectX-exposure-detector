"""Account-level review: IAM principals plus account-wide findings (audit logging, root/owner
security, network exposure, public databases and snapshots, key rotation).

One AccountReview per scanned account (AWS account, Azure subscription, GCP project).
Several reviews (all-accounts scans) are merged with merge_reviews().
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from clouddetectx.models import Finding

ACCOUNT_PREFIX = "account:"   # waiver resource for account-level findings: "account:<account id>"


def account_resource(account_id: str | None) -> str:
    return f"{ACCOUNT_PREFIX}{account_id or 'default'}"


@dataclass
class AccountReview:
    provider: str
    account_id: str
    iam: object | None = None                          # iam.IamReport
    findings: list[Finding] = field(default_factory=list)    # active (not waived), incl. IAM findings
    waived: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)      # check area -> error (e.g. missing permission)
    analyzed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def waiver_resource(self) -> str:
        return account_resource(self.account_id)

    def counts(self) -> dict:
        c = self.iam.counts() if self.iam is not None else {}
        return {**c, "findings": len(self.findings), "waived": len(self.waived)}

    def to_dict(self) -> dict:
        return {
            "provider": self.provider, "account_id": self.account_id,
            "analyzed_at": self.analyzed_at.isoformat(),
            "waiver_resource": self.waiver_resource,
            "iam": self.iam.to_dict() if self.iam is not None else None,
            "findings": [f.to_dict() for f in self.findings],
            "waived": [f.to_dict() for f in self.waived],
            "notes": self.notes, "errors": self.errors,
        }


def merge_reviews(reviews: list[AccountReview]) -> AccountReview | None:
    """Combine per-account reviews (all-accounts scans) into one view."""
    reviews = [r for r in reviews if r is not None]
    if not reviews:
        return None
    if len(reviews) == 1:
        return reviews[0]
    from clouddetectx.iam import IamReport

    def tag(f: Finding, acct: str) -> Finding:
        f.evidence = {**(f.evidence or {}), "account": acct}
        return f

    principals, iam_notes, skipped = [], [], 0
    for r in reviews:
        if r.iam is not None:
            for p in r.iam.principals:
                if not p.name.startswith(f"{r.account_id}/"):
                    p.name = f"{r.account_id}/{p.name}"
                principals.append(p)
            skipped += r.iam.skipped_service_roles
            iam_notes += [n for n in r.iam.notes if n not in iam_notes]
    merged_iam = None
    if any(r.iam is not None for r in reviews):
        merged_iam = IamReport("multiple", principals,
                               [f for r in reviews if r.iam is not None for f in r.iam.findings], iam_notes, skipped)
    return AccountReview(
        provider=reviews[0].provider,
        account_id="all",
        iam=merged_iam,
        findings=[tag(f, r.account_id) for r in reviews for f in r.findings],
        waived=[tag(f, r.account_id) for r in reviews for f in r.waived],
        notes=[f"{r.account_id}: {n}" for r in reviews for n in r.notes],
        errors={f"{r.account_id}: {k}": v for r in reviews for k, v in r.errors.items()},
    )
