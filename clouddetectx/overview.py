"""Account-level overview: security categories, priorities and compliance status.

Shared by the web dashboard, the CLI and the compliance report so they always agree.
`account` is an account.AccountReview (IAM + account-wide findings) or None.
"""

from __future__ import annotations

from clouddetectx.account import account_resource
from clouddetectx.compliance import (
    CATEGORIES,
    FRAMEWORKS,
    compliance_status,
    compliance_summary,
    evaluated_checks,
    is_account_level,
)
from clouddetectx.models import Severity


def grade(score: int | None) -> str | None:
    if score is None:
        return None
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"


def _worst(findings) -> str | None:
    top = max((f.severity for f in findings), key=lambda s: s.rank, default=None)
    return top.value if top else None


def account_entries(account) -> list[tuple[str, list]]:
    """[(waiver resource, active findings)] per account in the review (merged reviews have several)."""
    if account is None:
        return []
    groups: dict[str, list] = {}
    for f in account.findings:
        acct = (f.evidence or {}).get("account") or account.account_id
        groups.setdefault(account_resource(acct), []).append(f)
    return list(groups.items()) or [(account.waiver_resource, [])]


def categories(provider: str, results: list, account=None) -> list[dict]:
    """One entry per category: how many resources pass, worst severity, account-level counts."""
    checked = set(evaluated_checks(provider, account is not None, any(r.sensitive for r in results)))
    acct_findings = [f for f in (account.findings if account else []) if f.severity != Severity.INFO]
    out = []
    for key, (label, ids) in CATEGORIES.items():
        ids_here = [c for c in ids if c in checked]
        resource_ids = [c for c in ids_here if not is_account_level(c)]
        account_ids = [c for c in ids_here if is_account_level(c)]
        entry = {"key": key, "label": label, "checked": bool(ids_here), "resources_total": 0,
                 "resources_failing": 0, "findings": 0, "worst": None, "failing_resources": [],
                 "account_checks": len(account_ids), "account_findings": 0}
        if not ids_here:
            out.append(entry)
            continue
        pool = [r for r in results if r.sensitive] if key == "data" else results
        failing = []
        if resource_ids:
            entry["resources_total"] = len(pool)
            for r in pool:
                bad = [f for f in r.all_findings if f.check_id in resource_ids and f.severity != Severity.INFO]
                if bad:
                    entry["failing_resources"].append(r.posture.resource.name)
                    failing += bad
            entry["resources_failing"] = len(entry["failing_resources"])
        acct_bad = [f for f in acct_findings if f.check_id in account_ids]
        entry["account_findings"] = len(acct_bad)
        failing += acct_bad
        if key == "iam" and account is not None and account.iam is not None:
            c = account.iam.counts()
            entry.update(principals=c["principals"], risky_principals=c["risky"])
        entry["findings"] = len(failing)
        entry["worst"] = _worst(failing)
        out.append(entry)
    return out


def priorities(results: list, risks: dict, account=None, limit: int = 3) -> list[dict]:
    """The few things to fix first: riskiest resources, plus serious account-level findings."""
    items = []
    for r in results:
        name = r.posture.resource.name
        bad = [f for f in r.all_findings if f.severity.rank >= Severity.MEDIUM.rank]
        if not bad:
            continue
        top = max(bad, key=lambda f: (f.exposes_data, f.severity.rank))
        risk = risks[name].score if name in risks else 0
        items.append({"kind": "resource", "name": name, "risk": risk, "severity": top.severity.value,
                      "check_id": top.check_id, "title": top.title, "recommendation": top.recommendation,
                      "exposed": r.exposed, "sort": (r.exposed, risk, top.severity.rank)})
    serious = [f for f in (account.findings if account else []) if f.severity.rank >= Severity.HIGH.rank]
    for f in sorted(serious, key=lambda f: (-int(f.exposes_data), -f.severity.rank))[:2]:   # keep room for resources
        acct = (f.evidence or {}).get("account") or account.account_id
        items.append({"kind": "account", "name": f"Account {acct}", "risk": None, "severity": f.severity.value,
                      "check_id": f.check_id, "title": f.title, "recommendation": f.recommendation,
                      "exposed": f.exposes_data, "sort": (f.exposes_data, 50 + 10 * f.severity.rank, f.severity.rank)})
    items.sort(key=lambda i: i.pop("sort"), reverse=True)
    return items[:limit]


def compliance(provider: str, results: list, account=None) -> dict:
    """Failing control rows plus pass/fail counts per framework."""
    entries = [(r.posture.resource.name, r.all_findings) for r in results] + account_entries(account)
    rows = compliance_summary(entries)
    checks = evaluated_checks(provider, account is not None, any(r.sensitive for r in results))
    names = {r.posture.resource.name for r in results}
    discovered = {r.posture.resource.name for r in results if r.sensitive}
    accounts = {name for name, _ in account_entries(account)}
    applicable = {c: accounts if is_account_level(c) else discovered if c.startswith("DATA-") else names
                  for c in checks}
    return {"frameworks": FRAMEWORKS, "controls": rows, "status": compliance_status(checks, rows, applicable),
            "checks_evaluated": sorted(checks)}


def build(provider: str, results: list, risks: dict, account=None) -> dict:
    comp = compliance(provider, results, account)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    top = sorted(comp["controls"], key=lambda r: (order[r["worst"]], -len(r["resources"])))[:3]
    return {
        "categories": categories(provider, results, account),
        "priorities": priorities(results, risks, account),
        "compliance": {fw: {k: v[k] for k in ("name", "assessed", "failing", "passing", "pass_rate",
                                              "checks_total", "checks_failing")}
                       for fw, v in comp["status"].items()},
        "top_controls": [{"framework": r["framework"], "id": r["id"], "title": r["title"], "worst": r["worst"],
                          "resources": len(r["resources"])} for r in top],
        "account": account.counts() if account is not None else None,
        "iam": account.iam.counts() if account is not None and account.iam is not None else None,
    }
