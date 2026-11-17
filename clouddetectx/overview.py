"""Account-level overview: security categories, priorities and compliance status.

Shared by the web dashboard, the CLI and the compliance report so they always agree.
"""

from __future__ import annotations

from clouddetectx.compliance import (
    CATEGORIES,
    CHECK_CATEGORY,
    FRAMEWORKS,
    compliance_status,
    compliance_summary,
    evaluated_checks,
)
from clouddetectx.models import Severity

IAM_RESOURCE = "IAM (account)"


def grade(score: int | None) -> str | None:
    if score is None:
        return None
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"


def _worst(findings) -> str | None:
    top = max((f.severity for f in findings), key=lambda s: s.rank, default=None)
    return top.value if top else None


def categories(provider: str, results: list, iam=None) -> list[dict]:
    """One entry per category: how many resources pass, worst severity, and IAM counts."""
    checked = set(evaluated_checks(provider, iam is not None, any(r.sensitive for r in results)))
    out = []
    for key, (label, ids) in CATEGORIES.items():
        ids_here = [c for c in ids if c in checked]
        resource_ids = [c for c in ids_here if not c.startswith("AWS-IAM-")]
        entry = {"key": key, "label": label, "checked": bool(ids_here), "resources_total": 0,
                 "resources_failing": 0, "findings": 0, "worst": None, "failing_resources": []}
        if not ids_here:
            out.append(entry)
            continue
        pool = [r for r in results if r.sensitive] if key == "data" else results
        failing_all = []
        if resource_ids:
            entry["resources_total"] = len(pool)
            for r in pool:
                bad = [f for f in r.all_findings if f.check_id in resource_ids and f.severity != Severity.INFO]
                if bad:
                    entry["failing_resources"].append(r.posture.resource.name)
                    failing_all += bad
            entry["resources_failing"] = len(entry["failing_resources"])
        if key == "iam" and iam is not None:
            account = [f for f in iam.findings if f.severity != Severity.INFO]
            failing_all += account
            c = iam.counts()
            entry.update(principals=c["principals"], risky_principals=c["risky"], account_findings=len(account))
        entry["findings"] = len(failing_all)
        entry["worst"] = _worst(failing_all)
        out.append(entry)
    return out


def priorities(results: list, risks: dict, iam=None, limit: int = 3) -> list[dict]:
    """The few things to fix first: riskiest resources, plus serious account-level IAM findings."""
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
    serious_iam = [f for f in (iam.findings if iam else []) if f.severity.rank >= Severity.HIGH.rank]
    for f in sorted(serious_iam, key=lambda f: -f.severity.rank)[:2]:   # keep room for resources
        if True:
            items.append({"kind": "iam", "name": IAM_RESOURCE, "risk": None, "severity": f.severity.value,
                          "check_id": f.check_id, "title": f.title, "recommendation": f.recommendation,
                          "exposed": False, "sort": (False, 50 + 10 * f.severity.rank, f.severity.rank)})
    items.sort(key=lambda i: i.pop("sort"), reverse=True)
    return items[:limit]


def compliance(provider: str, results: list, iam=None) -> dict:
    """Failing control rows plus pass/fail counts per framework."""
    entries = [(r.posture.resource.name, r.all_findings) for r in results]
    if iam is not None:
        entries.append((IAM_RESOURCE, iam.findings))
    rows = compliance_summary(entries)
    checks = evaluated_checks(provider, iam is not None, any(r.sensitive for r in results))
    names = {r.posture.resource.name for r in results}
    discovered = {r.posture.resource.name for r in results if r.sensitive}
    applicable = {c: {IAM_RESOURCE} if c.startswith("AWS-IAM-") else discovered if c.startswith("DATA-") else names
                  for c in checks}
    return {"frameworks": FRAMEWORKS, "controls": rows, "status": compliance_status(checks, rows, applicable),
            "checks_evaluated": sorted(checks)}


def build(provider: str, results: list, risks: dict, iam=None) -> dict:
    comp = compliance(provider, results, iam)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    top = sorted(comp["controls"], key=lambda r: (order[r["worst"]], -len(r["resources"])))[:3]
    return {
        "categories": categories(provider, results, iam),
        "priorities": priorities(results, risks, iam),
        "compliance": {fw: {k: v[k] for k in ("name", "assessed", "failing", "passing", "pass_rate",
                                              "checks_total", "checks_failing")}
                       for fw, v in comp["status"].items()},
        "top_controls": [{"framework": r["framework"], "id": r["id"], "title": r["title"], "worst": r["worst"],
                          "resources": len(r["resources"])} for r in top],
        "iam": iam.counts() if iam is not None else None,
    }
