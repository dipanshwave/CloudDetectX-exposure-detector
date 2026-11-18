"""Incident reports in Markdown (for people) and JSON (for tooling / evidence)."""

from __future__ import annotations

import json
import re
from pathlib import Path

from clouddetectx.analysis import VERDICT_TEXT
from clouddetectx.compliance import MITRE, compliance_summary
from clouddetectx.models import Incident

VERDICT_ACTIONS = {
    "DATA_ACCESSED": [
        "Treat this as a confirmed data exposure: notify the data owner, legal and privacy teams to assess breach-notification obligations.",
        "Review the list of downloaded objects and identify any personal data, credentials or keys they contain.",
        "Rotate any secrets, API keys or credentials found in the exposed objects.",
        "Block the listed external IPs at the edge if access continues, and preserve this report as evidence.",
    ],
    "EXPOSURE_PROBED": [
        "Review the untrusted requests listed below to confirm none succeeded.",
        "Assume the resource is known to scanners; keep monitoring it closely.",
    ],
    "NO_LOGS_AVAILABLE": [
        "Logging was not available, so data access cannot be ruled out: treat the exposed data as potentially compromised.",
        "Enable access logging now so any future exposure can be investigated.",
    ],
    "NO_EVIDENCE_OF_ACCESS": [
        "Confirm the log retention covers the whole period the resource was public.",
    ],
}


def _md_escape(value: object) -> str:
    """Escape untrusted text (object keys, user agents, principals) for Markdown tables and code spans.

    These strings come from attacker-controlled requests, so HTML must never pass through raw.
    """
    return (str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace("|", "\\|").replace("`", "'").replace("\r", " ").replace("\n", " "))


def _fenced(obj) -> list[str]:
    """JSON in a code fence; untrusted strings can't close the fence early."""
    text = json.dumps(obj, indent=2, default=str)[:4000].replace("```", "'''")
    return ["```json", text, "```", ""]


CLASSIFICATION_LABEL = {"RESTRICTED": "RESTRICTED (secrets/credentials)", "CONFIDENTIAL": "CONFIDENTIAL (personal/sensitive data)",
                        "INTERNAL": "INTERNAL", "NONE_FOUND": "Nothing sensitive detected"}


def render_markdown(inc: Incident) -> str:
    r = inc.resource
    lines = [
        f"# Security Incident Report: {inc.incident_id}",
        "",
        "| | |",
        "|---|---|",
        f"| Status | **{inc.status}** |",
        f"| Severity | **{inc.severity.value}** |",
        *([f"| Risk score | **{inc.risk['score']}/100 ({inc.risk['level']})** |"] if inc.risk else []),
        *([f"| Data classification | **{CLASSIFICATION_LABEL[inc.sensitive['classification']]}** |"] if inc.sensitive else []),
        *([f"| Verified from internet | {_md_escape(inc.proof['summary'])} |"] if inc.proof else []),
        f"| Provider | {r.provider.upper()} |",
        f"| Resource | `{r.name}` ({r.kind}) |",
        f"| Resource ID | `{r.resource_id}` |",
        f"| Location | {r.location or 'unknown'} |",
        f"| Detected | {inc.detected_at:%Y-%m-%d %H:%M:%S} UTC |",
    ]
    if inc.investigation:
        lines.append(f"| Access verdict | **{inc.investigation.verdict}** |")
    lines += ["", "## Summary", ""]
    exposing = [f for f in inc.findings if f.exposes_data]
    lines.append(
        f"`{r.name}` was found publicly accessible ({len(exposing)} exposing misconfiguration(s))."
        if exposing else f"`{r.name}` was assessed; no effective public exposure was found."
    )
    if inc.investigation:
        lines.append(VERDICT_TEXT[inc.investigation.verdict])
    applied = [a for a in inc.remediation if a.status == "applied"]
    if applied:
        lines.append(f"{len(applied)} remediation action(s) were applied.")

    lines += ["", "## Findings", "", "| Severity | Check | Finding | Public now |", "|---|---|---|---|"]
    for f in sorted(inc.findings, key=lambda f: -f.severity.rank):
        lines.append(f"| {f.severity.value} | {f.check_id} | {_md_escape(f.title)} | {'yes' if f.exposes_data else 'no'} |")
    lines.append("")
    for f in sorted(inc.findings, key=lambda f: -f.severity.rank):
        if f.severity.rank >= 2:
            lines += [f"### {f.check_id}: {f.title}", "", f.description, "", f"**Recommendation:** {f.recommendation}", ""]
            if f.evidence:
                lines += _fenced(f.evidence)

    if inc.risk and inc.risk.get("factors"):
        lines += ["## Risk score", "", f"**{inc.risk['score']}/100 ({inc.risk['level']})**", "",
                  "| Points | Reason |", "|---|---|"]
        lines += [f"| +{x['points']} | {_md_escape(x['reason'])} |" for x in inc.risk["factors"]] + [""]

    if inc.proof:
        p = inc.proof
        lines += ["## Exposure verification (anonymous requests from the internet)", "", _md_escape(p["summary"]), "",
                  f"Performed: {p['performed_at']}", "", "| Check | Target | Result | Accessible |", "|---|---|---|---|"]
        lines += [f"| {x['check']} | {_md_escape(x['label'])} | {_md_escape(x['detail'])} | {'YES' if x['accessible'] else 'no'} |"
                  for x in p["results"]] + [""]

    if inc.sensitive:
        d = inc.sensitive
        lines += ["## Sensitive data discovery", "",
                  f"Classification: **{CLASSIFICATION_LABEL[d['classification']]}**. "
                  f"{d['objects_scanned']} object(s) inspected of {d['objects_listed']} listed; {d['bytes_read']:,} bytes read. "
                  "Matches are redacted; full values are never stored.", ""]
        if d["hits"]:
            lines += ["| Severity | Detector | Matches | Redacted samples | Objects |", "|---|---|---|---|---|"]
            lines += [f"| {h['severity']} | {_md_escape(h['name'])} | {h['count']} | {_md_escape(', '.join(h['samples']))} | "
                      f"{_md_escape(', '.join(h['objects'][:5]))} |" for h in d["hits"]] + [""]
        if d["risky_files"]:
            lines += ["Risky files:", ""] + [f"- {_md_escape(x['key'])}: {_md_escape(x['reason'])}" for x in d["risky_files"][:50]] + [""]
        if d["notes"]:
            lines += ["Notes:", ""] + [f"- {_md_escape(n)}" for n in d["notes"]] + [""]

    inv = inc.investigation
    if inv:
        s = inv.summary
        lines += ["## Investigation", "", f"**Verdict: {inv.verdict}**: {VERDICT_TEXT[inv.verdict]}", ""]
        lines += ["Log sources searched:", ""] + [f"- {src}" for src in inv.log_sources or ["none"]] + [""]
        if inv.notes:
            lines += ["Notes:", ""] + [f"- {n}" for n in inv.notes] + [""]
        lines += [
            "| Metric | Value |", "|---|---|",
            f"| Events analysed | {s['total_events']} |",
            f"| Period | {s['first_event'] or '-'} to {s['last_event'] or '-'} |",
            f"| Requests from untrusted sources | {s['untrusted_requests']} |",
            f"| Anonymous requests | {s['anonymous_requests']} |",
            f"| Objects downloaded by untrusted sources | {len(s['objects_downloaded_by_untrusted'])} |",
            f"| Bytes downloaded by untrusted sources | {s['bytes_downloaded_by_untrusted']:,} |",
            f"| Untrusted writes/deletes | {s['writes_by_untrusted']} |",
            f"| Denied requests from untrusted sources | {s['denied_requests_from_untrusted']} |",
            "",
        ]
        if inv.indicators:
            lines += ["### Indicators", "", "| Severity | Indicator | Detail | MITRE ATT&CK |", "|---|---|---|---|"]
            lines += [f"| {i.severity.value} | {_md_escape(i.title)} | {_md_escape(i.detail)} | "
                      f"{(i.mitre + ' ' + MITRE.get(i.mitre, '')) if i.mitre else '-'} |" for i in inv.indicators]
            lines.append("")
        if s["objects_downloaded_by_untrusted"]:
            lines += ["### Objects downloaded by untrusted sources", ""]
            lines += [f"- {_md_escape(k)}" for k in s["objects_downloaded_by_untrusted"][:200]] + [""]
        if s["top_untrusted_ips"]:
            lines += ["### Top untrusted source IPs", "", "| IP | Requests |", "|---|---|"]
            lines += [f"| {_md_escape(ip)} | {n} |" for ip, n in s["top_untrusted_ips"]] + [""]
        if inv.change_events:
            lines += ["### Configuration change history", "", "| Time (UTC) | Action | Actor | Source IP |", "|---|---|---|---|"]
            lines += [f"| {c.timestamp:%Y-%m-%d %H:%M:%S} | {_md_escape(c.action)} | {_md_escape(c.actor or '-')} | {_md_escape(c.source_ip or '-')} |"
                      for c in inv.change_events[-50:]] + [""]
        untrusted = [e for e in inv.access_events if e.anonymous or e.source_ip in s["external_ips"]]
        if untrusted:
            lines += ["### Untrusted access timeline (latest 100)", "",
                      "| Time (UTC) | Operation | Object | Source IP | Principal | Status |", "|---|---|---|---|---|---|"]
            for e in untrusted[-100:]:
                lines.append(f"| {e.timestamp:%Y-%m-%d %H:%M:%S} | {_md_escape(e.operation)} | {_md_escape(e.key or '-')} | "
                             f"{_md_escape(e.source_ip or '-')} | {_md_escape(e.principal or '-')} | {e.status or '-'} |")
            lines.append("")

    lines += ["## Remediation", ""]
    if inc.remediation:
        lines += ["| Status | Action | Detail |", "|---|---|---|"]
        lines += [f"| {a.status} | {_md_escape(a.action)} | {_md_escape(a.detail)} |" for a in inc.remediation]
        before = [a for a in inc.remediation if a.before is not None and a.status in ("applied", "planned")]
        if before:
            lines += ["", "<details><summary>Original configuration (for rollback)</summary>", ""]
            for a in before:
                lines += [f"**{_md_escape(a.action)}**", ""] + _fenced(a.before)
            lines.append("</details>")
    else:
        lines.append("No remediation was performed (assessment only).")
    lines.append("")

    if inc.verification is not None:
        still = [f for f in inc.verification if f.exposes_data]
        lines += ["## Verification", "",
                  "Re-scan after remediation: **no public exposure remains**." if not still
                  else "Re-scan after remediation: **exposure still present**:", ""]
        lines += [f"- {f.check_id}: {f.title}" for f in still] + [""]

    controls = compliance_summary([(r.name, inc.findings)])
    if controls:
        lines += ["## Compliance mapping", "", "Controls affected by the findings above:", "",
                  "| Framework | Control | Title | Checks |", "|---|---|---|---|"]
        lines += [f"| {c['framework_name']} | {c['id']} | {_md_escape(c['title'])} | {', '.join(c['checks'])} |" for c in controls] + [""]

    recs: list[str] = []
    if inv:
        recs += VERDICT_ACTIONS.get(inv.verdict, [])
    for f in sorted(inc.findings, key=lambda f: -f.severity.rank):
        if f.recommendation not in recs and f.severity.rank >= 1:
            recs.append(f.recommendation)
    lines += ["## Recommendations", ""] + [f"{i}. {rec}" for i, rec in enumerate(recs, 1)] + [""]
    lines.append("_Generated by CloudDetectX._")
    return "\n".join(lines)


def write_report(inc: Incident, reports_dir: Path) -> tuple[Path, Path]:
    reports_dir.mkdir(parents=True, exist_ok=True)
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", inc.incident_id)
    md_path = reports_dir / f"{stem}.md"
    json_path = reports_dir / f"{stem}.json"
    md_path.write_text(render_markdown(inc), encoding="utf-8")
    json_path.write_text(json.dumps(inc.to_dict(), indent=2, default=str), encoding="utf-8")
    return md_path, json_path


# --------------------------------------------------------------------------- compliance report

def render_compliance_markdown(data: dict) -> str:
    """data: see build_compliance_report()."""
    status, cats = data["compliance"]["status"], data["categories"]
    score = data["security_score"]
    lines = [
        f"# Compliance Report: {data['report_id']}",
        "",
        "| | |",
        "|---|---|",
        f"| Cloud | {_md_escape(data['provider_display'])} |",
        f"| Account | {_md_escape(data['account'])} |",
        f"| Generated | {data['generated_at']} |",
        f"| Resources assessed | {len(data['resources'])} |",
        f"| Account-wide checks | {'yes' if data.get('account_checked') else 'no'} |",
        f"| Security score | **{score}/100** (grade {data['grade']}) |" if score is not None else "| Security score | - |",
        "",
        "This report maps the latest scan's findings to security controls. It is evidence input for audits, "
        "not a certification: a passing control means no evaluated check mapped to it failed.",
        "",
        "## Framework summary",
        "",
        "| Framework | Controls assessed | Fully passing | Failing | Resource-level pass rate |",
        "|---|---|---|---|---|",
    ]
    for fw in status.values():
        if fw.get("pass_rate") is None:
            rate = "-"
        else:
            rate = f"{fw['pass_rate']}% ({fw['checks_total'] - fw['checks_failing']} of {fw['checks_total']})"
        lines.append(f"| {fw['name']} | {fw['assessed']} | {fw['passing']} | {fw['failing']} | {rate} |")
    lines += ["", "A control is *fully passing* only if no resource fails it. The resource-level rate counts each "
              "(resource, control) pair the control applies to."]

    lines += ["", "## Security categories", "", "| Category | Result | Worst severity |", "|---|---|---|"]
    for c in cats:
        if not c["checked"]:
            result = "not assessed"
        elif c["resources_total"]:
            result = f"{c['resources_total'] - c['resources_failing']} of {c['resources_total']} resources pass"
        else:
            result = "assessed"
        if c.get("principals") is not None:
            result += f"; {c['risky_principals']} of {c['principals']} IAM principals flagged"
        lines.append(f"| {c['label']} | {result} | {c['worst'] or '-'} |")

    rows = data["compliance"]["controls"]
    lines += ["", "## Failing controls", ""]
    if rows:
        lines += ["| Framework | Control | Title | Worst | Resources | Checks |", "|---|---|---|---|---|---|"]
        for r in rows:
            more = f" +{len(r['resources']) - 6}" if len(r["resources"]) > 6 else ""
            res = ", ".join(_md_escape(n) for n in r["resources"][:6]) + more
            lines.append(f"| {r['framework_name']} | {r['id']} | {_md_escape(r['title'])} | {r['worst']} | {res} | "
                         f"{', '.join(r['checks'])} |")
    else:
        lines.append("No failing controls.")

    lines += ["", "## Passing controls", ""]
    for fw in status.values():
        if fw["passing_controls"]:
            lines.append(f"**{fw['name']}:** " + "; ".join(f"{c['id']} {_md_escape(c['title'])}" for c in fw["passing_controls"]))
            lines.append("")

    lines += ["## Resources", "", "| Resource | Status | Risk | Encryption at rest | HTTPS enforced | Failing checks |",
              "|---|---|---|---|---|---|"]
    for r in data["resources"]:
        enc = r.get("encryption") or {}
        at_rest = enc.get("at_rest") or ("not configured" if enc else "-")
        tls = {True: "yes", False: "no"}.get(enc.get("in_transit_enforced"), "-")
        lines.append(f"| {_md_escape(r['name'])} | {r['status']} | {r['risk']} | {_md_escape(at_rest)} | {tls} | "
                     f"{', '.join(r['failing_checks']) or 'none'} |")

    iam = data["iam"]
    if iam:
        c = iam["counts"]
        lines += ["", "## IAM permissions", "",
                  f"{c['principals']} principals analysed ({c['users']} users, {c['roles']} roles; "
                  f"{iam['skipped_service_roles']} service-linked roles skipped). {c['risky']} flagged.", ""]
        flagged = [p for p in iam["principals"] if p["risky"]]
        if flagged:
            lines += ["| Principal | Type | Storage permissions | Console MFA | Keys over 90 days |", "|---|---|---|---|---|"]
            for p in flagged[:100]:
                caps = ", ".join(cap["label"] + (" (conditional)" if cap["level"] == "conditional" else "")
                                 for cap in p["capabilities"]) or "-"
                mfa = "-" if not p["console"] else ("yes" if p["mfa"] else "**no**")
                lines.append(f"| {_md_escape(p['name'])} | {p['kind']} | {caps} | {mfa} | {p['old_keys'] or '-'} |")
        lines += [""] + [f"- {_md_escape(n)}" for n in iam["notes"]]

    lines += ["", "## Findings and recommendations", ""]
    for f in data["findings"]:
        more = " ..." if len(f["resources"]) > 5 else ""
        lines.append(f"- **{f['severity']}** {f['check_id']} {_md_escape(f['title'])} "
                     f"({_md_escape(', '.join(f['resources'][:5]))}{more}): {_md_escape(f['recommendation'])}")
    lines += ["", "_Generated by CloudDetectX._"]
    return "\n".join(lines)


def build_compliance_report(provider: str, provider_display: str, account_label: str, results: list, risks: dict,
                            account=None, security_score: int | None = None) -> dict:
    from datetime import datetime, timezone

    from clouddetectx.overview import account_entries, categories, compliance, grade

    now = datetime.now(timezone.utc)
    by_check: dict[str, dict] = {}
    entries = [(r.posture.resource.name, r.all_findings) for r in results]
    entries += account_entries(account)
    for name, findings in entries:
        for f in findings:
            if f.severity.value == "INFO":
                continue
            row = by_check.setdefault(f.check_id, {"check_id": f.check_id, "title": f.title, "severity": f.severity.value,
                                                   "rank": f.severity.rank, "recommendation": f.recommendation,
                                                   "resources": []})
            if f.severity.rank > row["rank"]:
                row.update(severity=f.severity.value, rank=f.severity.rank)
            row["resources"].append(name)
    return {
        "report_id": f"CMP-{now:%Y%m%d-%H%M%S}-{provider}",
        "type": "compliance",
        "provider": provider, "provider_display": provider_display, "account": account_label,
        "generated_at": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "security_score": security_score, "grade": grade(security_score),
        "categories": categories(provider, results, account),
        "compliance": compliance(provider, results, account),
        "account_checked": account is not None,
        "account_errors": account.errors if account is not None else {},
        "resources": [{
            "name": r.posture.resource.name, "status": r.status,
            "risk": risks[r.posture.resource.name].score if r.posture.resource.name in risks else None,
            "encryption": r.posture.config.get("encryption_summary"),
            "failing_checks": sorted({f.check_id for f in r.all_findings if f.severity.value != "INFO"}),
        } for r in results],
        "iam": account.iam.to_dict() if account is not None and account.iam is not None else None,
        "findings": [{k: v for k, v in row.items() if k != "rank"}
                     for row in sorted(by_check.values(), key=lambda x: (-x["rank"], x["check_id"]))],
    }


def write_compliance_report(data: dict, reports_dir: Path) -> tuple[Path, Path]:
    reports_dir.mkdir(parents=True, exist_ok=True)
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", data["report_id"])
    md_path, json_path = reports_dir / f"{stem}.md", reports_dir / f"{stem}.json"
    md_path.write_text(render_compliance_markdown(data), encoding="utf-8")
    json_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return md_path, json_path


def record_rollback(json_path: Path, md_path: Path, actions: list) -> dict:
    """Record a rollback in an incident report (JSON + Markdown)."""
    from datetime import datetime, timezone

    failed = [a for a in actions if a.status == "failed"]
    applied = [a for a in actions if a.status == "applied"]
    status = "failed" if failed and not applied else "partial" if failed else "applied"
    entry = {"status": status, "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
             "actions": [a.to_dict() for a in actions]}
    data = json.loads(json_path.read_text(encoding="utf-8"))
    data["rollback"] = entry
    if status == "applied":
        data["status"] = "ROLLED_BACK"
    json_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    lines = ["", "## Rollback", "", f"Rolled back at {entry['at']} (status: **{status}**). The configuration saved "
             "before remediation was restored; public access may be back.", "",
             "| Status | Action | Detail |", "|---|---|---|"]
    lines += [f"| {a.status} | {_md_escape(a.action)} | {_md_escape(a.detail)} |" for a in actions]
    with md_path.open("a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return entry
