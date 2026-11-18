"""Export findings as SARIF 2.1.0, OCSF 1.3 Compliance Findings, CSV, and reports as PDF."""

from __future__ import annotations

import csv
import re
import io
import time
from datetime import datetime, timezone

from clouddetectx import __version__
from clouddetectx.compliance import controls_for

SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
OCSF_SEVERITY = {"INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
OCSF_SEVERITY_NAME = {1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}
FORMATS = ("sarif", "ocsf", "csv")


def rows(provider: str, results: list, account=None) -> list[dict]:
    """One row per finding (active and waived), from resources and the account review."""
    from clouddetectx.account import account_resource

    out = []
    for r in results:
        res = r.posture.resource
        for f, waived in [(f, False) for f in r.all_findings] + [(f, True) for f in r.accepted]:
            out.append({"provider": provider, "account": res.account or "", "resource": res.name,
                        "resource_id": res.resource_id, "location": res.location or "", "kind": res.kind,
                        "status": r.status, "finding": f, "waived": waived})
    if account is not None:
        for f, waived in [(f, False) for f in account.findings] + [(f, True) for f in account.waived]:
            acct = (f.evidence or {}).get("account") or account.account_id
            out.append({"provider": provider, "account": acct, "resource": account_resource(acct),
                        "resource_id": f"{provider}:{acct}", "location": "", "kind": "account",
                        "status": "", "finding": f, "waived": waived})
    return out


def to_sarif(provider: str, results: list, account=None) -> dict:
    data = rows(provider, results, account)
    rules, seen = [], {}
    for row in data:
        f = row["finding"]
        if f.check_id in seen:
            continue
        seen[f.check_id] = len(rules)
        controls = controls_for(f.check_id)
        rules.append({
            "id": f.check_id, "name": f.check_id.replace("-", ""),
            "shortDescription": {"text": f.title},
            "help": {"text": f.recommendation},
            "defaultConfiguration": {"level": SARIF_LEVEL[f.severity.value]},
            "properties": {"tags": ["security", provider] + [f"{c['framework']}:{c['id']}" for c in controls],
                           "problem.severity": f.severity.value.lower()},
        })
    sarif_results = []
    for row in data:
        f = row["finding"]
        result = {
            "ruleId": f.check_id, "ruleIndex": seen[f.check_id], "level": SARIF_LEVEL[f.severity.value],
            "message": {"text": f"{row['resource']}: {f.title}. {f.description}"},
            "locations": [{"logicalLocations": [{"name": row["resource"], "fullyQualifiedName": row["resource_id"],
                                                 "kind": "resource"}]}],
            "properties": {"severity": f.severity.value, "exposesData": f.exposes_data, "account": row["account"],
                           "location": row["location"]},
        }
        if row["waived"]:
            result["suppressions"] = [{"kind": "external", "status": "accepted",
                                       "justification": (f.waiver or {}).get("reason", "")}]
        sarif_results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "CloudDetectX", "version": __version__,
                                      "informationUri": "https://github.com/dipanshwave/CloudDetectX-exposure-detector",
                                      "rules": rules}},
                  "results": sarif_results,
                  "invocations": [{"executionSuccessful": True,
                                   "endTimeUtc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}]}],
    }


def to_ocsf(provider: str, results: list, account=None) -> list[dict]:
    """OCSF v1.3 Compliance Finding events (class_uid 2003)."""
    now = int(time.time() * 1000)
    out = []
    for row in rows(provider, results, account):
        f = row["finding"]
        sev = OCSF_SEVERITY[f.severity.value]
        controls = controls_for(f.check_id)
        out.append({
            "class_uid": 2003, "class_name": "Compliance Finding", "category_uid": 2, "category_name": "Findings",
            "activity_id": 1, "activity_name": "Create", "type_uid": 200301,
            "time": now, "severity_id": sev, "severity": OCSF_SEVERITY_NAME[sev],
            "status_id": 4 if row["waived"] else 1, "status": "Suppressed" if row["waived"] else "New",
            "message": f"{row['resource']}: {f.title}",
            "metadata": {"version": "1.3.0", "product": {"name": "CloudDetectX", "vendor_name": "CloudDetectX",
                                                         "version": __version__}},
            "finding_info": {"uid": f"{provider}:{row['resource']}:{f.check_id}", "title": f.title,
                             "desc": f.description, "types": [f.check_id]},
            "compliance": {"control": f.check_id, "status": "Fail", "status_id": 3,
                           "standards": sorted({c["framework_name"] for c in controls}),
                           "requirements": [f"{c['framework']} {c['id']}" for c in controls]},
            "remediation": {"desc": f.recommendation},
            "cloud": {"provider": provider.upper(), "account": {"uid": row["account"]}, "region": row["location"] or None},
            "resources": [{"uid": row["resource_id"], "name": row["resource"], "type": row["kind"],
                           "region": row["location"] or None}],
            "unmapped": {"exposes_data": f.exposes_data, "waiver": f.waiver},
        })
    return out


def to_csv(provider: str, results: list, account=None) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["provider", "account", "resource", "location", "resource_status", "check_id", "severity",
                     "title", "exposes_data", "waived", "waiver_reason", "waiver_expires", "controls", "recommendation"])
    for row in rows(provider, results, account):
        f = row["finding"]
        w = f.waiver or {}
        writer.writerow([_cell(v) for v in (
            provider, row["account"], row["resource"], row["location"], row["status"], f.check_id, f.severity.value,
            f.title, f.exposes_data, row["waived"], w.get("reason", ""), w.get("expires", ""),
            "; ".join(f"{c['framework']} {c['id']}" for c in controls_for(f.check_id)), f.recommendation)])
    return buf.getvalue()


def _cell(value) -> str:
    """Neutralise spreadsheet formula injection (resource names come from the cloud account)."""
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


# --------------------------------------------------------------------------- PDF

_REPLACEMENTS = {"•": "*", "→": "->", "←": "<-", "–": "-", "—": "-", "“": '"', "”": '"', "‘": "'", "’": "'",
                 "…": "...", "▲": "^", "▼": "v", "✓": "v", "≥": ">=", "≤": "<=", "×": "x"}


def _latin1(text: str) -> str:
    for a, b in _REPLACEMENTS.items():
        text = text.replace(a, b)
    return text.encode("latin-1", errors="replace").decode("latin-1")


def markdown_to_pdf(markdown_text: str, title: str) -> bytes:
    """Render a report's Markdown as a simple, printable PDF."""
    import markdown as md
    import nh3
    from fpdf import FPDF

    html = md.markdown(_latin1(markdown_text), extensions=["tables", "fenced_code"])
    html = nh3.clean(html, tags={"h1", "h2", "h3", "h4", "p", "table", "thead", "tbody", "tr", "th", "td", "code",
                                 "pre", "ul", "ol", "li", "strong", "em", "b", "i", "br", "hr"}, attributes={})
    # fpdf2's HTML renderer can't nest tags inside table cells or <code> inside <pre>: flatten them.
    flatten = lambda m: f"<{m.group(1)}>" + re.sub(r"<[^>]+>", "", m.group(2)) + f"</{m.group(1)}>"  # noqa: E731
    html = re.sub(r"<(td|th)>(.*?)</\1>", flatten, html, flags=re.S)
    html = re.sub(r"<pre><code>(.*?)</code></pre>", r"<pre>\1</pre>", html, flags=re.S)
    html = re.sub(r"</?code>", "", html)

    def new_pdf():
        doc = FPDF(format="A4")
        doc.set_title(_latin1(title))
        doc.set_author("CloudDetectX")
        doc.set_auto_page_break(True, margin=15)
        doc.add_page()
        doc.set_font("Helvetica", size=9)
        return doc

    pdf = new_pdf()
    try:
        pdf.write_html(html, table_line_separators=True)
    except Exception:  # noqa: BLE001 - unusual markup: fall back to plain text rather than failing
        pdf = new_pdf()
        pdf.multi_cell(0, 4.5, _latin1(markdown_text))
    return bytes(pdf.output())
