"""CloudDetectX command-line interface.

    python main.py                                  interactive mode (arrow-key menus)
    python main.py web                              web dashboard
    python main.py -p aws whoami                    check credentials
    python main.py -p aws,gcp scan                  find exposed storage, risk-score it, show drift (read-only)
    python main.py -p aws discover my-bucket        find secrets / personal data inside a bucket (read-only)
    python main.py -p aws verify my-bucket          prove exposure with anonymous requests from the internet
    python main.py -p aws investigate my-bucket     who accessed it / who made it public
    python main.py -p aws remediate my-bucket       plan, confirm, fix, verify, report
    python main.py -p aws respond --remediate       full workflow for every exposed resource
    python main.py -p aws compliance                controls affected (NIST 800-53, CIS v8, ISO 27001, CIS benchmarks)
    python main.py -p aws watch --every 30          continuous monitoring with drift alerts
"""

from __future__ import annotations

import argparse
import json
import re
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table

from clouddetectx.analysis import VERDICT_TEXT
from clouddetectx.config import Settings
from clouddetectx.engine import ScanResult, SecurityEngine, after_scan, alert_data_accessed
from clouddetectx.models import Finding, Incident, Investigation, RemediationAction, Severity
from clouddetectx.providers import PROVIDERS, ProviderError, get_provider
from clouddetectx.overview import grade
from clouddetectx.reporting import write_report

console = Console()

SEV_STYLE = {"CRITICAL": "bold white on red", "HIGH": "bold red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim",
             "NONE": "green"}
STATUS_STYLE = {"applied": "green", "planned": "cyan", "skipped": "dim", "failed": "bold red"}
VERDICT_STYLE = {"DATA_ACCESSED": "bold white on red", "EXPOSURE_PROBED": "bold yellow",
                 "NO_EVIDENCE_OF_ACCESS": "green", "NO_LOGS_AVAILABLE": "bold yellow"}
CLASS_STYLE = {"RESTRICTED": "bold white on red", "CONFIDENTIAL": "bold red", "INTERNAL": "yellow", "NONE_FOUND": "green"}

EXIT_OK, EXIT_ERROR, EXIT_EXPOSED = 0, 1, 2


def sev(s: Severity | str) -> str:
    v = s.value if isinstance(s, Severity) else s
    return f"[{SEV_STYLE[v]}] {v} [/]"


def risk_text(risk) -> str:
    return f"[{SEV_STYLE[risk.level]}] {risk.score:>3} [/]" if risk else "-"


# --------------------------------------------------------------------------- rendering

def print_scan_table(provider_name: str, account: str, results: list[ScanResult], risks: dict | None = None) -> None:
    risks = risks or {}
    table = Table(title=f"{PROVIDERS[provider_name]} | {account}", title_justify="left", expand=True)
    table.add_column("Resource", style="bold")
    table.add_column("Location")
    table.add_column("Exposure")
    table.add_column("Risk", justify="right")
    table.add_column("Highest")
    table.add_column("Findings", justify="right")
    order = {"public": 0, "accepted": 1, "mitigated": 2, "private": 3}
    for r in sorted(results, key=lambda r: (order[r.status], -(risks[r.posture.resource.name].score
                                                                if r.posture.resource.name in risks else 0))):
        exposure = {"public": "[bold white on red] PUBLIC [/]", "accepted": "[cyan]accepted[/]", "mitigated": "[yellow]mitigated[/]",
                    "private": "[green]private[/]"}[r.status]
        top = r.top_severity
        table.add_row(r.posture.resource.name, r.posture.resource.location or "-", exposure,
                      risk_text(risks.get(r.posture.resource.name)), sev(top) if top else "-", str(len(r.all_findings)))
    if not results:
        table.add_row("(no storage resources found)", "", "", "", "", "")
    console.print(table)


def print_outcome(outcome) -> None:
    if outcome.posture_score is not None:
        score = outcome.posture_score
        style = "green" if score >= 80 else "yellow" if score >= 50 else "bold red"
        console.print(f"Security score: [{style}]{score}/100[/]")
    d = outcome.drift
    if d is not None:
        if not d.previous_at:
            console.print("[dim]First scan of this account recorded; drift will be shown from the next scan.[/]")
        elif not d.changed:
            console.print(f"[dim]No changes since the last scan ({d.previous_at[:16].replace('T', ' ')} UTC).[/]")
        else:
            console.print(f"[bold]Changes since the last scan[/] ({d.previous_at[:16].replace('T', ' ')} UTC):")
            for n in d.new_public:
                console.print(f"  [bold red]+ newly PUBLIC[/] {n}")
            for n in d.resolved:
                console.print(f"  [green]- no longer public[/] {n}")
            for n in d.new_resources:
                console.print(f"  [cyan]+ new resource[/] {n}")
            for n in d.removed_resources:
                console.print(f"  [dim]- removed[/] {n}")
            for x in d.risk_increased:
                console.print(f"  [yellow]^ risk up[/] {x['name']}: {x['from']} -> {x['to']}")
            for n, checks in d.new_findings.items():
                console.print(f"  [yellow]+ new findings[/] {n}: {', '.join(checks)}")
    if outcome.alerts:
        console.print(f"[dim]Alerts sent: {len(outcome.alerts)}[/]" if not outcome.alert_error
                      else f"[bold red]Alert failed:[/] {outcome.alert_error}")


def print_findings(findings: list[Finding], min_rank: int = 2) -> None:
    shown = [f for f in sorted(findings, key=lambda f: -f.severity.rank) if f.severity.rank >= min_rank]
    for f in shown:
        console.print(f"  {sev(f.severity)} [bold]{f.check_id}[/] {f.title}")
        console.print(f"      {f.description}", style="dim", highlight=False)
        console.print(f"      [green]Fix:[/] {f.recommendation}", highlight=False)
    hidden = len(findings) - len(shown)
    if hidden:
        console.print(f"  [dim]+ {hidden} low/info finding(s) (use --all to show)[/]")


def print_investigation(inv: Investigation) -> None:
    from clouddetectx.compliance import MITRE

    s = inv.summary
    body = [
        f"[{VERDICT_STYLE[inv.verdict]}] {inv.verdict} [/]  {VERDICT_TEXT[inv.verdict]}",
        "",
        f"Log sources: {', '.join(inv.log_sources) or 'none'}",
        f"Events analysed: {s['total_events']}   Untrusted requests: {s['untrusted_requests']}   "
        f"Anonymous: {s['anonymous_requests']}",
        f"Objects downloaded by untrusted sources: {len(s['objects_downloaded_by_untrusted'])} "
        f"({s['bytes_downloaded_by_untrusted']:,} bytes)",
    ]
    if s["top_untrusted_ips"]:
        body.append("Top untrusted IPs: " + ", ".join(f"{ip} ({n})" for ip, n in s["top_untrusted_ips"][:5]))
    console.print(Panel("\n".join(body), title="Investigation", title_align="left"))
    for i in inv.indicators:
        tag = f" [dim]({i.mitre} {MITRE.get(i.mitre, '')})[/]" if i.mitre else ""
        console.print(f"  {sev(i.severity)} {i.title}: {i.detail}{tag}", highlight=False)
    for n in inv.notes:
        console.print(f"  [yellow]![/] {n}", highlight=False)


def print_sensitive(report) -> None:
    from clouddetectx.sensitive import CLASSIFICATION_TEXT

    c = report.classification
    console.print(Panel(
        f"[{CLASS_STYLE[c]}] {c} [/]  {CLASSIFICATION_TEXT[c]}\n\n"
        f"Objects listed: {report.objects_listed}   inspected: {report.objects_scanned}   skipped: {report.objects_skipped}   "
        f"read: {report.bytes_read:,} bytes",
        title="Sensitive data discovery", title_align="left"))
    if report.hits:
        table = Table(expand=True)
        for col in ("Severity", "Detected", "Matches", "Redacted samples", "Found in"):
            table.add_column(col)
        for h in report.hits:
            table.add_row(sev(h.severity), h.name, str(h.count), ", ".join(h.samples), ", ".join(h.objects[:3])
                          + (f" +{len(h.objects) - 3}" if len(h.objects) > 3 else ""))
        console.print(table)
    for f in report.risky_files[:15]:
        console.print(f"  {sev(f['severity'])} {f['key']}  [dim]{f['reason']}[/]", highlight=False)
    if len(report.risky_files) > 15:
        console.print(f"  [dim]+ {len(report.risky_files) - 15} more risky file(s) in the report[/]")
    for n in report.notes:
        console.print(f"  [dim]{n}[/]", highlight=False)


def print_proof(proof) -> None:
    style = "bold white on red" if proof.publicly_listable or proof.publicly_readable else "green"
    console.print(f"[{style}] {proof.summary} [/]")
    table = Table(expand=True)
    for col in ("Check", "Target", "Result", "Public"):
        table.add_column(col)
    for r in proof.results:
        table.add_row(r.check, r.label, r.detail, "[bold red]YES[/]" if r.accessible else "[green]no[/]")
    console.print(table)
    listed = [x for r in proof.results for x in r.sample]
    if listed:
        console.print(f"  [dim]Object names visible to anyone: {', '.join(listed[:8])}[/]", highlight=False)


def print_risk(risk) -> None:
    console.print(f"Risk score: {risk_text(risk)} [{SEV_STYLE[risk.level]}]{risk.level}[/]")
    for x in risk.factors:
        console.print(f"  [dim]+{x['points']:>2}[/] {x['reason']}", highlight=False)


def print_actions(actions: list[RemediationAction], title: str) -> None:
    table = Table(title=title, title_justify="left", expand=True)
    table.add_column("Status")
    table.add_column("Action")
    table.add_column("Detail", style="dim")
    for a in actions:
        table.add_row(f"[{STATUS_STYLE.get(a.status, '')}]{a.status}[/]", a.action, a.detail)
    console.print(table)


# --------------------------------------------------------------------------- workflow pieces

def review_account(engine: SecurityEngine, quiet: bool = False):
    """Account-wide review (IAM + account checks) or None when switched off."""
    if quiet:
        return engine.review_account()
    with console.status("Checking IAM and account-wide settings...") as status:
        return engine.review_account(on_progress=status.update)


def print_account_summary(review, show_all: bool = False) -> None:
    if review is None:
        return
    iam = review.iam
    console.print(f"\n[bold]Account-wide checks[/] ({review.account_id}): "
                  f"{len(review.findings)} finding(s)" + (f", {len(review.waived)} accepted" if review.waived else ""))
    if iam is not None:
        c = iam.counts()
        console.print(f"IAM: {c['principals']} principal(s) analysed ({c['users']} users, {c['roles']} roles), "
                      f"[bold]{c['risky']}[/] flagged")
        flagged = [p for p in iam.principals if p.risky or show_all]
        if flagged:
            table = Table(expand=True)
            for col in ("Principal", "Type", "Storage permissions", "Console MFA", "Keys > 90 days"):
                table.add_column(col)
            from clouddetectx.iam import CAPABILITY_LABELS, _risk_order
            for p in sorted(flagged, key=_risk_order)[:40]:
                caps = ", ".join(CAPABILITY_LABELS[k] + (" (conditional)" if v == "conditional" else "")
                                 for k, v in p.capabilities.items()) or "[dim]scoped[/]"
                mfa = "-" if not p.console else ("yes" if p.mfa else "[bold red]no[/]")
                table.add_row(p.name, p.kind, caps, mfa, str(len(p.old_keys)) if p.old_keys else "-")
            console.print(table)
    print_findings(review.findings, 0 if show_all else 2)
    for area, err in sorted(review.errors.items()):
        console.print(f"[yellow]Skipped {area}:[/] {err[:160]}")


def _scan_provider(name: str, settings: Settings, args, status=None):
    """Scan one cloud (one account or all accounts). Returns (label, results, reviews, scope, accounts, errors)."""
    from clouddetectx.engine import scan_all_accounts

    provider = get_provider(name, settings)
    engine = SecurityEngine(provider, settings)
    names = getattr(args, "names", None) or None
    skip_account = getattr(args, "no_account_checks", False)
    if skip_account:
        settings.account_checks = False
    if getattr(args, "all_accounts", False):
        if names:
            raise ProviderError("--all-accounts can't be combined with resource names.")
        with console.status(f"Scanning every {PROVIDERS[name]} account...") as st:
            scans, errors = scan_all_accounts(provider, settings, on_progress=st.update)
        for acct, err in errors.items():
            console.print(f"[yellow]Skipped account {acct}:[/] {err}")
        results = [r for sc in scans for r in sc.results]
        reviews = {sc.account["id"]: sc.review for sc in scans}
        return (f"All {PROVIDERS[name]} accounts ({len(scans)})", results, reviews, "all",
                [sc.account for sc in scans], errors)
    account = provider.account_label()
    with console.status(f"Scanning {PROVIDERS[name]}...") as st:
        results = engine.scan(names, on_progress=lambda n: st.update(f"Scanning {name}: {n}"))
    review = None if names else review_account(engine)
    return account, results, {provider.account_id(): review}, "account", [], {}


def _providers(arg: str | None) -> list[str]:
    raw = arg or os.getenv("CLOUDDETECTX_PROVIDERS") or ""
    names = [p.strip().lower() for p in raw.split(",") if p.strip()]
    if not names:
        raise ProviderError("Choose a provider with -p aws|azure|gcp (or several: -p aws,azure,gcp), or set CLOUDDETECTX_PROVIDERS.")
    for n in names:
        if n not in PROVIDERS:
            raise ProviderError(f"Unknown provider '{n}'. Choose from: {', '.join(PROVIDERS)}")
    return names


def _single_provider(arg: str | None) -> str:
    names = _providers(arg)
    if len(names) != 1:
        raise ProviderError("This command works on one provider at a time: pass -p aws, -p azure or -p gcp.")
    return names[0]


def _engine(args, settings: Settings) -> SecurityEngine:
    return SecurityEngine(get_provider(_single_provider(args.provider), settings), settings)


def _remediate_flow(engine: SecurityEngine, result: ScanResult, inc: Incident, harden: bool,
                    assume_yes: bool, dry_run: bool) -> None:
    plan, _ = engine.remediate(result, dry_run=True, harden=harden)
    print_actions(plan, f"Remediation plan for {result.posture.resource.name}")
    if dry_run or all(a.status == "skipped" for a in plan):
        inc.remediation = plan
        return
    if not assume_yes and not Confirm.ask(
        f"Apply these changes to [bold]{result.posture.resource.name}[/] in your live {engine.provider.name.upper()} account?",
        default=False,
    ):
        console.print("[yellow]Remediation cancelled; nothing was changed.[/]")
        inc.remediation = plan
        return
    with console.status("Applying remediation and re-scanning..."):
        actions, verification = engine.remediate(result, dry_run=False, harden=harden)
    inc.remediation, inc.verification = actions, verification
    print_actions(actions, "Remediation result")
    if verification is not None:
        still = [f for f in verification if f.exposes_data]
        if still:
            console.print("[bold red]Verification: exposure still present[/]")
            print_findings(still, 0)
        else:
            console.print("[bold green]Verification: no public exposure remains.[/]")


def save_incident(inc: Incident, settings: Settings) -> Path:
    SecurityEngine.finalize_status(inc)
    md, js = write_report(inc, settings.reports_dir)
    console.print(f"Report: [bold]{md}[/]  (evidence: {js})  status: [bold]{inc.status}[/]")
    return md


def _run_discovery(engine: SecurityEngine, result: ScanResult) -> None:
    with console.status("Discovering sensitive data...") as status:
        report = engine.discover(result, on_progress=lambda m: status.update(m))
    print_sensitive(report)


def _run_verify(engine: SecurityEngine, result: ScanResult) -> None:
    with console.status("Requesting public URLs without credentials..."):
        proof = engine.verify_exposure(result)
    print_proof(proof)


# --------------------------------------------------------------------------- commands

def cmd_whoami(args, settings: Settings) -> int:
    for name in _providers(args.provider):
        provider = get_provider(name, settings)
        console.print(f"[green]OK[/] {PROVIDERS[name]}: {provider.account_label()}")
    return EXIT_OK


def cmd_scan(args, settings: Settings) -> int:
    from clouddetectx import state
    from clouddetectx.account import merge_reviews

    any_exposed = False
    export = []
    for name in _providers(args.provider):
        account, results, reviews, scope, accounts, errors = _scan_provider(name, settings, args)
        outcome = after_scan(settings, name, account, results, full_scan=not args.names)
        review = merge_reviews(list(reviews.values()))
        print_scan_table(name, account, results, outcome.risks)
        print_outcome(outcome)
        if outcome.posture_score is not None:
            console.print(f"Grade: [bold]{grade(outcome.posture_score)}[/]")
        for r in results:
            if r.exposed or args.all:
                console.print(f"\n[bold]{r.posture.resource.name}[/]")
                print_findings(r.findings, 0 if args.all else 2)
            if r.accepted and args.all:
                console.print(f"  [dim]{len(r.accepted)} finding(s) accepted by waiver[/]")
            export.append({"provider": name, "account": r.posture.resource.account, "resource": r.posture.resource.name,
                           "status": r.status, "risk": outcome.risks[r.posture.resource.name].to_dict(),
                           "encryption": r.posture.config.get("encryption_summary"),
                           "findings": [f.to_dict() for f in r.findings],
                           "accepted": [f.to_dict() for f in r.accepted]})
        print_account_summary(review, args.all)
        if review is not None:
            export.append({"provider": name, "account_review": review.to_dict()})
        if not args.names:
            state.save_scan(settings, name, account, results, reviews, outcome, scope, accounts, errors)
        any_exposed |= any(r.exposed for r in results) or any(f.exposes_data for f in (review.findings if review else []))
    if args.json:
        Path(args.json).write_text(json.dumps(export, indent=2, default=str), encoding="utf-8")
        console.print(f"\nResults written to {args.json}")
    if any_exposed:
        console.print("\n[bold red]Public exposure found.[/] Next: `python main.py -p <provider> respond --verify --discover`")
    return EXIT_EXPOSED if any_exposed else EXIT_OK


def cmd_discover(args, settings: Settings) -> int:
    engine = _engine(args, settings)
    with console.status(f"Reading configuration of {args.name}..."):
        result = engine.scan_one(args.name)
    if args.max_objects:
        settings.discovery_max_objects = args.max_objects
    _run_discovery(engine, result)
    print_risk(engine.risk(result))
    save_incident(engine.new_incident(result), settings)
    return EXIT_EXPOSED if result.sensitive.classification == "RESTRICTED" and result.exposed else EXIT_OK


def cmd_verify(args, settings: Settings) -> int:
    engine = _engine(args, settings)
    with console.status(f"Reading configuration of {args.name}..."):
        result = engine.scan_one(args.name)
    _run_verify(engine, result)
    print_risk(engine.risk(result))
    save_incident(engine.new_incident(result), settings)
    return EXIT_EXPOSED if result.proof.publicly_listable or result.proof.publicly_readable else EXIT_OK


def cmd_investigate(args, settings: Settings) -> int:
    engine = _engine(args, settings)
    with console.status(f"Reading configuration of {args.name}..."):
        result = engine.scan_one(args.name)
    console.print(f"[bold]{args.name}[/]: {'[bold white on red] PUBLIC [/]' if result.exposed else '[green]not publicly exposed[/]'}")
    print_findings(result.findings)
    with console.status(f"Searching access and audit logs (last {args.days or settings.lookback_days} days)..."):
        inv = engine.investigate(result.posture, args.days)
    print_investigation(inv)
    err = alert_data_accessed(settings, engine.provider.name, args.name, inv)
    if err:
        console.print(f"[bold red]Alert failed:[/] {err}")
    print_risk(engine.risk(result, inv))
    save_incident(engine.new_incident(result, inv), settings)
    return EXIT_EXPOSED if result.exposed else EXIT_OK


def cmd_remediate(args, settings: Settings) -> int:
    engine = _engine(args, settings)
    with console.status(f"Reading configuration of {args.name}..."):
        result = engine.scan_one(args.name)
    print_findings(result.findings)
    inc = engine.new_incident(result)
    _remediate_flow(engine, result, inc, args.harden, args.yes, args.dry_run)
    save_incident(inc, settings)
    return EXIT_EXPOSED if inc.status not in ("CONTAINED", "NO_EXPOSURE") else EXIT_OK


def cmd_respond(args, settings: Settings) -> int:
    remaining = 0
    for name in _providers(args.provider):
        provider = get_provider(name, settings)
        account = provider.account_label()
        engine = SecurityEngine(provider, settings)
        console.rule(f"[bold]{PROVIDERS[name]}[/]")
        with console.status("[SCAN] Searching for storage resources...") as status:
            results = engine.scan(args.names or None, on_progress=lambda n: status.update(f"[SCAN] {n}"))
        outcome = after_scan(settings, name, account, results, full_scan=not args.names)
        print_scan_table(name, account, results, outcome.risks)
        print_outcome(outcome)
        exposed = [r for r in results if r.exposed]
        if not exposed:
            console.print("[green]No public exposure detected.[/]")
            continue
        for result in exposed:
            res = result.posture.resource
            console.rule(f"[bold red][ALERT][/] {res.name}")
            print_findings(result.findings)
            if args.verify:
                _run_verify(engine, result)
            if args.discover:
                _run_discovery(engine, result)
            with console.status("[INVESTIGATE] Analyzing access activity..."):
                inv = engine.investigate(result.posture, args.days)
            print_investigation(inv)
            alert_data_accessed(settings, name, res.name, inv)
            print_risk(engine.risk(result, inv))
            inc = engine.new_incident(result, inv)
            if args.remediate or args.dry_run:
                _remediate_flow(engine, result, inc, args.harden, args.yes, args.dry_run)
            save_incident(inc, settings)
            if inc.status != "CONTAINED":
                remaining += 1
    if remaining:
        console.print(f"\n[bold red]{remaining} exposed resource(s) still open.[/]"
                      + ("" if args.remediate else " Re-run with --remediate to fix them."))
    return EXIT_EXPOSED if remaining else EXIT_OK


def cmd_compliance(args, settings: Settings) -> int:
    from clouddetectx.compliance import FRAMEWORKS
    from clouddetectx.overview import compliance as compliance_data
    from clouddetectx.reporting import build_compliance_report, write_compliance_report
    from clouddetectx.risk import posture_score, score_resource

    rows_all = []
    for name in _providers(args.provider):
        from clouddetectx.account import merge_reviews

        account_label, results, reviews, *_ = _scan_provider(name, settings, args)
        review = merge_reviews(list(reviews.values()))
        data = compliance_data(name, results, review)
        rows = data["controls"]
        if args.framework:
            rows = [r for r in rows if r["framework"] == args.framework.upper()]
        rows_all += [{**r, "provider": name} for r in rows]

        summary = Table(title=f"Compliance | {PROVIDERS[name]} | {len(results)} resource(s)"
                              + (" + account-wide checks" if review is not None else ""), title_justify="left", expand=True)
        for col, just in (("Framework", "left"), ("Controls", "right"), ("Fully passing", "right"),
                          ("Failing", "right"), ("Resource-level pass rate", "right")):
            summary.add_column(col, justify=just)
        for fw, st in data["status"].items():
            if args.framework and fw != args.framework.upper():
                continue
            rate = st["pass_rate"]
            style = "green" if (rate or 0) >= 80 else "yellow" if (rate or 0) >= 50 else "red"
            summary.add_row(st["name"], str(st["assessed"]), str(st["passing"]), str(st["failing"]),
                            f"[{style}]{rate}%[/]" if rate is not None else "-")
        console.print(summary)

        table = Table(title="Failing controls", title_justify="left", expand=True)
        for col in ("Framework", "Control", "Title", "Worst", "Resources"):
            table.add_column(col)
        for r in rows:
            table.add_row(FRAMEWORKS[r["framework"]], r["id"], r["title"], sev(r["worst"]),
                          f"{len(r['resources'])}: " + ", ".join(r["resources"][:3])
                          + (" ..." if len(r["resources"]) > 3 else ""))
        if not rows:
            table.add_row("-", "-", "No failing controls", "-", "-")
        console.print(table)
        if args.report:
            risks = {r.posture.resource.name: score_resource(r.findings) for r in results}
            report = build_compliance_report(name, PROVIDERS[name], account_label, results, risks,
                                             review, posture_score(list(risks.values())))
            md_path, json_path = write_compliance_report(report, settings.reports_dir)
            console.print(f"[green]Compliance report:[/] {md_path}\n[dim]Evidence: {json_path}[/]")
            if args.pdf:
                from clouddetectx.export import markdown_to_pdf

                pdf_path = md_path.with_suffix(".pdf")
                pdf_path.write_bytes(markdown_to_pdf(md_path.read_text(encoding="utf-8"), md_path.stem))
                console.print(f"[green]PDF:[/] {pdf_path}")
    if args.json:
        Path(args.json).write_text(json.dumps(rows_all, indent=2), encoding="utf-8")
        console.print(f"Written to {args.json}")
    return EXIT_EXPOSED if rows_all else EXIT_OK


def cmd_account(args, settings: Settings) -> int:
    flagged_any = False
    settings.account_checks = True
    for name in _providers(args.provider):
        engine = SecurityEngine(get_provider(name, settings), settings)
        console.print(f"[bold]{PROVIDERS[name]}[/] | {engine.provider.account_label()}")
        review = review_account(engine)
        print_account_summary(review, args.all)
        for note in review.notes:
            console.print(f"[dim]{note}[/]")
        flagged_any |= any(f.severity.rank >= 2 for f in review.findings)
        if args.json:
            Path(args.json).write_text(json.dumps(review.to_dict(), indent=2, default=str), encoding="utf-8")
            console.print(f"Written to {args.json}")
    return EXIT_EXPOSED if flagged_any else EXIT_OK


def cmd_waivers(args, settings: Settings) -> int:
    from clouddetectx.waivers import WaiverError, WaiverStore

    store = WaiverStore(settings.data_dir)
    if args.action == "add":
        if not (args.resource and args.check and args.reason and args.expires):
            console.print("[red]add needs RESOURCE, --check, --reason and --expires.[/] Example:\n"
                          "  python main.py -p aws waivers add my-website-bucket --check '*' "
                          "--reason 'public website assets' --expires 2027-06-30\n"
                          "Account-wide findings use the resource 'account:<account id>'.")
            return EXIT_ERROR
        try:
            w = store.add(_single_provider(args.provider), args.resource, args.check, args.reason, args.expires,
                          os.getenv("USERNAME") or os.getenv("USER") or "")
        except WaiverError as exc:
            console.print(f"[red]{exc}[/]")
            return EXIT_ERROR
        console.print(f"[green]Waiver {w.id} added[/]: {w.provider} {w.resource} {w.check_id} until {w.expires}")
        return EXIT_OK
    if args.action == "remove":
        if not args.resource:
            console.print("[red]remove needs the waiver ID (see `waivers list`).[/]")
            return EXIT_ERROR
        ok = store.remove(args.resource)
        console.print("[green]Removed.[/]" if ok else "[yellow]No waiver with that ID.[/]")
        return EXIT_OK if ok else EXIT_ERROR
    table = Table(title="Accepted-risk waivers", title_justify="left", expand=True)
    for col in ("ID", "Cloud", "Resource", "Check", "Expires", "Reason"):
        table.add_column(col)
    for w in sorted(store.all(), key=lambda w: w.expires):
        table.add_row(w.id, w.provider, w.resource, w.check_id,
                      f"[red]{w.expires} (expired)[/]" if w.expired else w.expires, w.reason)
    if not store.all():
        table.add_row("-", "-", "No waivers", "-", "-", "-")
    console.print(table)
    return EXIT_OK


def cmd_rollback(args, settings: Settings) -> int:
    from clouddetectx.reporting import record_rollback

    if not re.fullmatch(r"INC-[A-Za-z0-9._-]+", args.report):
        console.print("[red]Give an incident report ID, e.g. INC-20261117-033902-aws-my-bucket.[/]")
        return EXIT_ERROR
    json_path = settings.reports_dir / f"{args.report}.json"
    md_path = settings.reports_dir / f"{args.report}.md"
    if not json_path.is_file():
        console.print(f"[red]Report not found in {settings.reports_dir}.[/]")
        return EXIT_ERROR
    report = json.loads(json_path.read_text(encoding="utf-8"))
    res = report.get("resource") or {}
    provider = get_provider(res.get("provider", ""), settings)
    if res.get("account") and res["account"] != provider.account_id():
        provider = provider.for_account(res["account"])
    engine = SecurityEngine(provider, settings)
    plan = engine.rollback(report, dry_run=True)
    print_actions(plan, f"Rollback plan for {res.get('name')}")
    if args.dry_run:
        return EXIT_OK
    console.print("[bold yellow]Rolling back restores the configuration from before remediation. "
                  "If the resource was public, it becomes public again.[/]")
    if not args.yes and not Confirm.ask(f"Roll back {res.get('name')}?", default=False):
        console.print("Cancelled.")
        return EXIT_OK
    actions = engine.rollback(report, dry_run=False)
    print_actions(actions, "Rollback result")
    entry = record_rollback(json_path, md_path, actions)
    console.print(f"Recorded in {md_path} (status: {entry['status']})")
    return EXIT_OK if entry["status"] == "applied" else EXIT_ERROR


def cmd_export(args, settings: Settings) -> int:
    from clouddetectx import export as exporter
    from clouddetectx.account import merge_reviews

    out = Path(args.output) if args.output else None
    formats = list(exporter.FORMATS) if args.format == "all" else [args.format]
    exit_code = EXIT_OK
    for name in _providers(args.provider):
        label, results, reviews, *_ = _scan_provider(name, settings, args)
        review = merge_reviews(list(reviews.values()))
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        for fmt in formats:
            if fmt == "csv":
                text, ext = exporter.to_csv(name, results, review), "csv"
            elif fmt == "sarif":
                text, ext = json.dumps(exporter.to_sarif(name, results, review), indent=2), "sarif"
            else:
                text, ext = json.dumps(exporter.to_ocsf(name, results, review), indent=2), "ocsf.json"
            if out and len(formats) == 1 and len(_providers(args.provider)) == 1 and out.suffix:
                path = out
            else:
                folder = out or settings.reports_dir
                folder.mkdir(parents=True, exist_ok=True)
                path = folder / f"clouddetectx-{name}-{stamp}.{ext}"
            path.write_text(text, encoding="utf-8")
            console.print(f"[green]{fmt.upper()}:[/] {path}")
        if any(r.exposed for r in results):
            exit_code = EXIT_EXPOSED
    return exit_code


def cmd_schedule(args, settings: Settings) -> int:
    from clouddetectx import schedule

    if args.action == "status":
        st = schedule.status()
        console.print(("[green]Installed[/]: " if st["installed"] else "[dim]") + st["detail"] + ("" if st["installed"] else "[/]"))
        return EXIT_OK
    if args.action == "remove":
        console.print(schedule.remove())
        return EXIT_OK
    try:
        plan = schedule.plan(settings.data_dir, args.every, _providers(args.provider), args.all_accounts)
    except schedule.ScheduleError as exc:
        console.print(f"[red]{exc}[/]")
        return EXIT_ERROR
    if args.print:
        console.print(f"[bold]Script[/] {plan.script}:\n{plan.script_body}")
        console.print(f"[bold]Install[/]: {plan.crontab or ' '.join(plan.install[0])}")
        return EXIT_OK
    try:
        console.print(f"[green]{schedule.install(plan)}[/]\nOutput is appended to {settings.data_dir / 'logs' / 'scheduled-scan.log'}.")
    except schedule.ScheduleError as exc:
        console.print(f"[red]{exc}[/]")
        return EXIT_ERROR
    return EXIT_OK


def cmd_history(args, settings: Settings) -> int:
    from clouddetectx.history import History

    history = History(settings.data_dir)
    try:
        for name in _providers(args.provider):
            rows = history.trend(name, limit=args.limit)
            table = Table(title=f"Scan history | {PROVIDERS[name]}", title_justify="left", expand=True)
            for col in ("Scanned (UTC)", "Account", "Resources", "Public", "Mitigated", "Security score"):
                table.add_column(col, justify="right" if col in ("Resources", "Public", "Mitigated", "Security score") else "left")
            for r in rows:
                table.add_row(r["scanned_at"][:19].replace("T", " "), r["account"][:50], str(r["resources"]),
                              f"[bold red]{r['public']}[/]" if r["public"] else "0", str(r["mitigated"]),
                              "-" if r["posture_score"] is None else str(r["posture_score"]))
            if not rows:
                table.add_row("No scans recorded yet", "", "", "", "", "")
            console.print(table)
    finally:
        history.close()
    return EXIT_OK


def cmd_watch(args, settings: Settings) -> int:
    names = _providers(args.provider)
    engines = {}
    for name in names:
        provider = get_provider(name, settings)
        engines[name] = (SecurityEngine(provider, settings), provider.account_label())
    console.print(Panel(f"Watching {', '.join(PROVIDERS[n] for n in names)} every {args.every} minute(s). "
                        f"Alerts: {'webhook configured' if settings.webhook_url else 'off (set a webhook in Settings > Alerts)'}.\n"
                        "Read-only. Press Ctrl+C to stop.", title="CloudDetectX watch", title_align="left"))
    while True:
        for name, (engine, account) in engines.items():
            try:
                results = engine.scan()
                outcome = after_scan(settings, name, account, results)
                public = [r.posture.resource.name for r in results if r.exposed]
                stamp = time.strftime("%Y-%m-%d %H:%M:%S")
                console.print(f"[dim]{stamp}[/] {name.upper()}: {len(results)} resources, "
                              + (f"[bold red]{len(public)} public[/]" if public else "[green]0 public[/]")
                              + (f", score {outcome.posture_score}" if outcome.posture_score is not None else ""))
                if outcome.drift and outcome.drift.changed:
                    print_outcome(outcome)
                elif outcome.alert_error:
                    console.print(f"[bold red]Alert failed:[/] {outcome.alert_error}")
            except ProviderError as exc:
                console.print(f"[bold red]{name.upper()} scan failed:[/] {exc}")
        time.sleep(max(1, args.every) * 60)


def cmd_alert_test(args, settings: Settings) -> int:
    from clouddetectx.alerts import AlertError, send

    if not settings.webhook_url:
        raise ProviderError("No webhook configured. Run: python main.py config set CLOUDDETECTX_WEBHOOK_URL")
    try:
        send(settings.webhook_url, "CloudDetectX test alert", ["Alerts are working. This is only a test."], {"test": True})
    except AlertError as exc:
        raise ProviderError(str(exc)) from exc
    console.print("[green]Test alert sent.[/]")
    return EXIT_OK


# --------------------------------------------------------------------------- entry point

def build_parser() -> argparse.ArgumentParser:
    def common_options(default):
        p = argparse.ArgumentParser(add_help=False)
        p.add_argument("-p", "--provider", default=default,
                       help="aws, azure, gcp, or a comma-separated list (default: $CLOUDDETECTX_PROVIDERS)")
        p.add_argument("--reports-dir", default=default, help="where incident reports are written (default: reports/)")
        return p

    # Options may go before or after the subcommand; SUPPRESS stops the subcommand
    # from overwriting a value given before it.
    common = common_options(argparse.SUPPRESS)
    parser = argparse.ArgumentParser(
        prog="clouddetectx", parents=[common_options(None)],
        description="CloudDetectX: find exposed cloud storage on AWS, Azure and GCP, prove what leaked, and seal it.",
    )
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("whoami", parents=[common], help="verify credentials for each provider")
    p.set_defaults(func=cmd_whoami)

    p = sub.add_parser("scan", parents=[common], help="find publicly exposed storage (read-only)")
    p.add_argument("names", nargs="*", help="only these buckets/storage accounts")
    p.add_argument("--all", action="store_true", help="show every finding for every resource")
    p.add_argument("--json", help="also write results to this JSON file")
    p.add_argument("--all-accounts", action="store_true",
                   help="every AWS Organizations account / Azure subscription / GCP project you can reach")
    p.add_argument("--no-account-checks", "--no-iam", dest="no_account_checks", action="store_true",
                   help="skip IAM and account-wide checks")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("discover", parents=[common], help="find secrets and personal data inside a resource (read-only)")
    p.add_argument("name")
    p.add_argument("--max-objects", type=int, help="objects to sample (default from settings)")
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser("verify", parents=[common], help="prove exposure with anonymous requests from the internet")
    p.add_argument("name")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("investigate", parents=[common], help="analyze access logs and change history (read-only)")
    p.add_argument("name")
    p.add_argument("--days", type=int, help="look-back window (default: $CLOUDDETECTX_LOOKBACK_DAYS or 30)")
    p.set_defaults(func=cmd_investigate)

    p = sub.add_parser("remediate", parents=[common], help="remove public access from one resource")
    p.add_argument("name")
    p.add_argument("--dry-run", action="store_true", help="show the plan only; change nothing")
    p.add_argument("--harden", action="store_true", help="also enable encryption/versioning/TLS where applicable")
    p.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    p.set_defaults(func=cmd_remediate)

    p = sub.add_parser("respond", parents=[common], help="full workflow: scan, investigate, remediate, verify, report")
    p.add_argument("names", nargs="*", help="only these buckets/storage accounts")
    p.add_argument("--days", type=int, help="investigation look-back window")
    p.add_argument("--verify", action="store_true", help="prove each exposure with anonymous requests")
    p.add_argument("--discover", action="store_true", help="scan each exposed resource for secrets / personal data")
    p.add_argument("--remediate", action="store_true", help="fix exposed resources (asks for confirmation)")
    p.add_argument("--dry-run", action="store_true", help="include the remediation plan without applying it")
    p.add_argument("--harden", action="store_true", help="also apply hardening during remediation")
    p.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    p.set_defaults(func=cmd_respond)

    p = sub.add_parser("compliance", parents=[common], help="controls affected by findings (NIST, CIS, ISO 27001)")
    p.add_argument("names", nargs="*", help="only these buckets/storage accounts")
    p.add_argument("--framework", choices=["NIST", "CIS8", "ISO", "CISB", "nist", "cis8", "iso", "cisb"])
    p.add_argument("--json", help="also write the result to this JSON file")
    p.add_argument("--report", action="store_true", help="write a compliance report (Markdown + JSON) to the reports folder")
    p.add_argument("--pdf", action="store_true", help="with --report, also write a PDF")
    p.add_argument("--all-accounts", action="store_true", help="every account / subscription / project you can reach")
    p.add_argument("--no-account-checks", "--no-iam", dest="no_account_checks", action="store_true",
                   help="skip IAM and account-wide checks")
    p.set_defaults(func=cmd_compliance)

    p = sub.add_parser("account", aliases=["iam"], parents=[common],
                       help="IAM permissions and account-wide checks (logging, root/MFA, network, databases, keys)")
    p.add_argument("--all", action="store_true", help="list every principal and finding, not only flagged ones")
    p.add_argument("--json", help="also write the review to this JSON file")
    p.set_defaults(func=cmd_account)

    p = sub.add_parser("waivers", parents=[common], help="accept a risk (e.g. a bucket that is public on purpose)")
    p.add_argument("action", nargs="?", choices=["list", "add", "remove"], default="list")
    p.add_argument("resource", nargs="?", help="resource name (add) or waiver ID (remove)")
    p.add_argument("--check", help="check ID, e.g. AWS-S3-003, or '*' for every check on the resource")
    p.add_argument("--reason", help="why this is acceptable")
    p.add_argument("--expires", help="date the waiver ends, e.g. 2027-06-30 (max two years)")
    p.set_defaults(func=cmd_waivers)

    p = sub.add_parser("rollback", parents=[common], help="undo a remediation using the configuration saved in its report")
    p.add_argument("report", help="incident report ID (INC-...)")
    p.add_argument("--dry-run", action="store_true", help="show what would be restored")
    p.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    p.set_defaults(func=cmd_rollback)

    p = sub.add_parser("export", parents=[common], help="scan and export findings as SARIF, OCSF or CSV")
    p.add_argument("--format", choices=["sarif", "ocsf", "csv", "all"], default="sarif")
    p.add_argument("-o", "--output", help="output file (single format) or folder (default: reports folder)")
    p.add_argument("--all-accounts", action="store_true", help="every account / subscription / project you can reach")
    p.add_argument("--no-account-checks", dest="no_account_checks", action="store_true", help="skip account-wide checks")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("schedule", parents=[common], help="run scans automatically (Task Scheduler / cron)")
    p.add_argument("action", nargs="?", choices=["install", "remove", "status"], default="status")
    p.add_argument("--every", type=int, default=1440, help="minutes between scans (default 1440 = daily, min 15)")
    p.add_argument("--all-accounts", action="store_true", help="scan every account each time")
    p.add_argument("--print", action="store_true", help="show the task instead of installing it")
    p.set_defaults(func=cmd_schedule)

    p = sub.add_parser("history", parents=[common], help="scan history and security-score trend")
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=cmd_history)

    p = sub.add_parser("watch", parents=[common], help="re-scan on a schedule and alert on new exposures")
    p.add_argument("--every", type=int, default=60, help="minutes between scans (default 60)")
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("alert-test", parents=[common], help="send a test message to the configured webhook")
    p.set_defaults(func=cmd_alert_test)

    p = sub.add_parser("web", parents=[common], help="open the web dashboard in your browser (local only)")
    p.add_argument("--port", type=int, default=8765, help="port on 127.0.0.1 (default 8765, next free one if taken)")
    p.add_argument("--no-browser", action="store_true", help="don't open the browser automatically")
    p.set_defaults(func=cmd_web)

    p = sub.add_parser("config", parents=[common],
                       help="view and change settings (interactive menu when no action is given)",
                       description="config            interactive settings menu\n"
                                   "config wizard     guided setup (sign in to clouds, investigation options)\n"
                                   "config show       list every setting\n"
                                   "config set KEY [VALUE]   change one (prompted if VALUE is omitted)\n"
                                   "config unset KEY  reset one to its default",
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("action", nargs="?", choices=["show", "set", "unset", "wizard", "migrate-secrets"])
    p.add_argument("key", nargs="?", help="setting name, e.g. AWS_PROFILE, aws_region, CLOUDDETECTX_LOOKBACK_DAYS")
    p.add_argument("value", nargs="?", help="new value; omit it to be prompted (recommended for secrets)")
    p.set_defaults(func=cmd_config)
    return parser


def cmd_web(args, settings: Settings) -> int:
    from clouddetectx.web.server import serve

    return serve(settings, port=args.port, open_browser=not args.no_browser)


def cmd_config(args, settings: Settings) -> int:
    from clouddetectx.config import ENV_FILE, FIELDS, ConfigError, display, find_field

    if args.action in (None, "wizard"):
        if not sys.stdin.isatty():
            raise ConfigError("The interactive settings menu needs a terminal; use `config set KEY VALUE` in scripts.")
        from clouddetectx.config_ui import ConfigMenu

        menu = ConfigMenu(settings)
        menu.wizard() if args.action == "wizard" else menu.run()
        return EXIT_OK

    if args.action == "show":
        table = Table(title=f"Settings ({ENV_FILE})", title_justify="left", expand=True)
        for col in ("Section", "Setting", "Value", "Variable"):
            table.add_column(col)
        for f in FIELDS:
            where = settings.secret_locations.get(f.key)
            value = display(f, settings.get(f)) + (f" [dim]in {'OS keychain' if where == 'keychain' else '.env'}[/]" if where else "")
            table.add_row(f.section, f.label, value, f.key)
        console.print(table)
        return EXIT_OK

    if args.action == "migrate-secrets":
        from clouddetectx.config import secret_store

        if not secret_store.available:
            console.print("[yellow]No OS keychain is available here; secrets stay in .env.[/]")
            return EXIT_ERROR
        moved = settings.migrate_secrets()
        console.print(f"[green]Moved to the OS keychain:[/] {', '.join(moved)}" if moved else "Nothing to move: no secrets in .env.")
        return EXIT_OK

    if not args.key:
        raise ConfigError(f"Usage: python main.py config {args.action} KEY" + (" [VALUE]" if args.action == "set" else ""))
    f = find_field(args.key)
    raw = "" if args.action == "unset" else args.value
    if raw is None:
        if not sys.stdin.isatty():
            raw = sys.stdin.readline().rstrip("\r\n")  # e.g. `echo $SECRET | python main.py config set KEY`
        else:
            import getpass

            console.print(f"[dim]{f.help}[/]")
            raw = getpass.getpass(f"{f.label} (hidden): ") if f.secret else input(f"{f.label}: ")
    value = settings.set(f, raw)
    where = "the OS keychain" if settings.secret_locations.get(f.key) == "keychain" else str(ENV_FILE)
    console.print(f"[green]Saved[/] {f.label} = [bold]{display(f, value)}[/]  [dim]({f.key} in {where})[/]")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = Settings.load()
    if args.reports_dir:
        settings.reports_dir = Path(args.reports_dir)
    from clouddetectx.config import ConfigError

    try:
        if not args.command:
            from clouddetectx.interactive import InteractiveApp

            provider = _providers(args.provider)[0] if (args.provider or os.getenv("CLOUDDETECTX_PROVIDERS")) else None
            return InteractiveApp(settings, provider).run()
        for warning in settings.warnings:
            console.print(f"[yellow]Config warning:[/] {warning}")
        return args.func(args, settings)
    except (ProviderError, ConfigError) as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        return EXIT_ERROR
    except KeyboardInterrupt:
        console.print("\nInterrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
