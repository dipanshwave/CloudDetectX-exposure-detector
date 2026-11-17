"""Interactive terminal UI (arrow-key menus). Started by running `python main.py` with no command."""

from __future__ import annotations

import os
import subprocess
import sys
import webbrowser
from datetime import datetime
from pathlib import Path

import questionary
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from clouddetectx import __version__
from clouddetectx.cli import (
    EXIT_ERROR,
    EXIT_OK,
    VERDICT_STYLE,
    console,
    print_actions,
    print_findings,
    print_investigation,
    print_outcome,
    print_proof,
    print_risk,
    print_scan_table,
    print_sensitive,
    save_incident,
    sev,
)
from clouddetectx.config import ENV_FILE, SECTION_PROVIDER, Field, Settings
from clouddetectx.config_ui import ConfigMenu
from clouddetectx.engine import ScanResult, SecurityEngine, after_scan, alert_data_accessed
from clouddetectx.models import Investigation
from clouddetectx.prompts import BACK, STYLE, Choice, Separator
from clouddetectx.prompts import confirm as _confirm
from clouddetectx.prompts import select as _select
from clouddetectx.prompts import text as _text
from clouddetectx.providers import PROVIDERS, ProviderError, get_provider

SEV_TOKEN = {"CRITICAL": "fg:#ffffff bg:#d70000 bold", "HIGH": "fg:#ff5f5f bold", "MEDIUM": "fg:#ffd700",
             "LOW": "fg:#5fafff", "INFO": "fg:#808080"}
PROVIDER_SECTION = {p: s for s, p in SECTION_PROVIDER.items()}


def _int_validator(lo: int, hi: int):
    def check(value: str):
        if value.isdigit() and lo <= int(value) <= hi:
            return True
        return f"Enter a whole number between {lo} and {hi}"
    return check


def _ago(ts: datetime | None) -> str:
    if not ts:
        return "never"
    secs = int((datetime.now() - ts).total_seconds())
    if secs < 60:
        return "just now"
    if secs < 3600:
        return f"{secs // 60} min ago"
    return f"{secs // 3600} h ago"


class InteractiveApp:
    def __init__(self, settings: Settings, provider_name: str | None = None):
        self.settings = settings
        self.initial_provider = provider_name
        self.provider_name: str | None = None
        self.provider = None
        self.engine: SecurityEngine | None = None
        self.account = ""
        self.results: dict[str, ScanResult] = {}
        self.investigations: dict[str, Investigation] = {}
        self.scanned_at: datetime | None = None
        self.iam = None
        self.iam_error: str | None = None
        self._reconnect = False

    # ------------------------------------------------------------------ main loop
    def run(self) -> int:
        if not sys.stdin.isatty():
            console.print("Interactive mode needs a terminal. For scripts use commands, e.g. "
                          "`python main.py -p aws scan` (see `python main.py --help`).")
            return EXIT_ERROR
        console.print(Panel.fit(
            f"[bold]CloudDetectX[/] v{__version__}\n"
            "[dim]Find it. Prove it. Seal it.[/]\n"
            "[dim]AWS S3 | Azure Blob Storage | Google Cloud Storage[/]",
            border_style="cyan",
        ))
        for warning in self.settings.warnings:
            console.print(f"[yellow]Config warning:[/] {warning}")
        if not ENV_FILE.exists():
            console.print("No configuration found yet.")
            if _confirm("Run the setup wizard now? (recommended)", True):
                self.config_menu().wizard()
                self.initial_provider = self.initial_provider or (self.settings.providers or [None])[0]
        if self.initial_provider:
            self.connect(self.initial_provider)

        while True:
            try:
                if not self.provider:
                    if not self.choose_provider():
                        break
                    continue
                action = self.main_menu()
                if action in (None, "exit"):
                    break
                getattr(self, action)()
            except ProviderError as exc:
                console.print(f"[bold red]Error:[/] {exc}")
            except KeyboardInterrupt:
                console.print("[dim]Cancelled.[/]")
        console.print("[dim]Goodbye.[/]")
        return EXIT_OK

    def main_menu(self):
        exposed = [r for r in self.results.values() if r.exposed]
        status = (f"{len(self.results)} resources scanned {_ago(self.scanned_at)}, "
                  + (f"[bold red]{len(exposed)} PUBLIC[/]" if exposed else "[green]none public[/]")
                  if self.scanned_at else "[dim]not scanned yet[/]")
        console.print()
        console.rule(f"[bold cyan]{PROVIDERS[self.provider_name]}[/]  [dim]{self.account}[/]")
        console.print(f"  {status}")
        browse = "Browse resources" + (f" ({len(self.results)})" if self.results else "")
        return _select("What do you want to do?", [
            Choice("Scan for public exposure", "do_scan"),
            Choice(browse, "do_browse"),
            Choice("Incident response: investigate and fix exposed resources", "do_respond"),
            Choice("Identity & access: who can reach your storage (IAM)", "do_iam"),
            Choice("Compliance: pass rates, failing controls, compliance report", "do_compliance"),
            Choice("Scan history and drift", "do_history"),
            Choice("View incident reports", "do_reports"),
            Separator(),
            Choice(f"Switch cloud provider (current: {self.provider_name.upper()})", "do_switch"),
            Choice("Settings", "do_settings"),
            Choice("Exit", "exit"),
        ])

    # ------------------------------------------------------------------ providers
    def _provider_hint(self, name: str) -> str:
        s = self.settings
        if name == "aws":
            return f"profile: {s.aws_profile or 'default credential chain'}"
        if name == "azure":
            return f"subscription: {s.azure_subscription_id}" if s.azure_subscription_id else "not set up yet"
        return f"project: {s.gcp_project or 'gcloud default'}"

    def choose_provider(self) -> bool:
        choices = [Choice(f"{PROVIDERS[n]:<34} [{self._provider_hint(n)}]", n) for n in PROVIDERS]
        choices += [Separator(), Choice("Settings", "settings"), Choice("Exit", "exit")]
        name = _select("Which cloud do you want to work on?", choices)
        if name in (None, "exit"):
            return False
        if name == "settings":
            self.do_settings()
            return True
        if name == "azure" and not self.settings.azure_subscription_id:
            console.print("Azure isn't set up yet.")
            if not self.config_menu().setup_provider("azure"):
                return True
        self.connect(name)
        return True

    def connect(self, name: str) -> bool:
        try:
            with console.status(f"Connecting to {PROVIDERS[name]}..."):
                provider = get_provider(name, self.settings)
                account = provider.account_label()
        except ProviderError as exc:
            console.print(f"[bold red]Could not connect:[/] {exc}")
            if _confirm(f"Open the {PROVIDER_SECTION[name]} sign-in settings to fix this?", True):
                if self.config_menu().setup_provider(name):
                    return self.connect(name)
            return False
        self.provider_name, self.provider, self.account = name, provider, account
        self.engine = SecurityEngine(provider, self.settings)
        self.results, self.investigations, self.scanned_at = {}, {}, None
        self.iam, self.iam_error = None, None
        console.print(f"[green]Connected:[/] {account}")
        return True

    # ------------------------------------------------------------------ settings
    def config_menu(self) -> ConfigMenu:
        return ConfigMenu(self.settings, on_change=self._on_config_change)

    def _on_config_change(self, f: Field) -> None:
        # Sign-in settings of the cloud we're connected to changed: reconnect on the next menu.
        if self.provider and SECTION_PROVIDER.get(f.section) == self.provider_name:
            self._reconnect = True

    def do_settings(self) -> None:
        self._reconnect = False
        self.config_menu().run()
        if self._reconnect and self.provider_name:
            console.print("Sign-in settings changed; reconnecting...")
            current = self.provider_name
            self.provider = None
            self.connect(current)

    def do_switch(self) -> None:
        self.provider = None

    # ------------------------------------------------------------------ scan / browse
    def _scan(self) -> None:
        with console.status("Scanning...") as status:
            results = self.engine.scan(on_progress=lambda n: status.update(f"Scanning [bold]{n}[/]..."))
        self.results = {r.posture.resource.name: r for r in results}
        self.scanned_at = datetime.now()
        outcome = after_scan(self.settings, self.provider_name, self.account, results, investigations=self.investigations)
        from clouddetectx.cli import _identity
        from clouddetectx.overview import grade

        self.iam, self.iam_error = _identity(self.provider)
        print_scan_table(self.provider_name, self.account, results, outcome.risks)
        print_outcome(outcome)
        if outcome.posture_score is not None:
            console.print(f"Grade: [bold]{grade(outcome.posture_score)}[/]")
        if self.iam is not None:
            c = self.iam.counts()
            console.print(f"IAM: {c['principals']} principal(s) analysed, "
                          + (f"[bold red]{c['risky']} flagged[/]" if c["risky"] else "[green]none flagged[/]")
                          + " (menu: Identity & access)")
        elif self.iam_error:
            console.print(f"[yellow]IAM analysis skipped:[/] {self.iam_error}")

    def do_scan(self) -> None:
        self._scan()
        exposed = [r for r in self.results.values() if r.exposed]
        if not exposed:
            console.print("[green]No publicly exposed storage found.[/]")
            return
        console.print(f"[bold red]{len(exposed)} resource(s) are publicly exposed.[/]")
        name = _select("Open one now?", self._resource_choices(exposed) + [Separator(), Choice("Back to menu", BACK)])
        if name:
            self.resource_menu(name)

    def _resource_choices(self, results: list[ScanResult]) -> list[Choice]:
        choices = []
        for r in sorted(results, key=lambda r: (not r.exposed, r.posture.resource.name)):
            top = max((f.severity for f in r.findings), key=lambda s: s.rank, default=None)
            title = [
                ("fg:#ffffff bg:#d70000 bold" if r.exposed else "fg:#5fd75f", " PUBLIC  " if r.exposed else " private "),
                ("", f" {r.posture.resource.name:<45} "),
                ("fg:#808080", f"{(r.posture.resource.location or '-'):<14} "),
            ]
            if top:
                title.append((SEV_TOKEN[top.value], f" {top.value} "))
            choices.append(Choice(title=title, value=r.posture.resource.name))
        return choices

    def do_browse(self) -> None:
        if not self.results:
            if not _confirm("No scan results yet. Scan now?", True):
                return
            self._scan()
        if not self.results:
            console.print("[yellow]No storage resources found.[/]")
            return
        name = _select("Choose a resource (type to filter):",
                       self._resource_choices(list(self.results.values())) + [Separator(), Choice("Back to menu", BACK)],
                       use_search_filter=True, use_jk_keys=False)
        if name:
            self.resource_menu(name)

    # ------------------------------------------------------------------ resource
    def resource_menu(self, name: str) -> None:
        while True:
            result = self.results[name]
            res = result.posture.resource
            console.print()
            console.rule(f"[bold]{name}[/]  [dim]{res.kind} | {res.location or '-'} | {res.resource_id}[/]")
            console.print("  Exposure: " + ("[bold white on red] PUBLIC [/]" if result.exposed else "[green]not publicly exposed[/]")
                          + f"   Findings: {len(result.findings)}"
                          + (f"   Access verdict: [{VERDICT_STYLE[self.investigations[name].verdict]}]"
                             f"{self.investigations[name].verdict}[/]" if name in self.investigations else ""))
            action = _select(f"{name}:", [
                Choice("View findings and risk score", "findings"),
                Choice("Discover sensitive data (secrets / personal data)", "discover"),
                Choice("Test exposure from the internet (anonymous requests)", "verify"),
                Choice("Investigate access and change history", "investigate"),
                Choice("Remediate (shows plan first)", "remediate"),
                Choice("Re-scan this resource", "rescan"),
                Choice("Save assessment report", "report"),
                Separator(),
                Choice("Back", BACK),
            ])
            if action is None:
                return
            if action == "findings":
                print_findings(result.all_findings, 0)
                print_risk(self.engine.risk(result, self.investigations.get(name)))
            elif action == "discover":
                with console.status("Discovering sensitive data...") as st:
                    report = self.engine.discover(result, on_progress=lambda m: st.update(m))
                print_sensitive(report)
            elif action == "verify":
                with console.status("Requesting public URLs without credentials..."):
                    proof = self.engine.verify_exposure(result)
                print_proof(proof)
            elif action == "investigate":
                self._investigate(name)
            elif action == "remediate":
                self._remediate(name, ask=True)
            elif action == "rescan":
                with console.status(f"Re-scanning {name}..."):
                    fresh = self.engine.scan_one(name)
                fresh.sensitive, fresh.proof, fresh.data_findings = result.sensitive, result.proof, result.data_findings
                self.results[name] = fresh
                print_findings(fresh.findings, 0)
            elif action == "report":
                save_incident(self.engine.new_incident(result, self.investigations.get(name)), self.settings)

    def _investigate(self, name: str, days: int | None = None) -> Investigation | None:
        if days is None:
            answer = _text("Look back how many days?", str(self.settings.lookback_days), _int_validator(1, 3650))
            if answer is None:
                return None
            days = int(answer)
        with console.status(f"Searching access and audit logs for the last {days} days..."):
            inv = self.engine.investigate(self.results[name].posture, days)
        self.investigations[name] = inv
        print_investigation(inv)
        err = alert_data_accessed(self.settings, self.provider_name, name, inv)
        if err:
            console.print(f"[bold red]Alert failed:[/] {err}")
        if inv.change_events:
            table = Table(title="Configuration changes", title_justify="left")
            for col in ("Time (UTC)", "Action", "Actor", "Source IP"):
                table.add_column(col)
            for c in inv.change_events[-15:]:
                table.add_row(f"{c.timestamp:%Y-%m-%d %H:%M}", c.action, c.actor or "-", c.source_ip or "-")
            console.print(table)
        return inv

    def _remediate(self, name: str, ask: bool, harden: bool | None = None) -> str:
        """Returns 'applied', 'planned', 'cancelled' or 'nothing'."""
        result = self.results[name]
        if harden is None:
            harden = _confirm("Also apply hardening (encryption / versioning / TLS where supported)?", False)
        with console.status("Building remediation plan..."):
            plan, _ = self.engine.remediate(result, dry_run=True, harden=harden)
        print_actions(plan, f"Remediation plan for {name}")
        inc = self.engine.new_incident(result, self.investigations.get(name))
        if all(a.status == "skipped" for a in plan):
            console.print("[green]Nothing to change.[/]")
            return "nothing"
        if ask:
            choice = _select("Apply these changes?", [
                Choice(f"Apply to the LIVE {self.provider_name.upper()} resource", "apply"),
                Choice("Save the plan as a report without changing anything", "plan"),
                Choice("Cancel", BACK),
            ])
            if choice is None:
                console.print("[yellow]Cancelled; nothing was changed.[/]")
                return "cancelled"
            if choice == "plan":
                inc.remediation = plan
                save_incident(inc, self.settings)
                return "planned"
            typed = _text(f"Type the resource name ({name}) to confirm:")
            if typed is None or typed.strip() != name:
                console.print("[yellow]Name did not match; nothing was changed.[/]")
                return "cancelled"
        with console.status("Applying remediation and verifying..."):
            actions, verification = self.engine.remediate(result, dry_run=False, harden=harden)
        inc.remediation, inc.verification = actions, verification
        print_actions(actions, "Remediation result")
        if verification is not None:
            still = [f for f in verification if f.exposes_data]
            if still:
                console.print("[bold red]Verification: exposure still present[/]")
                print_findings(still, 0)
            else:
                console.print("[bold green]Verification: no public exposure remains.[/]")
        save_incident(inc, self.settings)
        with console.status("Refreshing..."):
            fresh = self.engine.scan_one(name)
        fresh.sensitive, fresh.proof = result.sensitive, result.proof
        self.results[name] = fresh
        return "applied"

    # ------------------------------------------------------------------ incident response
    def do_respond(self) -> None:
        self._scan()
        exposed = [r for r in self.results.values() if r.exposed]
        if not exposed:
            console.print("[green]No publicly exposed storage found. Nothing to respond to.[/]")
            return
        selected = questionary.checkbox(
            "Which exposed resources should be handled?",
            choices=[Choice(r.posture.resource.name, r.posture.resource.name, checked=True) for r in exposed],
            style=STYLE, qmark=">", instruction="(space to toggle, Enter to continue)",
        ).ask()
        if not selected:
            return
        mode = _select("How should remediation be handled?", [
            Choice("Investigate, then ask me before fixing each resource", "ask"),
            Choice("Investigate and save plans only (change nothing)", "plan"),
            Choice("Investigate and fix all selected resources without asking", "auto"),
        ])
        if mode is None:
            return
        if mode == "auto" and not _confirm(
                f"This will modify {len(selected)} LIVE resource(s) without further prompts. Continue?", False):
            return
        harden = _confirm("Also apply hardening (encryption / versioning / TLS where supported)?", False)
        do_verify = _confirm("Prove each exposure with anonymous requests from the internet?", True)
        do_discover = _confirm("Scan contents for secrets and personal data (reads a sample of objects)?", True)
        days = self.settings.lookback_days

        summary = []
        for name in selected:
            console.print()
            console.rule(f"[bold red][ALERT][/] {name}")
            print_findings(self.results[name].findings)
            if do_verify:
                with console.status("Requesting public URLs without credentials..."):
                    print_proof(self.engine.verify_exposure(self.results[name]))
            if do_discover:
                with console.status("Discovering sensitive data...") as st:
                    print_sensitive(self.engine.discover(self.results[name], on_progress=lambda m: st.update(m)))
            inv = self._investigate(name, days)
            print_risk(self.engine.risk(self.results[name], inv))
            if mode == "plan":
                result = self.results[name]
                with console.status("Building remediation plan..."):
                    plan, _ = self.engine.remediate(result, dry_run=True, harden=harden)
                print_actions(plan, f"Remediation plan for {name}")
                inc = self.engine.new_incident(result, inv)
                inc.remediation = plan
                save_incident(inc, self.settings)
                outcome = "planned"
            else:
                outcome = self._remediate(name, ask=(mode == "ask"), harden=harden)
                if outcome == "cancelled":
                    save_incident(self.engine.new_incident(self.results[name], inv), self.settings)
            summary.append((name, inv.verdict if inv else "-", outcome,
                            "PUBLIC" if self.results[name].exposed else "private"))

        table = Table(title="Incident response summary", title_justify="left")
        for col in ("Resource", "Access verdict", "Remediation", "Exposure now"):
            table.add_column(col)
        for name, verdict, outcome, now in summary:
            table.add_row(name, f"[{VERDICT_STYLE.get(verdict, '')}]{verdict}[/]" if verdict != "-" else "-", outcome,
                          "[bold white on red] PUBLIC [/]" if now == "PUBLIC" else "[green]private[/]")
        console.print(table)
        console.print(f"Reports saved in [bold]{self.settings.reports_dir.resolve()}[/]")

    # ------------------------------------------------------------------ compliance & history
    def do_iam(self) -> None:
        from clouddetectx.cli import print_iam_summary

        if self.provider_name != "aws":
            console.print("[dim]IAM analysis is available for AWS. Azure RBAC and GCP IAM are not analysed yet.[/]")
            return
        if not self.results:
            self._scan()
        print_iam_summary(self.iam, self.iam_error, show_all=_confirm("List every principal (not only flagged ones)?", False))
        for note in (self.iam.notes if self.iam else []):
            console.print(f"[dim]{note}[/]")

    def do_compliance(self) -> None:
        from clouddetectx.compliance import FRAMEWORKS
        from clouddetectx.overview import compliance as compliance_data

        if not self.results:
            self._scan()
        data = compliance_data(self.provider_name, list(self.results.values()), self.iam)
        summary = Table(title="Compliance summary", title_justify="left", expand=True)
        for col, just in (("Framework", "left"), ("Controls", "right"), ("Fully passing", "right"),
                          ("Resource-level pass rate", "right")):
            summary.add_column(col, justify=just)
        for st in data["status"].values():
            rate = st["pass_rate"]
            style = "green" if (rate or 0) >= 80 else "yellow" if (rate or 0) >= 50 else "red"
            summary.add_row(st["name"], str(st["assessed"]), str(st["passing"]),
                            f"[{style}]{rate}%[/]" if rate is not None else "-")
        console.print(summary)
        fw = _select("Show failing controls for", [Choice("All frameworks", "all")]
                     + [Choice(v, k) for k, v in FRAMEWORKS.items()]
                     + [Choice("Save a compliance report", "report"), Choice("Back", BACK)])
        if fw is None:
            return
        if fw == "report":
            self._compliance_report()
            return
        rows = [r for r in data["controls"] if fw == "all" or r["framework"] == fw]
        table = Table(title=f"Failing controls ({len(self.results)} resources assessed)", title_justify="left", expand=True)
        for col in ("Framework", "Control", "Title", "Worst", "Resources"):
            table.add_column(col)
        for r in rows:
            table.add_row(FRAMEWORKS[r["framework"]], r["id"], r["title"], sev(r["worst"]),
                          ", ".join(r["resources"][:3]) + (f" +{len(r['resources']) - 3}" if len(r["resources"]) > 3 else ""))
        if not rows:
            table.add_row("-", "-", "No failing controls", "-", "-")
        console.print(table)

    def _compliance_report(self) -> None:
        from clouddetectx.reporting import build_compliance_report, write_compliance_report
        from clouddetectx.risk import posture_score, score_resource

        risks = {n: score_resource(r.findings, self.investigations.get(n), r.sensitive, r.proof)
                 for n, r in self.results.items()}
        data = build_compliance_report(self.provider_name, PROVIDERS[self.provider_name], self.account,
                                       list(self.results.values()), risks, self.iam,
                                       posture_score(list(risks.values())))
        md_path, _ = write_compliance_report(data, self.settings.reports_dir)
        console.print(f"[green]Compliance report saved:[/] {md_path}")

    def do_history(self) -> None:
        from clouddetectx.history import History

        h = History(self.settings.data_dir)
        try:
            rows = h.trend(self.provider_name, self.account, limit=20)
        finally:
            h.close()
        table = Table(title=f"Scan history | {self.account}", title_justify="left")
        for col in ("Scanned (UTC)", "Resources", "Public", "Mitigated", "Security score"):
            table.add_column(col, justify="left" if col.startswith("Scanned") else "right")
        for r in rows:
            table.add_row(r["scanned_at"][:19].replace("T", " "), str(r["resources"]),
                          f"[bold red]{r['public']}[/]" if r["public"] else "0", str(r["mitigated"]),
                          "-" if r["posture_score"] is None else str(r["posture_score"]))
        if not rows:
            table.add_row("No scans recorded yet", "", "", "", "")
        console.print(table)

    # ------------------------------------------------------------------ reports
    def do_reports(self) -> None:
        folder = self.settings.reports_dir
        reports = sorted(list(folder.glob("INC-*.md")) + list(folder.glob("CMP-*.md")),
                         key=lambda p: p.stat().st_mtime, reverse=True) if folder.exists() else []
        if not reports:
            console.print(f"[yellow]No reports in {folder.resolve()} yet.[/]")
            return
        path = _select("Choose a report (type to filter):",
                       [Choice(p.stem, p) for p in reports[:100]] + [Separator(), Choice("Back", BACK)],
                       use_search_filter=True, use_jk_keys=False)
        if not path:
            return
        action = _select(path.name, [
            Choice("Show here in the terminal", "show"),
            Choice("Open with the default app", "open"),
            Choice("Back", BACK),
        ])
        if action == "show":
            console.print(Markdown(path.read_text(encoding="utf-8")))
        elif action == "open":
            self._open_file(path)

    @staticmethod
    def _open_file(path: Path) -> None:
        try:
            if sys.platform == "win32":
                os.startfile(path.resolve())  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.run(["open", str(path)], check=False)
            else:
                webbrowser.open(path.resolve().as_uri())
        except OSError as exc:
            console.print(f"[red]Could not open {path}: {exc}[/]")
