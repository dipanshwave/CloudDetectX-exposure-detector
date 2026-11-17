"""Interactive configuration: every setting, cloud sign-in and a first-run setup wizard."""

from __future__ import annotations

import configparser
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Callable

from rich.panel import Panel
from rich.table import Table

from clouddetectx.cli import console
from clouddetectx.config import (
    ENV_FILE,
    FIELDS,
    PROVIDER_NAMES,
    SECTION_PROVIDER,
    SECTION_TITLES,
    SECTIONS,
    ConfigError,
    Field,
    Settings,
    display,
    find_field,
    parse_value,
    to_text,
)
from clouddetectx.prompts import BACK, Choice, Separator, checkbox, confirm, password, select, text
from clouddetectx.providers import PROVIDERS, ProviderError, get_provider


CLI_INSTALL = {
    "aws": "https://aws.amazon.com/cli/",
    "az": "https://aka.ms/installazurecli",
    "gcloud": "https://cloud.google.com/sdk/docs/install",
}


def _validator(f: Field) -> Callable[[str], bool | str]:
    def check(value: str):
        try:
            parse_value(f, value)
            return True
        except ConfigError as exc:
            return str(exc)
    return check


def _run_cli(*args: str) -> bool:
    """Run a cloud CLI attached to this terminal (for interactive sign-in)."""
    exe = shutil.which(args[0])
    if not exe:
        console.print(f"[yellow]'{args[0]}' is not installed.[/] Install it from {CLI_INSTALL[args[0]]} "
                      "or choose another sign-in method.")
        return False
    console.print(f"[dim]Running: {' '.join(args)}[/]")
    try:
        return subprocess.run([exe, *args[1:]], check=False).returncode == 0
    except OSError as exc:
        console.print(f"[red]Could not run {args[0]}: {exc}[/]")
        return False


def _cli_json(*args: str) -> list | dict | None:
    exe = shutil.which(args[0])
    if not exe:
        return None
    try:
        out = subprocess.run([exe, *args[1:]], capture_output=True, text=True, timeout=90, check=False)
        return json.loads(out.stdout) if out.returncode == 0 and out.stdout.strip() else None
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return None


# --------------------------------------------------------------------------- AWS helpers

def _aws_profiles() -> list[str]:
    try:
        import boto3

        return sorted(boto3.session.Session().available_profiles)
    except Exception:  # noqa: BLE001 - a broken ~/.aws/config must not stop the menu
        return []


def _aws_regions() -> list[str]:
    try:
        import boto3

        return sorted(boto3.session.Session().get_available_regions("s3"))
    except Exception:  # noqa: BLE001
        return ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-south-1"]


def _write_aws_profile(profile: str, key_id: str, secret: str, region: str | None) -> Path:
    """Write access keys the same way `aws configure` does (~/.aws/credentials + ~/.aws/config)."""
    cred_path = Path(os.getenv("AWS_SHARED_CREDENTIALS_FILE") or Path.home() / ".aws" / "credentials")
    conf_path = Path(os.getenv("AWS_CONFIG_FILE") or Path.home() / ".aws" / "config")
    cred_path.parent.mkdir(parents=True, exist_ok=True)

    creds = configparser.RawConfigParser()
    creds.read(cred_path)
    if not creds.has_section(profile):
        creds.add_section(profile)
    creds.set(profile, "aws_access_key_id", key_id)
    creds.set(profile, "aws_secret_access_key", secret)
    with open(cred_path, "w", encoding="utf-8") as fh:
        creds.write(fh)
    try:
        os.chmod(cred_path, 0o600)
    except OSError:
        pass

    if region:
        conf = configparser.RawConfigParser()
        conf.read(conf_path)
        section = "default" if profile == "default" else f"profile {profile}"
        if not conf.has_section(section):
            conf.add_section(section)
        conf.set(section, "region", region)
        with open(conf_path, "w", encoding="utf-8") as fh:
            conf.write(fh)
    return cred_path


# --------------------------------------------------------------------------- menu

class ConfigMenu:
    def __init__(self, settings: Settings, on_change: Callable[[Field], None] | None = None):
        self.settings = settings
        self.on_change = on_change

    # -- saving -----------------------------------------------------------------
    def save(self, f: Field, raw: str | None) -> bool:
        try:
            value = self.settings.set(f, raw)
        except ConfigError as exc:
            console.print(f"[red]{exc}[/]")
            return False
        console.print(f"[green]Saved[/] {f.label} = [bold]{display(f, value)}[/]  [dim]({f.key} in {ENV_FILE.name})[/]")
        if self.on_change:
            self.on_change(f)
        return True

    def field(self, key: str) -> Field:
        return find_field(key)

    # -- top level ----------------------------------------------------------------
    def run(self) -> None:
        while True:
            console.print()
            console.rule("[bold cyan]Settings[/]")
            console.print(f"  [dim]Saved in {ENV_FILE}[/]")
            choices = [Choice(f"{SECTION_TITLES[s]:<32} {self._section_summary(s)}", s) for s in SECTIONS]
            choices += [
                Separator(),
                Choice("Run the setup wizard", "wizard"),
                Choice("Show all settings", "show"),
                Choice("Back", BACK),
            ]
            choice = select("Which settings?", choices)
            if choice is None:
                return
            if choice == "wizard":
                self.wizard()
            elif choice == "show":
                self.show()
            else:
                self.section_menu(choice)

    def _section_summary(self, section: str) -> str:
        s = self.settings
        if section == "General":
            return f"[clouds: {', '.join(s.providers)}]"
        if section == "AWS":
            return f"[profile: {s.aws_profile or 'default chain'}, region: {s.aws_region or 'not set'}]"
        if section == "Azure":
            sub = s.azure_subscription_id
            return f"[subscription: {sub[:8] + '...' if sub else 'not set'}" + (", service principal]" if s.azure_client_id else "]")
        if section == "GCP":
            return f"[project: {s.gcp_project or 'gcloud default'}" + (", key file]" if s.gcp_credentials_file else "]")
        return f"[{s.lookback_days} days, {len(s.trusted_networks)} trusted network(s)]"

    def section_menu(self, section: str) -> None:
        provider = SECTION_PROVIDER.get(section)
        while True:
            fields = [f for f in FIELDS if f.section == section]
            width = max(len(f.label) for f in fields) + 2
            choices = [Choice(f"{f.label:<{width}} {display(f, self.settings.get(f))}", f.key, description=f.help)
                       for f in fields]
            if provider:
                choices += [Separator(),
                            Choice("Sign in / set up credentials", "signin"),
                            Choice("Test connection", "test")]
            choices += [Separator(), Choice("Back", BACK)]
            choice = select(f"{SECTION_TITLES[section]} settings:", choices)
            if choice is None:
                return
            if choice == "signin":
                self.sign_in(provider)
            elif choice == "test":
                self.test(provider)
            else:
                self.edit(self.field(choice))

    def show(self) -> None:
        table = Table(title=f"Settings ({ENV_FILE})", title_justify="left", expand=True)
        table.add_column("Section")
        table.add_column("Setting", style="bold")
        table.add_column("Value")
        table.add_column("Variable", style="dim")
        for f in FIELDS:
            table.add_row(f.section, f.label, display(f, self.settings.get(f)), f.key)
        console.print(table)

    # -- editing a single field ---------------------------------------------------------
    def edit(self, f: Field) -> bool:
        console.print(f"[dim]{f.help}[/]")
        current = to_text(f, self.settings.get(f))
        handler = getattr(self, f"_edit_{f.kind}", None)
        if handler:
            return handler(f, current)
        if f.secret:
            choice = select(f"{f.label}:", [Choice("Enter a new value", "set"), Choice("Clear it", "clear"),
                                            Choice("Back", BACK)])
            if choice == "set":
                value = password(f"{f.label}:", validate=lambda v: bool(v.strip()) or "Cannot be empty")
                return value is not None and self.save(f, value)
            return choice == "clear" and self.save(f, "")
        value = text(f"{f.label}:", current, _validator(f),
                     instruction="(empty = " + (f"default {f.default})" if f.default else "not set)"))
        return value is not None and self.save(f, value)

    def _edit_providers(self, f: Field, current: str) -> bool:
        chosen = checkbox("Which clouds do you use?",
                          [Choice(PROVIDERS[p], p, checked=p in self.settings.providers) for p in PROVIDER_NAMES],
                          validate=lambda v: bool(v) or "Select at least one")
        if not chosen:
            return False
        if len(chosen) > 1:
            first = select("Which one should interactive mode start on?", [Choice(PROVIDERS[p], p) for p in chosen])
            if first:
                chosen = [first] + [p for p in chosen if p != first]
        return self.save(f, ",".join(chosen))

    def _edit_region(self, f: Field, current: str) -> bool:
        regions = _aws_regions()
        if current and current not in regions:
            regions.insert(0, current)
        choices = [Choice("(not set)", "")] + [Choice(r, r) for r in regions] + [Choice("Back", BACK)]
        value = select("AWS region (type to filter):", choices, default=current or None,
                       use_search_filter=True, use_jk_keys=False)
        return value is not None and self.save(f, value)

    def _edit_profile(self, f: Field, current: str) -> bool:
        profiles = _aws_profiles()
        choices = [Choice("(not set: default credential chain)", "")]
        choices += [Choice(p + ("   <- current" if p == current else ""), p) for p in profiles]
        choices += [Separator(),
                    Choice("Create a profile with access keys", "__keys__"),
                    Choice("Set up an AWS IAM Identity Center (SSO) profile", "__sso__"),
                    Choice("Back", BACK)]
        value = select("AWS profile:", choices)
        if value is None:
            return False
        if value == "__keys__":
            return self._aws_create_key_profile(f)
        if value == "__sso__":
            return self._aws_sso_profile(f)
        return self.save(f, value)

    def _aws_create_key_profile(self, f: Field) -> bool:
        name = text("Profile name:", "clouddetectx", lambda v: (bool(v.strip()) and " " not in v) or "No spaces")
        if not name:
            return False
        key_id = text("Access key ID:", validate=lambda v: (len(v.strip()) >= 16) or "That doesn't look like an access key ID")
        if not key_id:
            return False
        secret = password("Secret access key:", validate=lambda v: (len(v.strip()) >= 20) or "That doesn't look like a secret key")
        if not secret:
            return False
        regions = _aws_regions()
        preferred = self.settings.aws_region if self.settings.aws_region in regions else "us-east-1"
        region = select("Default region for this profile (type to filter):", [Choice(r, r) for r in regions],
                        default=preferred if preferred in regions else None, use_search_filter=True, use_jk_keys=False)
        path = _write_aws_profile(name.strip(), key_id.strip(), secret.strip(), region)
        console.print(f"[green]Stored profile '{name.strip()}' in {path}[/] [dim](the key is not written to .env)[/]")
        return self.save(f, name.strip())

    def _aws_sso_profile(self, f: Field) -> bool:
        before = set(_aws_profiles())
        if not _run_cli("aws", "configure", "sso"):
            return False
        new = sorted(set(_aws_profiles()) - before)
        if new:
            return self.save(f, new[0])
        return self._edit_profile(f, to_text(f, self.settings.get(f)))

    def _edit_subscription(self, f: Field, current: str) -> bool:
        subs = _cli_json("az", "account", "list", "--all", "-o", "json") or []
        choices = [Choice(f"{s.get('name', '?')}  ({s['id']})" + ("   <- current" if s["id"] == current else ""), s["id"])
                   for s in subs if s.get("state", "Enabled") == "Enabled"]
        if not subs:
            console.print("[dim]No subscriptions found via the Azure CLI (not installed or not signed in).[/]")
        choices += [Separator(), Choice("Type a subscription ID", "__type__"),
                    Choice("Sign in with the Azure CLI first", "__login__"), Choice("Back", BACK)]
        value = select("Azure subscription:", choices)
        if value is None:
            return False
        if value == "__login__":
            if _run_cli("az", "login"):
                return self._edit_subscription(f, current)
            return False
        if value == "__type__":
            value = text("Subscription ID (az account show --query id -o tsv):", current, _validator(f))
            if value is None:
                return False
        return self.save(f, value)

    def _edit_project(self, f: Field, current: str) -> bool:
        projects = _cli_json("gcloud", "projects", "list", "--format=json") or []
        choices = [Choice("(not set: project of your gcloud credentials)", "")]
        choices += [Choice(f"{p['projectId']}  ({p.get('name', '')})" + ("   <- current" if p["projectId"] == current else ""),
                           p["projectId"]) for p in projects]
        if not projects:
            console.print("[dim]No projects found via gcloud (not installed or not signed in).[/]")
        choices += [Separator(), Choice("Type a project ID", "__type__"), Choice("Back", BACK)]
        value = select("GCP project (type to filter):", choices, use_search_filter=True, use_jk_keys=False)
        if value is None:
            return False
        if value == "__type__":
            value = text("Project ID:", current, _validator(f))
            if value is None:
                return False
        return self.save(f, value)

    def _edit_file(self, f: Field, current: str) -> bool:
        choice = select(f"{f.label}:", [Choice("Enter the path to the JSON key file", "set"),
                                        Choice("(not set: use gcloud application-default login)", "clear"),
                                        Choice("Back", BACK)])
        if choice == "clear":
            return self.save(f, "")
        if choice == "set":
            value = questionary_path(f"{f.label}:", current, _validator(f))
            return value is not None and self.save(f, value)
        return False

    def _edit_bucket(self, f: Field, current: str) -> bool:
        choice = select(f"{f.label}:", [Choice("Pick from the buckets in this AWS account", "pick"),
                                        Choice("Type a bucket name", "type"),
                                        Choice("(not set: don't search CloudTrail data events)", "clear"),
                                        Choice("Back", BACK)])
        if choice == "clear":
            return self.save(f, "")
        if choice == "type":
            value = text("Bucket name:", current)
            return value is not None and self.save(f, value)
        if choice == "pick":
            try:
                with console.status("Listing buckets..."):
                    names = [r.name for r in get_provider("aws", self.settings).list_resources()]
            except ProviderError as exc:
                console.print(f"[red]{exc}[/]")
                return False
            value = select("CloudTrail log bucket (type to filter):", [Choice(n, n) for n in names] + [Choice("Back", BACK)],
                           use_search_filter=True, use_jk_keys=False)
            return value is not None and self.save(f, value)
        return False

    # -- sign-in and connection tests ---------------------------------------------------------
    def sign_in(self, provider: str) -> None:
        if provider == "aws":
            self._edit_profile(self.field("AWS_PROFILE"), to_text(self.field("AWS_PROFILE"), self.settings.aws_profile))
            if self.settings.aws_profile and confirm("Refresh an SSO session for this profile (aws sso login)?", False):
                _run_cli("aws", "sso", "login", "--profile", self.settings.aws_profile)
        elif provider == "azure":
            method = select("How should the tool sign in to Azure?", [
                Choice("Azure CLI: az login (opens a browser)", "cli"),
                Choice("Azure CLI with device code (no browser on this machine)", "device"),
                Choice("Service principal (tenant ID, client ID, secret)", "sp"),
                Choice("I'm already signed in with the Azure CLI", "done"),
                Choice("Back", BACK),
            ])
            if method == "cli":
                _run_cli("az", "login")
            elif method == "device":
                _run_cli("az", "login", "--use-device-code")
            elif method == "sp":
                for key in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID"):
                    f = self.field(key)
                    value = text(f"{f.label}:", to_text(f, self.settings.get(f)),
                                 lambda v: len(v.strip()) == 36 or "Expected a 36-character GUID")
                    if value is None:
                        return
                    self.save(f, value)
                self.edit(self.field("AZURE_CLIENT_SECRET"))
            if method and method != "sp" and self.settings.azure_client_id and confirm(
                    "A service principal is configured and takes priority over the Azure CLI. Remove it?", True):
                for key in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"):
                    self.save(self.field(key), "")
            if method:
                self.edit(self.field("AZURE_SUBSCRIPTION_ID"))
        elif provider == "gcp":
            method = select("How should the tool sign in to Google Cloud?", [
                Choice("gcloud application-default login (opens a browser)", "cli"),
                Choice("Service account JSON key file", "key"),
                Choice("I'm already signed in with gcloud", "done"),
                Choice("Back", BACK),
            ])
            if method == "cli":
                _run_cli("gcloud", "auth", "application-default", "login")
            elif method == "key":
                self.edit(self.field("GOOGLE_APPLICATION_CREDENTIALS"))
            if method in ("cli", "done") and self.settings.gcp_credentials_file and confirm(
                    "A key file is configured and takes priority over gcloud login. Remove it?", True):
                self.save(self.field("GOOGLE_APPLICATION_CREDENTIALS"), "")
            if method:
                self.edit(self.field("GOOGLE_CLOUD_PROJECT"))

    def test(self, provider: str) -> bool:
        try:
            with console.status(f"Connecting to {PROVIDERS[provider]}..."):
                label = get_provider(provider, self.settings).account_label()
        except ProviderError as exc:
            console.print(f"[bold red]Connection failed:[/] {exc}")
            return False
        except Exception as exc:  # noqa: BLE001 - SDKs raise many types on bad credentials
            console.print(f"[bold red]Connection failed:[/] {type(exc).__name__}: {exc}")
            return False
        console.print(f"[bold green]Connected:[/] {label}")
        return True

    def setup_provider(self, provider: str) -> bool:
        """Sign-in + required settings + connection test, with retries. Returns True when connected."""
        section = next(s for s, p in SECTION_PROVIDER.items() if p == provider)
        console.rule(f"[bold]{SECTION_TITLES[section]}[/]")
        while True:
            self.sign_in(provider)
            if provider == "aws" and not self.settings.aws_region:
                self.edit(self.field("AWS_REGION"))
            if self.test(provider):
                return True
            again = select("What next?", [Choice("Change the sign-in settings and try again", "retry"),
                                          Choice("Skip this cloud for now", BACK)])
            if again is None:
                return False

    # -- wizard -------------------------------------------------------------------------------
    def wizard(self) -> None:
        console.print(Panel.fit(
            "[bold]Setup wizard[/]\nConnects the tool to your clouds and sets investigation options.\n"
            f"[dim]Everything is saved in {ENV_FILE}. Cloud secrets stay in each cloud's own credential store.[/]",
            border_style="cyan"))
        if not self._edit_providers(self.field("CLOUDDETECTX_PROVIDERS"), ""):
            return
        connected = {}
        for provider in self.settings.providers:
            connected[provider] = self.setup_provider(provider)
            if provider == "aws" and connected[provider] and confirm(
                    "Do you have a CloudTrail trail that logs S3 data events to a bucket?", False):
                if self.edit(self.field("CLOUDDETECTX_AWS_CLOUDTRAIL_BUCKET")):
                    self.edit(self.field("CLOUDDETECTX_AWS_CLOUDTRAIL_PREFIX"))

        console.rule("[bold]Investigation[/]")
        self.edit(self.field("CLOUDDETECTX_LOOKBACK_DAYS"))
        if confirm("Add trusted networks (office / VPN / NAT IPs) so your own traffic isn't flagged?", False):
            self.edit(self.field("CLOUDDETECTX_TRUSTED_CIDRS"))

        console.rule("[bold]Done[/]")
        for provider, ok in connected.items():
            console.print(f"  {PROVIDERS[provider]:<34} " + ("[green]connected[/]" if ok else "[yellow]not connected (Settings > Sign in)[/]"))
        console.print(f"  Settings saved in [bold]{ENV_FILE}[/]")


def questionary_path(message: str, default: str, validate) -> str | None:
    import questionary

    from clouddetectx.prompts import STYLE

    return questionary.path(message, default=default, validate=validate, style=STYLE, qmark=">").ask()
