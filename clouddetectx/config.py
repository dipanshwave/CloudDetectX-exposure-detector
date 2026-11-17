"""Settings: defined once in FIELDS, stored in the project's .env file, editable from the CLI.

Cloud credentials stay where each SDK expects them: AWS profiles in ~/.aws, Azure CLI /
service principal, GCP application-default credentials or a service-account key file.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dotenv import dotenv_values, load_dotenv, set_key, unset_key

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = Path(os.getenv("CLOUDDETECTX_ENV_FILE") or PROJECT_ROOT / ".env")
PROVIDER_NAMES = ("aws", "azure", "gcp")


@dataclass(frozen=True)
class Field:
    key: str            # variable name in .env
    attr: str           # attribute on Settings
    section: str        # one of SECTIONS
    label: str
    help: str
    kind: str = "str"   # str | int | cidrs | providers | path | file | url | region | profile | subscription | project | bucket
    default: str = ""
    lo: int = 0
    hi: int = 10**9
    secret: bool = False
    aliases: tuple[str, ...] = ()

    @property
    def env_names(self) -> tuple[str, ...]:
        """Primary key plus standard SDK aliases (e.g. AWS_DEFAULT_REGION)."""
        return (self.key, *self.aliases)


FIELDS: tuple[Field, ...] = (
    Field("CLOUDDETECTX_PROVIDERS", "providers", "General", "Default clouds",
          "Used when -p is not given; interactive mode starts on the first one.", "providers", "aws"),
    Field("CLOUDDETECTX_REPORTS_DIR", "reports_dir", "General", "Reports folder",
          "Where incident reports (.md + .json) are written.", "path", "reports"),
    Field("CLOUDDETECTX_DATA_DIR", "data_dir", "General", "Data folder",
          "Where scan history (history.db) is kept for drift detection and trends.", "path", "data"),

    Field("AWS_PROFILE", "aws_profile", "AWS", "AWS profile",
          "Named profile from ~/.aws. Not set = default credential chain (env vars, default profile, instance role).",
          "profile"),
    Field("AWS_REGION", "aws_region", "AWS", "Default region",
          "Region for STS and CloudTrail calls. Buckets in every region are scanned regardless.", "region",
          aliases=("AWS_DEFAULT_REGION",)),
    Field("CLOUDDETECTX_AWS_CLOUDTRAIL_BUCKET", "aws_cloudtrail_bucket", "AWS", "CloudTrail log bucket",
          "Optional. Bucket where a trail with S3 data events delivers logs; searched during investigations.", "bucket"),
    Field("CLOUDDETECTX_AWS_CLOUDTRAIL_PREFIX", "aws_cloudtrail_prefix", "AWS", "CloudTrail log prefix",
          "Optional. The S3 key prefix configured on that trail."),

    Field("AZURE_SUBSCRIPTION_ID", "azure_subscription_id", "Azure", "Subscription",
          "The subscription whose storage accounts are scanned.", "subscription"),
    Field("AZURE_TENANT_ID", "azure_tenant_id", "Azure", "Service principal tenant ID",
          "Only for service-principal sign-in (instead of az login)."),
    Field("AZURE_CLIENT_ID", "azure_client_id", "Azure", "Service principal client ID",
          "Only for service-principal sign-in (instead of az login)."),
    Field("AZURE_CLIENT_SECRET", "azure_client_secret", "Azure", "Service principal secret",
          "Only for service-principal sign-in. Stored in .env, which is git-ignored.", secret=True),

    Field("GOOGLE_CLOUD_PROJECT", "gcp_project", "GCP", "Project",
          "Project whose buckets are scanned. Not set = project of your gcloud credentials.", "project",
          aliases=("GCP_PROJECT",)),
    Field("GOOGLE_APPLICATION_CREDENTIALS", "gcp_credentials_file", "GCP", "Service account key file",
          "Optional path to a service-account JSON key. Not set = gcloud application-default login.", "file"),

    Field("CLOUDDETECTX_LOOKBACK_DAYS", "lookback_days", "Investigation", "Look-back window (days)",
          "How far back access and audit logs are searched.", "int", "30", 1, 3650),
    Field("CLOUDDETECTX_TRUSTED_CIDRS", "trusted_networks", "Investigation", "Trusted networks",
          "Your office/VPN/NAT IP ranges, comma-separated. Access from them is not flagged.", "cidrs"),
    Field("CLOUDDETECTX_MAX_LOG_OBJECTS", "max_log_objects", "Investigation", "Max log files per resource",
          "Upper bound on log files read per investigation.", "int", "2000", 1, 1_000_000),
    Field("CLOUDDETECTX_MAX_OBJECTS_TO_INSPECT", "max_objects_to_inspect", "Investigation", "Objects sampled for ACL checks",
          "Per-object ACL checks per bucket (AWS/GCP). 0 disables them.", "int", "200", 0, 100_000),

    Field("CLOUDDETECTX_DISCOVERY_MAX_OBJECTS", "discovery_max_objects", "Discovery", "Objects sampled per resource",
          "How many objects sensitive-data discovery inspects per bucket / storage account.", "int", "200", 1, 10_000),
    Field("CLOUDDETECTX_DISCOVERY_MAX_KB", "discovery_max_kb", "Discovery", "Bytes read per object (KB)",
          "Only the start of each object is read. Larger = more thorough, slower and costlier.", "int", "512", 4, 51_200),
    Field("CLOUDDETECTX_DISCOVERY_MAX_TOTAL_MB", "discovery_max_total_mb", "Discovery", "Total read budget (MB)",
          "Discovery stops once this much data has been read from one resource.", "int", "100", 1, 10_000),

    Field("CLOUDDETECTX_WEBHOOK_URL", "webhook_url", "Alerts", "Webhook URL",
          "Slack / Microsoft Teams / generic incoming-webhook URL. Not set = alerts off.", "url", secret=True),
    Field("CLOUDDETECTX_ALERT_MIN_RISK", "alert_min_risk", "Alerts", "Alert threshold (risk score)",
          "Alert when a newly exposed resource reaches this risk score (0-100). Confirmed data access always alerts.",
          "int", "40", 0, 100),
)

SECTIONS = ("General", "AWS", "Azure", "GCP", "Investigation", "Discovery", "Alerts")
SECTION_PROVIDER = {"AWS": "aws", "Azure": "azure", "GCP": "gcp"}
SECTION_TITLES = {"General": "General", "AWS": "AWS (S3)", "Azure": "Azure (Blob Storage)",
                  "GCP": "Google Cloud (Cloud Storage)", "Investigation": "Investigation",
                  "Discovery": "Sensitive data discovery", "Alerts": "Alerts"}


class ConfigError(ValueError):
    pass


def find_field(name: str) -> Field:
    norm = name.strip().upper().replace("-", "_")
    for f in FIELDS:
        names = {f.attr.upper(), *f.env_names}
        names |= {n.removeprefix("CLOUDDETECTX_") for n in names}
        if norm in names:
            return f
    raise ConfigError(f"Unknown setting '{name}'. Run `python main.py config show` to list settings.")


def _split(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def parse_value(f: Field, raw: str | None) -> Any:
    """Convert the text form (as stored in .env) into the typed value. Raises ConfigError."""
    raw = (raw or "").strip()
    if f.kind == "int":
        text = raw or f.default
        if not text.lstrip("-").isdigit():
            raise ConfigError(f"{f.label}: '{text}' is not a whole number")
        value = int(text)
        if not f.lo <= value <= f.hi:
            raise ConfigError(f"{f.label}: must be between {f.lo} and {f.hi}")
        return value
    if f.kind == "cidrs":
        nets = []
        for part in _split(raw):
            try:
                nets.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                raise ConfigError(f"{f.label}: '{part}' is not a valid IP or CIDR (e.g. 203.0.113.0/24)") from None
        return nets
    if f.kind == "providers":
        names = [n.lower() for n in _split(raw or f.default)]
        bad = [n for n in names if n not in PROVIDER_NAMES]
        if bad:
            raise ConfigError(f"{f.label}: unknown provider(s) {', '.join(bad)}; use aws, azure, gcp")
        return names
    if f.kind == "path":
        return Path(raw or f.default)
    if f.kind == "file":
        if raw and not Path(raw).expanduser().is_file():
            raise ConfigError(f"{f.label}: file not found: {raw}")
        return str(Path(raw).expanduser()) if raw else None
    if f.kind == "url" and raw:
        from urllib.parse import urlparse

        url = urlparse(raw)
        local = url.hostname in ("localhost", "127.0.0.1")
        if not url.hostname or not (url.scheme == "https" or (url.scheme == "http" and local)):
            raise ConfigError(f"{f.label}: must be an https:// URL")
        return raw
    if f.kind == "subscription" and raw and len(raw) != 36:
        raise ConfigError(f"{f.label}: expected a 36-character subscription GUID")
    if f.attr == "aws_cloudtrail_prefix":
        return raw
    return raw or None


def to_text(f: Field, value: Any) -> str:
    """Typed value -> text form stored in .env."""
    if value is None:
        return ""
    if f.kind in ("cidrs", "providers"):
        return ",".join(str(v) for v in value)
    return str(value)


def display(f: Field, value: Any) -> str:
    text = to_text(f, value)
    if not text:
        return "(not set)" if not f.default else f"{f.default} (default)"
    if f.secret:
        return "******** (set)"
    return text


@dataclass
class Settings:
    providers: list[str] = field(default_factory=lambda: ["aws"])
    reports_dir: Path = Path("reports")
    aws_profile: str | None = None
    aws_region: str | None = None
    aws_cloudtrail_bucket: str | None = None
    aws_cloudtrail_prefix: str = ""
    azure_subscription_id: str | None = None
    azure_tenant_id: str | None = None
    azure_client_id: str | None = None
    azure_client_secret: str | None = None
    gcp_project: str | None = None
    gcp_credentials_file: str | None = None
    lookback_days: int = 30
    trusted_networks: list = field(default_factory=list)
    max_log_objects: int = 2000
    max_objects_to_inspect: int = 200
    data_dir: Path = Path("data")
    discovery_max_objects: int = 200
    discovery_max_kb: int = 512
    discovery_max_total_mb: int = 100
    webhook_url: str | None = None
    alert_min_risk: int = 40
    warnings: list[str] = field(default_factory=list)

    @classmethod
    def load(cls) -> "Settings":
        load_dotenv(ENV_FILE)
        settings = cls()
        for f in FIELDS:
            raw = next((os.environ[k] for k in f.env_names if os.environ.get(k, "").strip()), "")
            # Blank entries (e.g. "AWS_PROFILE=") would be read by the cloud SDKs as real values.
            for k in f.env_names:
                if k in os.environ and not os.environ[k].strip():
                    del os.environ[k]
            try:
                setattr(settings, f.attr, parse_value(f, raw))
            except ConfigError as exc:
                settings.warnings.append(f"{exc} (in {f.key}; using the default)")
                setattr(settings, f.attr, parse_value(f, ""))
        return settings

    def get(self, f: Field) -> Any:
        return getattr(self, f.attr)

    def set(self, f: Field, raw: str | None, persist: bool = True) -> Any:
        """Validate, apply to this session (incl. os.environ for the SDKs) and save to .env."""
        value = parse_value(f, raw)
        setattr(self, f.attr, value)
        text = to_text(f, value)
        for alias in f.env_names[1:]:
            os.environ.pop(alias, None)
        if text:
            os.environ[f.key] = text
        else:
            os.environ.pop(f.key, None)
        if persist:
            ENV_FILE.touch(exist_ok=True)
            existing = dotenv_values(ENV_FILE)
            if text:
                set_key(str(ENV_FILE), f.key, text, quote_mode="auto")
            elif f.key in existing:
                unset_key(str(ENV_FILE), f.key, quote_mode="auto")
            for alias in f.env_names[1:]:
                if alias in existing:
                    unset_key(str(ENV_FILE), alias, quote_mode="auto")
        return value
