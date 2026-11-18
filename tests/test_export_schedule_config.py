import csv
import io
import json

import pytest
from conftest import make_public_acl_bucket


# ---------------------------------------------------------------- exports
def test_sarif_ocsf_csv_pdf(engine, aws):
    from clouddetectx import export

    make_public_acl_bucket(aws)
    results = engine.scan()
    sarif = export.to_sarif("aws", results)
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0" and run["tool"]["driver"]["name"] == "CloudDetectX"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "AWS-S3-001" in rule_ids and all(r["ruleId"] in rule_ids for r in run["results"])
    assert any(r["level"] == "error" for r in run["results"])

    ocsf = export.to_ocsf("aws", results)
    assert ocsf and all(e["class_uid"] == 2003 and e["type_uid"] == 200301 for e in ocsf)
    assert {e["severity_id"] for e in ocsf} <= {1, 2, 3, 4, 5}

    rows = list(csv.DictReader(io.StringIO(export.to_csv("aws", results))))
    assert rows and rows[0]["provider"] == "aws" and rows[0]["account"] == "123456789012"

    pdf = export.markdown_to_pdf("# Report\n\n| a | b |\n|---|---|\n| 1 | •••• → ok |\n", "test")
    assert pdf.startswith(b"%PDF")


def test_csv_neutralises_formula_injection():
    from clouddetectx.export import _cell

    assert _cell("=HYPERLINK(\"http://x\")").startswith("'=")
    assert _cell("normal") == "normal"


def test_waived_findings_are_suppressed_in_sarif(engine, aws):
    from datetime import date, timedelta

    from clouddetectx import export

    make_public_acl_bucket(aws)
    engine.waivers.add("aws", "public-acl", "AWS-S3-005", "logging via CloudTrail", (date.today() + timedelta(days=9)).isoformat())
    results = engine.scan()
    suppressed = [r for r in export.to_sarif("aws", results)["runs"][0]["results"] if r.get("suppressions")]
    assert [r["ruleId"] for r in suppressed] == ["AWS-S3-005"]


# ---------------------------------------------------------------- scheduling (plans only; nothing installed)
def test_schedule_plans(tmp_path):
    from clouddetectx import schedule

    win = schedule.plan(tmp_path, 60, ["aws"], platform="windows")
    assert win.install[0][:2] == ["schtasks", "/Create"] and ["/SC", "HOURLY", "/MO", "1"] == win.install[0][-4:]
    assert "scan" in win.script_body and "scheduled-scan.log" in win.script_body
    unix = schedule.plan(tmp_path, 1440, ["aws", "gcp"], all_accounts=True, platform="unix")
    assert unix.crontab.startswith("0 3 * * * ") and schedule.CRON_MARKER in unix.crontab
    assert "--all-accounts" in unix.script_body and "aws,gcp" in unix.script_body
    assert schedule.cron_expression(30) == "*/30 * * * *" and schedule.cron_expression(240) == "0 */4 * * *"
    for bad in (5, 99999):
        with pytest.raises(schedule.ScheduleError):
            schedule.plan(tmp_path, bad, ["aws"])
    with pytest.raises(schedule.ScheduleError):
        schedule.cron_expression(90)


# ---------------------------------------------------------------- settings and secrets
class MemoryKeyring:
    """In-memory stand-in for the OS keychain."""

    def __init__(self):
        self.data = {}

    def get_password(self, service, key):
        return self.data.get((service, key))

    def set_password(self, service, key, value):
        self.data[(service, key)] = value

    def delete_password(self, service, key):
        self.data.pop((service, key), None)


def test_bool_and_path_settings(settings):
    from clouddetectx.config import FIELDS, ConfigError, HOME, find_field, parse_value, to_text

    f = find_field("account_checks")
    assert parse_value(f, "on") is True and parse_value(f, "OFF") is False
    with pytest.raises(ConfigError):
        parse_value(f, "maybe")
    path_field = next(x for x in FIELDS if x.attr == "reports_dir")
    assert parse_value(path_field, "reports") == HOME / "reports"
    assert to_text(path_field, HOME / "reports") == "reports"


def test_secret_falls_back_to_env_without_keychain(settings):
    import clouddetectx.config as config

    f = config.find_field("CLOUDDETECTX_WEBHOOK_URL")
    settings.set(f, "https://hooks.example.com/abc")
    assert "hooks.example.com" in config.ENV_FILE.read_text(encoding="utf-8")
    assert settings.secret_locations[f.key] == ".env"


def test_secret_goes_to_keychain_and_migrates(settings, monkeypatch):
    import clouddetectx.config as config

    ring = MemoryKeyring()
    monkeypatch.setattr(config._SecretStore, "_ring", lambda self: ring)
    f = config.find_field("CLOUDDETECTX_WEBHOOK_URL")
    settings.set(f, "https://hooks.example.com/kc")
    assert ring.data[("clouddetectx", f.key)] == "https://hooks.example.com/kc"
    assert "hooks.example.com" not in config.ENV_FILE.read_text(encoding="utf-8")
    monkeypatch.delenv(f.key, raising=False)
    assert config.Settings.load().webhook_url == "https://hooks.example.com/kc"

    config.ENV_FILE.write_text("AZURE_CLIENT_SECRET=plain-secret\n", encoding="utf-8")
    assert settings.migrate_secrets() == ["AZURE_CLIENT_SECRET"]
    assert "plain-secret" not in config.ENV_FILE.read_text(encoding="utf-8")
    assert ring.data[("clouddetectx", "AZURE_CLIENT_SECRET")] == "plain-secret"
    json.dumps(settings.secret_locations)
