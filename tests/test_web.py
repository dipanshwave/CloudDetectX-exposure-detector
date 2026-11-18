import json
import time
from datetime import date, timedelta

import pytest
from conftest import make_private_bucket, make_public_acl_bucket, make_public_policy_bucket

H = {"X-CloudDetectX": "1"}


@pytest.fixture
def client(settings, aws):
    from fastapi.testclient import TestClient

    from clouddetectx.web.server import create_app

    settings.providers = ["aws"]

    def make():
        c = TestClient(create_app(settings, "tok"), base_url="http://127.0.0.1:8765")
        c.cookies.set("clouddetectx_session", "tok")
        return c

    c = make()
    c.make = make
    return c


def wait(c, resp):
    assert resp.status_code == 200, resp.text
    jid = resp.json()["job"]
    while (j := c.get(f"/api/jobs/{jid}").json())["status"] == "running":
        time.sleep(0.05)
    return j


def scan(c, **body):
    j = wait(c, c.post("/api/clouds/aws/scan", headers=H, json=body))
    assert j["status"] == "done", j
    return j["result"]


def test_security_guards(client):
    from fastapi.testclient import TestClient

    anon = TestClient(client.app, base_url="http://127.0.0.1:8765")
    assert anon.get("/api/status").status_code == 401
    assert client.post("/api/clouds/aws/connect").status_code == 403          # missing CSRF header
    evil = TestClient(client.app, base_url="http://evil.example")
    assert evil.get("/api/status").status_code == 403                       # DNS rebinding


def test_scan_waiver_and_restart_persistence(client, aws):
    make_public_policy_bucket(aws, "website")
    make_private_bucket(aws)
    summary = scan(client)
    assert summary["counts"]["public"] == 1 and summary["grade"] in list("ABCDF")
    before = summary["posture_score"]

    w = client.post("/api/waivers", headers=H, json={"provider": "aws", "resource": "website", "check_id": "*",
                                                     "reason": "public website", "expires": (date.today() + timedelta(days=30)).isoformat()})
    assert w.status_code == 200, w.text
    cloud = client.get("/api/status").json()["clouds"][0]
    assert cloud["counts"]["public"] == 0 and cloud["counts"]["accepted"] == 1
    assert cloud["posture_score"] > before
    detail = client.get("/api/clouds/aws/resources/website").json()
    assert detail["summary"]["status"] == "accepted" and detail["accepted"]
    bad = client.post("/api/waivers", headers=H, json={"provider": "aws", "resource": "x", "check_id": "*",
                                                       "reason": "ok reason", "expires": "2001-01-01"})
    assert bad.status_code == 400

    drift = scan(client)["drift"]
    assert drift["accepted"] == ["website"] and "website" not in drift["resolved"]

    restarted = client.make()                                     # dashboard restart
    cloud = restarted.get("/api/status").json()["clouds"][0]
    assert cloud["scanned_at"] and cloud["counts"]["resources"] == 2 and cloud["restored"]
    assert restarted.get("/api/clouds/aws/resources/website").json()["summary"]["status"] == "accepted"

    assert restarted.delete(f"/api/waivers/{w.json()['id']}", headers=H).status_code == 200
    assert restarted.get("/api/status").json()["clouds"][0]["counts"]["public"] == 1


def test_remediate_then_rollback(client, aws):
    make_public_acl_bucket(aws, "oops")
    scan(client)
    assert client.post("/api/clouds/aws/resources/oops/remediate", headers=H, json={"confirm_name": "wrong"}).status_code == 400
    j = wait(client, client.post("/api/clouds/aws/resources/oops/remediate", headers=H, json={"confirm_name": "oops"}))
    report_id = j["result"]["report_id"]
    assert j["result"]["still_exposed"] is False

    rep = client.get(f"/api/reports/{report_id}").json()
    assert rep["can_rollback"] is True
    plan = client.post(f"/api/reports/{report_id}/rollback", headers=H, json={"dry_run": True}).json()
    assert plan["dry_run"] and plan["actions"]
    assert client.post(f"/api/reports/{report_id}/rollback", headers=H, json={"confirm_name": "nope"}).status_code == 400
    done = client.post(f"/api/reports/{report_id}/rollback", headers=H, json={"confirm_name": "oops"})
    assert done.status_code == 200 and all(a["status"] != "failed" for a in done.json()["actions"])
    assert client.get("/api/clouds/aws/resources/oops").json()["summary"]["status"] == "public"
    assert client.get(f"/api/reports/{report_id}").json()["can_rollback"] is False
    assert client.get(f"/api/reports/{report_id}/download/pdf").content.startswith(b"%PDF")


def test_exports_overview_compliance_and_account(client, aws, settings):
    make_public_acl_bucket(aws)
    settings.account_checks = True
    scan(client)
    for fmt, check in (("sarif", lambda r: json.loads(r.content)["version"] == "2.1.0"),
                       ("ocsf", lambda r: json.loads(r.content)[0]["class_uid"] == 2003),
                       ("csv", lambda r: r.text.startswith("provider,"))):
        r = client.get(f"/api/clouds/aws/export/{fmt}")
        assert r.status_code == 200 and check(r) and "attachment" in r.headers["content-disposition"]
    assert client.get("/api/clouds/aws/export/xml").status_code == 400

    ov = client.get("/api/clouds/aws/overview").json()
    keys = {c["key"] for c in ov["categories"]}
    assert {"public", "iam", "network", "databases", "logging"} <= keys
    net = next(c for c in ov["categories"] if c["key"] == "network")
    assert net["checked"] and net["account_checks"] > 0
    acct = client.get("/api/clouds/aws/account").json()["report"]
    assert acct and any(f["check_id"] == "AWS-ACCT-001" for f in acct["findings"])
    assert all(f["waiver_resource"].startswith("account:") for f in acct["findings"])
    comp = client.get("/api/clouds/aws/compliance").json()
    assert comp["account_checked"] and any(r["framework"] == "CISB" for r in comp["controls"])
    rid = client.post("/api/clouds/aws/compliance/report", headers=H).json()["report_id"]
    assert any(x["id"] == rid and x["type"] == "compliance" for x in client.get("/api/reports").json()["reports"])


def test_gcp_key_upload_validation(client, settings):
    bad = client.post("/api/settings/gcp-key", headers=H, json={"content": json.dumps({"type": "authorized_user"})})
    assert bad.status_code == 400
    key = {"type": "service_account", "project_id": "demo-project", "client_email": "scanner@demo-project.iam.gserviceaccount.com",
           "private_key": "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n", "client_id": "1"}
    r = client.post("/api/settings/gcp-key", headers=H, json={"content": json.dumps(key)})
    assert r.status_code == 200 and r.json()["project"] == "demo-project"
    assert "private_key" not in r.text
    assert settings.gcp_credentials_file and settings.gcp_project == "demo-project"
    assert client.post("/api/settings/gcp-key", headers=H, json={"content": "x" * 40000}).status_code == 400


def test_settings_bool_and_schedule_validation(client):
    r = client.put("/api/settings/CLOUDDETECTX_ACCOUNT_CHECKS", headers=H, json={"value": "off"})
    assert r.status_code == 200 and r.json()["value"] == "off"
    assert client.put("/api/settings/CLOUDDETECTX_ACCOUNT_CHECKS", headers=H, json={"value": "maybe"}).status_code == 400
    assert client.post("/api/schedule", headers=H, json={"every": 1, "providers": ["aws"]}).status_code == 400
