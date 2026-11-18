import json
from datetime import date, timedelta

from conftest import make_private_bucket, make_public_acl_bucket


def test_scan_exit_codes_and_json(settings, aws, tmp_path):
    from clouddetectx.cli import main

    make_private_bucket(aws)
    assert main(["-p", "aws", "scan"]) == 0
    make_public_acl_bucket(aws)
    out = tmp_path / "scan.json"
    assert main(["-p", "aws", "scan", "--json", str(out)]) == 2
    data = json.loads(out.read_text(encoding="utf-8"))
    assert {d["resource"] for d in data if "resource" in d} == {"private", "public-acl"}


def test_scan_is_saved_for_the_dashboard(settings, aws):
    from clouddetectx import state
    from clouddetectx.cli import main

    make_public_acl_bucket(aws)
    main(["-p", "aws", "scan"])
    saved = state.load(settings.data_dir, "aws")
    assert "public-acl" in saved["results"]


def test_waivers_command(settings, aws):
    from clouddetectx.cli import main
    from clouddetectx.waivers import WaiverStore

    expires = (date.today() + timedelta(days=60)).isoformat()
    assert main(["-p", "aws", "waivers", "add", "public-acl", "--check", "*", "--reason", "public downloads",
                 "--expires", expires]) == 0
    assert main(["-p", "aws", "waivers", "add", "x", "--check", "*", "--reason", "ok reason", "--expires", "2000-01-01"]) == 1
    make_public_acl_bucket(aws)
    assert main(["-p", "aws", "scan"]) == 0          # the only exposure is accepted
    wid = WaiverStore(settings.data_dir).all()[0].id
    assert main(["waivers", "remove", wid]) == 0
    assert main(["waivers"]) == 0


def test_export_and_rollback_commands(settings, aws, tmp_path):
    from clouddetectx.cli import main

    make_public_acl_bucket(aws)
    sarif = tmp_path / "out.sarif"
    assert main(["-p", "aws", "export", "--format", "sarif", "-o", str(sarif)]) == 2
    assert json.loads(sarif.read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert main(["-p", "aws", "export", "--format", "all", "-o", str(tmp_path / "exports")]) == 2
    assert len(list((tmp_path / "exports").iterdir())) == 3

    assert main(["-p", "aws", "remediate", "public-acl", "-y"]) == 0
    report_id = next(p.stem for p in settings.reports_dir.glob("INC-*.json"))
    assert main(["rollback", report_id, "--dry-run"]) == 0
    assert main(["rollback", report_id, "-y"]) == 0
    assert main(["-p", "aws", "scan"]) == 2          # public again after rollback
    assert main(["rollback", "not-a-report"]) == 1


def test_schedule_print_and_compliance_pdf(settings, aws):
    from clouddetectx.cli import main

    assert main(["-p", "aws", "schedule", "install", "--every", "60", "--print"]) == 0
    assert main(["-p", "aws", "schedule", "install", "--every", "5", "--print"]) == 1
    make_public_acl_bucket(aws)
    main(["-p", "aws", "compliance", "--report", "--pdf"])
    assert list(settings.reports_dir.glob("CMP-*.pdf"))
