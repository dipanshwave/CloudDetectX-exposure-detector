import json
from datetime import date, timedelta

import pytest
from conftest import make_public_acl_bucket, make_public_policy_bucket


def future(days=30):
    return (date.today() + timedelta(days=days)).isoformat()


# ---------------------------------------------------------------- waivers
def test_waiver_makes_intentional_public_bucket_accepted(engine, aws):
    from clouddetectx.risk import score_resource

    make_public_policy_bucket(aws, "website-assets")
    before = engine.scan_one("website-assets")
    assert before.status == "public"
    engine.waivers.add("aws", "website-assets", "*", "public website assets", future())
    after = engine.scan_one("website-assets")
    assert after.status == "accepted" and not after.exposed
    assert after.accepted and all(f.waiver["reason"] == "public website assets" for f in after.accepted)
    assert score_resource(after.findings).score < score_resource(before.findings).score


def test_waiver_for_single_check_only(engine, aws):
    make_public_acl_bucket(aws, "logs-off-ok")
    engine.waivers.add("aws", "logs-off-ok", "AWS-S3-005", "logging handled by CloudTrail", future())
    r = engine.scan_one("logs-off-ok")
    assert [f.check_id for f in r.accepted] == ["AWS-S3-005"]
    assert r.status == "public"


def test_waiver_validation_and_expiry(settings):
    from clouddetectx.waivers import Waiver, WaiverError, WaiverStore

    store = WaiverStore(settings.data_dir)
    with pytest.raises(WaiverError):
        store.add("aws", "b", "*", "no", future())                     # reason too short
    with pytest.raises(WaiverError):
        store.add("aws", "b", "*", "valid reason", "2020-01-01")       # in the past
    with pytest.raises(WaiverError):
        store.add("aws", "b", "*", "valid reason", future(900))        # more than two years
    w = store.add("aws", "b", "AWS-S3-001", "valid reason", future())
    assert store.find("aws", "b", "AWS-S3-001").id == w.id
    expired = Waiver("x", "aws", "b", "*", "old", (date.today() - timedelta(days=1)).isoformat(), "")
    assert expired.expired and not expired.matches("aws", "b", "AWS-S3-001")
    assert store.remove(w.id) and not store.find("aws", "b", "AWS-S3-001")


# ---------------------------------------------------------------- saved state
def test_state_roundtrip_and_refuses_foreign_classes(engine, aws, settings):
    from clouddetectx import state

    make_public_acl_bucket(aws)
    results = engine.scan()
    state.save_scan(settings, "aws", "AWS account 123456789012", results, {"123456789012": None})
    loaded = state.load(settings.data_dir, "aws")
    r = loaded["results"]["public-acl"]
    assert r.status == "public" and r.findings[0].severity.value in ("HIGH", "CRITICAL")
    assert loaded["scanned_at"].tzinfo is not None

    evil = {"version": state.VERSION, "state": {"__dc__": "subprocess:Popen", "args": ["calc"]}}
    state.state_path(settings.data_dir, "gcp").parent.mkdir(parents=True, exist_ok=True)
    state.state_path(settings.data_dir, "gcp").write_text(json.dumps(evil), encoding="utf-8")
    assert state.load(settings.data_dir, "gcp") is None       # refused, not executed


# ---------------------------------------------------------------- rollback
def test_rollback_restores_saved_configuration(engine, aws, settings):
    from clouddetectx.reporting import record_rollback, write_report

    make_public_acl_bucket(aws)
    make_public_policy_bucket(aws)
    for name in ("public-acl", "public-policy"):
        result = engine.scan_one(name)
        inc = engine.new_incident(result)
        inc.remediation, _ = engine.remediate(result, dry_run=False, harden=True)
        engine.finalize_status(inc)
        md_path, json_path = write_report(inc, settings.reports_dir)
        assert not engine.scan_one(name).exposed

        report = json.loads(json_path.read_text(encoding="utf-8"))
        plan = engine.rollback(report, dry_run=True)
        assert plan and all(a.status in ("planned", "skipped") for a in plan)
        actions = engine.rollback(report, dry_run=False)
        assert not [a for a in actions if a.status == "failed"], [a.detail for a in actions]
        entry = record_rollback(json_path, md_path, actions)
        assert entry["status"] == "applied"
        assert engine.scan_one(name).exposed              # public again, exactly as before
        with pytest.raises(Exception, match="already rolled back"):
            engine.rollback(json.loads(json_path.read_text(encoding="utf-8")), dry_run=True)
    assert "## Rollback" in md_path.read_text(encoding="utf-8")


# ---------------------------------------------------------------- account-wide AWS checks
def test_aws_account_checks(settings, aws):
    import boto3

    from clouddetectx.engine import SecurityEngine
    from clouddetectx.providers.aws import AWSProvider

    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    sg = ec2.create_security_group(GroupName="ssh-open", Description="x", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    unused = ec2.create_security_group(GroupName="unused-open", Description="x", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=unused, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    ec2.create_network_interface(SubnetId=subnet, Groups=[sg])
    vol = ec2.create_volume(AvailabilityZone="us-east-1a", Size=1)["VolumeId"]
    snap = ec2.create_snapshot(VolumeId=vol)["SnapshotId"]
    ec2.modify_snapshot_attribute(SnapshotId=snap, Attribute="createVolumePermission", OperationType="add",
                                  GroupNames=["all"])
    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(DBInstanceIdentifier="prod-db", DBInstanceClass="db.t3.micro", Engine="postgres",
                           MasterUsername="admin", MasterUserPassword="Password-123", AllocatedStorage=20,
                           PubliclyAccessible=True)
    kms = boto3.client("kms", region_name="us-east-1")
    kms.create_key(Description="no rotation")

    settings.account_checks = True
    review = SecurityEngine(AWSProvider(settings), settings).review_account()
    found = {f.check_id: f for f in review.findings}
    assert {"AWS-ACCT-001", "AWS-ACCT-002", "AWS-ACCT-004", "AWS-ACCT-005", "AWS-ACCT-006",
            "AWS-ACCT-007", "AWS-ACCT-008", "AWS-ACCT-011"} <= set(found), sorted(found)
    rules = found["AWS-ACCT-005"].evidence["rules"]
    assert [r["group_id"] for r in rules] == [sg]               # unattached group is not flagged
    assert found["AWS-ACCT-007"].exposes_data
    assert review.iam is not None

    # an account-level waiver moves the finding to "waived"
    from clouddetectx.account import account_resource

    engine = SecurityEngine(AWSProvider(settings), settings)
    engine.waivers.add("aws", account_resource("123456789012"), "AWS-ACCT-002", "break-glass root has hardware MFA",
                       future())
    review2 = engine.review_account()
    assert "AWS-ACCT-002" not in {f.check_id for f in review2.findings}
    assert "AWS-ACCT-002" in {f.check_id for f in review2.waived}
