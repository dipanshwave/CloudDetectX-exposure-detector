import json

from conftest import make_private_bucket, make_public_acl_bucket, make_public_policy_bucket


def ids(result):
    return {f.check_id for f in result.findings}


def test_detects_public_acl_and_policy(engine, aws):
    make_public_acl_bucket(aws)
    make_public_policy_bucket(aws)
    make_private_bucket(aws)
    results = {r.posture.resource.name: r for r in engine.scan()}
    assert results["public-acl"].status == "public" and "AWS-S3-001" in ids(results["public-acl"])
    assert results["public-policy"].status == "public" and "AWS-S3-003" in ids(results["public-policy"])
    assert results["private"].status == "private" and not results["private"].exposed
    assert results["public-acl"].posture.resource.account == "123456789012"


def test_parallel_scan_keeps_listing_order(engine, aws, settings):
    names = [f"bucket-{i:02d}" for i in range(12)]
    for n in names:
        aws.create_bucket(Bucket=n)
    settings.scan_workers = 6
    assert [r.posture.resource.name for r in engine.scan()] == sorted(names)


def test_block_public_access_neutralises(engine, aws):
    make_public_acl_bucket(aws, "acl-but-blocked")
    aws.put_public_access_block(Bucket="acl-but-blocked", PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    r = engine.scan_one("acl-but-blocked")
    assert r.status == "mitigated" and not r.exposed


def test_https_and_cross_account_checks(engine, aws):
    aws.create_bucket(Bucket="shared")
    aws.put_bucket_policy(Bucket="shared", Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
         "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "arn:aws:s3:::shared/*"}]}))
    r = engine.scan_one("shared")
    cross = next(f for f in r.findings if f.check_id == "AWS-S3-009")
    assert cross.severity.value == "HIGH" and cross.evidence["statements"][0]["accounts"] == ["999988887777"]
    assert "AWS-S3-008" in ids(r)

    aws.create_bucket(Bucket="tls")
    aws.put_bucket_policy(Bucket="tls", Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": ["arn:aws:s3:::tls", "arn:aws:s3:::tls/*"],
         "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}))
    tls = engine.scan_one("tls")
    assert "AWS-S3-008" not in ids(tls) and tls.posture.config["encryption_summary"]["in_transit_enforced"]


def test_one_broken_bucket_does_not_stop_the_scan(engine, aws, monkeypatch):
    aws.create_bucket(Bucket="healthy")
    aws.create_bucket(Bucket="broken")
    original = engine.provider.collect_posture

    def flaky(resource):
        if resource.name == "broken":
            raise RuntimeError("boom")
        return original(resource)

    monkeypatch.setattr(engine.provider, "collect_posture", flaky)
    results = {r.posture.resource.name: r for r in engine.scan()}
    assert {f.check_id for f in results["broken"].findings} == {"SCAN-000"}
    assert results["healthy"].findings


def test_remediation_keeps_non_public_statements(engine, aws):
    make_public_policy_bucket(aws)
    result = engine.scan_one("public-policy")
    actions, verification = engine.remediate(result, dry_run=False, harden=False)
    assert all(a.status == "applied" for a in actions)
    assert {a.op for a in actions} >= {"s3.public_access_block", "s3.bucket_policy"}
    policy = json.loads(aws.get_bucket_policy(Bucket="public-policy")["Policy"])
    assert [s["Sid"] for s in policy["Statement"]] == ["Keep"]
    assert not any(f.exposes_data for f in verification)
