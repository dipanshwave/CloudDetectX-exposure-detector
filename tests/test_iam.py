import json

import boto3


def make_policy(iam, name, stmts):
    return iam.create_policy(PolicyName=name, PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": stmts}))["Policy"]["Arn"]


def test_iam_capabilities_and_findings(settings, aws):
    from clouddetectx.engine import SecurityEngine
    from clouddetectx.providers.aws import AWSProvider

    iam = boto3.client("iam", region_name="us-east-1")
    trust = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]})
    iam.create_user(UserName="admin")
    iam.attach_user_policy(UserName="admin", PolicyArn=make_policy(iam, "Admin", [{"Effect": "Allow", "Action": "*", "Resource": "*"}]))
    iam.create_login_profile(UserName="admin", Password="Example-Passw0rd!")
    iam.create_user(UserName="etl")
    iam.create_group(GroupName="data")
    iam.attach_group_policy(GroupName="data", PolicyArn=make_policy(iam, "S3All", [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]))
    iam.add_user_to_group(GroupName="data", UserName="etl")
    iam.create_user(UserName="reader")
    iam.attach_user_policy(UserName="reader", PolicyArn=make_policy(iam, "OneBucket", [
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
         "Resource": ["arn:aws:s3:::reports", "arn:aws:s3:::reports/*"]}]))
    iam.create_role(RoleName="exposer", AssumeRolePolicyDocument=trust)
    iam.attach_role_policy(RoleName="exposer", PolicyArn=make_policy(iam, "PolicyEdit", [
        {"Effect": "Allow", "Action": "s3:PutBucketPolicy", "Resource": "arn:aws:s3:::*"}]))
    iam.create_role(RoleName="denied", AssumeRolePolicyDocument=trust)
    iam.put_role_policy(RoleName="denied", PolicyName="p", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}, {"Effect": "Deny", "Action": "s3:*", "Resource": "*"}]}))

    settings.account_checks = True
    review = SecurityEngine(AWSProvider(settings), settings).review_account()
    caps = {p.name: list(p.capabilities) for p in review.iam.principals}
    assert caps["admin"] == ["admin"] and caps["etl"] == ["s3_full"] and caps["exposer"] == ["can_expose"]
    assert caps["reader"] == [] and caps["denied"] == []
    assert {"AWS-IAM-001", "AWS-IAM-002", "AWS-IAM-003", "AWS-IAM-004"} <= {f.check_id for f in review.findings}

    access = {r["name"]: r for r in review.iam.bucket_access("reports")}
    assert access["reader"]["read"] == "yes" and access["reader"]["write"] is None
    assert "denied" not in access and access["exposer"]["manage"] == "yes"
