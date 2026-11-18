"""Shared fixtures. Tests never touch real clouds, your .env, your keychain or your data folder.

AWS is simulated with moto; Azure and GCP checks are tested through their pure evaluate functions
and fakes. Everything is set up before clouddetectx is imported.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

_HOME = Path(tempfile.mkdtemp(prefix="clouddetectx-tests-"))
os.environ.update({
    "CLOUDDETECTX_HOME": str(_HOME),
    "CLOUDDETECTX_ENV_FILE": str(_HOME / ".env"),
    "CLOUDDETECTX_KEYRING": "off",
    "CLOUDDETECTX_ACCOUNT_CHECKS": "off",
    "CLOUDDETECTX_AWS_REGIONS": "us-east-1",
    "CLOUDDETECTX_SCAN_WORKERS": "4",
    "AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing", "AWS_SESSION_TOKEN": "testing",
    "AWS_DEFAULT_REGION": "us-east-1", "AWS_REGION": "us-east-1",
})
for var in ("AWS_PROFILE", "CLOUDDETECTX_WEBHOOK_URL", "AZURE_SUBSCRIPTION_ID", "GOOGLE_CLOUD_PROJECT",
            "GOOGLE_APPLICATION_CREDENTIALS", "CLOUDDETECTX_REPORTS_DIR", "CLOUDDETECTX_DATA_DIR"):
    os.environ.pop(var, None)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json  # noqa: E402

import pytest  # noqa: E402

PAB = {k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}


@pytest.fixture
def settings(tmp_path, monkeypatch):
    """Fresh Settings with their own .env, data and reports folders."""
    import clouddetectx.config as config

    env = tmp_path / ".env"
    for module in ("clouddetectx.config", "clouddetectx.web.server", "clouddetectx.interactive", "clouddetectx.cli"):
        mod = sys.modules.get(module)
        if mod is not None and hasattr(mod, "ENV_FILE"):
            monkeypatch.setattr(mod, "ENV_FILE", env)
    monkeypatch.setenv("CLOUDDETECTX_ENV_FILE", str(env))
    monkeypatch.setenv("CLOUDDETECTX_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("CLOUDDETECTX_REPORTS_DIR", str(tmp_path / "reports"))
    return config.Settings.load()


@pytest.fixture
def aws():
    """A moto-simulated AWS account. Yields an S3 client."""
    import boto3
    from moto import mock_aws

    with mock_aws():
        yield boto3.client("s3", region_name="us-east-1")


def make_public_acl_bucket(s3, name="public-acl"):
    s3.create_bucket(Bucket=name)
    s3.put_bucket_ownership_controls(Bucket=name, OwnershipControls={"Rules": [{"ObjectOwnership": "ObjectWriter"}]})
    s3.put_bucket_acl(Bucket=name, ACL="public-read")
    s3.put_object(Bucket=name, Key="data.txt", Body=b"hello")
    return name


def make_public_policy_bucket(s3, name="public-policy"):
    s3.create_bucket(Bucket=name)
    s3.put_bucket_policy(Bucket=name, Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Sid": "Keep", "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
         "Action": "s3:ListBucket", "Resource": f"arn:aws:s3:::{name}"},
        {"Sid": "Public", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{name}/*"}]}))
    return name


def make_private_bucket(s3, name="private"):
    s3.create_bucket(Bucket=name)
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=PAB)
    return name


@pytest.fixture
def engine(settings, aws):
    from clouddetectx.engine import SecurityEngine
    from clouddetectx.providers.aws import AWSProvider

    return SecurityEngine(AWSProvider(settings), settings)
