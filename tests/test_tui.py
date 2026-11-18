"""Drive the interactive terminal UI with scripted key presses (prompt_toolkit pipe input)."""

import json
import sys

from conftest import make_public_acl_bucket

DOWN, UP, ENTER, BS = "\x1b[B", "\x1b[A", "\r", "\x7f"


def test_terminal_walkthrough(settings, aws, monkeypatch):
    from prompt_toolkit.application import create_app_session
    from prompt_toolkit.input import create_pipe_input
    from prompt_toolkit.output import DummyOutput

    import clouddetectx.config as config
    import clouddetectx.interactive as ui
    from clouddetectx.cli import main

    config.ENV_FILE.write_text("", encoding="utf-8")          # configured: no first-run wizard
    monkeypatch.setenv("CLOUDDETECTX_ACCOUNT_CHECKS", "on")
    monkeypatch.setenv("CLOUDDETECTX_PROVIDERS", "")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    make_public_acl_bucket(aws, "aaa-acl-public")
    aws.create_bucket(Bucket="bbb-policy-public")
    aws.put_bucket_policy(Bucket="bbb-policy-public", Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bbb-policy-public/*"}]}))

    keys = [
        ENTER,                      # provider AWS
        DOWN, DOWN, ENTER,          # Incident response
        ENTER,                      # keep all exposed resources selected
        ENTER,                      # ask before fixing each
        "n", "n", "n",              # no hardening, no verification, no discovery
        DOWN, DOWN, ENTER,          # resource 1: cancel
        DOWN, ENTER,                # resource 2: save plan only
        DOWN * 6, ENTER,            # main menu: reports
        ENTER, ENTER,               # newest report, show in terminal
        DOWN * 8, ENTER,            # main menu: settings
        DOWN * 4, ENTER,            # Investigation section
        ENTER, BS, BS, "45", ENTER,  # look-back 30 -> 45
        UP, ENTER, UP, ENTER,       # back, back
        DOWN * 3, ENTER, "n",       # Account & IAM, flagged only
        DOWN * 4, ENTER,            # Compliance
        DOWN * 5, ENTER,            # save a compliance report
        UP, ENTER,                  # exit
    ]
    holder = {}
    original = ui.InteractiveApp.__init__

    def capture(self, *a, **k):
        original(self, *a, **k)
        holder["app"] = self

    monkeypatch.setattr(ui.InteractiveApp, "__init__", capture)
    with create_pipe_input() as inp:
        inp.send_text("".join(keys))
        with create_app_session(input=inp, output=DummyOutput()):
            assert main([]) == 0

    app = holder["app"]
    assert app.settings.lookback_days == 45
    assert app.review is not None and app.results
    assert any(g["Grantee"].get("URI", "").endswith("AllUsers") for g in aws.get_bucket_acl(Bucket="aaa-acl-public")["Grants"])
    assert list(settings.reports_dir.glob("INC-*bbb-policy-public*.md"))      # plan saved, nothing changed
    assert list(settings.reports_dir.glob("CMP-*.md"))

    from clouddetectx import state

    assert state.load(settings.data_dir, "aws")["results"]                   # scan saved for the dashboard
