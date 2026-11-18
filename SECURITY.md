# Security policy

## Reporting a vulnerability

Please **don't open a public issue** for security problems in CloudDetectX.

Report them privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Include the version (`clouddetectx --version` or `clouddetectx/__init__.py`), steps to reproduce and the impact you expect.

You should get a reply within 7 days. Fixes are released as a new version, and the reporter is credited unless they prefer not to be.

## Supported versions

Only the latest release receives security fixes.

## Scope

In scope: the CLI, the terminal UI and the local web dashboard, for example ways to bypass the dashboard's localhost and token checks, secrets leaking into reports or exports, or remediation and rollback changing more than they claim.

Out of scope: misconfigurations in your own cloud accounts (that's what the tool finds) and issues in third-party dependencies, which should go to those projects.
