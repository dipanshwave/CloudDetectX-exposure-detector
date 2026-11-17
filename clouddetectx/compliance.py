"""Compliance and threat-framework mapping for findings and indicators.

Controls are cited by stable identifiers (NIST SP 800-53 Rev. 5, CIS Controls v8,
ISO/IEC 27001:2022 Annex A). Cloud CIS Benchmarks renumber between versions, so they are
cited by recommendation title, with numbers only where they have been stable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

FRAMEWORKS = {
    "NIST": "NIST SP 800-53 Rev. 5",
    "CIS8": "CIS Controls v8",
    "ISO": "ISO/IEC 27001:2022 Annex A",
    "CISB": "CIS Cloud Benchmarks",
}


@dataclass(frozen=True)
class Control:
    framework: str
    id: str
    title: str

    def to_dict(self) -> dict:
        return {"framework": self.framework, "framework_name": FRAMEWORKS[self.framework], "id": self.id, "title": self.title}


def _c(fw: str, cid: str, title: str) -> Control:
    return Control(fw, cid, title)


AC3 = _c("NIST", "AC-3", "Access Enforcement")
AC6 = _c("NIST", "AC-6", "Least Privilege")
CM6 = _c("NIST", "CM-6", "Configuration Settings")
AU2 = _c("NIST", "AU-2", "Event Logging")
AU12 = _c("NIST", "AU-12", "Audit Record Generation")
SC7 = _c("NIST", "SC-7", "Boundary Protection")
SC8 = _c("NIST", "SC-8", "Transmission Confidentiality and Integrity")
SC28 = _c("NIST", "SC-28", "Protection of Information at Rest")
CP9 = _c("NIST", "CP-9", "System Backup")
IA2 = _c("NIST", "IA-2", "Identification and Authentication (Organizational Users)")
IA5_7 = _c("NIST", "IA-5(7)", "No Embedded Unprotected Authenticators")
RA2 = _c("NIST", "RA-2", "Security Categorization")
AC2 = _c("NIST", "AC-2", "Account Management")
AC6_5 = _c("NIST", "AC-6(5)", "Least Privilege | Privileged Accounts")
IA2_1 = _c("NIST", "IA-2(1)", "Multi-factor Authentication to Privileged Accounts")
IA5 = _c("NIST", "IA-5", "Authenticator Management")

CIS_3_3 = _c("CIS8", "3.3", "Configure Data Access Control Lists")
CIS_3_2 = _c("CIS8", "3.2", "Establish and Maintain a Data Inventory")
CIS_3_7 = _c("CIS8", "3.7", "Establish and Maintain a Data Classification Scheme")
CIS_3_10 = _c("CIS8", "3.10", "Encrypt Sensitive Data in Transit")
CIS_3_11 = _c("CIS8", "3.11", "Encrypt Sensitive Data at Rest")
CIS_4_1 = _c("CIS8", "4.1", "Establish and Maintain a Secure Configuration Process")
CIS_8_2 = _c("CIS8", "8.2", "Collect Audit Logs")
CIS_11_2 = _c("CIS8", "11.2", "Perform Automated Backups")
CIS_5_4 = _c("CIS8", "5.4", "Restrict Administrator Privileges to Dedicated Administrator Accounts")
CIS_6_3 = _c("CIS8", "6.3", "Require MFA for Externally-Exposed Applications")
CIS_6_8 = _c("CIS8", "6.8", "Define and Maintain Role-Based Access Control")

ISO_8_3 = _c("ISO", "A.8.3", "Information access restriction")
ISO_8_9 = _c("ISO", "A.8.9", "Configuration management")
ISO_8_12 = _c("ISO", "A.8.12", "Data leakage prevention")
ISO_8_13 = _c("ISO", "A.8.13", "Information backup")
ISO_8_15 = _c("ISO", "A.8.15", "Logging")
ISO_8_20 = _c("ISO", "A.8.20", "Networks security")
ISO_8_24 = _c("ISO", "A.8.24", "Use of cryptography")
ISO_5_12 = _c("ISO", "A.5.12", "Classification of information")
ISO_5_15 = _c("ISO", "A.5.15", "Access control")
ISO_5_17 = _c("ISO", "A.5.17", "Authentication information")
ISO_5_18 = _c("ISO", "A.5.18", "Access rights")
ISO_8_2 = _c("ISO", "A.8.2", "Privileged access rights")
ISO_8_5 = _c("ISO", "A.8.5", "Secure authentication")

PUBLIC = (AC3, AC6, CIS_3_3, ISO_8_3, ISO_8_12)
LOGGING = (AU2, AU12, CIS_8_2, ISO_8_15)
BACKUP = (CP9, CIS_11_2, ISO_8_13)
IN_TRANSIT = (SC8, CIS_3_10, ISO_8_24)

MAPPING: dict[str, tuple[Control, ...]] = {
    "AWS-S3-001": PUBLIC + (_c("CISB", "AWS", "S3 buckets are configured with 'Block public access'"),),
    "AWS-S3-002": PUBLIC,
    "AWS-S3-003": PUBLIC + (_c("CISB", "AWS", "S3 buckets are configured with 'Block public access'"),),
    "AWS-S3-004": (CM6, CIS_4_1, ISO_8_9, _c("CISB", "AWS", "S3 buckets are configured with 'Block public access'")),
    "AWS-S3-005": LOGGING,
    "AWS-S3-006": (SC28, CIS_3_11, ISO_8_24, _c("CISB", "AWS", "All S3 buckets employ encryption-at-rest")),
    "AWS-S3-007": BACKUP,
    "AWS-S3-008": IN_TRANSIT + (_c("CISB", "AWS", "S3 Bucket Policy is set to deny HTTP requests"),),
    "AWS-S3-009": (AC3, AC6, CIS_3_3, CIS_6_8, ISO_5_15, ISO_8_3),
    "AWS-IAM-001": (AC6, AC6_5, CIS_5_4, ISO_8_2,
                    _c("CISB", "AWS", "IAM policies that allow full \"*:*\" administrative privileges are not attached")),
    "AWS-IAM-002": (AC6, CIS_6_8, ISO_5_15, ISO_5_18),
    "AWS-IAM-003": (AC6, AC6_5, CM6, CIS_6_8, ISO_8_2),
    "AWS-IAM-004": (IA2_1, CIS_6_3, ISO_8_5, _c("CISB", "AWS", "MFA is enabled for all IAM users that have a console password")),
    "AWS-IAM-005": (IA5, AC2, ISO_5_17, _c("CISB", "AWS", "Access keys are rotated every 90 days or less")),
    "AZ-ST-001": PUBLIC + (_c("CISB", "Azure", "'Public access level' is disabled for storage accounts with blob containers"),),
    "AZ-ST-002": (CM6, CIS_4_1, ISO_8_9, _c("CISB", "Azure", "'Allow Blob Anonymous Access' is set to 'Disabled'")),
    "AZ-ST-003": (SC7, ISO_8_20, _c("CISB", "Azure", "Default network access rule for storage accounts is set to deny")),
    "AZ-ST-004": (IA2, ISO_8_3, _c("CISB", "Azure", "'Allow storage account key access' is disabled")),
    "AZ-ST-005": IN_TRANSIT + (_c("CISB", "Azure", "'Secure transfer required' is set to 'Enabled'"),),
    "AZ-ST-006": IN_TRANSIT + (_c("CISB", "Azure", "'Minimum TLS version' is set to TLS 1.2"),),
    "AZ-ST-007": LOGGING + (_c("CISB", "Azure", "Storage logging is enabled for Blob service read/write/delete requests"),),
    "AZ-ST-008": BACKUP + (_c("CISB", "Azure", "Soft delete for blobs is enabled"),),
    "GCP-GCS-001": PUBLIC + (_c("CISB", "GCP 5.1", "Cloud Storage bucket is not anonymously or publicly accessible"),),
    "GCP-GCS-002": PUBLIC + (_c("CISB", "GCP 5.1", "Cloud Storage bucket is not anonymously or publicly accessible"),),
    "GCP-GCS-003": PUBLIC,
    "GCP-GCS-004": (CM6, CIS_4_1, ISO_8_9),
    "GCP-GCS-005": (CM6, CIS_3_3, ISO_8_9, _c("CISB", "GCP 5.2", "Cloud Storage buckets have uniform bucket-level access enabled")),
    "GCP-GCS-006": LOGGING,
    "GCP-GCS-007": BACKUP,
    "DATA-001": (IA5_7, RA2, CIS_3_2, CIS_3_7, ISO_5_12, ISO_8_12),
    "DATA-002": (SC28, RA2, CIS_3_2, CIS_3_7, ISO_5_12, ISO_8_12),
}


def controls_for(check_id: str) -> list[dict]:
    return [c.to_dict() for c in MAPPING.get(check_id, ())]


# Security categories shown on the dashboard. Account-level IAM checks start with AWS-IAM-.
CATEGORIES = {
    "public": ("Public access", ("AWS-S3-001", "AWS-S3-002", "AWS-S3-003", "AWS-S3-004", "AZ-ST-001", "AZ-ST-002",
                                 "AZ-ST-003", "GCP-GCS-001", "GCP-GCS-002", "GCP-GCS-003", "GCP-GCS-004")),
    "iam": ("Identity & access", ("AWS-S3-009", "AZ-ST-004", "GCP-GCS-005", "AWS-IAM-001", "AWS-IAM-002",
                                  "AWS-IAM-003", "AWS-IAM-004", "AWS-IAM-005")),
    "encryption": ("Encryption", ("AWS-S3-006", "AWS-S3-008", "AZ-ST-005", "AZ-ST-006")),
    "logging": ("Logging", ("AWS-S3-005", "AZ-ST-007", "GCP-GCS-006")),
    "backup": ("Backup & recovery", ("AWS-S3-007", "AZ-ST-008", "GCP-GCS-007")),
    "data": ("Sensitive data", ("DATA-001", "DATA-002")),
}
CHECK_CATEGORY = {cid: key for key, (_, ids) in CATEGORIES.items() for cid in ids}
PROVIDER_PREFIX = {"aws": "AWS-S3-", "azure": "AZ-ST-", "gcp": "GCP-GCS-"}


def evaluated_checks(provider: str, identity_checked: bool, data_checked: bool) -> list[str]:
    """Check IDs that a scan of this provider actually evaluates."""
    prefix = PROVIDER_PREFIX[provider]
    ids = [c for c in MAPPING if c.startswith(prefix)]
    if identity_checked and provider == "aws":
        ids += [c for c in MAPPING if c.startswith("AWS-IAM-")]
    if data_checked:
        ids += ["DATA-001", "DATA-002"]
    return ids


def compliance_status(checks: list[str], failing_rows: list[dict], applicable: dict[str, set] | None = None) -> dict:
    """Per framework: controls assessed (mapped by evaluated checks), failing and passing.

    A control passes only when no resource fails it (strict, like most audit tools). Because one bucket
    out of hundreds fails a whole control, we also report the resource-level rate: of all
    (resource, control) pairs the control applies to, the share with no failing check.
    applicable: check_id -> resource names that check evaluates.
    """
    assessed: dict[str, dict[str, Control]] = {fw: {} for fw in FRAMEWORKS}
    scope: dict[tuple[str, str], set] = {}
    for cid in checks:
        for c in MAPPING.get(cid, ()):
            assessed[c.framework][c.id + c.title] = c
            scope.setdefault((c.framework, c.id + c.title), set()).update((applicable or {}).get(cid, set()))
    failing = {(r["framework"], r["id"] + r["title"]): set(r["resources"]) for r in failing_rows}
    out = {}
    for fw, controls in assessed.items():
        fails = sum((fw, k) in failing for k in controls)
        pairs = sum(len(scope[(fw, k)]) for k in controls)
        bad = sum(len(failing.get((fw, k), set()) & scope[(fw, k)]) for k in controls)
        out[fw] = {"name": FRAMEWORKS[fw], "assessed": len(controls), "failing": fails,
                   "passing": len(controls) - fails,
                   "checks_total": pairs, "checks_failing": bad,
                   "pass_rate": round(100 * (pairs - bad) / pairs) if pairs else None,
                   "passing_controls": sorted(({"id": c.id, "title": c.title} for k, c in controls.items()
                                               if (fw, k) not in failing), key=lambda c: _natural(c["id"]))}
    return out


def _natural(control_id: str) -> list:
    # "3.11" after "3.2", "AC-12" after "AC-3"
    return [(0, int(t)) if t.isdigit() else (1, t) for t in re.split(r"(\d+)", control_id)]


# MITRE ATT&CK (Enterprise, Cloud) techniques for investigation indicators.
MITRE = {
    "T1530": "Data from Cloud Storage",
    "T1619": "Cloud Storage Object Discovery",
    "T1565.001": "Data Manipulation: Stored Data Manipulation",
    "T1485": "Data Destruction",
    "T1595": "Active Scanning",
}


def compliance_summary(results: list[tuple[str, list]]) -> list[dict]:
    """results: [(resource_name, findings)]. Returns one row per control with the resources failing it."""
    rows: dict[tuple[str, str], dict] = {}
    for name, findings in results:
        for f in findings:
            if f.severity.value == "INFO":
                continue
            for c in MAPPING.get(f.check_id, ()):
                row = rows.setdefault((c.framework, c.id + c.title), {**c.to_dict(), "resources": [], "checks": set(), "worst": "LOW"})
                if name not in row["resources"]:
                    row["resources"].append(name)
                row["checks"].add(f.check_id)
                order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
                if order.index(f.severity.value) > order.index(row["worst"]):
                    row["worst"] = f.severity.value
    out = []
    for row in rows.values():
        row["checks"] = sorted(row["checks"])
        out.append(row)
    fw_order = list(FRAMEWORKS)
    return sorted(out, key=lambda r: (fw_order.index(r["framework"]), _natural(r["id"])))
