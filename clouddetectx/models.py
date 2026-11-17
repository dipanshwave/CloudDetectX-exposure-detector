"""Provider-neutral data models shared by every part of the tool."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}[self.value]


@dataclass
class Resource:
    """A storage resource: an S3 bucket, an Azure storage account or a GCS bucket."""

    provider: str          # aws | azure | gcp
    name: str              # what the user types on the command line
    resource_id: str       # ARN / Azure resource ID / gs:// URL
    location: str | None = None
    kind: str = "bucket"   # bucket | storage-account
    extra: dict[str, Any] = field(default_factory=dict)  # e.g. Azure resource group


@dataclass
class Posture:
    """Raw security configuration collected from the provider."""

    resource: Resource
    config: dict[str, Any] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)


@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    description: str
    recommendation: str
    # True when this misconfiguration currently lets the public reach data.
    exposes_data: bool = False
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class AccessEvent:
    """A single data-plane request against the storage resource."""

    timestamp: datetime
    operation: str            # normalised: GetObject, ListBucket, PutObject, DeleteObject, HeadObject, ...
    key: str | None
    source_ip: str | None
    principal: str | None     # "anonymous" for unauthenticated requests
    status: int | None
    bytes_sent: int = 0
    user_agent: str | None = None
    source: str = ""          # which log produced it

    @property
    def anonymous(self) -> bool:
        return self.principal in (None, "", "-", "anonymous")

    @property
    def succeeded(self) -> bool:
        return self.status is not None and 200 <= self.status < 300

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d


@dataclass
class ChangeEvent:
    """A control-plane change to the resource (who made it public, and when)."""

    timestamp: datetime
    action: str
    actor: str | None
    source_ip: str | None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d


@dataclass
class Indicator:
    severity: Severity
    title: str
    detail: str
    mitre: str | None = None      # MITRE ATT&CK technique ID, e.g. T1530

    def to_dict(self) -> dict[str, Any]:
        from clouddetectx.compliance import MITRE

        return {"severity": self.severity.value, "title": self.title, "detail": self.detail, "mitre": self.mitre,
                "mitre_name": MITRE.get(self.mitre or "")}


@dataclass
class Investigation:
    verdict: str                              # DATA_ACCESSED | EXPOSURE_PROBED | NO_EVIDENCE_OF_ACCESS | NO_LOGS_AVAILABLE
    summary: dict[str, Any]
    indicators: list[Indicator]
    access_events: list[AccessEvent]
    change_events: list[ChangeEvent]
    log_sources: list[str]
    notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "summary": self.summary,
            "indicators": [i.to_dict() for i in self.indicators],
            "access_events": [e.to_dict() for e in self.access_events],
            "change_events": [e.to_dict() for e in self.change_events],
            "log_sources": self.log_sources,
            "notes": self.notes,
        }


@dataclass
class RemediationAction:
    action: str
    status: str               # planned | applied | skipped | failed
    detail: str
    before: Any = None        # original configuration, kept for rollback

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Incident:
    incident_id: str
    resource: Resource
    detected_at: datetime
    findings: list[Finding]
    investigation: Investigation | None = None
    remediation: list[RemediationAction] = field(default_factory=list)
    verification: list[Finding] | None = None
    status: str = "OPEN"      # OPEN | CONTAINED | REMEDIATION_FAILED | REMEDIATION_PLANNED | NO_EXPOSURE
    risk: dict | None = None        # risk.RiskScore.to_dict()
    sensitive: dict | None = None   # sensitive.SensitiveReport.to_dict()
    proof: dict | None = None       # probe.ExposureProof.to_dict()

    @property
    def severity(self) -> Severity:
        exposed = [f for f in self.findings if f.exposes_data] or self.findings
        return max((f.severity for f in exposed), key=lambda s: s.rank, default=Severity.INFO)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "status": self.status,
            "severity": self.severity.value,
            "detected_at": self.detected_at.isoformat(),
            "resource": asdict(self.resource),
            "findings": [f.to_dict() for f in self.findings],
            "investigation": self.investigation.to_dict() if self.investigation else None,
            "remediation": [a.to_dict() for a in self.remediation],
            "verification": [f.to_dict() for f in self.verification] if self.verification is not None else None,
            "risk": self.risk,
            "sensitive_data": self.sensitive,
            "exposure_proof": self.proof,
        }
