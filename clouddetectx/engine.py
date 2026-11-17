"""Orchestrates Detect -> Discover -> Verify -> Investigate -> Remediate -> Verify -> Report."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable

from clouddetectx.analysis import analyze_access
from clouddetectx.config import Settings
from clouddetectx.models import Finding, Incident, Investigation, Posture, RemediationAction, Severity
from clouddetectx.probe import ExposureProof, run_probes
from clouddetectx.providers.base import ProviderError, StorageProvider
from clouddetectx.risk import RiskScore, posture_score, score_resource
from clouddetectx.sensitive import EMAIL_BULK_THRESHOLD, SensitiveReport, discover


@dataclass
class ScanResult:
    posture: Posture
    findings: list[Finding]
    sensitive: SensitiveReport | None = None
    proof: ExposureProof | None = None
    data_findings: list[Finding] = field(default_factory=list)

    @property
    def exposed(self) -> bool:
        return any(f.exposes_data for f in self.findings)

    @property
    def status(self) -> str:
        if self.exposed:
            return "public"
        mitigated = any(f.evidence and not f.exposes_data and f.check_id.endswith(("001", "002", "003"))
                        for f in self.findings)
        return "mitigated" if mitigated else "private"

    @property
    def all_findings(self) -> list[Finding]:
        return self.findings + self.data_findings

    @property
    def top_severity(self) -> Severity | None:
        return max((f.severity for f in self.all_findings), key=lambda s: s.rank, default=None)


def data_findings_from(report: SensitiveReport, exposed: bool) -> list[Finding]:
    out = []
    secrets = [h for h in report.hits if h.category == "secret"]
    secret_files = [r for r in report.risky_files if r["category"] == "secret"]
    if secrets or secret_files:
        parts = [f"{h.count} x {h.name}" for h in secrets] + [f"{len(secret_files)} credential/key file(s)"] * bool(secret_files)
        out.append(Finding(
            "DATA-001", "Secrets or credentials stored in this resource",
            Severity.CRITICAL if exposed else Severity.HIGH,
            "Found " + ", ".join(parts) + ". If the resource was public, treat every one of them as compromised.",
            "Rotate the exposed credentials now, remove them from storage, and keep secrets in a secrets manager.",
            evidence={"detectors": [{"name": h.name, "count": h.count, "samples": h.samples, "objects": h.objects[:10]}
                                    for h in secrets], "files": [r["key"] for r in secret_files[:20]]},
        ))
    pii = [h for h in report.hits if h.category == "pii" and (h.detector != "email" or h.count >= EMAIL_BULK_THRESHOLD)]
    dumps = [r for r in report.risky_files if r["category"] == "backup"]
    if pii or dumps:
        parts = [f"{h.count} x {h.name}" for h in pii] + [f"{len(dumps)} database dump/backup file(s)"] * bool(dumps)
        out.append(Finding(
            "DATA-002", "Personal or sensitive data stored in this resource",
            Severity.HIGH if exposed else Severity.MEDIUM,
            "Found " + ", ".join(parts) + ". Exposure of this data may trigger breach-notification duties.",
            "Confirm the data's owner and classification, minimise or encrypt it, and restrict access to named roles.",
            evidence={"detectors": [{"name": h.name, "count": h.count, "samples": h.samples, "objects": h.objects[:10]}
                                    for h in pii], "files": [r["key"] for r in dumps[:20]]},
        ))
    return out


class SecurityEngine:
    def __init__(self, provider: StorageProvider, settings: Settings):
        self.provider = provider
        self.settings = settings

    # -- detect ---------------------------------------------------------------------
    def scan_one(self, name: str) -> ScanResult:
        posture = self.provider.collect_posture(self.provider.get_resource(name))
        return ScanResult(posture, self.provider.evaluate(posture))

    def scan(self, names: list[str] | None = None, on_progress: Callable[[str], None] | None = None) -> list[ScanResult]:
        resources = [self.provider.get_resource(n) for n in names] if names else self.provider.list_resources()
        results = []
        for res in resources:
            if on_progress:
                on_progress(res.name)
            posture = self.provider.collect_posture(res)
            results.append(ScanResult(posture, self.provider.evaluate(posture)))
        return results

    # -- discover / verify -------------------------------------------------------------
    def discover(self, result: ScanResult, on_progress: Callable[[str], None] | None = None) -> SensitiveReport:
        s = self.settings
        if on_progress:
            on_progress("Listing objects")
        candidates, notes = self.provider.sample_objects(result.posture, min(5000, s.discovery_max_objects * 5))
        report = discover(
            candidates,
            lambda obj, n: self.provider.read_object(result.posture, obj, n),
            max_objects=s.discovery_max_objects,
            max_bytes=s.discovery_max_kb * 1024,
            max_total_bytes=s.discovery_max_total_mb * 1024 * 1024,
            on_progress=on_progress,
            notes=notes,
        )
        result.sensitive = report
        result.data_findings = data_findings_from(report, result.exposed)
        return report

    def verify_exposure(self, result: ScanResult) -> ExposureProof:
        try:
            sample, _ = self.provider.sample_objects(result.posture, 3)
        except ProviderError:
            sample = []
        proof = run_probes(self.provider.probe_targets(result.posture, sample[:3]))
        result.proof = proof
        return proof

    # -- investigate ---------------------------------------------------------------------
    def investigate(self, posture: Posture, days: int | None = None) -> Investigation:
        since = datetime.now(timezone.utc) - timedelta(days=days or self.settings.lookback_days)
        events, sources, notes = self.provider.collect_access_events(posture, since)
        changes, change_notes = self.provider.collect_change_events(posture, since)
        return analyze_access(events, changes, sources, notes + change_notes, self.settings.trusted_networks)

    def risk(self, result: ScanResult, investigation: Investigation | None = None) -> RiskScore:
        return score_resource(result.findings, investigation, result.sensitive, result.proof)

    # -- remediate -------------------------------------------------------------------------
    def remediate(
        self, result: ScanResult, dry_run: bool, harden: bool
    ) -> tuple[list[RemediationAction], list[Finding] | None]:
        actions = self.provider.remediate(result.posture, result.findings, dry_run=dry_run, harden=harden)
        if dry_run or not any(a.status == "applied" for a in actions):
            return actions, None
        fresh = self.provider.collect_posture(result.posture.resource)
        return actions, self.provider.evaluate(fresh)

    # -- incidents -------------------------------------------------------------------------
    def new_incident(self, result: ScanResult, investigation: Investigation | None = None) -> Incident:
        now = datetime.now(timezone.utc)
        res = result.posture.resource
        inc = Incident(
            incident_id=f"INC-{now:%Y%m%d-%H%M%S}-{res.provider}-{res.name}",
            resource=res,
            detected_at=now,
            findings=result.all_findings,
            investigation=investigation,
        )
        inc.sensitive = result.sensitive.to_dict() if result.sensitive else None
        inc.proof = result.proof.to_dict() if result.proof else None
        inc.risk = self.risk(result, investigation).to_dict()
        return inc

    @staticmethod
    def finalize_status(inc: Incident) -> None:
        if not inc.remediation:
            inc.status = "OPEN" if any(f.exposes_data for f in inc.findings) else "NO_EXPOSURE"
        elif all(a.status in ("planned", "skipped") for a in inc.remediation):
            inc.status = "REMEDIATION_PLANNED"
        elif any(a.status == "failed" for a in inc.remediation) or (
            inc.verification is not None and any(f.exposes_data for f in inc.verification)
        ):
            inc.status = "REMEDIATION_FAILED"
        else:
            inc.status = "CONTAINED"


@dataclass
class ScanOutcome:
    risks: dict[str, RiskScore]
    posture_score: int | None
    drift: object | None          # history.Drift
    alerts: list[str]             # messages sent (or attempted)
    alert_error: str | None = None


def after_scan(settings: Settings, provider_name: str, account: str, results: list[ScanResult],
               full_scan: bool = True, investigations: dict | None = None) -> ScanOutcome:
    """Risk-score every resource, record history (full scans), detect drift and send alerts."""
    from clouddetectx.alerts import AlertError, send
    from clouddetectx.history import History

    investigations = investigations or {}
    risks = {r.posture.resource.name: score_resource(r.findings, investigations.get(r.posture.resource.name),
                                                     r.sensitive, r.proof) for r in results}
    score = posture_score(list(risks.values()))
    drift = None
    if full_scan:
        history = History(settings.data_dir)
        try:
            drift = history.record(provider_name, account, [{
                "name": r.posture.resource.name, "status": r.status, "risk": risks[r.posture.resource.name].score,
                "top_severity": r.top_severity.value if r.top_severity else None,
                "checks": [f.check_id for f in r.findings if f.severity != Severity.INFO],
            } for r in results], score)
        finally:
            history.close()

    lines: list[str] = []
    if drift and drift.previous_at:
        candidates = drift.new_public
    else:
        candidates = [r.posture.resource.name for r in results if r.exposed]   # first scan: alert on all exposures
    for name in candidates:
        risk = risks.get(name)
        if risk and risk.score >= settings.alert_min_risk:
            lines.append(f"{provider_name.upper()} {name} is publicly exposed (risk {risk.score}/100, {risk.level})")
    error = None
    if lines and settings.webhook_url:
        try:
            send(settings.webhook_url, f"CloudDetectX: {len(lines)} storage exposure(s) in {account}", lines,
                 {"provider": provider_name, "account": account, "resources": candidates})
        except AlertError as exc:
            error = str(exc)
    return ScanOutcome(risks, score, drift, lines if settings.webhook_url else [], error)


def alert_data_accessed(settings: Settings, provider_name: str, name: str, inv: Investigation) -> str | None:
    """Confirmed data access always alerts (when a webhook is configured). Returns an error message or None."""
    from clouddetectx.alerts import AlertError, send

    if not settings.webhook_url or inv.verdict != "DATA_ACCESSED":
        return None
    s = inv.summary
    try:
        send(settings.webhook_url, f"CloudDetectX: data accessed in {provider_name.upper()} {name}", [
            f"{len(s['objects_downloaded_by_untrusted'])} object(s) downloaded by untrusted sources",
            f"Source IPs: {', '.join(s['external_ips'][:5]) or 'unknown'}",
        ], {"provider": provider_name, "resource": name, "verdict": inv.verdict})
    except AlertError as exc:
        return str(exc)
    return None
