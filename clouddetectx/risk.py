"""Risk scoring: one 0-100 number per resource, with the reasons that produced it."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from clouddetectx.models import Finding, Investigation, Severity

LEVELS = ((80, "CRITICAL"), (60, "HIGH"), (30, "MEDIUM"), (1, "LOW"), (0, "NONE"))


@dataclass
class RiskScore:
    score: int
    level: str
    factors: list[dict] = field(default_factory=list)   # {"points": int, "reason": str}

    def to_dict(self) -> dict:
        return asdict(self)


def level_for(score: int) -> str:
    return next(name for floor, name in LEVELS if score >= floor)


def score_resource(findings: list[Finding], investigation: Investigation | None = None,
                   sensitive=None, proof=None) -> RiskScore:
    factors: list[tuple[int, str]] = []
    exposing = [f for f in findings if f.exposes_data]

    if exposing:
        top = max(exposing, key=lambda f: f.severity.rank)
        factors.append((45 if top.severity == Severity.CRITICAL else 35, f"Publicly exposed: {top.title}"))
        if any(any(w in (f.description + f.title).lower() for w in ("write", "upload", "full_control")) for f in exposing):
            factors.append((10, "The public can write or overwrite data"))
    if proof is not None:
        if proof.publicly_listable or proof.publicly_readable:
            factors.append((10, "Exposure confirmed by an anonymous request from the internet"))
    if sensitive is not None:
        points = {"RESTRICTED": 30, "CONFIDENTIAL": 20, "INTERNAL": 5}.get(sensitive.classification, 0)
        if points:
            factors.append((points if exposing else points // 3,
                            f"Contains {sensitive.classification.lower()} data"
                            + ("" if exposing else " (not currently public)")))
    if investigation is not None:
        verdict_points = {"DATA_ACCESSED": 25, "EXPOSURE_PROBED": 10, "NO_LOGS_AVAILABLE": 8 if exposing else 0}
        points = verdict_points.get(investigation.verdict, 0)
        if points:
            factors.append((points, {"DATA_ACCESSED": "Logs show untrusted parties downloaded or changed data",
                                     "EXPOSURE_PROBED": "Logs show untrusted parties probing the resource",
                                     "NO_LOGS_AVAILABLE": "No access logs: data access cannot be ruled out"}[investigation.verdict]))

    medium = sum(1 for f in findings if not f.exposes_data and f.severity == Severity.MEDIUM)
    low = sum(1 for f in findings if not f.exposes_data and f.severity == Severity.LOW)
    if medium:
        factors.append((min(15, 4 * medium), f"{medium} medium-severity hardening gap(s)"))
    if low:
        factors.append((min(5, low), f"{low} low-severity hardening gap(s)"))

    score = min(100, sum(p for p, _ in factors))
    return RiskScore(score, level_for(score), [{"points": p, "reason": r} for p, r in factors])


def posture_score(risks: list[RiskScore]) -> int | None:
    """Account-level security score (100 = best). Weighted towards the worst resource, so one
    exposed bucket among hundreds of private ones still pulls the score down noticeably."""
    if not risks:
        return None
    worst = max(r.score for r in risks)
    mean = sum(r.score for r in risks) / len(risks)
    return max(0, round(100 - (0.7 * worst + 0.3 * mean)))
