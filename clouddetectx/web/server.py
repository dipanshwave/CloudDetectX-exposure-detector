"""Local web dashboard: `python main.py web`.

Runs on 127.0.0.1 only. A random access token is printed in the terminal and opened in the
browser; it is exchanged for a SameSite=Strict cookie, every API call needs that cookie, and
state-changing calls also need an `X-CloudDetectX: 1` header, so other websites can't drive the API.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import socket
import threading
import time
import uuid
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import markdown as md
import nh3
from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from clouddetectx import __version__, overview
from clouddetectx import state as saved_state
from clouddetectx.account import account_resource, merge_reviews
from clouddetectx.alerts import AlertError
from clouddetectx.alerts import send as send_alert
from clouddetectx.analysis import VERDICT_TEXT
from clouddetectx.compliance import CHECK_CATEGORY, controls_for
from clouddetectx.config import (
    ENV_FILE,
    HOME,
    FIELDS,
    PROVIDER_NAMES,
    SECTION_PROVIDER,
    SECTION_TITLES,
    SECTIONS,
    ConfigError,
    Field,
    Settings,
    display,
    find_field,
    secret_store,
    to_text,
)
from clouddetectx.engine import (
    ScanResult,
    SecurityEngine,
    after_scan,
    alert_data_accessed,
    data_findings_from,
    scan_all_accounts,
)
from clouddetectx.history import History
from clouddetectx.models import Severity
from clouddetectx.providers import PROVIDERS, ProviderError, get_provider
from clouddetectx.reporting import build_compliance_report, write_compliance_report, write_report
from clouddetectx.risk import RiskScore, posture_score, score_resource
from clouddetectx.waivers import WaiverError, WaiverStore

STATIC = Path(__file__).parent / "static"
COOKIE = "clouddetectx_session"
REPORT_ID = re.compile(r"^(INC|CMP)-[A-Za-z0-9._-]+$")
SEVERITIES = [s.value for s in Severity]
STATUSES = ("public", "accepted", "mitigated", "private")

LOCKED_PAGE = """<!doctype html><meta charset="utf-8"><title>Locked</title>
<body style="font-family:system-ui;max-width:36rem;margin:4rem auto;padding:0 1rem;line-height:1.5">
<h1>Dashboard locked</h1><p>Open the link printed in the terminal where you ran
<code>python main.py web</code>. It contains a one-time access token.</p></body>"""


# --------------------------------------------------------------------------- background jobs

class Job:
    def __init__(self, kind: str, target: str):
        self.id = uuid.uuid4().hex[:12]
        self.kind, self.target = kind, target
        self.status = "running"
        self.progress: list[dict] = []
        self.result: Any = None
        self.error: str | None = None
        self.started = time.time()
        self.finished: float | None = None

    def log(self, msg: str) -> None:
        self.progress.append({"t": time.time(), "msg": msg})

    def to_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "target": self.target, "status": self.status,
                "progress": self.progress[-200:], "result": self.result, "error": self.error,
                "elapsed": round((self.finished or time.time()) - self.started, 1)}


class JobManager:
    def __init__(self):
        self.jobs: dict[str, Job] = {}
        self.pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="clouddetectx-job")

    def submit(self, kind: str, target: str, fn: Callable[[Job], Any]) -> Job:
        job = Job(kind, target)
        self.jobs[job.id] = job
        if len(self.jobs) > 300:
            for old in sorted(self.jobs.values(), key=lambda j: j.started)[:100]:
                if old.status != "running":
                    self.jobs.pop(old.id, None)

        def run():
            try:
                job.result = fn(job)
                job.status = "done"
            except (ProviderError, ConfigError, WaiverError) as exc:
                job.error, job.status = str(exc), "error"
            except Exception as exc:  # noqa: BLE001 - report every failure to the UI
                job.error, job.status = f"{type(exc).__name__}: {exc}", "error"
            finally:
                job.finished = time.time()

        self.pool.submit(run)
        return job


# --------------------------------------------------------------------------- per-cloud state

class CloudSession:
    def __init__(self, name: str, settings: Settings):
        self.name = name
        self.settings = settings
        self.lock = threading.RLock()
        self.reset()

    def reset(self, keep_results: bool = False) -> None:
        self.provider = None
        self.engine: SecurityEngine | None = None
        self.engines: dict[str, SecurityEngine] = {}     # account id -> engine (all-accounts scans)
        self.error: str | None = None
        if keep_results:
            return
        self.account: str | None = None
        self.results: dict[str, ScanResult] = {}
        self.investigations: dict = {}
        self.scanned_at: datetime | None = None
        self.outcome = None
        self.reviews: dict[str, Any] = {}                # account id -> AccountReview
        self.scope = "account"                           # account | all
        self.accounts: list[dict] = []
        self.account_errors: dict[str, str] = {}
        self.restored = False

    # -- connection --------------------------------------------------------------
    def connect(self) -> None:
        with self.lock:
            try:
                provider = get_provider(self.name, self.settings)
                account = provider.account_label()
            except ProviderError as exc:
                self.provider, self.error = None, str(exc)
                raise
            except Exception as exc:  # noqa: BLE001 - SDK-specific auth errors
                self.provider, self.error = None, f"{type(exc).__name__}: {exc}"
                raise ProviderError(self.error) from exc
            if self.restored and self.account and self.scope == "account" and account != self.account:
                self.reset()      # signed in to a different account: the saved scan doesn't apply
            self.provider, self.error = provider, None
            self.account = self.account if self.scope == "all" and self.results else account
            self.engine = SecurityEngine(provider, self.settings)
            self.engines = {provider.account_id(): self.engine}

    def require(self) -> SecurityEngine:
        if not self.engine:
            self.connect()
        return self.engine  # type: ignore[return-value]

    def engine_for(self, result: ScanResult) -> SecurityEngine:
        engine = self.require()
        acct = result.posture.resource.account
        if not acct or acct in self.engines:
            return self.engines.get(acct, engine)
        self.engines[acct] = SecurityEngine(engine.provider.for_account(acct), self.settings)
        return self.engines[acct]

    def result(self, name: str) -> ScanResult:
        if name not in self.results:
            raise HTTPException(404, f"'{name}' is not in the latest scan. Run a scan first.")
        return self.results[name]

    # -- derived ------------------------------------------------------------------
    @property
    def review(self):
        return merge_reviews(list(self.reviews.values()))

    def risks(self) -> dict:
        return {n: score_resource(r.findings, self.investigations.get(n), r.sensitive, r.proof)
                for n, r in self.results.items()}

    def reapply_waivers(self) -> None:
        store = SecurityEngine.__new__(SecurityEngine)
        store.waivers = WaiverStore(self.settings.data_dir)
        with self.lock:
            for r in self.results.values():
                store.apply_waivers(r)
            for review in self.reviews.values():
                store.apply_account_waivers(review)

    # -- persistence ----------------------------------------------------------------
    def save(self) -> None:
        if not self.results and not self.reviews:
            return
        with self.lock:
            saved_state.save(self.settings.data_dir, self.name, {
                "account": self.account, "scanned_at": self.scanned_at, "results": self.results,
                "investigations": self.investigations, "outcome": self.outcome, "reviews": self.reviews,
                "scope": self.scope, "accounts": self.accounts, "account_errors": self.account_errors,
            })

    def restore(self) -> None:
        data = saved_state.load(self.settings.data_dir, self.name)
        if not data:
            return
        self.account = data.get("account")
        self.scanned_at = data.get("scanned_at")
        self.results = data.get("results") or {}
        self.investigations = data.get("investigations") or {}
        self.outcome = data.get("outcome")
        self.reviews = data.get("reviews") or {}
        self.scope = data.get("scope") or "account"
        self.accounts = data.get("accounts") or []
        self.account_errors = data.get("account_errors") or {}
        self.restored = True
        self.reapply_waivers()     # waivers may have been added or expired since


# --------------------------------------------------------------------------- serialisers

def summarize(r: ScanResult, inv=None) -> dict:
    counts = {s: 0 for s in SEVERITIES}
    for f in r.all_findings:
        counts[f.severity.value] += 1
    top = r.top_severity
    res = r.posture.resource
    risk = score_resource(r.findings, inv, r.sensitive, r.proof)
    return {
        "name": res.name, "location": res.location, "kind": res.kind, "resource_id": res.resource_id,
        "account": res.account, "status": r.status, "top_severity": top.value if top else None,
        "findings": len(r.all_findings), "accepted": len(r.accepted),
        "severity_counts": counts, "verdict": inv.verdict if inv else None,
        "risk": risk.score, "risk_level": risk.level,
        "classification": r.sensitive.classification if r.sensitive else None,
        "verified_public": (r.proof.publicly_listable or bool(r.proof.publicly_readable)) if r.proof else None,
        "failing_categories": sorted({CHECK_CATEGORY[f.check_id] for f in r.all_findings
                                      if f.check_id in CHECK_CATEGORY and f.severity != Severity.INFO}),
        "encryption": r.posture.config.get("encryption_summary"),
    }


def finding_dict(f, resource: str | None = None) -> dict:
    d = {**f.to_dict(), "controls": controls_for(f.check_id)}
    if resource:
        d["waiver_resource"] = resource
    return d


def investigation_dict(inv) -> dict | None:
    if not inv:
        return None
    d = inv.to_dict()
    d["access_events"] = d["access_events"][-500:]
    d["verdict_text"] = VERDICT_TEXT[inv.verdict]
    return d


def provider_hint(name: str, s: Settings) -> str | None:
    if name == "azure" and not s.azure_subscription_id:
        return "Azure subscription not set. Open Settings > Azure."
    return None


def _shown_path(path: Path) -> str:
    """Paths inside the app folder are shown relative to it (keeps user names out of screenshots)."""
    try:
        return Path(path).resolve().relative_to(HOME).as_posix()
    except ValueError:
        return str(path)


def _account_finding_resource(f, review) -> str:
    return account_resource((f.evidence or {}).get("account") or review.account_id)


# --------------------------------------------------------------------------- app

def create_app(settings: Settings, token: str) -> FastAPI:
    app = FastAPI(title="CloudDetectX", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    jobs = JobManager()
    sessions = {n: CloudSession(n, settings) for n in PROVIDER_NAMES}
    for s in sessions.values():
        s.restore()
    waivers = WaiverStore(settings.data_dir)

    def session(name: str) -> CloudSession:
        if name not in sessions:
            raise HTTPException(404, f"Unknown cloud '{name}'")
        return sessions[name]

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if request.headers.get("host", "").rsplit(":", 1)[0] not in ("127.0.0.1", "localhost"):
            return PlainTextResponse("Forbidden host", status_code=403)  # blocks DNS-rebinding
        supplied = request.query_params.get("token")
        if supplied and secrets.compare_digest(supplied, token):
            resp = RedirectResponse(request.url.path or "/", status_code=303)
            resp.set_cookie(COOKIE, token, httponly=True, samesite="strict")
            return resp
        if not secrets.compare_digest(request.cookies.get(COOKIE, ""), token):
            if request.url.path.startswith("/api"):
                return JSONResponse({"detail": "Not authorised. Open the link printed in the terminal."}, 401)
            return HTMLResponse(LOCKED_PAGE, 401)
        if request.method in ("POST", "PUT", "DELETE") and request.headers.get("x-clouddetectx") != "1":
            return JSONResponse({"detail": "Missing X-CloudDetectX header"}, 403)
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
        response.headers["Cache-Control"] = "no-store"
        return response

    for exc_type in (ProviderError, ConfigError, WaiverError):
        app.add_exception_handler(exc_type, lambda _r, exc: JSONResponse({"detail": str(exc)}, 400))

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    # -- status ----------------------------------------------------------------------
    def cloud_summary(s: CloudSession) -> dict:
        resources = [summarize(r, s.investigations.get(n)) for n, r in s.results.items()]
        sev = {k: 0 for k in SEVERITIES}
        for r in resources:
            for k, v in r["severity_counts"].items():
                sev[k] += v
        review = s.review
        for f in (review.findings if review else []):
            sev[f.severity.value] += 1
        risks = [RiskScore(r["risk"], r["risk_level"]) for r in resources]
        score = posture_score(risks) if resources else None
        o = s.outcome
        return {
            "name": s.name, "display": PROVIDERS[s.name], "connected": bool(s.engine), "account": s.account,
            "error": s.error, "hint": provider_hint(s.name, settings),
            "scanned_at": s.scanned_at.isoformat() if s.scanned_at else None, "restored": s.restored and not s.engine,
            "scope": s.scope, "accounts": s.accounts, "account_errors": s.account_errors,
            "counts": {"resources": len(resources), **{st: sum(1 for r in resources if r["status"] == st) for st in STATUSES}},
            "severity_counts": sev,
            "posture_score": score, "grade": overview.grade(score),
            "account_review": review is not None,
            "drift": o.drift.to_dict() if o and o.drift else None,
            "alert_error": o.alert_error if o else None,
            "alerts_sent": len(o.alerts) if o else 0,
        }

    @app.get("/api/status")
    def status():
        return {
            "version": __version__, "env_file": _shown_path(ENV_FILE), "configured": ENV_FILE.exists(),
            "default_providers": settings.providers, "warnings": settings.warnings,
            "reports_dir": _shown_path(settings.reports_dir),
            "clouds": [cloud_summary(s) for s in sessions.values()],
        }

    @app.get("/api/jobs/{job_id}")
    def job_status(job_id: str):
        job = jobs.jobs.get(job_id)
        if not job:
            raise HTTPException(404, "Unknown job")
        return job.to_dict()

    # -- clouds ------------------------------------------------------------------------
    @app.post("/api/clouds/{name}/connect")
    def connect(name: str):
        s = session(name)
        s.reset(keep_results=True)
        s.connect()
        return cloud_summary(s)

    @app.get("/api/clouds/{name}/accounts")
    def list_accounts(name: str):
        s = session(name)
        return {"accounts": s.require().provider.list_accounts()}

    @app.post("/api/clouds/{name}/scan")
    def scan(name: str, body: dict = Body(default={})):
        s = session(name)
        all_accounts = bool(body.get("all_accounts"))

        def work(job: Job):
            engine = s.require()
            if all_accounts:
                job.log("Listing accounts")
                scans, errors = scan_all_accounts(engine.provider, settings, on_progress=job.log)
                results = [r for sc in scans for r in sc.results]
                label = f"All {PROVIDERS[name]} accounts ({len(scans)})"
                with s.lock:
                    s.results = {r.posture.resource.name: r for r in results}
                    s.engines = {sc.account["id"]: sc.engine for sc in scans}
                    s.reviews = {sc.account["id"]: sc.review for sc in scans if sc.review is not None}
                    s.accounts, s.account_errors, s.scope, s.account = [sc.account for sc in scans], errors, "all", label
                for acct, err in errors.items():
                    job.log(f"Skipped account {acct}: {err}")
            else:
                job.log(f"Connected: {s.account}")
                results = engine.scan(on_progress=lambda n: job.log(f"Scanning {n}"))
                review = engine.review_account(on_progress=job.log)
                with s.lock:
                    s.results = {r.posture.resource.name: r for r in results}
                    s.reviews = {engine.provider.account_id(): review} if review is not None else {}
                    s.scope, s.accounts, s.account_errors = "account", [], {}
                    s.account = engine.provider.account_label()
                    s.engines = {engine.provider.account_id(): engine}
            with s.lock:
                s.investigations = {k: v for k, v in s.investigations.items() if k in s.results}
                s.scanned_at = datetime.now(timezone.utc)
                s.restored = False
            review = s.review
            if review is not None:
                job.log(f"Account checks: {len(review.findings)} finding(s)"
                        + (f", {len(review.errors)} area(s) skipped" if review.errors else ""))
            job.log("Scoring risk, recording history, checking drift")
            s.outcome = after_scan(settings, name, s.account or "", results, investigations=s.investigations)
            s.save()
            exposed = sum(1 for r in results if r.exposed)
            job.log(f"Done: {len(results)} resource(s), {exposed} publicly exposed")
            if s.outcome.alert_error:
                job.log(f"Alert failed: {s.outcome.alert_error}")
            elif s.outcome.alerts:
                job.log(f"Alerts sent: {len(s.outcome.alerts)}")
            return cloud_summary(s)

        return {"job": jobs.submit("scan", name, work).id}

    @app.get("/api/clouds/{name}/resources")
    def resources(name: str):
        s = session(name)
        return {"scanned_at": s.scanned_at.isoformat() if s.scanned_at else None,
                "resources": [summarize(r, s.investigations.get(n)) for n, r in s.results.items()]}

    def access_dict(s: CloudSession, r: ScanResult) -> dict:
        cfg = r.posture.config
        external = [f.evidence.get("statements", []) for f in r.findings + r.accepted if f.check_id == "AWS-S3-009"]
        review = s.reviews.get(r.posture.resource.account) or (next(iter(s.reviews.values())) if len(s.reviews) == 1 else None)
        iam = review.iam if review is not None else None
        bucket_level = s.name == "aws"
        return {
            "iam_supported": bucket_level,
            "iam_analyzed": iam is not None,
            "iam_error": (review.errors.get("iam") if review else None) if bucket_level else None,
            "principals": iam.bucket_access(r.posture.resource.name) if (iam is not None and bucket_level) else [],
            "external_accounts": external[0] if external else [],
            "public": r.exposed,
            "encryption": cfg.get("encryption_summary"),
        }

    def detail(s: CloudSession, rname: str) -> dict:
        r = s.result(rname)
        inv = s.investigations.get(rname)
        return {
            "summary": summarize(r, inv),
            "resource": asdict(r.posture.resource),
            "findings": [finding_dict(f, rname) for f in sorted(r.all_findings, key=lambda f: -f.severity.rank)],
            "accepted": [finding_dict(f, rname) for f in r.accepted],
            "investigation": investigation_dict(inv),
            "risk": score_resource(r.findings, inv, r.sensitive, r.proof).to_dict(),
            "sensitive": r.sensitive.to_dict() if r.sensitive else None,
            "proof": r.proof.to_dict() if r.proof else None,
            "access": access_dict(s, r),
        }

    @app.get("/api/clouds/{name}/resources/{rname}")
    def resource(name: str, rname: str):
        return detail(session(name), rname)

    @app.post("/api/clouds/{name}/resources/{rname}/rescan")
    def rescan(name: str, rname: str):
        s = session(name)
        old = s.result(rname)
        engine = s.engine_for(old)
        result = engine.scan_one(rname)
        result.sensitive, result.proof = old.sensitive, old.proof  # these describe content, not configuration
        result.data_findings = data_findings_from(old.sensitive, result.exposed) if old.sensitive else []
        engine.apply_waivers(result)
        with s.lock:
            s.results[rname] = result
        s.save()
        return detail(s, rname)

    @app.post("/api/clouds/{name}/resources/{rname}/investigate")
    def investigate(name: str, rname: str, body: dict = Body(default={})):
        s = session(name)
        result = s.result(rname)
        days = int(body.get("days") or settings.lookback_days)
        if not 1 <= days <= 3650:
            raise HTTPException(400, "days must be between 1 and 3650")

        def work(job: Job):
            job.log(f"Searching access and audit logs for the last {days} days")
            inv = s.engine_for(result).investigate(result.posture, days)
            s.investigations[rname] = inv
            s.save()
            job.log(f"Verdict: {inv.verdict}")
            err = alert_data_accessed(settings, name, rname, inv)
            if err:
                job.log(f"Alert failed: {err}")
            return investigation_dict(inv)

        return {"job": jobs.submit("investigate", rname, work).id}

    @app.post("/api/clouds/{name}/resources/{rname}/discover")
    def discover_data(name: str, rname: str):
        s = session(name)
        result = s.result(rname)

        def work(job: Job):
            report = s.engine_for(result).discover(result, on_progress=job.log)
            s.save()
            job.log(f"Classification: {report.classification}")
            return report.to_dict()

        return {"job": jobs.submit("discover", rname, work).id}

    @app.post("/api/clouds/{name}/resources/{rname}/verify")
    def verify(name: str, rname: str):
        s = session(name)
        result = s.result(rname)

        def work(job: Job):
            job.log("Requesting public URLs without credentials")
            proof = s.engine_for(result).verify_exposure(result)
            s.save()
            job.log(proof.summary)
            return proof.to_dict()

        return {"job": jobs.submit("verify", rname, work).id}

    @app.post("/api/clouds/{name}/resources/{rname}/plan")
    def plan(name: str, rname: str, body: dict = Body(default={})):
        s = session(name)
        result = s.result(rname)
        actions, _ = s.engine_for(result).remediate(result, dry_run=True, harden=bool(body.get("harden")))
        return {"actions": [a.to_dict() for a in actions]}

    def apply_fix(s: CloudSession, rname: str, harden: bool, job: Job) -> dict:
        result = s.result(rname)
        engine = s.engine_for(result)
        inc = engine.new_incident(result, s.investigations.get(rname))
        job.log(f"Applying remediation to {rname}")
        inc.remediation, inc.verification = engine.remediate(result, dry_run=False, harden=harden)
        for a in inc.remediation:
            job.log(f"[{a.status}] {a.action}")
        SecurityEngine.finalize_status(inc)
        md_path, _ = write_report(inc, settings.reports_dir)
        job.log(f"Re-scanning {rname}")
        fresh = engine.scan_one(rname)
        fresh.sensitive = result.sensitive
        fresh.data_findings = data_findings_from(result.sensitive, fresh.exposed) if result.sensitive else []
        engine.apply_waivers(fresh)
        with s.lock:
            s.results[rname] = fresh
        s.save()
        return {"status": inc.status, "actions": [a.to_dict() for a in inc.remediation],
                "verification": [f.to_dict() for f in inc.verification] if inc.verification is not None else None,
                "still_exposed": fresh.exposed, "report_id": md_path.stem}

    @app.post("/api/clouds/{name}/resources/{rname}/remediate")
    def remediate(name: str, rname: str, body: dict = Body(default={})):
        s = session(name)
        s.result(rname)
        if (body.get("confirm_name") or "").strip() != rname:
            raise HTTPException(400, "Type the resource name exactly to confirm.")
        harden = bool(body.get("harden"))
        return {"job": jobs.submit("remediate", rname, lambda job: apply_fix(s, rname, harden, job)).id}

    @app.post("/api/clouds/{name}/resources/{rname}/report")
    def save_report(name: str, rname: str):
        s = session(name)
        result = s.result(rname)
        inc = s.engine_for(result).new_incident(result, s.investigations.get(rname))
        SecurityEngine.finalize_status(inc)
        md_path, _ = write_report(inc, settings.reports_dir)
        return {"report_id": md_path.stem}

    @app.post("/api/clouds/{name}/respond")
    def respond(name: str, body: dict = Body(default={})):
        s = session(name)
        names = [n for n in body.get("names") or [] if n in s.results]
        if not names:
            raise HTTPException(400, "Select at least one resource from the latest scan.")
        mode = body.get("mode", "plan")
        if mode == "apply" and body.get("confirm") != "REMEDIATE":
            raise HTTPException(400, "Type REMEDIATE to confirm changes to live resources.")
        harden, do_verify, do_discover = bool(body.get("harden")), bool(body.get("verify")), bool(body.get("discover"))
        days = int(body.get("days") or settings.lookback_days)

        def work(job: Job):
            out = []
            for rname in names:
                result = s.results[rname]
                engine = s.engine_for(result)
                job.log(f"=== {rname}")
                if do_verify:
                    job.log("Verifying exposure from the internet")
                    job.log(engine.verify_exposure(result).summary)
                if do_discover:
                    job.log("Discovering sensitive data")
                    job.log(f"Classification: {engine.discover(result, on_progress=job.log).classification}")
                job.log("Investigating access activity")
                inv = engine.investigate(result.posture, days)
                s.investigations[rname] = inv
                job.log(f"Verdict: {inv.verdict}")
                alert_data_accessed(settings, name, rname, inv)
                risk = engine.risk(result, inv)
                job.log(f"Risk score: {risk.score}/100 ({risk.level})")
                if mode == "apply":
                    res = apply_fix(s, rname, harden, job)
                    out.append({"name": rname, "verdict": inv.verdict, "outcome": res["status"], "risk": risk.score,
                                "classification": result.sensitive.classification if result.sensitive else None,
                                "still_exposed": res["still_exposed"], "report_id": res["report_id"]})
                else:
                    inc = engine.new_incident(result, inv)
                    inc.remediation, _ = engine.remediate(result, dry_run=True, harden=harden)
                    SecurityEngine.finalize_status(inc)
                    md_path, _ = write_report(inc, settings.reports_dir)
                    job.log(f"Plan saved ({len(inc.remediation)} action(s))")
                    out.append({"name": rname, "verdict": inv.verdict, "outcome": inc.status, "risk": risk.score,
                                "classification": result.sensitive.classification if result.sensitive else None,
                                "still_exposed": result.exposed, "report_id": md_path.stem})
            s.save()
            return out

        return {"job": jobs.submit("respond", name, work).id}

    # -- account-wide review (IAM + account checks) ------------------------------------------
    def account_payload(s: CloudSession) -> dict:
        review = s.review
        if review is None:
            return {"supported": True, "scanned": s.scanned_at is not None, "enabled": settings.account_checks,
                    "report": None, "controls": {}}
        d = review.to_dict()
        d["findings"] = [finding_dict(f, _account_finding_resource(f, review)) for f in
                         sorted(review.findings, key=lambda f: -f.severity.rank)]
        d["waived"] = [finding_dict(f, _account_finding_resource(f, review)) for f in review.waived]
        return {"supported": True, "scanned": True, "enabled": settings.account_checks, "report": d,
                "scope": s.scope, "accounts": s.accounts}

    @app.get("/api/clouds/{name}/account")
    def account_review(name: str):
        return account_payload(session(name))

    @app.post("/api/clouds/{name}/account/analyze")
    def account_analyze(name: str):
        s = session(name)

        def work(job: Job):
            engines = list(s.engines.values()) if s.scope == "all" and s.engines else [s.require()]
            reviews = {}
            for engine in engines:
                review = engine.review_account(on_progress=job.log)
                if review is not None:
                    reviews[engine.provider.account_id()] = review
            if not reviews:
                raise ProviderError("Account-wide checks are switched off (Settings > General).")
            with s.lock:
                s.reviews = reviews
            s.save()
            return s.review.counts()

        return {"job": jobs.submit("account", name, work).id}

    # -- waivers (accepted risk) -------------------------------------------------------------
    @app.get("/api/waivers")
    def list_waivers():
        return {"waivers": [w.to_dict() for w in sorted(waivers.all(), key=lambda w: w.expires)]}

    @app.post("/api/waivers")
    def add_waiver(body: dict = Body(...)):
        provider = body.get("provider")
        if provider not in sessions:
            raise HTTPException(400, "Unknown cloud")
        w = waivers.add(provider, str(body.get("resource") or ""), str(body.get("check_id") or ""),
                        str(body.get("reason") or ""), str(body.get("expires") or ""), str(body.get("created_by") or ""))
        sessions[provider].reapply_waivers()
        sessions[provider].save()
        return w.to_dict()

    @app.delete("/api/waivers/{waiver_id}")
    def delete_waiver(waiver_id: str):
        if not re.fullmatch(r"[0-9a-f]{10}", waiver_id):
            raise HTTPException(400, "Bad waiver id")
        if not waivers.remove(waiver_id):
            raise HTTPException(404, "Waiver not found")
        for s in sessions.values():
            s.reapply_waivers()
            s.save()
        return {"ok": True}

    # -- compliance, history, alerts, exports -------------------------------------------------
    @app.get("/api/clouds/{name}/compliance")
    def compliance(name: str):
        s = session(name)
        data = overview.compliance(name, list(s.results.values()), s.review)
        return {"scanned_at": s.scanned_at.isoformat() if s.scanned_at else None, "resources": len(s.results),
                "account_checked": s.review is not None, **data}

    @app.post("/api/clouds/{name}/compliance/report")
    def compliance_report(name: str):
        s = session(name)
        if not s.results:
            raise HTTPException(400, "Run a scan first.")
        risks = s.risks()
        data = build_compliance_report(name, PROVIDERS[name], s.account or "", list(s.results.values()), risks,
                                       s.review, posture_score(list(risks.values())))
        md_path, _ = write_compliance_report(data, settings.reports_dir)
        return {"report_id": md_path.stem}

    @app.get("/api/clouds/{name}/overview")
    def cloud_overview(name: str):
        s = session(name)
        risks = s.risks()
        data = overview.build(name, list(s.results.values()), risks, s.review)
        score = posture_score(list(risks.values())) if risks else None
        h = History(settings.data_dir)
        try:
            rows = h.trend(name, s.account or None, limit=2) if s.account else []
        finally:
            h.close()
        recorded = [r["posture_score"] for r in rows if r.get("posture_score") is not None]
        data.update(score=score, grade=overview.grade(score),
                    score_delta=recorded[-1] - recorded[-2] if len(recorded) == 2 else None)
        return data

    @app.get("/api/clouds/{name}/export/{fmt}")
    def export(name: str, fmt: str):
        from clouddetectx import export as exporter

        s = session(name)
        if fmt not in exporter.FORMATS:
            raise HTTPException(400, f"Format must be one of: {', '.join(exporter.FORMATS)}")
        if not s.results and s.review is None:
            raise HTTPException(400, "Run a scan first.")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        results = list(s.results.values())
        if fmt == "csv":
            body, mime, ext = exporter.to_csv(name, results, s.review), "text/csv", "csv"
        elif fmt == "sarif":
            body, mime, ext = json.dumps(exporter.to_sarif(name, results, s.review), indent=2), "application/sarif+json", "sarif"
        else:
            body, mime, ext = json.dumps(exporter.to_ocsf(name, results, s.review), indent=2), "application/json", "ocsf.json"
        return Response(body, media_type=mime,
                        headers={"Content-Disposition": f'attachment; filename="clouddetectx-{name}-{stamp}.{ext}"'})

    @app.get("/api/clouds/{name}/history")
    def history(name: str):
        s = session(name)
        h = History(settings.data_dir)
        try:
            rows = h.trend(name, s.account or None, limit=60) if s.account else h.trend(name, limit=60)
        finally:
            h.close()
        return {"scans": rows, "drift": s.outcome.drift.to_dict() if s.outcome and s.outcome.drift else None}

    @app.post("/api/alerts/test")
    def alert_test():
        if not settings.webhook_url:
            raise HTTPException(400, "No webhook configured. Set it under Settings > Alerts.")
        try:
            send_alert(settings.webhook_url, "CloudDetectX test alert", ["Alerts are working. This is only a test."], {"test": True})
        except AlertError as exc:
            raise HTTPException(400, str(exc)) from exc
        return {"ok": True}

    # -- reports ------------------------------------------------------------------------
    def report_path(report_id: str, ext: str) -> Path:
        if not REPORT_ID.match(report_id):
            raise HTTPException(400, "Bad report id")
        path = (settings.reports_dir / f"{report_id}.{ext}").resolve()
        if path.parent != settings.reports_dir.resolve() or not path.is_file():
            raise HTTPException(404, "Report not found")
        return path

    @app.get("/api/reports")
    def reports():
        folder = settings.reports_dir
        items = []
        if folder.exists():
            paths = list(folder.glob("INC-*.json")) + list(folder.glob("CMP-*.json"))
            for p in sorted(paths, key=lambda p: p.stat().st_mtime, reverse=True)[:500]:
                try:
                    data = json.loads(p.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                if data.get("type") == "compliance":
                    st = (data.get("compliance") or {}).get("status") or {}
                    items.append({"id": p.stem, "type": "compliance", "provider": data.get("provider"),
                                  "resource": f"{len(data.get('resources') or [])} resources",
                                  "detected_at": data.get("generated_at"), "grade": data.get("grade"),
                                  "controls_failing": sum(v.get("failing", 0) for v in st.values()),
                                  "controls_assessed": sum(v.get("assessed", 0) for v in st.values())})
                    continue
                inv = data.get("investigation") or {}
                items.append({
                    "id": p.stem, "type": "incident", "status": data.get("status"), "severity": data.get("severity"),
                    "provider": (data.get("resource") or {}).get("provider"),
                    "resource": (data.get("resource") or {}).get("name"),
                    "detected_at": data.get("detected_at"), "verdict": inv.get("verdict"),
                    "rolled_back": (data.get("rollback") or {}).get("status") == "applied",
                })
        return {"folder": _shown_path(folder), "reports": items}

    def _report_json(report_id: str) -> dict:
        return json.loads(report_path(report_id, "json").read_text(encoding="utf-8"))

    @app.get("/api/reports/{report_id}")
    def report(report_id: str):
        text = report_path(report_id, "md").read_text(encoding="utf-8")
        html = md.markdown(text, extensions=["tables", "fenced_code"])
        # Reports contain attacker-controlled strings (object keys, user agents): sanitise.
        safe = nh3.clean(html, tags={"h1", "h2", "h3", "h4", "p", "table", "thead", "tbody", "tr", "th", "td", "code",
                                     "pre", "ul", "ol", "li", "strong", "em", "details", "summary", "br", "hr"},
                         attributes={})
        meta = {}
        if report_id.startswith("INC-"):
            data = _report_json(report_id)
            applied = [a for a in data.get("remediation") or [] if a.get("status") == "applied"]
            meta = {"resource": (data.get("resource") or {}).get("name"),
                    "provider": (data.get("resource") or {}).get("provider"),
                    "can_rollback": bool(applied) and (data.get("rollback") or {}).get("status") != "applied",
                    "rollback": data.get("rollback")}
        return {"id": report_id, "html": safe, **meta}

    @app.get("/api/reports/{report_id}/download/{fmt}")
    def download(report_id: str, fmt: str):
        if fmt not in ("md", "json", "pdf"):
            raise HTTPException(400, "fmt must be md, json or pdf")
        if fmt == "pdf":
            from clouddetectx.export import markdown_to_pdf

            pdf = markdown_to_pdf(report_path(report_id, "md").read_text(encoding="utf-8"), report_id)
            return Response(pdf, media_type="application/pdf",
                            headers={"Content-Disposition": f'attachment; filename="{report_id}.pdf"'})
        path = report_path(report_id, fmt)
        return FileResponse(path, filename=path.name)

    @app.post("/api/reports/{report_id}/rollback")
    def rollback(report_id: str, body: dict = Body(default={})):
        if not report_id.startswith("INC-"):
            raise HTTPException(400, "Only incident reports can be rolled back.")
        data = _report_json(report_id)
        res = data.get("resource") or {}
        dry_run = bool(body.get("dry_run"))
        if not dry_run and (body.get("confirm_name") or "").strip() != res.get("name"):
            raise HTTPException(400, "Type the resource name exactly to confirm. Rolling back can make data public again.")
        s = session(res.get("provider", ""))
        engine = s.require()
        if res.get("account") and res["account"] != engine.provider.account_id():
            engine = SecurityEngine(engine.provider.for_account(res["account"]), settings)
        actions = engine.rollback(data, dry_run=dry_run)
        if dry_run:
            return {"actions": [a.to_dict() for a in actions], "dry_run": True}
        from clouddetectx.reporting import record_rollback

        record_rollback(report_path(report_id, "json"), report_path(report_id, "md"), actions)
        if res.get("name") in s.results:
            fresh = engine.scan_one(res["name"])
            old = s.results[res["name"]]
            fresh.sensitive, fresh.proof = old.sensitive, old.proof
            with s.lock:
                s.results[res["name"]] = fresh
            s.save()
        return {"actions": [a.to_dict() for a in actions], "dry_run": False}

    # -- settings ------------------------------------------------------------------------------
    def field_dict(f: Field) -> dict:
        value = settings.get(f)
        text = to_text(f, value)
        return {"key": f.key, "label": f.label, "help": f.help, "kind": f.kind, "secret": f.secret,
                "default": f.default, "value": "" if f.secret else text, "is_set": bool(text),
                "display": display(f, value), "min": f.lo if f.kind == "int" else None,
                "max": f.hi if f.kind == "int" else None,
                "stored_in": settings.secret_locations.get(f.key) if f.secret else None}

    @app.get("/api/settings")
    def get_settings():
        return {"env_file": _shown_path(ENV_FILE), "keychain": secret_store.available, "sections": [
            {"name": sec, "title": SECTION_TITLES[sec], "provider": SECTION_PROVIDER.get(sec),
             "fields": [field_dict(f) for f in FIELDS if f.section == sec]} for sec in SECTIONS]}

    @app.put("/api/settings/{key}")
    def put_setting(key: str, body: dict = Body(...)):
        f = find_field(key)
        settings.set(f, str(body.get("value") or ""))
        provider = SECTION_PROVIDER.get(f.section)
        if provider:
            sessions[provider].reset(keep_results=True)  # sign-in settings changed: reconnect on next use
        return field_dict(f)

    @app.post("/api/settings/migrate-secrets")
    def migrate_secrets():
        if not secret_store.available:
            raise HTTPException(400, "No OS keychain is available on this system; secrets stay in .env.")
        return {"moved": settings.migrate_secrets()}

    @app.post("/api/settings/gcp-key")
    def gcp_key(body: dict = Body(...)):
        content = str(body.get("content") or "")
        if len(content) > 32 * 1024:
            raise HTTPException(400, "That file is too large to be a service-account key.")
        try:
            key = json.loads(content)
        except ValueError as exc:
            raise HTTPException(400, "Not a JSON file.") from exc
        if not isinstance(key, dict) or key.get("type") != "service_account" or not all(
                key.get(k) for k in ("client_email", "private_key", "project_id")):
            raise HTTPException(400, "Not a Google Cloud service-account key (expected type 'service_account').")
        folder = settings.data_dir / "keys"
        folder.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(key["client_email"].encode()).hexdigest()[:8]
        path = folder / f"gcp-{re.sub(r'[^a-z0-9-]', '', key['project_id'].lower())[:40]}-{digest}.json"
        path.write_text(json.dumps(key), encoding="utf-8")
        if os.name != "nt":
            path.chmod(0o600)
        settings.set(find_field("GOOGLE_APPLICATION_CREDENTIALS"), str(path.resolve()))
        if not settings.gcp_project:
            settings.set(find_field("GOOGLE_CLOUD_PROJECT"), key["project_id"])
        sessions["gcp"].reset(keep_results=True)
        return {"project": key["project_id"], "client_email": key["client_email"], "path": str(path.name)}

    @app.get("/api/settings/options/{kind}")
    def options(kind: str):
        from clouddetectx.config_ui import _aws_profiles, _aws_regions, _cli_json

        if kind == "region":
            return {"options": [{"value": r, "label": r} for r in _aws_regions()]}
        if kind == "profile":
            return {"options": [{"value": p, "label": p} for p in _aws_profiles()]}
        if kind == "subscription":
            subs = _cli_json("az", "account", "list", "--all", "-o", "json") or []
            return {"options": [{"value": x["id"], "label": f"{x.get('name', '?')} ({x['id']})"} for x in subs],
                    "note": None if subs else "No subscriptions found: the Azure CLI is not installed or not signed in."}
        if kind == "project":
            projects = _cli_json("gcloud", "projects", "list", "--format=json") or []
            return {"options": [{"value": p["projectId"], "label": f"{p['projectId']} ({p.get('name', '')})"} for p in projects],
                    "note": None if projects else "No projects found: gcloud is not installed or not signed in."}
        if kind == "bucket":
            names = [r.name for r in sessions["aws"].require().provider.list_resources()]
            return {"options": [{"value": n, "label": n} for n in names]}
        raise HTTPException(404, "No options for this setting")

    @app.post("/api/settings/aws-profile")
    def aws_profile(body: dict = Body(...)):
        from clouddetectx.config_ui import _write_aws_profile

        name = (body.get("name") or "").strip()
        key_id, secret = (body.get("key_id") or "").strip(), (body.get("secret") or "").strip()
        if not name or " " in name:
            raise HTTPException(400, "Profile name is required and cannot contain spaces.")
        if len(key_id) < 16 or len(secret) < 20:
            raise HTTPException(400, "That doesn't look like an AWS access key ID and secret.")
        path = _write_aws_profile(name, key_id, secret, body.get("region") or None)
        settings.set(find_field("AWS_PROFILE"), name)
        sessions["aws"].reset(keep_results=True)
        return {"profile": name, "path": str(path)}

    @app.post("/api/clouds/{name}/signin")
    def signin(name: str, body: dict = Body(default={})):
        from clouddetectx.config_ui import _run_cli

        commands = {
            ("aws", "sso"): ["aws", "sso", "login"] + (["--profile", settings.aws_profile] if settings.aws_profile else []),
            ("azure", "cli"): ["az", "login"],
            ("azure", "device"): ["az", "login", "--use-device-code"],
            ("gcp", "cli"): ["gcloud", "auth", "application-default", "login"],
        }
        cmd = commands.get((name, body.get("method")))
        if not cmd:
            raise HTTPException(400, "Unknown sign-in method")

        def work(job: Job):
            job.log(f"Running {' '.join(cmd)}: finish the sign-in in the browser window it opens "
                    "(device codes are shown in the terminal running the dashboard).")
            if not _run_cli(*cmd):
                raise ProviderError(f"`{' '.join(cmd)}` failed or is not installed.")
            sessions[name].reset(keep_results=True)
            return {"ok": True}

        return {"job": jobs.submit("signin", name, work).id}

    @app.post("/api/clouds/{name}/test")
    def test_connection(name: str):
        s = session(name)
        s.reset(keep_results=True)
        s.connect()
        return {"account": s.engine.provider.account_label()}

    # -- scheduled scans -------------------------------------------------------------------------
    @app.get("/api/schedule")
    def schedule_status():
        from clouddetectx import schedule

        return schedule.status()

    @app.post("/api/schedule")
    def schedule_install(body: dict = Body(...)):
        from clouddetectx import schedule

        every = int(body.get("every") or 0)
        providers = [p for p in body.get("providers") or settings.providers if p in PROVIDER_NAMES]
        if not providers:
            raise HTTPException(400, "Choose at least one cloud.")
        try:
            message = schedule.install(schedule.plan(settings.data_dir, every, providers, bool(body.get("all_accounts"))))
        except schedule.ScheduleError as exc:
            raise HTTPException(400, str(exc)) from exc
        return {"message": message, **schedule.status()}

    @app.delete("/api/schedule")
    def schedule_remove():
        from clouddetectx import schedule

        return {"message": schedule.remove(), **schedule.status()}

    return app


def _free_port(preferred: int) -> int:
    for port in range(preferred, preferred + 50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise OSError("No free port found")


def serve(settings: Settings, port: int = 8765, open_browser: bool = True) -> int:
    import uvicorn
    from rich.panel import Panel

    from clouddetectx.cli import console

    token = secrets.token_urlsafe(24)
    port = _free_port(port)
    url = f"http://127.0.0.1:{port}/?token={token}"
    console.print(Panel(f"[bold]Dashboard:[/] {url}\n[dim]Only reachable from this computer. Keep this link private; "
                        "it grants access to your cloud accounts.\nPress Ctrl+C to stop.[/]",
                        title="CloudDetectX", border_style="cyan"))
    if open_browser:
        threading.Timer(1.0, webbrowser.open, [url]).start()
    uvicorn.run(create_app(settings, token), host="127.0.0.1", port=port, log_level="warning")
    return 0
