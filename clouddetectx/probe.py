"""External exposure verification: request the resource's public URLs with NO credentials.

This is the attacker's-eye view. Configuration analysis says a bucket *should* be public;
this proves whether anyone on the internet can actually list it or read an object right now.
Only HEAD requests are used for objects and only the first page of a listing is read.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

USER_AGENT = "CloudDetectX-exposure-check/2.0 (+authorised self-assessment)"
MAX_BODY = 64 * 1024


@dataclass
class ProbeTarget:
    check: str      # anonymous-list | anonymous-read
    label: str      # human readable, e.g. container or object key
    url: str
    method: str = "GET"


@dataclass
class ProbeResult:
    check: str
    label: str
    url: str
    status: int | None
    accessible: bool
    detail: str
    sample: list[str] = field(default_factory=list)


@dataclass
class ExposureProof:
    performed_at: str
    results: list[ProbeResult]
    publicly_listable: bool
    publicly_readable: bool | None   # None = no object available to test
    summary: str

    def to_dict(self) -> dict:
        return asdict(self)


_NAME_PATTERNS = (
    re.compile(r"<Key>(.*?)</Key>"),            # S3 ListObjectsV2
    re.compile(r"<Name>(.*?)</Name>"),          # Azure List Blobs
    re.compile(r'"name"\s*:\s*"([^"]+)"'),      # GCS JSON API
)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # report redirects instead of silently following them
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def _request(target: ProbeTarget, timeout: float) -> ProbeResult:
    req = urllib.request.Request(target.url, method=target.method, headers={"User-Agent": USER_AGENT})
    try:
        with _opener.open(req, timeout=timeout) as resp:
            body = resp.read(MAX_BODY) if target.method == "GET" else b""
            sample: list[str] = []
            if target.check == "anonymous-list":
                text = body.decode("utf-8", errors="replace")
                for rx in _NAME_PATTERNS:
                    sample = rx.findall(text)
                    if sample:
                        break
                if rx.pattern.startswith("<Name>") and sample and "<Blob>" not in text:
                    sample = []
            accessible = 200 <= resp.status < 300
            what = "listing returned" if target.check == "anonymous-list" else "object is downloadable"
            return ProbeResult(target.check, target.label, target.url, resp.status, accessible,
                               f"HTTP {resp.status}: {what} without credentials", sample[:10])
    except urllib.error.HTTPError as exc:
        reason = {401: "authentication required", 403: "access denied", 404: "not found or not public",
                  409: "public access not permitted"}.get(exc.code, exc.reason)
        return ProbeResult(target.check, target.label, target.url, exc.code, False, f"HTTP {exc.code}: {reason}")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        return ProbeResult(target.check, target.label, target.url, None, False, f"Request failed: {reason}")


def run_probes(targets: list[ProbeTarget], timeout: float = 10.0, request=_request) -> ExposureProof:
    results = [request(t, timeout) for t in targets]
    lists = [r for r in results if r.check == "anonymous-list"]
    reads = [r for r in results if r.check == "anonymous-read"]
    listable = any(r.accessible for r in lists)
    readable = any(r.accessible for r in reads) if reads else None
    unreachable = [r for r in results if r.status is None]
    if listable and readable:
        summary = "Confirmed from the internet: anyone can list the contents AND download objects."
    elif listable:
        summary = "Confirmed from the internet: anyone can list object names."
    elif readable:
        summary = "Confirmed from the internet: objects can be downloaded by anyone who knows or guesses their names."
    elif unreachable and len(unreachable) == len(results):
        summary = "Could not reach the storage endpoint from this machine; exposure not verified."
    else:
        summary = "Not reachable anonymously: every request without credentials was refused."
    return ExposureProof(datetime.now(timezone.utc).isoformat(), results, listable, readable, summary)
