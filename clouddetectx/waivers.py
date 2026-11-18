"""Accepted-risk waivers: "this bucket is meant to be public" with a reason and an expiry date.

A waiver matches (provider, resource, check_id). check_id "*" covers every check on the resource.
Waived findings are kept and shown, but no longer count towards risk, scores, compliance, alerts,
exit codes or "public" status. Expired waivers stop applying automatically.
"""

from __future__ import annotations

import json
import threading
import uuid
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from pathlib import Path

ACCOUNT_RESOURCE = "account"   # account-level findings (IAM, CloudTrail, network ...) use this resource name
MAX_DAYS = 366 * 2


class WaiverError(ValueError):
    pass


@dataclass
class Waiver:
    id: str
    provider: str
    resource: str
    check_id: str          # "*" = every check on the resource
    reason: str
    expires: str           # ISO date (YYYY-MM-DD), inclusive
    created_at: str
    created_by: str = ""

    @property
    def expired(self) -> bool:
        return date.fromisoformat(self.expires) < datetime.now(timezone.utc).date()

    def matches(self, provider: str, resource: str, check_id: str) -> bool:
        return (self.provider == provider and self.resource == resource
                and self.check_id in ("*", check_id) and not self.expired)

    def to_dict(self) -> dict:
        return {**asdict(self), "expired": self.expired}


class WaiverStore:
    def __init__(self, data_dir: Path):
        self.path = Path(data_dir) / "waivers.json"
        self._lock = threading.Lock()

    def all(self) -> list[Waiver]:
        if not self.path.exists():
            return []
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        out = []
        for item in raw if isinstance(raw, list) else []:
            try:
                out.append(Waiver(**{k: item[k] for k in Waiver.__dataclass_fields__ if k in item}))
            except TypeError:
                continue
        return out

    def _write(self, items: list[Waiver]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps([asdict(w) for w in items], indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def add(self, provider: str, resource: str, check_id: str, reason: str, expires: str, created_by: str = "") -> Waiver:
        reason = (reason or "").strip()
        if len(reason) < 5:
            raise WaiverError("Give a reason (at least 5 characters), e.g. 'public website assets'.")
        try:
            exp = date.fromisoformat(expires)
        except (TypeError, ValueError) as exc:
            raise WaiverError("Expiry must be a date like 2027-03-31.") from exc
        today = datetime.now(timezone.utc).date()
        if exp < today:
            raise WaiverError("Expiry date is in the past.")
        if (exp - today).days > MAX_DAYS:
            raise WaiverError("Waivers can last at most two years; review them regularly.")
        if not resource or not check_id:
            raise WaiverError("Resource and check are required.")
        w = Waiver(uuid.uuid4().hex[:10], provider, resource, check_id.strip().upper() if check_id != "*" else "*",
                   reason[:500], exp.isoformat(), datetime.now(timezone.utc).isoformat(timespec="seconds"),
                   created_by[:100])
        with self._lock:
            items = [x for x in self.all() if not (x.provider == provider and x.resource == resource
                                                   and x.check_id == w.check_id)]
            items.append(w)
            self._write(items)
        return w

    def remove(self, waiver_id: str) -> bool:
        with self._lock:
            items = self.all()
            kept = [w for w in items if w.id != waiver_id]
            if len(kept) == len(items):
                return False
            self._write(kept)
        return True

    def find(self, provider: str, resource: str, check_id: str) -> Waiver | None:
        return next((w for w in self.all() if w.matches(provider, resource, check_id)), None)

    def split(self, provider: str, resource: str, findings: list) -> tuple[list, list]:
        """(active findings, waived findings). Waived findings get .waiver set."""
        waivers = [w for w in self.all() if w.provider == provider and w.resource == resource and not w.expired]
        active, waived = [], []
        for f in findings:
            w = next((x for x in waivers if x.check_id in ("*", f.check_id)), None)
            if w is None:
                f.waiver = None
                active.append(f)
            else:
                f.waiver = {"id": w.id, "reason": w.reason, "expires": w.expires, "check_id": w.check_id}
                waived.append(f)
        return active, waived
