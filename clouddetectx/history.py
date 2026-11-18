"""Local scan history (SQLite): drift detection and trends.

Each full scan stores one row per resource. Comparing a scan with the previous one for the
same account shows what became exposed, what was fixed, and what appeared or disappeared.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    account TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    resources INTEGER NOT NULL,
    public INTEGER NOT NULL,
    mitigated INTEGER NOT NULL,
    posture_score INTEGER
);
CREATE TABLE IF NOT EXISTS snapshots (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    resource TEXT NOT NULL,
    status TEXT NOT NULL,
    risk INTEGER NOT NULL,
    top_severity TEXT,
    checks TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_account ON scans(provider, account, id);
CREATE INDEX IF NOT EXISTS idx_snap_scan ON snapshots(scan_id);
"""


@dataclass
class Drift:
    previous_at: str | None
    new_public: list[str] = field(default_factory=list)
    resolved: list[str] = field(default_factory=list)
    accepted: list[str] = field(default_factory=list)      # was public, now covered by a waiver
    new_resources: list[str] = field(default_factory=list)
    removed_resources: list[str] = field(default_factory=list)
    new_findings: dict[str, list[str]] = field(default_factory=dict)
    risk_increased: list[dict] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.new_public or self.resolved or self.accepted or self.new_resources or self.removed_resources
                     or self.new_findings or self.risk_increased)

    def to_dict(self) -> dict:
        return {**asdict(self), "changed": self.changed}


class History:
    def __init__(self, data_dir: Path):
        data_dir.mkdir(parents=True, exist_ok=True)
        self.path = data_dir / "history.db"
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(SCHEMA)
        self._db.execute("PRAGMA foreign_keys = ON")

    def close(self) -> None:
        self._db.close()

    def record(self, provider: str, account: str, rows: list[dict], posture_score: int | None) -> Drift:
        """rows: [{"name", "status", "risk", "top_severity", "checks": [...]}] for a FULL scan."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            prev = self._db.execute(
                "SELECT id, scanned_at FROM scans WHERE provider=? AND account=? ORDER BY id DESC LIMIT 1",
                (provider, account)).fetchone()
            prev_rows = {}
            if prev:
                for r in self._db.execute("SELECT * FROM snapshots WHERE scan_id=?", (prev["id"],)):
                    prev_rows[r["resource"]] = {"status": r["status"], "risk": r["risk"], "checks": set(json.loads(r["checks"]))}
            cur = self._db.execute(
                "INSERT INTO scans(provider, account, scanned_at, resources, public, mitigated, posture_score) VALUES (?,?,?,?,?,?,?)",
                (provider, account, now, len(rows), sum(r["status"] == "public" for r in rows),
                 sum(r["status"] == "mitigated" for r in rows), posture_score))
            self._db.executemany(
                "INSERT INTO snapshots(scan_id, resource, status, risk, top_severity, checks) VALUES (?,?,?,?,?,?)",
                [(cur.lastrowid, r["name"], r["status"], r["risk"], r.get("top_severity"), json.dumps(sorted(r["checks"])))
                 for r in rows])
            self._db.commit()

        drift = Drift(previous_at=prev["scanned_at"] if prev else None)
        if not prev:
            return drift
        current = {r["name"]: r for r in rows}
        for name, r in current.items():
            before = prev_rows.get(name)
            if before is None:
                drift.new_resources.append(name)
                if r["status"] == "public":
                    drift.new_public.append(name)
                continue
            if r["status"] == "public" and before["status"] != "public":
                drift.new_public.append(name)
            if r["status"] != "public" and before["status"] == "public":
                (drift.accepted if r["status"] == "accepted" else drift.resolved).append(name)
            added = sorted(set(r["checks"]) - before["checks"])
            if added:
                drift.new_findings[name] = added
            if r["risk"] >= before["risk"] + 10:
                drift.risk_increased.append({"name": name, "from": before["risk"], "to": r["risk"]})
        drift.removed_resources = sorted(set(prev_rows) - set(current))
        return drift

    def trend(self, provider: str, account: str | None = None, limit: int = 60) -> list[dict]:
        q = "SELECT * FROM scans WHERE provider=?" + (" AND account=?" if account else "") + " ORDER BY id DESC LIMIT ?"
        args = (provider, account, limit) if account else (provider, limit)
        with self._lock:
            rows = [dict(r) for r in self._db.execute(q, args)]
        return list(reversed(rows))
