"""Save and restore the last scan so the dashboard and terminal UI survive a restart.

Uses tagged JSON, not pickle: only dataclasses and enums from clouddetectx modules can be
rebuilt, so a tampered state file can't execute code. Unknown or broken files are ignored.
"""

from __future__ import annotations

import dataclasses
import importlib
import ipaddress
import json
from datetime import datetime
from enum import Enum
from pathlib import Path

VERSION = 2
_ALLOWED_PREFIX = "clouddetectx."


def encode(obj):
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {"__dc__": f"{type(obj).__module__}:{type(obj).__qualname__}",
                **{f.name: encode(getattr(obj, f.name)) for f in dataclasses.fields(obj)}}
    if isinstance(obj, Enum):
        return {"__enum__": f"{type(obj).__module__}:{type(obj).__qualname__}", "v": obj.value}
    if isinstance(obj, datetime):
        return {"__dt__": obj.isoformat()}
    if isinstance(obj, (set, frozenset)):
        return {"__set__": [encode(v) for v in obj]}
    if isinstance(obj, tuple):
        return {"__tuple__": [encode(v) for v in obj]}
    if isinstance(obj, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return str(obj)
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, dict):
        return {"__dict__": [[encode(k), encode(v)] for k, v in obj.items()]}
    if isinstance(obj, list):
        return [encode(v) for v in obj]
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    return str(obj)      # anything exotic (SDK objects) degrades to text


def _class(path: str):
    module, _, name = path.partition(":")
    if not module.startswith(_ALLOWED_PREFIX):
        raise ValueError(f"refusing to load {path}")
    cls = importlib.import_module(module)
    for part in name.split("."):
        cls = getattr(cls, part)
    return cls


def decode(obj):
    if isinstance(obj, list):
        return [decode(v) for v in obj]
    if not isinstance(obj, dict):
        return obj
    if "__dc__" in obj:
        cls = _class(obj["__dc__"])
        if not dataclasses.is_dataclass(cls):
            raise ValueError(f"{obj['__dc__']} is not a dataclass")
        names = {f.name for f in dataclasses.fields(cls)}
        init = {f.name for f in dataclasses.fields(cls) if f.init}
        values = {k: decode(v) for k, v in obj.items() if k in names}
        inst = cls(**{k: v for k, v in values.items() if k in init})
        for k, v in values.items():
            if k not in init:
                object.__setattr__(inst, k, v)
        return inst
    if "__enum__" in obj:
        cls = _class(obj["__enum__"])
        if not issubclass(cls, Enum):
            raise ValueError(f"{obj['__enum__']} is not an enum")
        return cls(obj["v"])
    if "__dt__" in obj:
        return datetime.fromisoformat(obj["__dt__"])
    if "__set__" in obj:
        return set(decode(v) for v in obj["__set__"])
    if "__tuple__" in obj:
        return tuple(decode(v) for v in obj["__tuple__"])
    if "__dict__" in obj:
        return {decode(k): decode(v) for k, v in obj["__dict__"]}
    return {k: decode(v) for k, v in obj.items()}


def state_path(data_dir: Path, provider: str) -> Path:
    return Path(data_dir) / "state" / f"{provider}.json"


def save(data_dir: Path, provider: str, payload: dict) -> None:
    path = state_path(data_dir, provider)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"version": VERSION, "state": encode(payload)}), encoding="utf-8")
    tmp.replace(path)


def load(data_dir: Path, provider: str) -> dict | None:
    path = state_path(data_dir, provider)
    if not path.exists():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if raw.get("version") != VERSION:
            return None
        return decode(raw["state"])
    except Exception:  # noqa: BLE001 - a broken or old state file just means "no saved scan"
        return None


def clear(data_dir: Path, provider: str) -> None:
    state_path(data_dir, provider).unlink(missing_ok=True)


def save_scan(settings, provider: str, account_label: str, results: list, reviews: dict, outcome=None,
              scope: str = "account", accounts: list | None = None, account_errors: dict | None = None,
              investigations: dict | None = None) -> None:
    """Save a scan in the same shape the dashboard uses, so CLI and scheduled scans show up there."""
    from datetime import datetime, timezone

    previous = load(settings.data_dir, provider) or {}
    names = {r.posture.resource.name for r in results}
    kept = {k: v for k, v in (investigations or previous.get("investigations") or {}).items() if k in names}
    save(settings.data_dir, provider, {
        "account": account_label, "scanned_at": datetime.now(timezone.utc),
        "results": {r.posture.resource.name: r for r in results}, "investigations": kept,
        "outcome": outcome, "reviews": {k: v for k, v in reviews.items() if v is not None},
        "scope": scope, "accounts": accounts or [], "account_errors": account_errors or {},
    })
