"""Scheduled scans as an OS task: Windows Task Scheduler or cron (Linux/macOS).

Each run executes `scan` (history, drift detection and webhook alerts happen as usual) and
appends its output to <data dir>/logs/scheduled-scan.log.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

TASK_NAME = "CloudDetectX scheduled scan"
CRON_MARKER = "# clouddetectx-scheduled-scan"
MIN_MINUTES, MAX_MINUTES = 15, 7 * 24 * 60


class ScheduleError(RuntimeError):
    pass


@dataclass
class Plan:
    platform: str
    script: Path
    script_body: str
    install: list[list[str]]     # commands to run (or the crontab text in `crontab`)
    crontab: str | None = None
    description: str = ""


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _scan_args(providers: list[str], all_accounts: bool) -> list[str]:
    args = ["-p", ",".join(providers), "scan"]
    if all_accounts:
        args.append("--all-accounts")
    return args


def _validate(every: int) -> None:
    if not MIN_MINUTES <= every <= MAX_MINUTES:
        raise ScheduleError(f"--every must be between {MIN_MINUTES} minutes and 7 days ({MAX_MINUTES} minutes).")


def cron_expression(every: int) -> str:
    _validate(every)
    if every < 60:
        return f"*/{every} * * * *"
    if every % 1440 == 0:
        return "0 3 * * *" if every == 1440 else f"0 3 */{every // 1440} * *"
    if every % 60 == 0 and every < 1440:
        return f"0 */{every // 60} * * *"
    raise ScheduleError("With cron, use minutes below 60, whole hours, or whole days (e.g. 30, 120, 1440).")


def plan(data_dir: Path, every: int, providers: list[str], all_accounts: bool = False,
         platform: str | None = None) -> Plan:
    _validate(every)
    platform = platform or ("windows" if os.name == "nt" else "unix")
    data_dir = Path(data_dir).resolve()
    logs = data_dir / "logs"
    python, main = sys.executable, _project_root() / "main.py"
    entry = [python, str(main)] if main.exists() else [python, "-m", "clouddetectx"]
    args = _scan_args(providers, all_accounts)
    if platform == "windows":
        script = data_dir / "scheduled-scan.cmd"
        cmd = " ".join(f'"{a}"' for a in entry + args)
        body = (f'@echo off\r\ncd /d "{_project_root()}"\r\nif not exist "{logs}" mkdir "{logs}"\r\n'
                f'echo ==== %DATE% %TIME% >> "{logs / "scheduled-scan.log"}"\r\n'
                f'{cmd} >> "{logs / "scheduled-scan.log"}" 2>&1\r\n')
        if every % 1440 == 0:
            sched = ["/SC", "DAILY", "/MO", str(every // 1440), "/ST", "03:00"]
        elif every % 60 == 0:
            sched = ["/SC", "HOURLY", "/MO", str(every // 60)]
        else:
            sched = ["/SC", "MINUTE", "/MO", str(every)]
        install = [["schtasks", "/Create", "/F", "/TN", TASK_NAME, "/TR", f'"{script}"', *sched]]
        return Plan("windows", script, body, install, description=f"Windows Task Scheduler task '{TASK_NAME}'")
    script = data_dir / "scheduled-scan.sh"
    cmd = " ".join(shlex.quote(a) for a in entry + args)
    body = (f"#!/bin/sh\ncd {shlex.quote(str(_project_root()))} || exit 1\nmkdir -p {shlex.quote(str(logs))}\n"
            f"echo \"==== $(date)\" >> {shlex.quote(str(logs / 'scheduled-scan.log'))}\n"
            f"{cmd} >> {shlex.quote(str(logs / 'scheduled-scan.log'))} 2>&1\n")
    line = f"{cron_expression(every)} {shlex.quote(str(script))} {CRON_MARKER}"
    return Plan("unix", script, body, [], crontab=line, description="crontab entry")


def _current_crontab() -> str:
    try:
        out = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=20)
    except FileNotFoundError as exc:
        raise ScheduleError("crontab is not available on this system.") from exc
    return out.stdout if out.returncode == 0 else ""


def install(p: Plan) -> str:
    p.script.parent.mkdir(parents=True, exist_ok=True)
    p.script.write_text(p.script_body, encoding="utf-8", newline="")
    if p.platform == "windows":
        for cmd in p.install:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if res.returncode != 0:
                raise ScheduleError(f"schtasks failed: {(res.stderr or res.stdout).strip()}")
        return f"Installed {p.description}."
    p.script.chmod(0o700)
    lines = [ln for ln in _current_crontab().splitlines() if CRON_MARKER not in ln]
    lines.append(p.crontab)
    res = subprocess.run(["crontab", "-"], input="\n".join(lines) + "\n", text=True, capture_output=True, timeout=20)
    if res.returncode != 0:
        raise ScheduleError(f"crontab failed: {res.stderr.strip()}")
    return f"Installed {p.description}: {p.crontab}"


def remove() -> str:
    if os.name == "nt":
        res = subprocess.run(["schtasks", "/Delete", "/F", "/TN", TASK_NAME], capture_output=True, text=True, timeout=60)
        if res.returncode != 0:
            return "No scheduled scan was installed."
        return f"Removed the Task Scheduler task '{TASK_NAME}'."
    current = _current_crontab()
    if CRON_MARKER not in current:
        return "No scheduled scan was installed."
    kept = [ln for ln in current.splitlines() if CRON_MARKER not in ln]
    subprocess.run(["crontab", "-"], input="\n".join(kept) + ("\n" if kept else ""), text=True, timeout=20)
    return "Removed the crontab entry."


def status() -> dict:
    """{"installed": bool, "detail": str}"""
    if os.name == "nt":
        try:
            res = subprocess.run(["schtasks", "/Query", "/TN", TASK_NAME, "/FO", "LIST", "/V"],
                                 capture_output=True, text=True, timeout=30)
        except FileNotFoundError:
            return {"installed": False, "detail": "Task Scheduler is not available."}
        if res.returncode != 0:
            return {"installed": False, "detail": "Not installed."}
        keep = ("Next Run Time", "Last Run Time", "Last Result", "Schedule Type", "Repeat: Every", "Status")
        lines = [ln.strip() for ln in res.stdout.splitlines() if ln.strip().startswith(keep)]
        return {"installed": True, "detail": "; ".join(lines) or "Installed."}
    try:
        current = _current_crontab()
    except ScheduleError as exc:
        return {"installed": False, "detail": str(exc)}
    line = next((ln for ln in current.splitlines() if CRON_MARKER in ln), None)
    return {"installed": bool(line), "detail": line.split(" " + CRON_MARKER)[0] if line else "Not installed."}
