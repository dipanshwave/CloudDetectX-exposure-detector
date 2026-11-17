"""Webhook alerts (Slack, Microsoft Teams incoming webhooks, or any endpoint accepting JSON).

The payload carries a plain `text` field (rendered by Slack and Teams) plus a structured
`clouddetectx` object for SIEMs and automation.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from clouddetectx import __version__


class AlertError(RuntimeError):
    pass


def send(webhook_url: str, title: str, lines: list[str], data: dict | None = None, timeout: float = 10.0) -> None:
    text = f"*{title}*\n" + "\n".join(f"• {line}" for line in lines)
    body = json.dumps({"text": text, "clouddetectx": {"title": title, "details": lines, **(data or {})}}).encode()
    req = urllib.request.Request(webhook_url, data=body, method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": f"CloudDetectX/{__version__}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status >= 300:
                raise AlertError(f"Webhook returned HTTP {resp.status}")
    except urllib.error.HTTPError as exc:
        raise AlertError(f"Webhook returned HTTP {exc.code}: {exc.reason}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise AlertError(f"Webhook request failed: {getattr(exc, 'reason', exc)}") from exc
