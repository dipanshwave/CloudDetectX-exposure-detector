"""Provider-neutral analysis of access logs: did anyone outside actually get the data?"""

from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict

from clouddetectx.models import AccessEvent, ChangeEvent, Indicator, Investigation, Severity

DOWNLOAD_OPS = {"GetObject"}
LIST_OPS = {"ListBucket"}
WRITE_OPS = {"PutObject", "DeleteObject", "PutObjectAcl"}

BULK_OBJECTS_PER_IP = 10
BULK_REQUESTS_PER_IP = 100
PROBING_DENIED_THRESHOLD = 5
TOOLING_AGENTS = ("curl", "wget", "python-requests", "python-urllib", "go-http-client", "aiohttp", "masscan",
                  "zgrab", "nuclei", "sqlmap", "nmap", "scrapy", "httpx", "bucket", "s3scanner", "grayhatwarfare")

VERDICT_TEXT = {
    "DATA_ACCESSED": "Untrusted parties successfully read or modified data while it was exposed.",
    "EXPOSURE_PROBED": "Untrusted parties reached the resource but no successful data read was recorded.",
    "NO_EVIDENCE_OF_ACCESS": "Logs were available and show no access from untrusted parties.",
    "NO_LOGS_AVAILABLE": "No access logs are available; it cannot be ruled out that data was accessed.",
}


def is_external(ip: str | None, trusted: list) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip.strip("[]"))
    except ValueError:
        return False  # e.g. "AWS Internal" or a service hostname
    if any(addr in net for net in trusted):
        return False
    return addr.is_global


def analyze_access(
    events: list[AccessEvent],
    changes: list[ChangeEvent],
    sources: list[str],
    notes: list[str],
    trusted_networks: list,
) -> Investigation:
    def untrusted(e: AccessEvent) -> bool:
        return e.anonymous or is_external(e.source_ip, trusted_networks)

    suspect = [e for e in events if untrusted(e)]
    downloads = [e for e in suspect if e.operation in DOWNLOAD_OPS and e.succeeded]
    listings = [e for e in suspect if e.operation in LIST_OPS and e.succeeded]
    writes = [e for e in suspect if e.operation in WRITE_OPS and e.succeeded]
    denied = [e for e in suspect if e.status in (401, 403)]

    per_ip_requests = Counter(e.source_ip or "unknown" for e in suspect)
    per_ip_objects: dict[str, set] = defaultdict(set)
    for e in downloads:
        per_ip_objects[e.source_ip or "unknown"].add(e.key)

    summary = {
        "total_events": len(events),
        "first_event": events[0].timestamp.isoformat() if events else None,
        "last_event": events[-1].timestamp.isoformat() if events else None,
        "unique_source_ips": len({e.source_ip for e in events if e.source_ip}),
        "untrusted_requests": len(suspect),
        "anonymous_requests": sum(1 for e in events if e.anonymous),
        "external_ips": sorted({e.source_ip for e in suspect if e.source_ip}),
        "objects_downloaded_by_untrusted": sorted({e.key for e in downloads if e.key}),
        "bytes_downloaded_by_untrusted": sum(e.bytes_sent for e in downloads),
        "successful_listings_by_untrusted": len(listings),
        "writes_by_untrusted": len(writes),
        "denied_requests_from_untrusted": len(denied),
        "top_untrusted_ips": per_ip_requests.most_common(10),
    }

    indicators: list[Indicator] = []
    if downloads:
        indicators.append(Indicator(
            Severity.CRITICAL, "Data downloaded by untrusted parties",
            f"{len(summary['objects_downloaded_by_untrusted'])} object(s), {summary['bytes_downloaded_by_untrusted']:,} bytes, "
            f"from {len({e.source_ip for e in downloads})} source IP(s).", "T1530",
        ))
    deletes = [e for e in writes if e.operation == "DeleteObject"]
    if writes:
        indicators.append(Indicator(
            Severity.CRITICAL, "Data modified by untrusted parties",
            f"{len(writes)} successful write/delete request(s): "
            + ", ".join(sorted({f'{e.operation} {e.key}' for e in writes})[:10]),
            "T1485" if deletes and len(deletes) == len(writes) else "T1565.001",
        ))
    if listings:
        indicators.append(Indicator(Severity.HIGH, "Bucket contents enumerated",
                                    f"{len(listings)} successful anonymous/external listing request(s).", "T1619"))
    for ip, objs in per_ip_objects.items():
        if len(objs) >= BULK_OBJECTS_PER_IP:
            indicators.append(Indicator(Severity.HIGH, f"Bulk download from {ip}", f"{len(objs)} distinct objects downloaded.", "T1530"))
    for ip, count in per_ip_requests.items():
        if count >= BULK_REQUESTS_PER_IP and len(per_ip_objects.get(ip, ())) < BULK_OBJECTS_PER_IP:
            indicators.append(Indicator(Severity.MEDIUM, f"High request volume from {ip}", f"{count} requests."))
    if len(denied) >= PROBING_DENIED_THRESHOLD:
        indicators.append(Indicator(Severity.MEDIUM, "Access-denied probing",
                                    f"{len(denied)} denied requests from untrusted sources.", "T1595"))
    tools = sorted({e.user_agent for e in suspect if e.user_agent and any(t in e.user_agent.lower() for t in TOOLING_AGENTS)})
    if tools:
        indicators.append(Indicator(Severity.MEDIUM, "Automated tooling observed", "; ".join(t[:80] for t in tools[:5])))
    for c in changes:
        indicators.append(Indicator(Severity.INFO, f"Configuration change: {c.action}",
                                    f"{c.timestamp:%Y-%m-%d %H:%M:%S} UTC by {c.actor or 'unknown'} from {c.source_ip or 'unknown IP'}"))

    if not sources:
        verdict = "NO_LOGS_AVAILABLE"
    elif downloads or writes:
        verdict = "DATA_ACCESSED"
    elif suspect:
        verdict = "EXPOSURE_PROBED"
    else:
        verdict = "NO_EVIDENCE_OF_ACCESS"

    # Keep reports bounded: every untrusted event plus a sample of the rest.
    kept = suspect + [e for e in events if not untrusted(e)][: max(0, 2000 - len(suspect))]
    kept.sort(key=lambda e: e.timestamp)

    return Investigation(
        verdict=verdict,
        summary=summary,
        indicators=indicators,
        access_events=kept,
        change_events=changes,
        log_sources=sources,
        notes=notes,
    )
