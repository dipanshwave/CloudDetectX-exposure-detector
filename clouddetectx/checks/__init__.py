"""Account-wide checks (beyond individual buckets) and Azure/GCP identity analysis."""

# Ports that should never be open to the whole internet.
EXPOSED_PORTS = {
    22: "SSH", 23: "Telnet", 445: "SMB", 1433: "SQL Server", 1521: "Oracle", 2375: "Docker API",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5601: "Kibana", 6379: "Redis", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB",
}
OPEN_CIDRS = {"0.0.0.0/0", "::/0", "*", "Internet", "Any", "0.0.0.0"}


def risky_ports(from_port, to_port, all_traffic: bool = False) -> list[str]:
    """Names of sensitive ports inside [from_port, to_port]."""
    if all_traffic or from_port in (None, -1):
        return ["all ports"]
    lo, hi = int(from_port), int(to_port if to_port not in (None, -1) else from_port)
    if lo == 0 and hi >= 65535:
        return ["all ports"]
    return [f"{p} ({name})" for p, name in sorted(EXPOSED_PORTS.items()) if lo <= p <= hi]


def short_list(items: list, limit: int = 8) -> str:
    items = [str(i) for i in items]
    return ", ".join(items[:limit]) + (f" and {len(items) - limit} more" if len(items) > limit else "")
