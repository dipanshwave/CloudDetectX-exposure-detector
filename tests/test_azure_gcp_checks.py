"""Azure and GCP account checks, tested through their pure evaluate functions with API-shaped data."""

from clouddetectx.checks import azure_account as az
from clouddetectx.checks import gcp_account as gcp


def nsg(name, rules, attached=True):
    return {"name": name, "properties": {"networkInterfaces": [{"id": "nic"}] if attached else [],
                                         "securityRules": rules}}


def rule(name, src, ports, access="Allow", direction="Inbound"):
    props = {"sourceAddressPrefix": src, "access": access, "direction": direction}
    props["destinationPortRange" if isinstance(ports, str) else "destinationPortRanges"] = ports
    return {"name": name, "properties": props}


def test_azure_nsg_rules():
    found = az.evaluate_nsgs([
        nsg("web", [rule("ssh", "Internet", "22"), rule("https", "*", "443"), rule("rdp-range", "*", ["3380-3390"]),
                    rule("deny", "*", "22", access="Deny"), rule("office", "203.0.113.0/24", "22")]),
        nsg("detached", [rule("all", "*", "*")], attached=False),
    ])
    assert [(r["rule"], r["ports"]) for r in found] == [("ssh", ["22 (SSH)"]), ("rdp-range", ["3389 (RDP)"])]


def test_azure_sql_and_aks():
    servers = [{"id": "s1", "name": "open", "properties": {"publicNetworkAccess": "Enabled"}},
               {"id": "s2", "name": "private", "properties": {"publicNetworkAccess": "Disabled"}}]
    fw = {"s1": [{"name": "AllowAll", "properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255"}},
                 {"name": "AzureServices", "properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "0.0.0.0"}}],
          "s2": [{"name": "AllowAll", "properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255"}}]}
    assert az.evaluate_sql(servers, fw) == [{"server": "open", "rule": "AllowAll"}]
    clusters = [{"name": "public", "properties": {"apiServerAccessProfile": {}}},
                {"name": "restricted", "properties": {"apiServerAccessProfile": {"authorizedIPRanges": ["1.2.3.4/32"]}}},
                {"name": "private", "properties": {"apiServerAccessProfile": {"enablePrivateCluster": True}}}]
    assert az.evaluate_aks(clusters) == [{"cluster": "public"}]


def test_azure_rbac():
    sub = "00000000-0000-0000-0000-000000000001"
    defs = {"/owner": {"roleName": "Owner", "type": "BuiltInRole"},
            "/blobowner": {"roleName": "Storage Blob Data Owner", "type": "BuiltInRole"},
            "/custom": {"roleName": "God mode", "type": "CustomRole", "permissions": [{"actions": ["*"]}]}}

    def assign(pid, role, scope=f"/subscriptions/{sub}", ptype="User"):
        return {"properties": {"principalId": pid, "roleDefinitionId": role, "scope": scope, "principalType": ptype}}

    assignments = [assign(f"owner{i}", "/owner") for i in range(5)] + [
        assign("etl", "/blobowner", f"/subscriptions/{sub}/resourceGroups/data", "ServicePrincipal"),
        assign("scoped", "/blobowner", f"/subscriptions/{sub}/resourceGroups/data/providers/Microsoft.Storage/storageAccounts/x")]
    principals, findings = az.evaluate_rbac(sub, assignments, defs)
    ids = {f.check_id for f in findings}
    assert ids == {"AZ-IAM-001", "AZ-IAM-002", "AZ-IAM-003"}
    caps = {p.name: p.capabilities for p in principals}
    assert caps["owner0"] == {"admin": "yes"} and caps["etl"] == {"s3_full": "yes"} and caps["scoped"] == {}


def test_gcp_network_sql_gke_audit():
    rules = [{"name": "ssh", "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]},
             {"name": "web", "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}]},
             {"name": "all", "sourceRanges": ["::/0"], "allowed": [{"IPProtocol": "all"}]},
             {"name": "off", "disabled": True, "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "all"}]},
             {"name": "egress", "direction": "EGRESS", "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "all"}]}]
    assert [r["rule"] for r in gcp.evaluate_firewalls(rules)] == ["ssh", "all"]
    sql = [{"name": "open", "settings": {"ipConfiguration": {"ipv4Enabled": True, "authorizedNetworks": [{"value": "0.0.0.0/0"}]}}},
           {"name": "private", "settings": {"ipConfiguration": {"ipv4Enabled": False}}}]
    assert [i["instance"] for i in gcp.evaluate_sql(sql)] == ["open"]
    gke = [{"name": "open"}, {"name": "ok", "masterAuthorizedNetworksConfig": {"enabled": True}}]
    assert [c["cluster"] for c in gcp.evaluate_gke(gke)] == ["open"]
    assert not gcp.data_access_logged({})
    assert gcp.data_access_logged({"auditConfigs": [{"service": "allServices", "auditLogConfigs": [{"logType": "DATA_READ"}]}]})


def test_gcp_iam():
    policy = {"bindings": [
        {"role": "roles/owner", "members": ["user:alice@example.com", "serviceAccount:ci@p.iam.gserviceaccount.com"]},
        {"role": "roles/storage.admin", "members": ["group:data@example.com"]},
        {"role": "roles/storage.objectViewer", "members": ["allUsers"]},
    ]}
    keys = {"ci@p.iam.gserviceaccount.com": [{"name": "projects/p/serviceAccounts/ci/keys/abcd1234",
                                               "validAfterTime": "2020-01-01T00:00:00Z"}]}
    principals, findings = gcp.evaluate_iam("p", policy, keys)
    by_id = {f.check_id: f for f in findings}
    assert set(by_id) == {"GCP-IAM-001", "GCP-IAM-002", "GCP-IAM-003", "GCP-IAM-004"}
    assert by_id["GCP-IAM-001"].severity.value == "HIGH"          # includes a service account
    assert by_id["GCP-IAM-004"].exposes_data
    ci = next(p for p in principals if p.name == "ci@p.iam.gserviceaccount.com")
    assert ci.old_keys and ci.capabilities == {"admin": "yes"}


def test_every_check_is_mapped_and_categorised():
    import pathlib
    import re

    from clouddetectx.compliance import CHECK_CATEGORY, MAPPING

    root = pathlib.Path(__file__).resolve().parent.parent / "clouddetectx"
    emitted = set()
    for f in root.rglob("*.py"):
        emitted |= set(re.findall(r'"((?:AWS|AZ|GCP)-(?:S3|ST|GCS|ACCT|IAM)-\d{3})"', f.read_text(encoding="utf-8")))
    emitted = {c for c in emitted if not c.endswith("000")} | {"DATA-001", "DATA-002"}
    assert emitted - set(MAPPING) == set()
    assert emitted - set(CHECK_CATEGORY) == set()
