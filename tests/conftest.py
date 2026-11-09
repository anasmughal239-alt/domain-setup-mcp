import itertools

import pytest

from domain_setup_mcp.cloudflare import CloudflareError
from domain_setup_mcp.models import Record
from domain_setup_mcp.resolver import FakeResolver

# Fixture SPF trees for testing the counter. NOTE: these model Google's pre-Dec-2025 record (4 lookups).
# Live _spf.google.com now inlines its IPs and costs 1 lookup; the server always resolves live, so it
# reports the real number. Keep the nested fixture: it exercises recursive counting.
SPF_TREE = {
    "_spf.google.com": ["v=spf1 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com ~all"],
    "_netblocks.google.com": ["v=spf1 ip4:35.190.247.0/24 ~all"],
    "_netblocks2.google.com": ["v=spf1 ip6:2001:4860:4000::/36 ~all"],
    "_netblocks3.google.com": ["v=spf1 ip4:172.217.0.0/19 ~all"],
    "spf.protection.outlook.com": ["v=spf1 include:spfd.protection.outlook.com -all"],
    "spfd.protection.outlook.com": ["v=spf1 ip4:40.92.0.0/15 -all"],
    "amazonses.com": ["v=spf1 ip4:199.255.192.0/22 ~all"],
    "sendgrid.net": ["v=spf1 ip4:167.89.0.0/17 ~all"],
    "mailgun.org": ["v=spf1 include:_spf.mailgun.org ~all"],
    "_spf.mailgun.org": ["v=spf1 ip4:209.61.151.0/24 ~all"],
    "loop-a.test": ["v=spf1 include:loop-b.test ~all"],
    "loop-b.test": ["v=spf1 include:loop-a.test ~all"],
}
# Heavy includes to push SPF over the 10-lookup limit.
for i in range(8):
    SPF_TREE[f"heavy{i}.test"] = ["v=spf1 a mx ~all"]


@pytest.fixture
def resolver():
    return FakeResolver(txt=SPF_TREE)


class FakeCloudflare:
    """In-memory Cloudflare with the same semantics as the real API: atomic batch, redirect ruleset."""

    def __init__(self, zones: dict[str, list[Record]]):
        self._ids = itertools.count(1)
        self.zones = {f"zone-{d}": [r.model_copy(update={"id": r.id or self._nid()}) for r in recs] for d, recs in zones.items()}
        self.rules: dict[str, list[dict]] = {}
        self.calls: list[str] = []
        self.fail_on: str | None = None   # "batch" | "rules_get" | "rules_put"

    def _nid(self):
        return f"rec{next(self._ids)}"

    def zone_id(self, domain):
        z = f"zone-{domain}"
        if z not in self.zones:
            raise CloudflareError(f"Zone {domain} not found")
        return z

    def list_records(self, zid):
        return [r.model_copy() for r in self.zones[zid]]

    def batch(self, zid, deletes, puts, posts):
        if self.fail_on == "batch":
            raise CloudflareError("simulated batch failure")
        recs = [r.model_copy() for r in self.zones[zid]]  # work on a copy: all-or-nothing
        for i in deletes:
            if not any(r.id == i for r in recs):
                raise CloudflareError(f"delete: {i} not found")
            recs = [r for r in recs if r.id != i]
        for p in puts:
            idx = next((k for k, r in enumerate(recs) if r.id == p.id), None)
            if idx is None:
                raise CloudflareError(f"put: {p.id} not found")
            recs[idx] = p.model_copy()
        for p in posts:
            if p.type == "CNAME" and any(r.name == p.name for r in recs):
                raise CloudflareError(f"CNAME conflict at {p.name}")
            recs.append(p.model_copy(update={"id": self._nid()}))
        self.zones[zid] = recs
        self.calls.append(f"batch -{len(deletes)} ~{len(puts)} +{len(posts)}")

    def get_redirect_rules(self, zid):
        if self.fail_on == "rules_get":
            raise CloudflareError("403: Token lacks the needed permission on this zone.")
        return [dict(r) for r in self.rules.get(zid, [])]

    def put_redirect_rules(self, zid, rules):
        if self.fail_on == "rules_put":
            raise CloudflareError("simulated rules failure")
        self.rules[zid] = [dict(r) for r in rules]
        self.calls.append(f"rules {len(rules)}")


@pytest.fixture
def fake_cf():
    return FakeCloudflare


@pytest.fixture(autouse=True)
def tmp_home(tmp_path, monkeypatch):
    monkeypatch.setenv("DOMAIN_SETUP_HOME", str(tmp_path))
