import pytest

from domain_setup_mcp import ops
from domain_setup_mcp.models import Record
from domain_setup_mcp.providers import DkimInput, DomainConfig, DomainSecrets
from domain_setup_mcp.resolver import FakeResolver

ORIGINAL = [
    Record(type="TXT", name="a.com", content="v=spf1 include:sendgrid.net ~all"),
    Record(type="TXT", name="a.com", content="google-site-verification=xyz"),
    Record(type="A", name="a.com", content="1.2.3.4"),
]


def key(d):
    return f"v=DKIM1; k=rsa; p=KEY{d.replace('.', '')}"


def cfg(*domains, **kw):
    base = dict(provider="google", dmarc_rua="dmarc@agency.com", tracking_tool="smartlead",
                per_domain={d: DomainSecrets(dkim=DkimInput(google_txt=key(d))) for d in domains})
    base.update(kw)
    return DomainConfig(**base)


def setup(fake_cf):
    return fake_cf({"a.com": list(ORIGINAL), "b.com": []})


def state(cf, d):
    return sorted(r.key() for r in cf.zones[f"zone-{d}"])


def test_plan_batch_and_unknown_zone(fake_cf, resolver):
    cf = setup(fake_cf)
    out = ops.plan(["a.com", "B.com", "missing.com", "a.com"], cfg("a.com", "b.com", "missing.com"), cf, resolver)
    s = out["summary"]
    assert s["domains"] == 3 and s["ready"] == 2 and s["blocked"] == 1
    assert cf.calls == []  # planning never writes


def test_shared_dkim_across_domains_rejected(fake_cf, resolver):
    bad = DomainConfig(provider="google", dkim=DkimInput(google_txt=key("x")))
    with pytest.raises(ValueError, match="unique per domain"):
        ops.plan(["a.com", "b.com"], bad, setup(fake_cf), resolver)


def test_shared_dkim_ok_for_single_domain(fake_cf, resolver):
    one = DomainConfig(provider="google", dkim=DkimInput(google_txt=key("b.com")))
    out = ops.plan(["b.com"], one, setup(fake_cf), resolver)
    assert any("google._domainkey.b.com" in (c["after"] or "") for c in out["plans"][0]["changes"])


def test_per_domain_typo_rejected(fake_cf, resolver):
    with pytest.raises(ValueError, match="not in this plan"):
        ops.plan(["a.com"], cfg("a.co"), setup(fake_cf), resolver)


def test_each_domain_gets_its_own_key(fake_cf, resolver):
    cf = setup(fake_cf)
    pid = ops.plan(["a.com", "b.com"], cfg("a.com", "b.com"), cf, resolver)["plan_id"]
    ops.apply(pid, cf, confirm=True)
    for d in ("a.com", "b.com"):
        dk = [r.content for r in cf.zones[f"zone-{d}"] if r.name == f"google._domainkey.{d}"]
        assert dk == [key(d)]


def test_apply_dry_run_writes_nothing(fake_cf, resolver):
    cf = setup(fake_cf)
    pid = ops.plan(["a.com", "b.com"], cfg("a.com", "b.com"), cf, resolver)["plan_id"]
    out = ops.apply(pid, cf, confirm=False)
    assert out["dry_run"] and cf.calls == []


def test_apply_uses_one_batch_per_domain_then_replan_is_noop(fake_cf, resolver):
    cf = setup(fake_cf)
    c = cfg("a.com", "b.com")
    out = ops.apply(ops.plan(["a.com", "b.com"], c, cf, resolver)["plan_id"], cf, confirm=True)
    assert all(d["status"] == "applied" for d in out["domains"])
    assert [x for x in cf.calls if x.startswith("batch")] and len([x for x in cf.calls if x.startswith("batch")]) == 2
    assert ops.plan(["a.com", "b.com"], c, cf, resolver)["summary"]["total_changes"] == 0
    spf = [r for r in cf.zones["zone-a.com"] if r.content.startswith("v=spf1")]
    assert len(spf) == 1 and spf[0].content == "v=spf1 include:sendgrid.net include:_spf.google.com ~all"


def test_drift_check_skips_changed_zone(fake_cf, resolver):
    cf = setup(fake_cf)
    pid = ops.plan(["a.com"], cfg("a.com"), cf, resolver)["plan_id"]
    cf.zones["zone-a.com"].append(Record(type="TXT", name="a.com", content="someone-else-edited", id="x"))
    out = ops.apply(pid, cf, confirm=True)
    assert "DNS changed" in out["domains"][0]["status"] and cf.calls == []


def test_rollback_restores_exact_original(fake_cf, resolver):
    cf = setup(fake_cf)
    before = state(cf, "a.com")
    run = ops.apply(ops.plan(["a.com"], cfg("a.com"), cf, resolver)["plan_id"], cf, confirm=True)["run_id"]
    assert state(cf, "a.com") != before
    assert ops.rollback(run, cf, confirm=False)["dry_run"]
    out = ops.rollback(run, cf, confirm=True)
    assert out["errors"] == [] and state(cf, "a.com") == before


def test_rollback_restores_deleted_duplicate_spf(fake_cf, resolver):
    cf = fake_cf({"c.com": [Record(type="TXT", name="c.com", content="v=spf1 include:sendgrid.net ~all"),
                            Record(type="TXT", name="c.com", content="v=spf1 include:mailgun.org ~all")]})
    before = state(cf, "c.com")
    run = ops.apply(ops.plan(["c.com"], cfg("c.com"), cf, resolver)["plan_id"], cf, confirm=True)["run_id"]
    assert len([r for r in cf.zones["zone-c.com"] if r.content.startswith("v=spf1")]) == 1
    ops.rollback(run, cf, confirm=True)
    assert state(cf, "c.com") == before


def test_failed_batch_changes_nothing(fake_cf, resolver):
    cf = setup(fake_cf)
    before = state(cf, "a.com")
    pid = ops.plan(["a.com"], cfg("a.com"), cf, resolver)["plan_id"]
    cf.fail_on = "batch"
    out = ops.apply(pid, cf, confirm=True)
    assert out["domains"][0]["status"].startswith("FAILED") and "Nothing was changed" in out["domains"][0]["status"]
    assert state(cf, "a.com") == before
    cf.fail_on = None
    assert ops.apply(pid, cf, confirm=True)["domains"][0]["status"] == "applied"  # can retry


def test_apply_only_subset(fake_cf, resolver):
    cf = setup(fake_cf)
    pid = ops.plan(["a.com", "b.com"], cfg("a.com", "b.com"), cf, resolver)["plan_id"]
    ops.apply(pid, cf, confirm=True, only=["b.com"])
    assert state(cf, "a.com") == sorted(r.key() for r in ORIGINAL)


def test_verify_pending_then_live(fake_cf, resolver):
    cf = fake_cf({"b.com": []})
    pid = ops.plan(["b.com"], cfg("b.com"), cf, resolver)["plan_id"]
    assert ops.verify(pid, FakeResolver())["summary"]["pending"] == 1
    live = FakeResolver(
        txt={"b.com": ["v=spf1 include:_spf.google.com ~all"], "google._domainkey.b.com": [key("b.com")],
             "_dmarc.b.com": ["v=DMARC1; p=none; rua=mailto:dmarc@agency.com;"]},
        mx={"b.com": [("smtp.google.com", 1)]}, cname={"emailtracking.b.com": ["open.sleadtrack.com"]})
    assert ops.verify(pid, live)["summary"]["live"] == 1


def test_audit_flags_problems():
    r = FakeResolver(txt={"bad.com": ["v=spf1 +all", "v=spf1 ~all"], "good.com": ["v=spf1 ip4:1.2.3.4 ~all"],
                          "_dmarc.good.com": ["v=DMARC1; p=none; rua=mailto:d@good.com"],
                          "google._domainkey.good.com": ["v=DKIM1; p=abc"]},
                     mx={"good.com": [("smtp.google.com", 1)]})
    by = {d["domain"]: d for d in ops.audit(["bad.com", "good.com"], r)["domains"]}
    assert by["bad.com"]["status"] == "fail" and by["good.com"]["status"] == "pass"


def test_audit_flags_deprecated_dmarc_tags():
    r = FakeResolver(txt={"x.com": ["v=spf1 ~all"], "_dmarc.x.com": ["v=DMARC1; p=quarantine; pct=50; rua=mailto:d@x.com"]})
    f = " ".join(x["message"] for x in ops.audit(["x.com"], r)["domains"][0]["findings"])
    assert "RFC 9989" in f and "t=y" in f
