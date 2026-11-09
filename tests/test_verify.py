"""Redirect read errors reach the user; domain_verify really checks A records and the 301."""
import pytest

from domain_setup_mcp import ops
from domain_setup_mcp.providers import DomainConfig
from domain_setup_mcp.resolver import FakeResolver

D = "b.com"
TARGET = "https://acme.com"
CFG = DomainConfig(provider="google", dmarc_rua="dmarc@agency.com", forward_to=TARGET)


def live_dns(**over):
    parts = {"txt": {D: ["v=spf1 include:_spf.google.com ~all"],
                     f"_dmarc.{D}": ["v=DMARC1; p=none; rua=mailto:dmarc@agency.com;"]},
             "mx": {D: [("smtp.google.com", 1)]},
             "a": {D: ["104.21.0.1"], f"www.{D}": ["104.21.0.1"]}}
    return FakeResolver(**{**parts, **over})


def planned(fake_cf, resolver):
    return ops.plan([D], CFG, fake_cf({D: []}), resolver)["plan_id"]


def check(result, record):
    return next(c for c in result["domains"][0]["checks"] if c["record"] == record)


def test_plan_shows_the_real_redirect_read_error(fake_cf, resolver):
    cf = fake_cf({D: []})
    cf.fail_on = "rules_get"
    out = ops.plan([D], CFG, cf, resolver)
    assert out["plans"][0]["blocked"]
    assert any("403: Token lacks" in f for f in out["plans"][0]["findings"])


def test_verify_live_when_both_hosts_redirect(fake_cf, resolver):
    pid = planned(fake_cf, resolver)
    out = ops.verify(pid, live_dns(), probe=lambda url: (301, f"{TARGET}/"))
    assert out["summary"]["live"] == 1
    assert check(out, f"301 www.{D}")["ok"]


@pytest.mark.parametrize("answer", [(200, None), (302, TARGET), (301, "https://other.com/"), (530, None)])
def test_verify_pending_on_wrong_redirect(fake_cf, resolver, answer):
    pid = planned(fake_cf, resolver)
    out = ops.verify(pid, live_dns(), probe=lambda url: answer)
    assert out["summary"]["pending"] == 1
    assert not check(out, f"301 {D}")["ok"]


def test_verify_pending_when_the_request_fails(fake_cf, resolver):
    def boom(url):
        raise RuntimeError(f"ConnectError requesting {url}")

    out = ops.verify(planned(fake_cf, resolver), live_dns(), probe=boom)
    assert out["summary"]["pending"] == 1
    assert "ConnectError" in check(out, f"301 {D}")["got"]


def test_verify_needs_proxied_a_records_to_resolve(fake_cf, resolver):
    pid = planned(fake_cf, resolver)
    out = ops.verify(pid, live_dns(a={D: ["104.21.0.1"]}), probe=lambda url: (301, TARGET))
    assert out["summary"]["pending"] == 1
    assert check(out, f"A {D}")["ok"] and not check(out, f"A www.{D}")["ok"]
