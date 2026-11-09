"""Tests for the review fixes: vendor defaults, input validation, DMARC auth, retries, chunking."""
import json

import httpx
import pytest
from pydantic import ValidationError

from domain_setup_mcp import ops, spf
from domain_setup_mcp.cloudflare import Cloudflare, CloudflareError, RateLimited, quote_txt
from domain_setup_mcp.models import Record, normalize_txt
from domain_setup_mcp.planner import build_plan
from domain_setup_mcp.providers import DkimInput, DomainConfig
from domain_setup_mcp.resolver import FakeResolver

D = "getacme.com"
KEY = "v=DKIM1; k=rsa; p=" + "M" * 392  # 2048-bit keys are ~410 chars


def cfg(**kw):
    base = dict(provider="google", dmarc_rua="dmarc@getacme.com", dkim=DkimInput(google_txt=KEY))
    base.update(kw)
    return DomainConfig(**base)


def warnings(p, check):
    return [f.message for f in p.findings if f.check == check and f.severity in ("warning", "error")]


# ---------- vendor defaults ----------

def test_instantly_default_host_is_inst(resolver):
    p = build_plan(D, [], cfg(tracking_tool="instantly"), resolver)
    c = next(c.after for c in p.changes if c.after.type == "CNAME")
    assert (c.name, c.content) == (f"inst.{D}", "prox.itrackly.com")


def test_smartlead_default_host(resolver):
    p = build_plan(D, [], cfg(tracking_tool="smartlead"), resolver)
    c = next(c.after for c in p.changes if c.after.type == "CNAME")
    assert (c.name, c.content) == (f"emailtracking.{D}", "open.sleadtrack.com")


def test_google_legacy_mx_accepted(resolver):
    legacy = [("aspmx.l.google.com", 1), ("alt1.aspmx.l.google.com", 5), ("alt2.aspmx.l.google.com", 5),
              ("alt3.aspmx.l.google.com", 10), ("alt4.aspmx.l.google.com", 10)]
    recs = [Record(type="MX", name=D, content=h.upper() + ".", priority=p) for h, p in legacy]
    p = build_plan(D, recs, cfg(), resolver)
    assert not any((c.after or c.before).type == "MX" for c in p.changes) and not warnings(p, "mx")


def test_partial_google_legacy_still_flagged(resolver):
    recs = [Record(type="MX", name=D, content="aspmx.l.google.com", priority=1)]
    assert warnings(build_plan(D, recs, cfg(), resolver), "mx")


def test_microsoft_new_mx_format_accepted(resolver):
    recs = [Record(type="MX", name=D, content="getacme-com.l-v1.mx.microsoft", priority=0)]
    p = build_plan(D, recs, DomainConfig(provider="microsoft"), resolver)
    assert not any((c.after or c.before).type == "MX" for c in p.changes)


# ---------- DMARC external destination (RFC 7489 7.1) ----------

def test_external_rua_without_authorization_warns(resolver):
    p = build_plan(D, [], cfg(dmarc_rua="dmarc@agency.com"), resolver)
    msg = " ".join(warnings(p, "dmarc"))
    assert "getacme.com._report._dmarc.agency.com" in msg and not p.blocked


def test_external_rua_authorized_is_quiet():
    r = FakeResolver(txt={**_spf_tree(), "getacme.com._report._dmarc.agency.com": ["v=DMARC1;"]})
    assert not warnings(build_plan(D, [], cfg(dmarc_rua="dmarc@agency.com"), r), "dmarc")


def test_same_domain_rua_is_quiet(resolver):
    assert not warnings(build_plan(D, [], cfg(), resolver), "dmarc")


def test_existing_dmarc_external_rua_checked(resolver):
    recs = [Record(type="TXT", name=f"_dmarc.{D}", content="v=DMARC1; p=none; rua=mailto:r@vendor.io")]
    assert any("vendor.io" in m for m in warnings(build_plan(D, recs, cfg(), resolver), "dmarc"))


def _spf_tree():
    from tests.conftest import SPF_TREE
    return SPF_TREE


# ---------- CNAME conflicts ----------

def test_txt_at_cname_name_blocks(resolver):
    recs = [Record(type="CNAME", name=f"mail.{D}", content="elsewhere.com")]
    p = build_plan(D, recs, DomainConfig(provider="ses", ses_mail_from="mail"), resolver)
    assert p.blocked and not any(c.after and c.after.name == f"mail.{D}" for c in p.changes)


# ---------- input validation ----------

def test_dkim_paste_with_quotes_and_newlines_is_cleaned():
    raw = '"v=DKIM1; k=rsa; " "p=MIIBIj\nANBg"'
    assert DkimInput(google_txt=raw).google_txt == "v=DKIM1; k=rsa; p=MIIBIjANBg"


def test_dkim_garbage_rejected():
    with pytest.raises(ValidationError, match="v=DKIM1"):
        DkimInput(google_txt="google-site-verification=abc")


def test_bad_inputs_rejected():
    with pytest.raises(ValidationError):
        DomainConfig(provider="google", dmarc_rua="not-an-email")
    with pytest.raises(ValidationError):
        DomainConfig(provider="google", tracking_subdomain="a.b")
    with pytest.raises(ValidationError):
        DkimInput(ses_tokens=["short"])


def test_mailto_prefix_stripped():
    assert DomainConfig(provider="google", dmarc_rua="mailto:D@X.com").dmarc_rua == "d@x.com"


@pytest.mark.parametrize("bad", ["https://getacme.com", "me@getacme.com", "getacme", "getacme.com/path", "-x.com"])
def test_domain_validation(bad, resolver):
    with pytest.raises(ValueError, match="Not valid domain"):
        ops.audit([bad], resolver)


def test_domain_cleanup_ok(resolver):
    out = ops.audit(["GetAcme.COM.", " getacme.com "], resolver)
    assert [d["domain"] for d in out["domains"]] == ["getacme.com"]


# ---------- apply safety ----------

def test_double_apply_is_skipped(fake_cf, resolver):
    cf = fake_cf({D: []})
    pid = ops.plan([D], cfg(), cf, resolver)["plan_id"]
    ops.apply(pid, cf, confirm=True)
    n = len(cf.calls)
    out = ops.apply(pid, cf, confirm=True)
    assert "already applied" in out["domains"][0]["status"] and len(cf.calls) == n


def test_reapply_after_rollback(fake_cf, resolver):
    cf = fake_cf({D: []})
    pid = ops.plan([D], cfg(), cf, resolver)["plan_id"]
    run = ops.apply(pid, cf, confirm=True)["run_id"]
    ops.rollback(run, cf, confirm=True)
    assert ops.apply(pid, cf, confirm=True)["domains"][0]["status"] == "applied"


# ---------- SPF extras ----------

def test_ptr_and_macro_warnings(resolver):
    c = spf.count_lookups("v=spf1 ptr include:%{i}._spf.x.com ~all", resolver)
    assert c.total == 2 and c.void == 0
    assert any("ptr" in w for w in c.warnings) and any("macro" in w for w in c.warnings)


# ---------- TXT chunking ----------

def test_long_dkim_is_chunked_and_round_trips():
    q = quote_txt(KEY)
    parts = q.split('" "')
    assert len(parts) == 2 and all(len(p.strip('"')) <= 255 for p in parts)
    assert normalize_txt(q) == KEY


def test_short_txt_single_string():
    assert quote_txt("v=spf1 ~all") == '"v=spf1 ~all"'


def test_unsafe_txt_rejected():
    with pytest.raises(CloudflareError):
        quote_txt('v=spf1 "evil" ~all')


# ---------- Cloudflare client over a mock HTTP server ----------

def _cf(handler, **kw):
    return Cloudflare("tok", transport=httpx.MockTransport(handler), sleep=lambda s: None, **kw)


def ok(result, **extra):
    return httpx.Response(200, json={"success": True, "errors": [], "result": result, **extra})


def test_retries_429_then_succeeds():
    calls = []

    def h(req):
        calls.append(1)
        if len(calls) < 3:
            return httpx.Response(429, headers={"retry-after": "1"}, json={"success": False, "errors": []})
        return ok([{"id": "z1"}])

    assert _cf(h).zone_id(D) == "z1" and len(calls) == 3


def test_long_429_fails_fast_without_waiting():
    calls, slept = [], []
    def h(req):
        calls.append(1)
        return httpx.Response(429, headers={"retry-after": "300"}, json={"success": False, "errors": []})
    cf = Cloudflare("tok", transport=httpx.MockTransport(h), sleep=slept.append)
    with pytest.raises(RateLimited, match="blocked for about 300s"):
        cf.zone_id(D)
    assert len(calls) == 1 and slept == []


def test_network_error_becomes_actionable():
    def h(req):
        raise httpx.ConnectError("boom")

    with pytest.raises(CloudflareError, match="Network error"):
        _cf(h, retries=1).zone_id(D)


def test_403_hint():
    h = lambda req: httpx.Response(403, json={"success": False, "errors": [{"code": 10000, "message": "Authentication error"}]})  # noqa: E731
    with pytest.raises(CloudflareError, match="lacks the needed permission"):
        _cf(h).zone_id(D)


def test_unknown_zone():
    with pytest.raises(CloudflareError, match="not found"):
        _cf(lambda req: ok([])).zone_id(D)


def test_list_records_paginates_normalizes_and_filters():
    pages = {
        "1": [{"id": "a", "type": "TXT", "name": "GetAcme.com", "content": '"v=spf1 " "~all"', "ttl": 1},
              {"id": "b", "type": "SRV", "name": D, "content": "x", "ttl": 1}],
        "2": [{"id": "c", "type": "MX", "name": D, "content": "smtp.google.com", "priority": 1, "ttl": 1}],
    }

    def h(req):
        page = req.url.params["page"]
        return ok(pages[page], result_info={"total_pages": 2})

    recs = _cf(h).list_records("z")
    assert [(r.id, r.type, r.name, r.content) for r in recs] == [
        ("a", "TXT", D, "v=spf1 ~all"), ("c", "MX", D, "smtp.google.com")]


def test_batch_body_chunked_txt_priority_and_proxy():
    sent = []

    def h(req):
        sent.append((req.method, req.url.path, json.loads(req.content)))
        return ok({})

    _cf(h).batch("z", ["old1"],
                 [Record(type="TXT", name=D, content="v=spf1 ~all", id="r9")],
                 [Record(type="TXT", name=f"google._domainkey.{D}", content=KEY),
                  Record(type="MX", name=D, content="smtp.google.com", priority=1),
                  Record(type="CNAME", name=f"inst.{D}", content="prox.itrackly.com"),
                  Record(type="A", name=D, content="192.0.2.1", proxied=True)])
    method, path, body = sent[0]
    assert (method, path) == ("POST", "/client/v4/zones/z/dns_records/batch")
    assert body["deletes"] == [{"id": "old1"}] and body["puts"][0]["id"] == "r9"
    posts = body["posts"]
    assert posts[0]["content"].count('" "') == 1
    assert posts[1]["priority"] == 1 and "proxied" not in posts[1]
    assert posts[2]["proxied"] is False and posts[3]["proxied"] is True
    assert "patches" not in body


def test_batch_put_without_id_refused():
    with pytest.raises(CloudflareError, match="id"):
        _cf(lambda r: ok({})).batch("z", [], [Record(type="TXT", name=D, content="x")], [])


def test_redirect_rules_get_404_means_empty_and_put_strips_readonly():
    seen = []

    def h(req):
        seen.append((req.method, req.url.path, req.content))
        if req.method == "GET":
            return httpx.Response(404, json={"success": False, "errors": [{"code": 10003, "message": "not found"}]})
        return ok({})

    cf = _cf(h)
    assert cf.get_redirect_rules("z") == []
    cf.put_redirect_rules("z", [{"id": "1", "ref": "r", "expression": "true", "action": "redirect",
                                 "version": "3", "last_updated": "2026"}])
    method, path, content = seen[1]
    assert path == "/client/v4/zones/z/rulesets/phases/http_request_dynamic_redirect/entrypoint"
    assert json.loads(content)["rules"][0] == {"id": "1", "ref": "r", "expression": "true", "action": "redirect"}
