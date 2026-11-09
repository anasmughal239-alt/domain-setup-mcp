"""v0.3 research fixes: forwarding, verification TXT, SES single MX, DMARC policy, partial-failure recovery."""
import pytest
from pydantic import ValidationError

from domain_setup_mcp import ops
from domain_setup_mcp.models import Record
from domain_setup_mcp.planner import build_plan, redirect_ref
from domain_setup_mcp.providers import DkimInput, DomainConfig, DomainSecrets

D = "getacme.com"
GV = "google-site-verification=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"


def G(**kw):
    base = dict(provider="google", dmarc_rua="d@getacme.com",
                per_domain={D: DomainSecrets(dkim=DkimInput(google_txt="v=DKIM1; k=rsa; p=KEY"))})
    base.update(kw)
    return DomainConfig(**base)


def adds(p):
    return {(c.after.type, c.after.name, c.after.content, c.after.proxied) for c in p.changes if c.action == "create"}


# ---------- forwarding ----------

def test_forwarding_creates_proxied_placeholders_and_rule(resolver):
    p = build_plan(D, [], G(forward_to="https://acme.com"), resolver, redirect_rules=[])
    assert ("A", D, "192.0.2.1", True) in adds(p) and ("A", f"www.{D}", "192.0.2.1", True) in adds(p)
    assert p.redirect["action"] == "create"
    rule = p.redirect["rule"]
    assert rule["expression"] == f'(http.host eq "{D}" or http.host eq "www.{D}")'
    assert rule["action_parameters"]["from_value"]["status_code"] == 301


def test_forwarding_already_configured_is_noop(resolver):
    recs = [Record(type="A", name=D, content="192.0.2.1", proxied=True),
            Record(type="A", name=f"www.{D}", content="192.0.2.1", proxied=True)]
    p1 = build_plan(D, [], G(forward_to="https://acme.com"), resolver, [])
    p = build_plan(D, recs, G(forward_to="https://acme.com"), resolver, [p1.redirect["rule"]])
    assert p.redirect["action"] == "none" and not any(c.after and c.after.type == "A" for c in p.changes)


def test_forwarding_target_change_is_update(resolver):
    old = build_plan(D, [], G(forward_to="https://old.com"), resolver, []).redirect["rule"]
    p = build_plan(D, [], G(forward_to="https://new.com"), resolver, [old])
    assert p.redirect["action"] == "update"


def test_forwarding_leaves_existing_website_alone(resolver):
    recs = [Record(type="A", name=D, content="203.0.113.9", proxied=False)]
    p = build_plan(D, recs, G(forward_to="https://acme.com"), resolver, [])
    assert not any(c.after and c.after.name == D and c.after.type == "A" for c in p.changes)
    assert any(f.check == "forwarding" and "DNS-only" in f.message for f in p.findings)


def test_forwarding_loop_blocks(resolver):
    assert build_plan(D, [], G(forward_to=f"https://www.{D}/x"), resolver, []).blocked


def test_forwarding_without_permission_blocks(resolver):
    p = build_plan(D, [], G(forward_to="https://acme.com"), resolver, redirect_rules=None)
    assert p.blocked and any("Single Redirect" in f.message for f in p.findings)


def test_apply_forwarding_keeps_other_rules_and_rollback_restores(fake_cf, resolver):
    cf = fake_cf({D: []})
    other = {"ref": "someone_elses_rule", "expression": "true", "action": "redirect"}
    cf.rules[f"zone-{D}"] = [other]
    cfg = G(forward_to="https://acme.com")
    run = ops.apply(ops.plan([D], cfg, cf, resolver)["plan_id"], cf, confirm=True)["run_id"]
    refs = [r["ref"] for r in cf.rules[f"zone-{D}"]]
    assert refs == ["someone_elses_rule", redirect_ref(D)]
    ops.rollback(run, cf, confirm=True)
    assert cf.rules[f"zone-{D}"] == [other] and cf.zones[f"zone-{D}"] == []


def test_redirect_failure_after_dns_reports_partial_and_rolls_back(fake_cf, resolver):
    cf = fake_cf({D: []})
    pid = ops.plan([D], G(forward_to="https://acme.com"), cf, resolver)["plan_id"]
    cf.fail_on = "rules_put"
    out = ops.apply(pid, cf, confirm=True)
    assert "DNS records were applied; the redirect was not" in out["domains"][0]["status"]
    cf.fail_on = None
    assert ops.rollback(out["run_id"], cf, confirm=True)["errors"] == []
    assert cf.zones[f"zone-{D}"] == []


# ---------- verification TXT ----------

def test_verification_txt_added_once_and_never_touches_other_txt(resolver):
    recs = [Record(type="TXT", name=D, content="some-other=1", id="o")]
    cfg = G(per_domain={D: DomainSecrets(verification_txt=GV)})
    p = build_plan(D, recs, cfg, resolver)
    assert ("TXT", D, GV, False) in adds(p)
    assert all(c.before is None or c.before.id != "o" for c in p.changes)
    p2 = build_plan(D, recs + [Record(type="TXT", name=D, content=GV)], cfg, resolver)
    assert ("TXT", D, GV, False) not in adds(p2)


@pytest.mark.parametrize("bad", ["hello", "v=spf1 ~all", "google-site-verification=short"])
def test_verification_txt_validated(bad):
    with pytest.raises(ValidationError):
        DomainSecrets(verification_txt=bad)


# ---------- SES MAIL FROM ----------

def test_ses_mail_from_extra_mx_removed(resolver):
    mf = f"mail.{D}"
    recs = [Record(type="MX", name=mf, content="feedback-smtp.us-east-1.amazonses.com", priority=10, id="good"),
            Record(type="MX", name=mf, content="old.mx.com", priority=20, id="bad")]
    p = build_plan(D, recs, DomainConfig(provider="ses", ses_mail_from="mail"), resolver)
    mx_changes = [(c.action, (c.before or c.after).id) for c in p.changes if (c.before or c.after).name == mf
                  and (c.before or c.after).type == "MX"]
    assert mx_changes == [("delete", "bad")]  # correct record untouched, only the extra goes


def test_ses_mail_from_only_for_ses():
    with pytest.raises(ValidationError, match="ses"):
        DomainConfig(provider="google", ses_mail_from="mail")


# ---------- DMARC ----------

def test_dmarc_quarantine_and_np(resolver):
    p = build_plan(D, [], G(dmarc_policy="quarantine", dmarc_np="reject"), resolver)
    rec = next(c.after.content for c in p.changes if c.after.name == f"_dmarc.{D}")
    assert rec == "v=DMARC1; p=quarantine; np=reject; rua=mailto:d@getacme.com;"


def test_dmarc_reject_on_new_domain_warns(resolver):
    p = build_plan(D, [], G(dmarc_policy="reject"), resolver)
    assert any("p=reject" in f.message for f in p.findings if f.check == "dmarc")


# ---------- config validation ----------

@pytest.mark.parametrize("bad", ["acme.com", "ftp://acme.com", "https://"])
def test_forward_to_must_be_url(bad):
    with pytest.raises(ValidationError):
        G(forward_to=bad)


def test_microsoft_target_must_be_microsoft():
    with pytest.raises(ValidationError, match="Microsoft DKIM target"):
        DkimInput(microsoft_selector1_target="selector1-x-com._domainkey.evil.com")


def test_bad_region_rejected():
    with pytest.raises(ValidationError):
        DomainConfig(provider="ses", ses_region="useast1")
