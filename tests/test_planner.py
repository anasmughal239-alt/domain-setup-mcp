from domain_setup_mcp.models import Record
from domain_setup_mcp.planner import build_plan
from domain_setup_mcp.providers import DkimInput, DomainConfig, DomainSecrets

D = "getacme.com"
GKEY = "v=DKIM1; k=rsa; p=MIIBIjANBgkq"
T1, T2, T3 = ("a" * 32, "b1" * 16, "c2" * 16)


def G(**kw):
    base = dict(provider="google", dmarc_rua="dmarc@agency.com", dkim=DkimInput(google_txt=GKEY))
    base.update(kw)
    return DomainConfig(**base)


def actions(p):
    return sorted((c.action, c.after.type if c.after else c.before.type, (c.after or c.before).name) for c in p.changes)


def test_fresh_google_domain(resolver):
    p = build_plan(D, [], G(tracking_tool="smartlead"), resolver)
    assert not p.blocked
    assert actions(p) == sorted([
        ("create", "TXT", D),                          # SPF
        ("create", "MX", D),
        ("create", "TXT", f"google._domainkey.{D}"),
        ("create", "TXT", f"_dmarc.{D}"),
        ("create", "CNAME", f"emailtracking.{D}"),
    ])
    spf = next(c.after for c in p.changes if c.after.content.startswith("v=spf1"))
    assert spf.content == "v=spf1 include:_spf.google.com ~all"
    dmarc = next(c.after for c in p.changes if c.after.name.startswith("_dmarc"))
    assert "p=none" in dmarc.content and "rua=mailto:dmarc@agency.com" in dmarc.content
    assert p.spf_lookups == 4


def test_already_configured_is_noop(resolver):
    recs = [
        Record(type="TXT", name=D, content="v=spf1 include:_spf.google.com ~all"),
        Record(type="MX", name=D, content="smtp.google.com", priority=1),
        Record(type="TXT", name=f"google._domainkey.{D}", content=GKEY),
        Record(type="TXT", name=f"_dmarc.{D}", content="v=DMARC1; p=none; rua=mailto:x@y.com"),
    ]
    p = build_plan(D, recs, G(), resolver)
    assert p.changes == [] and not p.blocked


def test_existing_spf_is_merged_not_duplicated(resolver):
    recs = [Record(type="TXT", name=D, content="v=spf1 include:sendgrid.net -all", id="r1")]
    p = build_plan(D, recs, G(), resolver)
    spf = [c for c in p.changes if (c.after or c.before).type == "TXT" and (c.after or c.before).name == D]
    assert len(spf) == 1 and spf[0].action == "update" and spf[0].after.id == "r1"
    assert spf[0].after.content == "v=spf1 include:sendgrid.net include:_spf.google.com -all"


def test_two_spf_records_merged_and_extra_deleted(resolver):
    recs = [Record(type="TXT", name=D, content="v=spf1 include:sendgrid.net ~all", id="a"),
            Record(type="TXT", name=D, content="v=spf1 include:mailgun.org ~all", id="b")]
    p = build_plan(D, recs, G(), resolver)
    kinds = [(c.action, (c.before or c.after).id) for c in p.changes if (c.after or c.before).name == D and (c.after or c.before).type == "TXT"]
    assert ("update", "a") in kinds and ("delete", "b") in kinds


def test_non_spf_txt_untouched(resolver):
    recs = [Record(type="TXT", name=D, content="google-site-verification=abc", id="v")]
    p = build_plan(D, recs, G(), resolver)
    assert all((c.before is None or c.before.id != "v") for c in p.changes)


def test_spf_over_limit_blocks_plan(resolver):
    heavy = " ".join(f"include:heavy{i}.test" for i in range(3))
    recs = [Record(type="TXT", name=D, content=f"v=spf1 {heavy} ~all")]
    p = build_plan(D, recs, G(), resolver)
    assert p.blocked and p.spf_lookups == 13
    assert not any(c.after and c.after.content.startswith("v=spf1") for c in p.changes)


def test_live_mx_elsewhere_left_alone(resolver):
    recs = [Record(type="MX", name=D, content="mx.zoho.com", priority=10)]
    p = build_plan(D, recs, G(), resolver)
    assert not any((c.after or c.before).type == "MX" for c in p.changes)
    assert any(f.check == "mx" and f.severity == "warning" for f in p.findings)


def test_replace_mx_when_asked(resolver):
    recs = [Record(type="MX", name=D, content="mx.zoho.com", priority=10, id="z")]
    p = build_plan(D, recs, G(replace_mx=True), resolver)
    mx = [(c.action, (c.after or c.before).content) for c in p.changes if (c.after or c.before).type == "MX"]
    assert ("delete", "mx.zoho.com") in mx and ("create", "smtp.google.com") in mx


def test_existing_dmarc_never_changed(resolver):
    recs = [Record(type="TXT", name=f"_dmarc.{D}", content="v=DMARC1; p=reject; rua=mailto:a@b.com")]
    p = build_plan(D, recs, G(), resolver)
    assert not any((c.after or c.before).name == f"_dmarc.{D}" for c in p.changes)


def test_duplicate_dmarc_blocks(resolver):
    recs = [Record(type="TXT", name=f"_dmarc.{D}", content="v=DMARC1; p=none"),
            Record(type="TXT", name=f"_dmarc.{D}", content="v=DMARC1; p=reject")]
    assert build_plan(D, recs, G(), resolver).blocked


def test_dkim_rotation_is_update_with_warning(resolver):
    recs = [Record(type="TXT", name=f"google._domainkey.{D}", content="v=DKIM1; p=OLDKEY", id="k")]
    p = build_plan(D, recs, G(), resolver)
    c = next(c for c in p.changes if c.after and c.after.name.startswith("google._domainkey"))
    assert c.action == "update" and c.after.id == "k"
    assert any(f.check == "dkim" and f.severity == "warning" for f in p.findings)


def test_missing_google_dkim_warns_not_blocks(resolver):
    p = build_plan(D, [], G(dkim=DkimInput()), resolver)
    assert not p.blocked and any(f.check == "dkim" for f in p.findings)


def test_tracking_cname_conflict_blocks(resolver):
    recs = [Record(type="A", name=f"inst.{D}", content="1.2.3.4")]
    assert build_plan(D, recs, G(tracking_tool="instantly"), resolver).blocked


def test_instantly_tracking_target(resolver):
    p = build_plan(D, [], G(tracking_tool="instantly", tracking_subdomain="inst"), resolver)
    c = next(c.after for c in p.changes if c.after.type == "CNAME")
    assert c.name == f"inst.{D}" and c.content == "prox.itrackly.com" and c.proxied is False


MS1 = "selector1-getacme-com._domainkey.acme.n-v1.dkim.mail.microsoft"
MS2 = "selector2-getacme-com._domainkey.acme.n-v1.dkim.mail.microsoft"


def test_microsoft_records(resolver):
    cfg = DomainConfig(provider="microsoft", dmarc_rua="d@getacme.com", per_domain={D: DomainSecrets(
        dkim=DkimInput(microsoft_selector1_target=MS1, microsoft_selector2_target=MS2),
        mx=[("getacme-com.o-v1.mx.microsoft", 0)], verification_txt="MS=ms12345678")})
    p = build_plan(D, [], cfg, resolver)
    got = {(c.after.type, c.after.name, c.after.content) for c in p.changes}
    assert ("MX", D, "getacme-com.o-v1.mx.microsoft") in got
    assert ("CNAME", f"selector1._domainkey.{D}", MS1) in got
    assert ("CNAME", f"autodiscover.{D}", "autodiscover.outlook.com") in got
    assert ("TXT", D, "MS=ms12345678") in got
    assert p.spf_lookups == 2


def test_microsoft_mx_never_guessed(resolver):
    p = build_plan(D, [], DomainConfig(provider="microsoft"), resolver)
    assert not any(c.after.type == "MX" for c in p.changes)
    assert any("mx.microsoft" in f.message for f in p.findings if f.check == "mx")


def test_microsoft_dkim_for_wrong_domain_blocks(resolver):
    other = "selector1-other-com._domainkey.acme.onmicrosoft.com"
    cfg = DomainConfig(provider="microsoft", per_domain={D: DomainSecrets(dkim=DkimInput(
        microsoft_selector1_target=other, microsoft_selector2_target=MS2))})
    assert build_plan(D, [], cfg, resolver).blocked


def test_ses_with_mail_from(resolver):
    cfg = DomainConfig(provider="ses", ses_mail_from="mail", dkim=DkimInput(ses_tokens=[T1, T2, T3]))
    p = build_plan(D, [], cfg, resolver)
    names = {(c.after.type, c.after.name, c.after.content, c.after.priority) for c in p.changes}
    assert ("TXT", f"mail.{D}", "v=spf1 include:amazonses.com ~all", None) in names
    assert ("MX", f"mail.{D}", "feedback-smtp.us-east-1.amazonses.com", 10) in names
    assert ("CNAME", f"{T1}._domainkey.{D}", f"{T1}.dkim.amazonses.com", None) in names
    assert not any(c.after.type == "MX" and c.after.name == D for c in p.changes)  # root MX untouched


def test_ses_mail_from_correct_is_noop(resolver):
    recs = [Record(type="MX", name=f"mail.{D}", content="feedback-smtp.us-east-1.amazonses.com", priority=10),
            Record(type="TXT", name=f"mail.{D}", content="v=spf1 include:amazonses.com ~all")]
    p = build_plan(D, recs, DomainConfig(provider="ses", ses_mail_from="mail"), resolver)
    assert not any(c.after and c.after.name == f"mail.{D}" for c in p.changes)


def test_ses_without_mail_from_warns(resolver):
    p = build_plan(D, [], DomainConfig(provider="ses"), resolver)
    assert any("MAIL FROM" in f.message for f in p.findings)
