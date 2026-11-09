from domain_setup_mcp import spf


def test_merge_adds_include_before_all_and_keeps_existing():
    r = spf.merge(["v=spf1 include:sendgrid.net -all"], ["_spf.google.com"])
    assert r.record == "v=spf1 include:sendgrid.net include:_spf.google.com -all"
    assert r.added == ["_spf.google.com"]


def test_merge_is_idempotent():
    rec = "v=spf1 include:_spf.google.com ~all"
    r = spf.merge([rec], ["_spf.google.com"])
    assert r.record == rec and r.added == []


def test_merge_combines_duplicate_records_and_warns():
    r = spf.merge(["v=spf1 include:sendgrid.net ~all", "v=spf1 include:mailgun.org ~all"], ["_spf.google.com"])
    assert r.record == "v=spf1 include:sendgrid.net include:mailgun.org include:_spf.google.com ~all"
    assert any("Multiple SPF" in w for w in r.warnings)


def test_merge_conflicting_all_keeps_first():
    r = spf.merge(["v=spf1 -all", "v=spf1 ~all"], [])
    assert r.record.endswith("-all")
    assert any("disagree" in w for w in r.warnings)


def test_merge_flags_plus_all():
    r = spf.merge(["v=spf1 +all"], ["_spf.google.com"])
    assert any("+all" in w for w in r.warnings)


def test_merge_adds_softfail_when_no_all():
    r = spf.merge(["v=spf1 include:sendgrid.net"], [])
    assert r.record.endswith("~all")


def test_merge_keeps_redirect():
    r = spf.merge(["v=spf1 redirect=_spf.example.com"], ["_spf.google.com"])
    assert r.record == "v=spf1 include:_spf.google.com redirect=_spf.example.com"


def test_merge_dedupes_case_and_plus_qualifier():
    r = spf.merge(["v=spf1 +include:_SPF.google.com ~all"], ["_spf.google.com"])
    assert r.added == []


def test_merge_new_record():
    assert spf.merge([], ["_spf.google.com"]).record == "v=spf1 include:_spf.google.com ~all"


def test_google_costs_four_lookups(resolver):
    assert spf.count_lookups("v=spf1 include:_spf.google.com ~all", resolver).total == 4


def test_microsoft_costs_two_lookups(resolver):
    assert spf.count_lookups("v=spf1 include:spf.protection.outlook.com -all", resolver).total == 2


def test_ip_mechanisms_are_free(resolver):
    assert spf.count_lookups("v=spf1 ip4:1.2.3.4 ip6:::1 ~all", resolver).total == 0


def test_a_mx_count(resolver):
    assert spf.count_lookups("v=spf1 a mx a:x.com ~all", resolver).total == 3


def test_over_limit(resolver):
    rec = "v=spf1 include:_spf.google.com " + " ".join(f"include:heavy{i}.test" for i in range(3)) + " ~all"
    # google 4 + 3 * (1 include + a + mx) = 13
    assert spf.count_lookups(rec, resolver).total == 13


def test_void_lookup_detected(resolver):
    c = spf.count_lookups("v=spf1 include:dead.test ~all", resolver)
    assert c.void == 1 and any("void" in w for w in c.warnings)


def test_loop_does_not_hang(resolver):
    c = spf.count_lookups("v=spf1 include:loop-a.test ~all", resolver)
    assert any("loop" in w for w in c.warnings)


def test_is_spf():
    assert spf.is_spf("v=spf1 -all") and spf.is_spf("V=SPF1 ~all")
    assert not spf.is_spf("v=spf10") and not spf.is_spf("google-site-verification=x")
