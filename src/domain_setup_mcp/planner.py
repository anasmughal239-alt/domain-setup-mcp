"""Turn current DNS + desired config into a safe, reviewable list of changes."""
from __future__ import annotations

from . import spf
from .models import Change, DomainPlan, Finding, Record, fingerprint, normalize_name
from .providers import (
    GOOGLE_LEGACY_MX, GOOGLE_MX, MICROSOFT_AUTODISCOVER, REDIRECT_PLACEHOLDER_IP, SPF_INCLUDE, TRACKING_TARGET,
    DomainConfig, DomainSecrets,
)

DEPRECATED_DMARC_TAGS = ("pct", "rf", "ri")  # RFC 9989 (May 2026)


def _at(records: list[Record], name: str, rtype: str | None = None) -> list[Record]:
    return [r for r in records if r.name == name and (rtype is None or r.type == rtype)]


def redirect_ref(domain: str) -> str:
    return "domain_setup_mcp_fwd_" + domain.replace(".", "_").replace("-", "_")


def redirect_rule(domain: str, target: str) -> dict:
    return {
        "ref": redirect_ref(domain),
        "description": f"domain-setup-mcp: forward {domain} to {target}",
        "expression": f'(http.host eq "{domain}" or http.host eq "www.{domain}")',
        "action": "redirect",
        "action_parameters": {"from_value": {"target_url": {"value": target}, "status_code": 301,
                                             "preserve_query_string": False}},
        "enabled": True,
    }


class _Builder:
    def __init__(self, domain: str, records: list[Record]):
        self.domain = domain.lower().rstrip(".")
        self.records = records
        self.plan = DomainPlan(domain=self.domain, fingerprint=fingerprint(records))

    def note(self, severity: str, check: str, message: str) -> None:
        self.plan.findings.append(Finding(severity=severity, check=check, message=message))  # type: ignore[arg-type]
        if severity == "error":
            self.plan.blocked = True

    def change(self, action: str, reason: str, before: Record | None = None, after: Record | None = None) -> None:
        self.plan.changes.append(Change(action=action, before=before, after=after, reason=reason))  # type: ignore[arg-type]

    def cname_blocks(self, check: str, name: str) -> bool:
        """A name with a CNAME cannot hold any other record (RFC 1034)."""
        if _at(self.records, name, "CNAME"):
            self.note("error", check, f"{name} is a CNAME; TXT/MX/A records cannot be added there. Remove the CNAME first.")
            return True
        return False

    def ensure_single(self, check: str, rtype: str, name: str, content: str, label: str,
                      priority: int | None = None, proxied: bool = False) -> None:
        """Exactly one record of this type at this name, with this content. Updates in place; removes extras."""
        if rtype == "CNAME":
            others = [r for r in _at(self.records, name) if r.type != "CNAME"]
            if others:
                self.note("error", check, f"{name} already has {others[0].type} records; a CNAME cannot coexist with them.")
                return
        elif self.cname_blocks(check, name):
            return
        existing = _at(self.records, name, rtype)
        want = Record(type=rtype, name=name, content=content, priority=priority, proxied=proxied)  # type: ignore[arg-type]
        match = [r for r in existing if r.key() == want.key()]
        if match and len(existing) == 1:
            self.note("ok", check, f"{label} already correct.")
            return
        if match:  # correct one exists plus extras
            for extra in existing:
                if extra is not match[0]:
                    self.change("delete", f"Remove extra {rtype} at {name} ({label} needs exactly one)", before=extra)
            return
        if not existing:
            self.change("create", f"Add {label}", after=want)
            return
        cur = existing[0]
        self.change("update", f"{label} differs from expected", before=cur, after=want.model_copy(update={"id": cur.id}))
        self.note("warning", check, f"{label} at {name} will be overwritten. Old value: {cur.content[:80]}")
        for extra in existing[1:]:
            self.change("delete", f"Remove extra {rtype} at {name} ({label} needs exactly one)", before=extra)

    def ensure_txt_present(self, check: str, name: str, content: str, label: str) -> None:
        """Add a TXT if this exact value is missing. Never touches other TXT records at the name."""
        if self.cname_blocks(check, name):
            return
        if any(r.content == content for r in _at(self.records, name, "TXT")):
            self.note("ok", check, f"{label} already present.")
        else:
            self.change("create", f"Add {label}", after=Record(type="TXT", name=name, content=content))


def build_plan(domain: str, records: list[Record], cfg: DomainConfig, resolver: spf.TxtResolver,
               redirect_rules: list[dict] | None = None, redirect_error: str | None = None) -> DomainPlan:
    """redirect_rules: current rules of the zone's redirect ruleset ([] if none). None = could not be read,
    and redirect_error says why."""
    b = _Builder(domain, records)
    d = b.domain
    sec = cfg.secrets_for(d)
    if sec.verification_txt:
        b.ensure_txt_present("verification", d, sec.verification_txt, "domain verification TXT")
    _plan_spf(b, d, cfg, resolver)
    _plan_mx(b, d, cfg, sec)
    _plan_dkim(b, d, cfg, sec)
    _plan_dmarc(b, d, cfg, resolver)
    if cfg.provider == "microsoft" and cfg.microsoft_autodiscover:
        b.ensure_single("autodiscover", "CNAME", normalize_name("autodiscover", d), MICROSOFT_AUTODISCOVER,
                        "Microsoft Autodiscover CNAME")
    if cfg.tracking_tool:
        b.ensure_single("tracking", "CNAME", normalize_name(cfg.tracking_host(), d), TRACKING_TARGET[cfg.tracking_tool],
                        f"{cfg.tracking_tool} tracking CNAME (DNS-only)")
    if cfg.forward_to:
        _plan_forwarding(b, d, cfg.forward_to, redirect_rules, redirect_error)
    if not b.plan.changes and not (b.plan.redirect and b.plan.redirect["action"] != "none"):
        b.note("ok", "summary", "Nothing to change.")
    return b.plan


# ---------- SPF ----------

def _plan_spf(b: _Builder, d: str, cfg: DomainConfig, resolver: spf.TxtResolver) -> None:
    if cfg.provider == "ses":
        if cfg.ses_mail_from:
            mf = normalize_name(cfg.ses_mail_from, d)
            _merge_spf_at(b, mf, ["amazonses.com"], resolver)
            # SES: exactly one MX on the MAIL FROM subdomain, and the subdomain must not be used for anything else.
            b.ensure_single("ses_mail_from", "MX", mf, f"feedback-smtp.{cfg.ses_region}.amazonses.com",
                            "SES MAIL FROM MX", priority=10)
            if _at(b.records, mf, "A") or _at(b.records, mf, "AAAA"):
                b.note("warning", "ses_mail_from", f"{mf} also has A/AAAA records. SES requires the MAIL FROM "
                       "subdomain to be used for nothing else.")
        else:
            b.note("warning", "spf", "SES without a custom MAIL FROM: SPF will not align with your domain, so "
                   "DMARC depends on DKIM alone. Set ses_mail_from (e.g. 'mail').")
        return
    _merge_spf_at(b, d, [SPF_INCLUDE[cfg.provider]], resolver)


def _merge_spf_at(b: _Builder, name: str, includes: list[str], resolver: spf.TxtResolver) -> None:
    if b.cname_blocks("spf", name):
        return
    current = [r for r in _at(b.records, name, "TXT") if spf.is_spf(r.content)]
    merged = spf.merge([r.content for r in current], includes)
    for w in merged.warnings:
        b.note("warning", "spf", w)

    count = spf.count_lookups(merged.record, resolver)
    b.plan.spf_lookups = count.total
    for w in count.warnings:
        b.note("warning", "spf", w)
    if count.total > spf.LOOKUP_LIMIT:
        b.note("error", "spf", f"Merged SPF needs {count.total} DNS lookups (limit {spf.LOOKUP_LIMIT}). "
               "Receivers will fail SPF. Remove unused includes or flatten before applying.")
        return
    if count.void > spf.VOID_LOOKUP_LIMIT:
        b.note("error", "spf", f"{count.void} void lookups (limit {spf.VOID_LOOKUP_LIMIT}). Remove dead includes.")
        return

    want = Record(type="TXT", name=name, content=merged.record)
    if not current:
        b.change("create", "Add SPF record", after=want)
    elif len(current) == 1 and current[0].content == merged.record:
        b.note("ok", "spf", f"SPF already includes {', '.join(includes)} ({count.total} lookups).")
    else:
        keep = current[0]
        b.change("update", f"Merge SPF (added: {', '.join(merged.added) or 'none'}), existing mechanisms kept",
                 before=keep, after=want.model_copy(update={"id": keep.id}))
        for extra in current[1:]:
            b.change("delete", "Remove duplicate SPF record (merged into one)", before=extra)


# ---------- MX ----------

def _plan_mx(b: _Builder, d: str, cfg: DomainConfig, sec: DomainSecrets) -> None:
    current = _at(b.records, d, "MX")
    cur_set = {(r.content.lower().rstrip("."), r.priority) for r in current}

    if sec.mx:
        want = sec.mx
    elif cfg.provider == "google":
        want = GOOGLE_MX
        if _equivalent_mx(cfg.provider, cur_set):
            b.note("ok", "mx", "MX already correct (Google legacy set, still supported).")
            return
    elif cfg.provider == "microsoft":
        if _equivalent_mx(cfg.provider, cur_set):
            b.note("ok", "mx", "MX already points to Exchange Online.")
        else:
            b.note("warning", "mx", "Microsoft MX not planned: its value is tenant-specific (new domains use *.mx.microsoft "
                   "since July 2026). Copy it from Admin center > Domains > DNS records and pass per_domain[...].mx.")
        return
    else:
        return  # SES is send-only; inbound mail stays wherever it is.

    want_set = {(h, p) for h, p in want}
    if cur_set == want_set:
        b.note("ok", "mx", "MX already correct.")
        return
    if current and not cfg.replace_mx:
        b.note("warning", "mx", "Existing MX points to " + ", ".join(sorted(h for h, _ in cur_set))
               + ". Left unchanged so live inbound mail is not broken. Set replace_mx=true to replace.")
        return
    for r in current:
        if (r.content.lower().rstrip("."), r.priority) not in want_set:
            b.change("delete", "Replace MX (replace_mx=true)" if current else "Remove MX", before=r)
    for host, prio in want:
        if (host, prio) not in cur_set:
            b.change("create", f"Add MX {host}", after=Record(type="MX", name=d, content=host, priority=prio))


def _equivalent_mx(provider: str, cur: set) -> bool:
    """Other valid MX layouts for the same provider. Never 'fix' a working setup."""
    if not cur:
        return False
    if provider == "google":
        return cur == GOOGLE_LEGACY_MX
    if provider == "microsoft":
        return len(cur) == 1 and next(iter(cur))[0].endswith((".mail.protection.outlook.com", ".mx.microsoft"))
    return False


# ---------- DKIM ----------

def _plan_dkim(b: _Builder, d: str, cfg: DomainConfig, sec: DomainSecrets) -> None:
    k = sec.dkim
    if cfg.provider == "google":
        if not k.google_txt:
            b.note("warning", "dkim", "Google DKIM key not supplied for this domain. In Admin console > Apps > Gmail > "
                   "Authenticate email, generate a 2048-bit key (available 24-72h after Gmail is activated) and pass "
                   "per_domain[...].dkim.google_txt. Do not click Generate again later: it replaces the key.")
            return
        b.ensure_single("dkim", "TXT", normalize_name(f"{k.google_selector}._domainkey", d), k.google_txt, "Google DKIM")
    elif cfg.provider == "microsoft":
        targets = {"selector1": k.microsoft_selector1_target, "selector2": k.microsoft_selector2_target}
        if not all(targets.values()):
            b.note("warning", "dkim", "Microsoft DKIM targets not supplied. Copy Selector1CNAME and Selector2CNAME from "
                   "Defender portal > Email authentication > DKIM (or Get-DkimSigningConfig). Never build them by hand. "
                   "Use 2048-bit keys (Microsoft defaults to 1024).")
            return
        slug = d.replace(".", "-")
        for sel, tgt in targets.items():
            if not tgt.startswith(f"{sel}-{slug}._domainkey."):
                b.note("error", "dkim", f"{sel} target '{tgt}' is for a different domain or selector "
                       f"(expected it to start with '{sel}-{slug}._domainkey.'). Check you pasted this domain's values.")
                return
        for sel, tgt in targets.items():
            b.ensure_single("dkim", "CNAME", normalize_name(f"{sel}._domainkey", d), tgt, f"Microsoft DKIM {sel}")
    elif cfg.provider == "ses":
        if len(k.ses_tokens) != 3:
            b.note("warning", "dkim", "SES Easy DKIM needs exactly 3 tokens for this identity. DKIM not planned.")
            return
        for t in k.ses_tokens:
            b.ensure_single("dkim", "CNAME", normalize_name(f"{t}._domainkey", d), f"{t}.dkim.amazonses.com", "SES DKIM")


# ---------- DMARC ----------

def _plan_dmarc(b: _Builder, d: str, cfg: DomainConfig, resolver: spf.TxtResolver) -> None:
    name = normalize_name("_dmarc", d)
    if b.cname_blocks("dmarc", name):
        return
    current = [r for r in _at(b.records, name, "TXT") if r.content.lower().startswith("v=dmarc1")]
    if len(current) > 1:
        b.note("error", "dmarc", "Multiple DMARC records found; receivers ignore all of them. Delete extras manually.")
        return
    if current:
        rec = current[0].content
        b.note("ok", "dmarc", f"DMARC exists (p={dmarc_tag(rec, 'p')}). Left unchanged; this tool never changes an existing policy.")
        for w in dmarc_record_warnings(rec):
            b.note("warning", "dmarc", w)
        for addr in rua_addresses(rec):
            _check_external_rua(b, d, addr, resolver)
        return
    value = f"v=DMARC1; p={cfg.dmarc_policy};"
    if cfg.dmarc_np:
        value += f" np={cfg.dmarc_np};"
    if cfg.dmarc_rua:
        value += f" rua=mailto:{cfg.dmarc_rua};"
        _check_external_rua(b, d, cfg.dmarc_rua, resolver)
    else:
        b.note("warning", "dmarc", "No dmarc_rua given; DMARC will be created without reporting.")
    if cfg.dmarc_policy == "reject":
        b.note("warning", "dmarc", "Starting a new domain at p=reject drops any mail that fails alignment. "
               "p=none first, then quarantine after reports look clean, is the safer path.")
    b.change("create", f"Add DMARC at p={cfg.dmarc_policy}", after=Record(type="TXT", name=name, content=value))


def dmarc_tag(record: str, tag: str) -> str | None:
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            if k.strip().lower() == tag:
                return v.strip()
    return None


def rua_addresses(record: str) -> list[str]:
    out = []
    for a in (dmarc_tag(record, "rua") or "").split(","):
        a = a.strip().removeprefix("mailto:").split("!")[0]
        if "@" in a:
            out.append(a.lower())
    return out


def dmarc_record_warnings(record: str) -> list[str]:
    w = []
    if not dmarc_tag(record, "rua"):
        w.append("DMARC has no rua; you get no reports on who sends as this domain.")
    used = [t for t in DEPRECATED_DMARC_TAGS if dmarc_tag(record, t) is not None]
    if used:
        w.append(f"DMARC uses {', '.join(used)}, removed in RFC 9989 (May 2026). Receivers on the new spec ignore them"
                 + ("; for staged rollout pair pct with t=y." if "pct" in used and dmarc_tag(record, "t") is None else "."))
    if "!" in (dmarc_tag(record, "rua") or ""):
        w.append("rua has a size limit suffix (e.g. !10m), which RFC 9989 removed.")
    return w


def _check_external_rua(b: _Builder, d: str, addr: str, resolver: spf.TxtResolver) -> None:
    """RFC 7489 7.1 / RFC 9990: reports to another domain are only sent if that domain opts in."""
    rua_domain = addr.split("@", 1)[1].lower()
    if rua_domain == d or d.endswith("." + rua_domain) or rua_domain.endswith("." + d):
        return
    auth = f"{d}._report._dmarc.{rua_domain}"
    try:
        ok = any(t.lower().startswith("v=dmarc1") for t in resolver.txt(auth))
    except RuntimeError:
        ok = False
    if not ok:
        b.note("warning", "dmarc", f"Reports go to {rua_domain}, which has not authorized reports for {d}. "
               f"Receivers will drop them. On {rua_domain} add TXT '{auth}' = 'v=DMARC1;' "
               f"(or once: '*._report._dmarc.{rua_domain}' = 'v=DMARC1;').")


# ---------- forwarding ----------

def _plan_forwarding(b: _Builder, d: str, target: str, rules: list[dict] | None, error: str | None = None) -> None:
    host = target.split("://", 1)[1].split("/", 1)[0].lower()
    if host in (d, f"www.{d}"):
        b.note("error", "forwarding", f"forward_to points at {d} itself; that is a redirect loop.")
        return
    for name in (d, f"www.{d}"):
        web = [r for r in _at(b.records, name) if r.type in ("A", "AAAA", "CNAME")]
        if not web:
            b.change("create", "Add proxied placeholder so Cloudflare can serve the redirect",
                     after=Record(type="A", name=name, content=REDIRECT_PLACEHOLDER_IP, proxied=True))
        elif not all(r.proxied for r in web):
            b.note("warning", "forwarding", f"{name} already has a DNS-only web record ({web[0].type} {web[0].content}). "
                   "Redirect rules only run on proxied hostnames; left unchanged. Enable the proxy or remove it.")
    if rules is None:
        b.note("error", "forwarding", f"Could not read redirect rules: {error or 'no details from Cloudflare.'} "
               "If this is a permission error, give the token Zone > Single Redirect > Edit (the token summary "
               "calls it Dynamic URL Redirects Write), or drop forward_to.")
        return
    mine = next((r for r in rules if r.get("ref") == redirect_ref(d)), None)
    if mine is None:
        action = "create"
    elif mine.get("action_parameters", {}).get("from_value", {}).get("target_url", {}).get("value") == target:
        action = "none"
        b.note("ok", "forwarding", f"Already forwarding to {target}.")
    else:
        action = "update"
    b.plan.redirect = {"action": action, "target": target, "rule": redirect_rule(d, target)}
