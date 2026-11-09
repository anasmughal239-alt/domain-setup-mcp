"""Tool logic. Provider and resolver are injected so everything is testable offline."""
from __future__ import annotations

import re
import time

from . import spf, store
from .cloudflare import CloudflareError, DnsProvider
from .models import DomainPlan, Finding, Record, fingerprint, normalize_name
from .planner import build_plan, dmarc_record_warnings
from .providers import COMMON_DKIM_SELECTORS, DomainConfig

MAX_DOMAINS = 100


DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")


def _clean(domains: list[str]) -> list[str]:
    out = sorted({d.strip().lower().rstrip(".") for d in domains if d.strip()})
    if not out:
        raise ValueError("No domains given.")
    bad = [d for d in out if not DOMAIN_RE.match(d)]
    if bad:
        raise ValueError(f"Not valid domain names: {', '.join(bad[:5])}. Pass bare domains like 'getacme.com' "
                         "(no https://, paths or email addresses).")
    if len(out) > MAX_DOMAINS:
        raise ValueError(f"Max {MAX_DOMAINS} domains per call; split the list.")
    return out


# ---------- audit (read-only, public DNS) ----------

def audit(domains: list[str], resolver, dkim_selectors: list[str] | None = None) -> dict:
    results = []
    for d in _clean(domains):
        f: list[Finding] = []
        add = lambda sev, chk, msg: f.append(Finding(severity=sev, check=chk, message=msg))  # noqa: E731
        try:
            spfs = [t for t in resolver.txt(d) if spf.is_spf(t)]
            if not spfs:
                add("error", "spf", "No SPF record.")
            elif len(spfs) > 1:
                add("error", "spf", f"{len(spfs)} SPF records; SPF permerror. Merge into one.")
            else:
                c = spf.count_lookups(spfs[0], resolver)
                sev = "error" if c.total > spf.LOOKUP_LIMIT else "ok"
                add(sev, "spf", f"{spfs[0]}  ({c.total}/{spf.LOOKUP_LIMIT} lookups)")
                for w in c.warnings:
                    add("warning", "spf", w)
                at = (spf.all_term(spfs[0]) or "").lower()
                if at in ("all", "+all"):
                    add("error", "spf", "SPF ends in +all: anyone can send as this domain.")

            mx = resolver.mx(d)
            add("ok" if mx else "warning", "mx", ", ".join(f"{h} ({p})" for h, p in sorted(mx, key=lambda x: x[1]))
                or "No MX: replies to this domain bounce, which hurts cold email trust.")

            dm = [t for t in resolver.txt(f"_dmarc.{d}") if t.lower().startswith("v=dmarc1")]
            if not dm:
                add("error", "dmarc", "No DMARC record. Google/Yahoo bulk-sender rules require one.")
            elif len(dm) > 1:
                add("error", "dmarc", "Multiple DMARC records; all are ignored.")
            else:
                add("ok", "dmarc", dm[0])
                for w in dmarc_record_warnings(dm[0]):
                    add("warning", "dmarc", w)

            found = []
            for sel in dkim_selectors or COMMON_DKIM_SELECTORS:
                n = f"{sel}._domainkey.{d}"
                if any("p=" in t.lower() for t in resolver.txt(n)) or resolver.cname(n):
                    found.append(sel)
            add("ok" if found else "warning", "dkim",
                f"DKIM selectors found: {', '.join(found)}" if found
                else "No DKIM found on common selectors. Pass dkim_selectors if yours is custom.")
        except RuntimeError as e:
            add("error", "dns", str(e))
        status = "fail" if any(x.severity == "error" for x in f) else "warn" if any(x.severity == "warning" for x in f) else "pass"
        results.append({"domain": d, "status": status, "findings": [x.model_dump() for x in f]})
    return {"summary": _tally(results), "domains": results}


def _tally(results: list[dict]) -> dict:
    t = {"pass": 0, "warn": 0, "fail": 0}
    for r in results:
        t[r["status"]] += 1
    return t


# ---------- plan (read-only, Cloudflare + public DNS for SPF includes) ----------

def validate_plan_input(domains: list[str], cfg: DomainConfig) -> list[str]:
    """Checks that need no network. Run before anything touches Cloudflare."""
    doms = _clean(domains)
    if len(doms) > 1 and not cfg.dkim.is_empty():
        raise ValueError("config.dkim applies one key to every domain, but DKIM keys are unique per domain. "
                         "Put each domain's values under config.per_domain['<domain>'].dkim.")
    unknown = sorted(set(cfg.per_domain) - set(doms))
    if unknown:
        raise ValueError(f"per_domain has entries for domains not in this plan: {', '.join(unknown)}.")
    return doms


def plan(domains: list[str], cfg: DomainConfig, dns: DnsProvider, resolver) -> dict:
    doms = validate_plan_input(domains, cfg)
    plans: list[DomainPlan] = []
    zones: dict[str, str] = {}
    for d in doms:
        try:
            zid = dns.zone_id(d)
            zones[d] = zid
            rules, rules_error = None, None
            if cfg.forward_to:
                try:
                    rules = dns.get_redirect_rules(zid)
                except CloudflareError as e:
                    rules_error = str(e)  # planner reports it with Cloudflare's own wording
            plans.append(build_plan(d, dns.list_records(zid), cfg, resolver, rules, rules_error))
        except Exception as e:  # one bad domain must not sink the batch
            p = DomainPlan(domain=d, blocked=True)
            p.findings.append(Finding(severity="error", check="cloudflare", message=str(e)))
            plans.append(p)
    plan_id = store.new_id("plan")
    store.save("plans", plan_id, {"plan_id": plan_id, "config": cfg.model_dump(), "zones": zones,
                                  "plans": [p.model_dump() for p in plans]})
    ready = [p for p in plans if not p.blocked and _has_work(p)]
    return {
        "plan_id": plan_id,
        "summary": {
            "domains": len(plans),
            "ready": len(ready),
            "no_changes": sum(1 for p in plans if not p.blocked and not _has_work(p)),
            "blocked": sum(1 for p in plans if p.blocked),
            "total_changes": sum(len(p.changes) + _redirect_work(p) for p in ready),
        },
        "plans": [_render(p) for p in plans],
        "next_step": f"Review the diff, then call domain_apply(plan_id='{plan_id}', confirm=true).",
    }


def _redirect_work(p: DomainPlan) -> int:
    return 1 if p.redirect and p.redirect["action"] in ("create", "update") else 0


def _has_work(p: DomainPlan) -> bool:
    return bool(p.changes) or bool(_redirect_work(p))


def _render(p: DomainPlan) -> dict:
    def rec(r: Record | None):
        if not r:
            return None
        s = f"{r.type} {r.name} -> {r.content}"
        if r.priority is not None:
            s += f" (prio {r.priority})"
        if r.proxied:
            s += " (proxied)"
        return s

    out = {
        "domain": p.domain,
        "blocked": p.blocked,
        "spf_lookups": p.spf_lookups,
        "changes": [{"action": c.action, "before": rec(c.before), "after": rec(c.after), "reason": c.reason} for c in p.changes],
        "findings": [f"[{f.severity}] {f.check}: {f.message}" for f in p.findings if f.severity != "ok"],
    }
    if _redirect_work(p):
        out["changes"].append({"action": p.redirect["action"], "before": None,
                               "after": f"301 redirect {p.domain}, www.{p.domain} -> {p.redirect['target']}",
                               "reason": "Domain forwarding (Cloudflare redirect rule)"})
    return out


# ---------- apply (writes; dry-run unless confirm) ----------

def apply(plan_id: str, dns: DnsProvider, confirm: bool = False, only: list[str] | None = None) -> dict:
    saved = store.load("plans", plan_id)
    plans = [DomainPlan(**p) for p in saved["plans"]]
    if only:
        wanted = set(_clean(only))
        plans = [p for p in plans if p.domain in wanted]

    applied: dict = saved.setdefault("applied", {})
    run_id = store.new_id("run") if confirm else None
    log: list[dict] = []
    report = []
    for p in plans:
        entry = {"domain": p.domain, "status": ""}
        report.append(entry)
        if p.blocked:
            entry["status"] = "skipped: plan blocked by errors"
            continue
        if p.domain in applied:
            entry["status"] = f"skipped: already applied in {applied[p.domain]}"
            continue
        if not _has_work(p):
            entry["status"] = "nothing to do"
            continue
        dns_done = False
        try:
            zid = saved["zones"][p.domain]
            current = dns.list_records(zid)
            if fingerprint(current) != p.fingerprint:
                entry["status"] = "skipped: DNS changed since plan was made. Re-run domain_plan."
                continue
            if not confirm:
                entry["status"] = f"dry run: would apply {len(p.changes) + _redirect_work(p)} change(s)"
                continue
            if p.changes:
                deletes = [c.before for c in p.changes if c.action == "delete"]
                updates = [c for c in p.changes if c.action == "update"]
                creates = [c.after for c in p.changes if c.action == "create"]
                dns.batch(zid, [r.id for r in deletes], [c.after for c in updates], creates)  # atomic
                dns_done = True
                created = _find_created(dns.list_records(zid), current, creates)
                log.append({"type": "batch", "domain": p.domain, "zone_id": zid,
                            "snapshot": [r.model_dump() for r in current],
                            "deleted": [r.model_dump() for r in deletes],
                            "updated": [{"before": c.before.model_dump(), "after": c.after.model_dump()} for c in updates],
                            "created": [r.model_dump() for r in created]})
            if _redirect_work(p):
                before = dns.get_redirect_rules(zid)
                ref = p.redirect["rule"]["ref"]
                dns.put_redirect_rules(zid, [r for r in before if r.get("ref") != ref] + [p.redirect["rule"]])
                log.append({"type": "redirect", "domain": p.domain, "zone_id": zid, "rules_before": before})
            entry["status"] = "applied"
            applied[p.domain] = run_id
        except Exception as e:
            entry["status"] = (f"FAILED: {e}. " + ("DNS records were applied; the redirect was not. "
                               f"Undo with domain_rollback(run_id='{run_id}')." if dns_done
                               else "Nothing was changed for this domain (batch is all-or-nothing)."))
        finally:
            if confirm:
                store.save("runs", run_id, {"run_id": run_id, "plan_id": plan_id, "log": log})
                store.save("plans", plan_id, saved)

    out = {"dry_run": not confirm, "domains": report}
    if confirm:
        out["run_id"] = run_id
        out["next_step"] = f"Call domain_verify(plan_id='{plan_id}') in a few minutes. Undo with domain_rollback(run_id='{run_id}')."
    else:
        out["next_step"] = "Nothing written. Call again with confirm=true to apply."
    return out


def _find_created(after: list[Record], before: list[Record], wanted: list[Record]) -> list[Record]:
    """Match new records by content, so rollback knows their ids regardless of the batch response shape."""
    old_ids = {r.id for r in before}
    fresh = [r for r in after if r.id not in old_ids]
    out = []
    for w in wanted:
        hit = next((r for r in fresh if r.key() == w.key()), None)
        if hit is None:
            raise CloudflareError(f"Batch succeeded but {w.type} {w.name} was not found afterwards. Check the zone manually.")
        fresh.remove(hit)
        out.append(hit)
    return out


# ---------- rollback ----------

def rollback(run_id: str, dns: DnsProvider, confirm: bool = False) -> dict:
    run = store.load("runs", run_id)
    steps = run["log"][::-1]
    plan_lines = []
    for e in steps:
        if e["type"] == "redirect":
            plan_lines.append(f"{e['domain']}: restore previous redirect rules")
        elif e["type"] == "batch":
            plan_lines.append(f"{e['domain']}: delete {len(e['created'])}, restore {len(e['updated'])}, "
                              f"recreate {len(e['deleted'])} record(s) in one atomic batch")
    if not confirm:
        return {"dry_run": True, "would_do": plan_lines, "next_step": "Call again with confirm=true to roll back."}
    done, errors = [], []
    for e, line in zip(steps, plan_lines):
        try:
            if e["type"] == "redirect":
                dns.put_redirect_rules(e["zone_id"], e["rules_before"])
            else:
                dns.batch(e["zone_id"],
                          [r["id"] for r in e["created"]],
                          [Record(**u["before"]) for u in e["updated"]],
                          [Record(**{**r, "id": None}) for r in e["deleted"]])
            done.append(line)
        except Exception as ex:
            errors.append(f"{line}: {ex}")
    if not errors:  # allow the same plan to be applied again after a clean rollback
        try:
            plan = store.load("plans", run["plan_id"])
            for dom in {e["domain"] for e in run["log"]}:
                if plan.get("applied", {}).get(dom) == run_id:
                    del plan["applied"][dom]
            store.save("plans", run["plan_id"], plan)
        except FileNotFoundError:
            pass
    return {"dry_run": False, "rolled_back": done, "errors": errors}


# ---------- verify (read-only, public DNS) ----------

def verify(plan_id: str, resolver, wait_seconds: int = 0, probe=None) -> dict:
    """probe(url) -> (status, location) checks forwarding over HTTPS; without one, redirects are not checked."""
    saved = store.load("plans", plan_id)
    plans = [DomainPlan(**p) for p in saved["plans"] if not p["blocked"]]
    deadline = time.time() + min(max(wait_seconds, 0), 120)
    while True:
        results = [_verify_one(p, resolver, probe) for p in plans]
        pending = [r for r in results if r["status"] != "live"]
        if not pending or time.time() >= deadline:
            break
        time.sleep(10)
    return {
        "summary": {"live": len(results) - len(pending), "pending": len(pending)},
        "domains": results,
        "note": "Pending usually means propagation (minutes). If still pending after 1h, re-run domain_audit.",
    }


def _visible(r: Record, resolver) -> bool:
    if r.type == "TXT":
        return r.content in resolver.txt(r.name)
    if r.type == "CNAME":
        return r.content.lower().rstrip(".") in resolver.cname(r.name)
    if r.type == "MX":
        return r.content.lower().rstrip(".") in [h for h, _ in resolver.mx(r.name)]
    if r.type == "A":  # proxied records answer with Cloudflare IPs, so only their presence can be checked
        ips = resolver.a(r.name)
        return bool(ips) if r.proxied else r.content in ips
    return True


def _check_redirect(host: str, target: str, probe) -> dict:
    url = f"https://{host}/"
    try:
        status, location = probe(url)
    except RuntimeError as e:
        return {"record": f"301 {host}", "expected": target, "ok": False, "got": str(e)}
    ok = status == 301 and (location or "").rstrip("/") == target.rstrip("/")
    return {"record": f"301 {host}", "expected": target, "ok": ok, "got": f"HTTP {status} -> {location}"}


def _verify_one(p: DomainPlan, resolver, probe=None) -> dict:
    checks = []
    for c in p.changes:
        if c.action == "delete":
            gone = not _visible(c.before, resolver)
            checks.append({"record": f"{c.before.type} {c.before.name}", "expected": "removed", "ok": gone})
        else:
            checks.append({"record": f"{c.after.type} {c.after.name}", "expected": c.after.content,
                           "ok": _visible(c.after, resolver)})
    if p.redirect and probe:
        checks += [_check_redirect(h, p.redirect["target"], probe) for h in (p.domain, f"www.{p.domain}")]
    status = "live" if all(x["ok"] for x in checks) else "pending"
    return {"domain": p.domain, "status": status, "checks": checks}


def normalize(domain: str, name: str) -> str:
    return normalize_name(name, domain)
