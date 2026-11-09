"""Minimal Cloudflare API client (v4): DNS records, atomic batch, redirect rules.

Docs used:
- Batch: POST /zones/{id}/dns_records/batch. One DB transaction; on failure nothing is applied.
  Execution order is always deletes, patches, puts, posts.
- Rate limit: 1200 requests / 5 min per token. Exceeding it blocks ALL calls for 5 minutes (HTTP 429).
- Redirect rules: zone entry point ruleset of phase http_request_dynamic_redirect.
  GET/PUT /zones/{id}/rulesets/phases/http_request_dynamic_redirect/entrypoint. Token needs
  Zone > Single Redirect > Edit. Hostnames must be proxied.
"""
from __future__ import annotations

import time
from typing import Protocol

import httpx

from .models import Record, normalize_txt

API = "https://api.cloudflare.com/client/v4"
EMAIL_TYPES = {"TXT", "MX", "CNAME", "A", "AAAA"}
REDIRECT_PHASE = "http_request_dynamic_redirect"
RULE_FIELDS = ("id", "ref", "description", "expression", "action", "action_parameters", "enabled")
MAX_RETRY_WAIT = 10  # seconds; longer waits mean the 5-minute block, which a tool call should not sit through


class DnsProvider(Protocol):
    def zone_id(self, domain: str) -> str: ...
    def list_records(self, zone_id: str) -> list[Record]: ...
    def batch(self, zone_id: str, deletes: list[str], puts: list[Record], posts: list[Record]) -> None: ...
    def get_redirect_rules(self, zone_id: str) -> list[dict]: ...
    def put_redirect_rules(self, zone_id: str, rules: list[dict]) -> None: ...


class CloudflareError(RuntimeError):
    pass


class RateLimited(CloudflareError):
    pass


def quote_txt(value: str) -> str:
    """Encode a TXT value as RFC 1035 character-strings of at most 255 bytes each.

    Email auth values are plain ASCII with no quotes or backslashes, so anything else is rejected.
    """
    if '"' in value or "\\" in value or not value.isascii():
        raise CloudflareError("TXT value contains quotes, backslashes or non-ASCII; refusing to write it.")
    chunks = [value[i:i + 255] for i in range(0, len(value), 255)] or [""]
    return " ".join(f'"{c}"' for c in chunks)


def record_body(r: Record) -> dict:
    content = quote_txt(r.content) if r.type == "TXT" else r.content
    body = {"type": r.type, "name": r.name, "content": content, "ttl": r.ttl}
    if r.type in ("A", "AAAA", "CNAME"):
        body["proxied"] = r.proxied  # email records stay DNS-only; only redirect placeholders are proxied
    if r.type == "MX":
        body["priority"] = r.priority if r.priority is not None else 10
    return body


def clean_rule(rule: dict) -> dict:
    """Keep only writable fields when sending rules back (drops version, last_updated, etc.)."""
    return {k: rule[k] for k in RULE_FIELDS if k in rule}


class Cloudflare:
    def __init__(self, token: str, timeout: float = 30.0, transport: httpx.BaseTransport | None = None,
                 retries: int = 3, sleep=time.sleep):
        if not token:
            raise CloudflareError("CLOUDFLARE_API_TOKEN is not set. Create a token with Zone:Read + DNS:Edit "
                                  "(+ Single Redirect:Edit if you use forward_to).")
        self._c = httpx.Client(base_url=API, timeout=timeout, transport=transport,
                               headers={"Authorization": f"Bearer {token}"})
        self._retries, self._sleep = retries, sleep

    def _call(self, method: str, path: str, ok_404: bool = False, **kw) -> dict | None:
        for attempt in range(self._retries + 1):
            try:
                resp = self._c.request(method, path, **kw)
            except httpx.TransportError as e:
                if attempt == self._retries:
                    raise CloudflareError(f"Network error calling Cloudflare ({type(e).__name__}). Check connectivity and retry.") from e
                self._sleep(2 ** attempt)
                continue
            if resp.status_code == 429:
                wait = float(resp.headers.get("retry-after", 300))
                if wait > MAX_RETRY_WAIT or attempt == self._retries:
                    raise RateLimited(f"Cloudflare rate limit hit (1200 requests / 5 min per token). "
                                      f"All calls are blocked for about {int(wait)}s. Wait, then re-run.")
                self._sleep(wait)
                continue
            if resp.status_code >= 500 and attempt < self._retries:
                self._sleep(2 ** attempt)
                continue
            break
        if ok_404 and resp.status_code == 404:
            return None
        try:
            data = resp.json()
        except ValueError as e:
            raise CloudflareError(f"Cloudflare returned HTTP {resp.status_code} with no JSON.") from e
        if not data.get("success"):
            errs = "; ".join(f"{e.get('code')}: {e.get('message')}" for e in data.get("errors", []))
            hint = {401: " Token invalid or expired.", 403: " Token lacks the needed permission on this zone."}.get(resp.status_code, "")
            raise CloudflareError(f"Cloudflare {method} {path} failed: {errs or resp.status_code}.{hint}")
        return data

    # ---- zones and records ----

    def zone_id(self, domain: str) -> str:
        res = self._call("GET", "/zones", params={"name": domain})["result"]
        if not res:
            raise CloudflareError(f"Zone {domain} not found in this Cloudflare account (or token lacks Zone:Read).")
        return res[0]["id"]

    def list_records(self, zone_id: str) -> list[Record]:
        out, page = [], 1
        while True:
            data = self._call("GET", f"/zones/{zone_id}/dns_records", params={"page": page, "per_page": 500})
            for r in data["result"]:
                if r["type"] not in EMAIL_TYPES:
                    continue
                content = normalize_txt(r["content"]) if r["type"] == "TXT" else r["content"]
                out.append(Record(type=r["type"], name=r["name"].lower(), content=content, priority=r.get("priority"),
                                  ttl=r.get("ttl", 1), proxied=bool(r.get("proxied", False)), id=r["id"]))
            info = data.get("result_info") or {}
            if page >= info.get("total_pages", 1):
                return out
            page += 1

    def batch(self, zone_id: str, deletes: list[str], puts: list[Record], posts: list[Record]) -> None:
        """Atomic: all changes apply or none do."""
        for r in puts:
            if not r.id:
                raise CloudflareError("Batch put needs a record id.")
        body = {
            "deletes": [{"id": i} for i in deletes],
            "puts": [{"id": r.id, **record_body(r)} for r in puts],
            "posts": [record_body(r) for r in posts],
        }
        self._call("POST", f"/zones/{zone_id}/dns_records/batch", json={k: v for k, v in body.items() if v})

    # ---- redirect rules ----

    def get_redirect_rules(self, zone_id: str) -> list[dict]:
        data = self._call("GET", f"/zones/{zone_id}/rulesets/phases/{REDIRECT_PHASE}/entrypoint", ok_404=True)
        if data is None:
            return []
        return [clean_rule(r) for r in (data.get("result") or {}).get("rules", [])]

    def put_redirect_rules(self, zone_id: str, rules: list[dict]) -> None:
        self._call("PUT", f"/zones/{zone_id}/rulesets/phases/{REDIRECT_PHASE}/entrypoint",
                   json={"rules": [clean_rule(r) for r in rules]})
