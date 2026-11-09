"""Public DNS lookups (what receiving mail servers see)."""
from __future__ import annotations

import dns.exception
import dns.resolver
import httpx


class PublicResolver:
    def __init__(self, nameservers: list[str] | None = None, timeout: float = 5.0):
        self._r = dns.resolver.Resolver(configure=False)
        self._r.nameservers = nameservers or ["1.1.1.1", "8.8.8.8"]
        self._r.lifetime = timeout

    def _query(self, name: str, rtype: str):
        try:
            return list(self._r.resolve(name, rtype))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except dns.exception.Timeout as e:
            raise RuntimeError(f"DNS timeout resolving {rtype} {name}. Check network or try again.") from e

    def txt(self, name: str) -> list[str]:
        return [b"".join(r.strings).decode(errors="replace") for r in self._query(name, "TXT")]

    def mx(self, name: str) -> list[tuple[str, int]]:
        return [(str(r.exchange).rstrip(".").lower(), r.preference) for r in self._query(name, "MX")]

    def cname(self, name: str) -> list[str]:
        return [str(r.target).rstrip(".").lower() for r in self._query(name, "CNAME")]

    def a(self, name: str) -> list[str]:
        return [r.address for r in self._query(name, "A")]


def probe_redirect(url: str, timeout: float = 10.0) -> tuple[int, str | None]:
    """First response for a URL (status, Location), without following it: what a visitor's browser receives."""
    try:
        resp = httpx.get(url, follow_redirects=False, timeout=timeout)
    except httpx.HTTPError as e:
        raise RuntimeError(f"{type(e).__name__} requesting {url}") from e
    return resp.status_code, resp.headers.get("location")


class FakeResolver:
    """Dict-backed resolver for tests and offline planning."""

    def __init__(self, txt: dict | None = None, mx: dict | None = None, cname: dict | None = None,
                 a: dict | None = None):
        self._txt, self._mx, self._cname, self._a = txt or {}, mx or {}, cname or {}, a or {}

    def txt(self, name: str) -> list[str]:
        return list(self._txt.get(name.lower(), []))

    def mx(self, name: str) -> list[tuple[str, int]]:
        return list(self._mx.get(name.lower(), []))

    def cname(self, name: str) -> list[str]:
        return list(self._cname.get(name.lower(), []))

    def a(self, name: str) -> list[str]:
        return list(self._a.get(name.lower(), []))
