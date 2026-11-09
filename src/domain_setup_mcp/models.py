"""Shared data models."""
from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, Field

RecordType = Literal["A", "AAAA", "CNAME", "MX", "TXT", "NS"]


def normalize_name(name: str, domain: str) -> str:
    """Turn '@', 'track' or 'track.example.com.' into a full lowercase name."""
    name = name.strip().lower().rstrip(".")
    domain = domain.strip().lower().rstrip(".")
    if name in ("", "@"):
        return domain
    if name == domain or name.endswith("." + domain):
        return name
    return f"{name}.{domain}"


def normalize_txt(content: str) -> str:
    """Cloudflare returns TXT as '"part1" "part2"'. Join into one plain string."""
    c = content.strip()
    if c.startswith('"') and c.endswith('"'):
        parts = [p for p in c[1:-1].split('" "')]
        return "".join(parts)
    return c


class Record(BaseModel):
    type: RecordType
    name: str
    content: str
    priority: int | None = None
    ttl: int = 1  # 1 = Cloudflare "auto"
    proxied: bool = False
    id: str | None = None  # Cloudflare record id, when known

    def key(self) -> tuple:
        content = self.content.lower().rstrip(".") if self.type in ("CNAME", "MX") else self.content
        return (self.type, self.name.lower(), content, self.priority)


class Change(BaseModel):
    action: Literal["create", "update", "delete"]
    before: Record | None = None
    after: Record | None = None
    reason: str


class Finding(BaseModel):
    severity: Literal["error", "warning", "info", "ok"]
    check: str
    message: str


class DomainPlan(BaseModel):
    domain: str
    changes: list[Change] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    spf_lookups: int | None = None
    blocked: bool = False  # True when an error makes the plan unsafe to apply
    fingerprint: str = ""  # hash of DNS state the plan was built from
    redirect: dict | None = None  # {"action": create|update|none, "target": url, "rule": {...}}


def fingerprint(records: list[Record]) -> str:
    keys = sorted(json.dumps(r.key()) for r in records)
    return hashlib.sha256("\n".join(keys).encode()).hexdigest()[:16]
