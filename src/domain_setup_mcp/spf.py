"""SPF parsing, merging and DNS lookup counting (RFC 7208)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

LOOKUP_LIMIT = 10
VOID_LOOKUP_LIMIT = 2
LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists"}


class TxtResolver(Protocol):
    def txt(self, name: str) -> list[str]: ...


def is_spf(txt: str) -> bool:
    t = txt.strip().lower()
    return t == "v=spf1" or t.startswith("v=spf1 ")


def _mech(term: str) -> tuple[str, str]:
    """Return (mechanism, value) with qualifier stripped. 'include:x' -> ('include','x')."""
    t = term.lower()
    if t and t[0] in "+-~?":
        t = t[1:]
    if t.startswith("redirect="):
        return "redirect", t.split("=", 1)[1]
    for sep in (":", "/"):
        if sep in t:
            name, val = t.split(sep, 1)
            return name, val if sep == ":" else ""
    return t, ""


def terms(record: str) -> list[str]:
    return record.split()[1:]


def all_term(record: str) -> str | None:
    for t in terms(record):
        if _mech(t)[0] == "all":
            return t
    return None


@dataclass
class MergeResult:
    record: str
    added: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def merge(existing: list[str], required_includes: list[str]) -> MergeResult:
    """Merge one or more existing SPF records plus required includes into ONE record.

    Never removes an existing mechanism. Keeps the existing 'all' qualifier.
    """
    warnings: list[str] = []
    body: list[str] = []
    seen: set[str] = set()
    all_terms: list[str] = []
    redirect: str | None = None

    if len(existing) > 1:
        warnings.append(
            f"Found {len(existing)} SPF records. Multiple SPF records make SPF fail (permerror); merging into one."
        )

    for rec in existing:
        for t in terms(rec):
            mech, _ = _mech(t)
            if mech == "all":
                all_terms.append(t)
                continue
            if mech == "redirect":
                redirect = redirect or t
                continue
            k = t.lower().lstrip("+")
            if k not in seen:
                seen.add(k)
                body.append(t)

    added = []
    for inc in required_includes:
        k = f"include:{inc}".lower()
        if k not in seen:
            seen.add(k)
            body.append(f"include:{inc}")
            added.append(inc)

    if all_terms:
        chosen = all_terms[0]
        if len({a.lower() for a in all_terms}) > 1:
            warnings.append(f"Existing SPF records disagree on 'all' ({', '.join(all_terms)}); kept '{chosen}'.")
        if chosen.lower() in ("all", "+all"):
            warnings.append("SPF ends in '+all', which authorizes every server on the internet. Change it to '~all'.")
        tail = [chosen]
    elif redirect:
        tail = [redirect]
    else:
        tail = ["~all"]
        if existing:
            warnings.append("Existing SPF had no 'all' term; added '~all'.")

    record = " ".join(["v=spf1", *body, *tail])
    if len(record) > 450:
        warnings.append(f"SPF record is {len(record)} characters. Long records are often truncated by DNS panels.")
    return MergeResult(record=record, added=added, warnings=warnings)


@dataclass
class LookupCount:
    total: int = 0
    void: int = 0
    warnings: list[str] = field(default_factory=list)


def count_lookups(record: str, resolver: TxtResolver, _seen: set[str] | None = None, _depth: int = 0) -> LookupCount:
    """Count DNS-querying terms recursively, as receivers do. Limit is 10."""
    result = LookupCount()
    seen = _seen if _seen is not None else set()
    if _depth > 10:
        result.warnings.append("SPF include chain is too deep (loop?).")
        return result

    for t in terms(record):
        mech, val = _mech(t)
        if mech not in LOOKUP_MECHANISMS and mech != "redirect":
            continue
        result.total += 1
        if mech == "ptr":
            result.warnings.append("SPF uses 'ptr', which RFC 7208 deprecates and some receivers ignore. Remove it.")
        if mech not in ("include", "redirect"):
            continue
        if "%" in val:
            result.warnings.append(f"'{mech}:{val}' uses SPF macros; nested lookups not counted.")
            continue
        if val in seen:
            result.warnings.append(f"SPF include loop at {val}.")
            continue
        seen.add(val)
        child = [r for r in resolver.txt(val) if is_spf(r)]
        if not child:
            result.void += 1
            result.warnings.append(f"'{mech}:{val}' has no SPF record (void lookup, include fails).")
            continue
        sub = count_lookups(child[0], resolver, seen, _depth + 1)
        result.total += sub.total
        result.void += sub.void
        result.warnings.extend(sub.warnings)
    return result
