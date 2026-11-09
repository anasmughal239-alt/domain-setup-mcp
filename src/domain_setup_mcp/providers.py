"""Per-provider record templates and plan configuration.

Sources (checked Nov 2026):
- Google MX/SPF/DKIM: knowledge.workspace.google.com (Set up DKIM, MX records)
- Microsoft DKIM CNAMEs: learn.microsoft.com/defender-office-365/email-authentication-dkim-configure
  (targets are tenant-specific and cannot be predicted; new format *.dkim.mail.microsoft since May 2025)
- Microsoft MX: MC1048624, new domains get *.mx.microsoft from July 2026; value must come from the
  admin center or Graph serviceConfigurationRecords, so it is never guessed here
- SES MAIL FROM: docs.aws.amazon.com/ses/latest/dg/mail-from.html (exactly one MX on the subdomain)
- Tracking: Smartlead help (emailtracking -> open.sleadtrack.com), Instantly help (inst -> prox.itrackly.com)
- Forwarding: developers.cloudflare.com/fundamentals/manage-domains/redirect-domain (proxied 192.0.2.1)
"""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

Provider = Literal["google", "microsoft", "ses"]
TrackingTool = Literal["smartlead", "instantly"]
DmarcPolicy = Literal["none", "quarantine", "reject"]

SPF_INCLUDE: dict[str, str] = {
    "google": "_spf.google.com",
    "microsoft": "spf.protection.outlook.com",
    "ses": "amazonses.com",
}

TRACKING_TARGET: dict[str, str] = {"smartlead": "open.sleadtrack.com", "instantly": "prox.itrackly.com"}
TRACKING_DEFAULT_HOST: dict[str, str] = {"smartlead": "emailtracking", "instantly": "inst"}

GOOGLE_MX = [("smtp.google.com", 1)]  # single-host MX, Google's default since April 2023
GOOGLE_LEGACY_MX = {
    ("aspmx.l.google.com", 1), ("alt1.aspmx.l.google.com", 5), ("alt2.aspmx.l.google.com", 5),
    ("alt3.aspmx.l.google.com", 10), ("alt4.aspmx.l.google.com", 10),
}
MICROSOFT_AUTODISCOVER = "autodiscover.outlook.com"
REDIRECT_PLACEHOLDER_IP = "192.0.2.1"  # Cloudflare-documented placeholder for redirect-only hostnames

COMMON_DKIM_SELECTORS = ["google", "selector1", "selector2", "s1", "s2", "default", "k1", "dkim"]

_LABEL = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"


def _clean_txt_paste(v: str) -> str:
    """People paste TXT values with quotes, split strings and line breaks. Rebuild one clean value."""
    parts = re.findall(r'"([^"]*)"', v)
    v = "".join(parts) if parts else v
    return re.sub(r"\s+", " ", v).strip()


class DkimInput(BaseModel):
    """DKIM values only the mailbox provider can generate. Unique per domain."""

    google_txt: str | None = Field(
        None, description="Google: 'v=DKIM1; k=rsa; p=...' from Admin console > Apps > Gmail > Authenticate email. "
        "Available 24-72h after Gmail is activated. Clicking Generate again replaces the key.")
    google_selector: str = Field("google", description="Google DKIM selector (default 'google').")
    microsoft_selector1_target: str | None = Field(
        None, description="Microsoft: exact Selector1CNAME from Defender portal or Get-DkimSigningConfig. Never hand-built.")
    microsoft_selector2_target: str | None = Field(None, description="Microsoft: exact Selector2CNAME.")
    ses_tokens: list[str] = Field(default_factory=list, description="AWS SES: the 3 Easy DKIM tokens for this identity.")

    @field_validator("google_txt")
    @classmethod
    def _clean_dkim(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = _clean_txt_paste(v)
        head, sep, key = v.rpartition("p=")
        if sep:  # base64 key must have no whitespace
            v = head + sep + re.sub(r"\s+", "", key)
        if not v.lower().startswith("v=dkim1") or "p=" not in v.lower():
            raise ValueError("dkim.google_txt must look like 'v=DKIM1; k=rsa; p=MIIB...'. Copy the full value from Admin console.")
        return v

    @field_validator("google_selector")
    @classmethod
    def _check_selector(cls, v: str) -> str:
        if not re.fullmatch(_LABEL, v.strip().lower()):
            raise ValueError("google_selector must be a single DNS label.")
        return v.strip().lower()

    @field_validator("microsoft_selector1_target", "microsoft_selector2_target")
    @classmethod
    def _check_ms(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip().lower().rstrip(".")
        if "._domainkey." not in v or not v.endswith((".onmicrosoft.com", ".dkim.mail.microsoft")):
            raise ValueError(f"'{v}' is not a Microsoft DKIM target (expect ..._domainkey....onmicrosoft.com "
                             "or ..._domainkey....dkim.mail.microsoft). Copy it from the Defender portal.")
        return v

    @field_validator("ses_tokens")
    @classmethod
    def _check_tokens(cls, v: list[str]) -> list[str]:
        out = [t.strip().lower() for t in v]
        for t in out:
            if not re.fullmatch(r"[a-z0-9]{20,64}", t):
                raise ValueError(f"'{t}' is not an SES DKIM token (expect ~32 lowercase letters/digits).")
        return out

    def is_empty(self) -> bool:
        return not (self.google_txt or self.microsoft_selector1_target or self.microsoft_selector2_target or self.ses_tokens)


MxList = list[tuple[str, int]]


def _check_mx(v: MxList | None) -> MxList | None:
    if v is None:
        return v
    out = []
    for host, prio in v:
        host = host.strip().lower().rstrip(".")
        if not re.fullmatch(rf"({_LABEL}\.)+{_LABEL}", host) or not 0 <= prio <= 65535:
            raise ValueError(f"Invalid MX ({host}, {prio}).")
        out.append((host, prio))
    return out


class DomainSecrets(BaseModel):
    """Values that differ for every domain. Copy them from the provider's admin console."""

    dkim: DkimInput = Field(default_factory=DkimInput)
    verification_txt: str | None = Field(
        None, description="Ownership TXT for the root, e.g. 'google-site-verification=...' or 'MS=ms12345678'.")
    mx: MxList | None = Field(None, description="Exact MX (host, priority) list. Required for Microsoft 365.")

    @field_validator("verification_txt")
    @classmethod
    def _check_verification(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = _clean_txt_paste(v)
        if not re.fullmatch(r"(google-site-verification=[A-Za-z0-9_-]{20,}|MS=ms\d{6,})", v):
            raise ValueError("verification_txt must be 'google-site-verification=...' or 'MS=ms12345678'.")
        return v

    _mx = field_validator("mx")(classmethod(lambda cls, v: _check_mx(v)))


class DomainConfig(BaseModel):
    provider: Provider
    dmarc_rua: str | None = Field(None, description="Mailbox for DMARC aggregate reports, e.g. dmarc@youragency.com.")
    dmarc_policy: DmarcPolicy = Field("none", description="Policy for NEW DMARC records. Start at none; existing records are never changed.")
    dmarc_np: DmarcPolicy | None = Field(
        None, description="RFC 9989 policy for non-existent subdomains. 'reject' blocks spoofing of made-up subdomains.")
    per_domain: dict[str, DomainSecrets] = Field(
        default_factory=dict, description="Per-domain DKIM keys, verification TXT and MX, keyed by domain.")
    dkim: DkimInput = Field(default_factory=DkimInput, description="Shortcut for a single-domain plan only.")
    mx_override: MxList | None = Field(None, description="MX applied to every domain (rarely right; prefer per_domain.mx).")
    tracking_tool: TrackingTool | None = None
    tracking_subdomain: str | None = Field(
        None, description="CNAME host. Default: 'inst' for Instantly (required by Instantly), 'emailtracking' for Smartlead.")
    replace_mx: bool = Field(False, description="Replace existing MX records that point elsewhere. Off by default.")
    microsoft_autodiscover: bool = Field(True, description="Microsoft only: add autodiscover CNAME for Outlook clients.")
    ses_mail_from: str | None = Field(None, description="SES only: custom MAIL FROM subdomain, e.g. 'mail'.")
    ses_region: str = "us-east-1"
    forward_to: str | None = Field(
        None, description="Redirect the domain's website (root and www) to this URL with a 301, e.g. https://acme.com.")

    @field_validator("dmarc_rua")
    @classmethod
    def _check_rua(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip().removeprefix("mailto:")
        if not re.fullmatch(r"[^@\s;,!]+@[a-z0-9.-]+\.[a-z]{2,}", v, re.I):
            raise ValueError(f"dmarc_rua '{v}' is not a valid email address.")
        return v.lower()

    @field_validator("tracking_subdomain", "ses_mail_from")
    @classmethod
    def _check_label(cls, v: str | None) -> str | None:
        if v is not None and not re.fullmatch(_LABEL, v.strip().lower()):
            raise ValueError(f"'{v}' must be a single DNS label, e.g. 'inst' or 'mail'.")
        return v.strip().lower() if v else v

    @field_validator("ses_region")
    @classmethod
    def _check_region(cls, v: str) -> str:
        if not re.fullmatch(r"[a-z]{2}(-[a-z]+)+-\d", v):
            raise ValueError(f"'{v}' is not an AWS region like us-east-1.")
        return v

    @field_validator("forward_to")
    @classmethod
    def _check_url(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        if not re.fullmatch(r"https?://[a-z0-9.-]+\.[a-z]{2,}(/[^\s\"]*)?", v, re.I):
            raise ValueError("forward_to must be a full URL like https://acme.com")
        return v

    _mx = field_validator("mx_override")(classmethod(lambda cls, v: _check_mx(v)))

    @field_validator("per_domain")
    @classmethod
    def _lower_keys(cls, v: dict) -> dict:
        return {k.strip().lower().rstrip("."): s for k, s in v.items()}

    @model_validator(mode="after")
    def _check_provider_fit(self):
        if self.ses_mail_from and self.provider != "ses":
            raise ValueError("ses_mail_from only applies to provider 'ses'.")
        return self

    def tracking_host(self) -> str | None:
        if not self.tracking_tool:
            return None
        return self.tracking_subdomain or TRACKING_DEFAULT_HOST[self.tracking_tool]

    def secrets_for(self, domain: str) -> DomainSecrets:
        """Per-domain values win. The shared `dkim` shortcut is only used when no per-domain entry exists."""
        s = self.per_domain.get(domain)
        if s is not None:
            return s if s.mx is not None or self.mx_override is None else s.model_copy(update={"mx": self.mx_override})
        return DomainSecrets(dkim=self.dkim, mx=self.mx_override)
