"""MCP server: bulk email-auth setup for cold email domains on Cloudflare."""
from __future__ import annotations

import os
from typing import Annotated

import functools

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from . import ops
from .cloudflare import Cloudflare, CloudflareError
from .providers import DomainConfig
from .resolver import PublicResolver, probe_redirect

mcp = MCPServer(
    "domain_setup_mcp",
    instructions=(
        "Sets up SPF, DKIM, DMARC, MX, verification TXT, tracking CNAMEs and website forwarding for cold email "
        "domains on Cloudflare. Workflow: domain_audit -> domain_plan -> show the user the diff -> "
        "domain_apply(confirm=true) only after the user approves -> domain_verify. Never call domain_apply or "
        "domain_rollback with confirm=true without explicit user approval of that exact plan. DKIM keys, "
        "verification codes and Microsoft MX values are unique per domain: ask the user for them and pass them "
        "under config.per_domain; never invent or reuse them across domains."
    ),
)

Domains = Annotated[list[str], Field(description="Domains, e.g. ['getacme.com','tryacme.com']. Max 100.", min_length=1)]


def _actionable(fn):
    """Surface expected failures (bad token, unknown plan id, bad input) to the agent verbatim."""
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        try:
            return fn(*a, **kw)
        except (CloudflareError, FileNotFoundError, ValueError, RuntimeError) as e:
            raise ToolError(str(e)) from e
    return wrapper


def _cf() -> Cloudflare:
    return Cloudflare(os.environ.get("CLOUDFLARE_API_TOKEN", ""))


@mcp.tool(annotations=ToolAnnotations(title="Audit email auth", readOnlyHint=True, openWorldHint=True))
@_actionable
def domain_audit(
    domains: Domains,
    dkim_selectors: Annotated[list[str] | None, Field(description="Custom DKIM selectors to check.")] = None,
) -> dict:
    """Check SPF, DKIM, DMARC and MX on public DNS for each domain. Read-only; needs no Cloudflare token."""
    return ops.audit(domains, PublicResolver(), dkim_selectors)


@mcp.tool(annotations=ToolAnnotations(title="Plan DNS changes", readOnlyHint=True, openWorldHint=True))
@_actionable
def domain_plan(domains: Domains, config: DomainConfig) -> dict:
    """Build a reviewable diff of DNS changes per domain. Writes nothing to DNS.

    Merges into existing SPF (never adds a second record), blocks plans over the 10-lookup limit,
    never overwrites live MX unless replace_mx=true, never changes an existing DMARC policy, and never
    guesses Microsoft MX or DKIM values. Per-domain values go in config.per_domain. Returns a plan_id.
    """
    ops.validate_plan_input(domains, config)
    return ops.plan(domains, config, _cf(), PublicResolver())


@mcp.tool(annotations=ToolAnnotations(title="Apply DNS plan", readOnlyHint=False, destructiveHint=True,
                                      idempotentHint=False, openWorldHint=True))
@_actionable
def domain_apply(
    plan_id: str,
    confirm: Annotated[bool, Field(description="False = dry run. True writes to Cloudflare. Requires user approval.")] = False,
    only: Annotated[list[str] | None, Field(description="Apply to a subset of the plan's domains.")] = None,
) -> dict:
    """Apply a saved plan to Cloudflare. Each domain's DNS changes go in one atomic batch (all or nothing).
    Skips any domain whose DNS changed since the plan was made. Returns run_id for domain_rollback."""
    return ops.apply(plan_id, _cf(), confirm, only)


@mcp.tool(annotations=ToolAnnotations(title="Verify propagation", readOnlyHint=True, openWorldHint=True))
@_actionable
def domain_verify(
    plan_id: str,
    wait_seconds: Annotated[int, Field(ge=0, le=120, description="Poll up to this long for records to appear.")] = 0,
) -> dict:
    """Check that every planned change is visible on public DNS and that forwarding answers with its 301."""
    return ops.verify(plan_id, PublicResolver(), wait_seconds, probe_redirect)


@mcp.tool(annotations=ToolAnnotations(title="Roll back an apply run", readOnlyHint=False, destructiveHint=True,
                                      openWorldHint=True))
@_actionable
def domain_rollback(
    run_id: str,
    confirm: Annotated[bool, Field(description="False = show what would be undone.")] = False,
) -> dict:
    """Undo every change made by one domain_apply run, in reverse order."""
    return ops.rollback(run_id, _cf(), confirm)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
