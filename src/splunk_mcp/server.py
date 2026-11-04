"""FastMCP server: tools, resources and prompts. Every tool is read-only."""

from __future__ import annotations

import json
from collections.abc import Callable
from functools import lru_cache
from typing import Any

from mcp.server.fastmcp import FastMCP

from .audit import audited
from .client import SplunkClient, SplunkError
from .config import ConfigError, Settings
from .guard import UnsafeSPL, check_spl, ensure_head

mcp = FastMCP(
    "splunk",
    instructions=(
        "Read-only access to Splunk. Use explain_spl to validate a search, then search to run "
        "it. Always bound searches with an index and a time range. Searches that write, delete "
        "or execute anything are refused. Results are capped; prefer stats/table over raw events."
    ),
)


@lru_cache(maxsize=1)
def _default_settings() -> Settings:
    return Settings.from_env()


@lru_cache(maxsize=1)
def _default_client() -> SplunkClient:
    return SplunkClient(_default_settings())


# Module-level factories so tests can inject a client built on httpx.MockTransport.
settings_factory: Callable[[], Settings] = _default_settings
client_factory: Callable[[], SplunkClient] = _default_client


def _error(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, (SplunkError, UnsafeSPL, ConfigError)):
        return {"error": str(exc)}
    return {"error": f"Unexpected error ({type(exc).__name__})."}


def _audit_path() -> str | None:
    try:
        return settings_factory().audit_log
    except Exception:  # noqa: BLE001 - a missing configuration is reported by the tool itself
        return None


audit = audited(_audit_path)


@mcp.tool()
@audit
def search(
    spl: str, earliest: str = "-24h", latest: str = "now", max_rows: int = 100
) -> dict[str, Any]:
    """Run a read-only SPL search and return the result rows.

    The search is validated first: commands that write, delete, export or execute (delete,
    outputlookup, collect, sendemail, script, map, ...) are refused. A leading `search` is
    added when missing and `| head N` is appended so results are always bounded.

    Args:
        spl: The SPL query, e.g. `index=wineventlog EventCode=4625 | stats count by src_ip`.
        earliest: Start of the time range, Splunk syntax (default `-24h`).
        latest: End of the time range (default `now`).
        max_rows: Maximum rows to return (default 100, capped by the server, hard limit 1000).

    Returns a dict with `results` (list of rows), `count`, `spl` (the SPL actually run),
    and `truncated` when the row limit was reached. On failure returns `{"error": ...}`.
    """
    try:
        settings = settings_factory()
        limit = max(1, min(int(max_rows), settings.max_rows))
        safe = check_spl(spl, allowed_indexes=settings.allowed_indexes)
        final = ensure_head(safe, limit)
        out = client_factory().oneshot_search(final, earliest or settings.default_earliest, latest, limit)
        out["truncated"] = out["count"] >= limit
        if out["truncated"]:
            out["note"] = (
                f"Output reached the {limit}-row limit; narrow the search or aggregate with stats."
            )
        return out
    except Exception as exc:  # noqa: BLE001 - tools must never raise
        return _error(exc)


@mcp.tool()
def explain_spl(spl: str) -> dict[str, Any]:
    """Check an SPL query against the safety rules without running it.

    Use this to validate a search before `search`. Nothing is sent to Splunk.

    Args:
        spl: The SPL query to validate.

    Returns `{"ok": bool, "normalised": str | None, "reason": str | None}`.
    """
    try:
        normalised = check_spl(spl, allowed_indexes=settings_factory().allowed_indexes)
        return {"ok": True, "normalised": normalised, "reason": None}
    except UnsafeSPL as exc:
        return {"ok": False, "normalised": None, "reason": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "normalised": None, "reason": _error(exc)["error"]}


@mcp.tool()
@audit
def list_indexes() -> dict[str, Any]:
    """List the Splunk indexes with event count, size in MB and retention in days.

    Use it to discover which indexes exist before writing a search. Takes no parameters.
    Returns `{"indexes": [...], "count": n}`.
    """
    try:
        items = client_factory().list_indexes()
        return {"indexes": items, "count": len(items)}
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


@mcp.tool()
@audit
def list_saved_searches(filter: str = "", limit: int = 50) -> dict[str, Any]:
    """List saved searches and alerts (name, SPL, cron schedule, app, owner).

    Args:
        filter: Optional substring to match against the saved search name.
        limit: Maximum number of saved searches (default 50).

    Returns `{"saved_searches": [...], "count": n}`.
    """
    try:
        items = client_factory().list_saved_searches(filter or None, max(1, min(int(limit), 500)))
        return {"saved_searches": items, "count": len(items)}
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


@mcp.tool()
@audit
def server_info() -> dict[str, Any]:
    """Return the Splunk version, server name, product type, OS and CPU architecture."""
    try:
        return client_factory().server_info()
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


@mcp.tool()
@audit
def health() -> dict[str, Any]:
    """Return the splunkd health status and the status of each health feature.

    Returns `{"status": ..., "features": [{"name", "status", "reasons"}]}`.
    """
    try:
        return client_factory().health()
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


@mcp.tool()
@audit
def notables(hours: int = 24, limit: int = 50) -> dict[str, Any]:
    """List recent Enterprise Security notable events (requires Splunk ES).

    Uses the ES `notable` macro, so it returns an error on a Splunk without Enterprise Security.

    Args:
        hours: How many hours back to look (default 24).
        limit: Maximum notables to return (default 50, server cap applies).

    Returns `{"notables": [...], "count": n}` with rule_name, severity, urgency, status,
    owner, src, dest, user and risk_score.
    """
    try:
        cap = min(max(1, int(limit)), settings_factory().max_rows)
        items = client_factory().notables(max(1, int(hours)), cap)
        return {"notables": items, "count": len(items)}
    except Exception as exc:  # noqa: BLE001
        return _error(exc)


@mcp.resource("splunk://indexes", mime_type="application/json")
def indexes_resource() -> str:
    """The Splunk indexes as JSON text."""
    return json.dumps(list_indexes(), indent=2)


@mcp.prompt()
def triage_notable(rule_name: str) -> str:
    """Investigation checklist for a notable event raised by a given correlation rule."""
    return (
        f"Triage the Splunk notable event for the rule '{rule_name}'.\n"
        "1. Call notables to find recent notables for this rule; note src, dest, user, severity.\n"
        f"2. Call list_saved_searches with filter='{rule_name}' to read the rule's SPL and schedule.\n"
        "3. Use explain_spl, then search, to pull the raw events behind it for the affected "
        "src/dest/user over the surrounding hour.\n"
        "4. Look for the same entities in other indexes (authentication, proxy, endpoint).\n"
        "5. Conclude: true positive, benign or needs more data, with the evidence and the SPL used."
    )


@mcp.prompt()
def coverage_question() -> str:
    """Ask which saved searches cover a given attack technique."""
    return (
        "Which Splunk saved searches cover the attack technique I name (for example MITRE "
        "T1110 brute force)? Call list_saved_searches with relevant keyword filters, read the "
        "SPL of each match, and report the covered data sources, the gaps and whether each "
        "search is enabled or disabled."
    )

