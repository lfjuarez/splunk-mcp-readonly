"""Append-only JSON Lines audit log of every tool call.

Enabled by setting ``SPLUNK_MCP_AUDIT_LOG`` to a file path. One line per call with the tool name, the
arguments the model passed, the outcome (row count or error) and the duration. Credentials never reach
this module: it only sees tool arguments and a summary of the result.
"""

from __future__ import annotations

import inspect
import json
import os
import time
from collections.abc import Callable
from datetime import UTC, datetime
from functools import wraps
from typing import Any

# Tool arguments that are worth recording. Anything else is dropped rather than logged by accident.
_RECORDED_ARGS = ("spl", "earliest", "latest", "max_rows", "filter", "limit", "hours")


def _summary(result: Any) -> dict[str, Any]:
    if not isinstance(result, dict):
        return {"outcome": "ok"}
    if "error" in result:
        return {"outcome": "error", "error": str(result["error"])[:300]}
    out: dict[str, Any] = {"outcome": "ok"}
    if "count" in result:
        out["count"] = result["count"]
    if "spl" in result:
        out["spl_run"] = result["spl"]
    if result.get("truncated"):
        out["truncated"] = True
    return out


def write_entry(path: str, entry: dict[str, Any]) -> None:
    """Append one JSON line. Failures to write never break the tool call."""
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
    except OSError:
        return


def audited(path_getter: Callable[[], str | None]) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator factory: records the call when ``path_getter()`` returns a path, is a no-op otherwise."""

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            started = time.perf_counter()
            result = fn(*args, **kwargs)
            path = path_getter()
            if not path:
                return result
            call = inspect.signature(fn).bind_partial(*args, **kwargs)
            call.apply_defaults()
            bound = call.arguments
            entry = {
                "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
                "tool": fn.__name__,
                "args": {k: bound[k] for k in _RECORDED_ARGS if k in bound},
                "duration_ms": round((time.perf_counter() - started) * 1000, 1),
                "pid": os.getpid(),
            }
            entry.update(_summary(result))
            write_entry(path, entry)
            return result

        return wrapper

    return decorator
