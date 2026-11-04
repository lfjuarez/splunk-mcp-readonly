"""SPL safety checks. Pure functions, no I/O.

The guard is a defence-in-depth layer. The primary control is always a dedicated Splunk role
without write capabilities; this module simply stops an LLM from even attempting commands
that write, delete, exfiltrate or execute.

Commands that are expected to pass (``SAFE_READ_COMMANDS``, not exhaustive; anything not on
the blocklist is allowed):

    search, stats, eventstats, streamstats, chart, timechart, tstats, top, rare, table,
    fields, rename, sort, dedup, head, tail, rex, regex, eval, where, lookup, inputlookup,
    join, append, appendcols, transaction, bin, bucket, fillnull, makeresults, datamodel,
    pivot, rest (GET only), mvexpand, spath, extract, iplocation, geostats, eventcount,
    metadata, typeahead, tags
"""

from __future__ import annotations

import re

SAFE_READ_COMMANDS = [
    "search", "stats", "eventstats", "streamstats", "chart", "timechart", "tstats", "top",
    "rare", "table", "fields", "rename", "sort", "dedup", "head", "tail", "rex", "regex",
    "eval", "where", "lookup", "inputlookup", "join", "append", "appendcols", "transaction",
    "bin", "bucket", "fillnull", "makeresults", "datamodel", "pivot", "rest", "mvexpand",
    "spath", "extract", "iplocation", "geostats", "eventcount", "metadata", "typeahead", "tags",
]  # fmt: skip

BLOCKED_COMMANDS = frozenset(
    {
        "delete", "outputlookup", "outputcsv", "outputtext", "collect", "mcollect",
        "meventcollect", "sendemail", "sendalert", "script", "runshellscript", "run",
        "dbxquery", "dbxoutput", "crawl", "input", "savedsearch", "loadjob",
    }
)  # fmt: skip


class UnsafeSPL(ValueError):
    """Raised when a search is refused by the guard."""


def _scan(spl: str) -> list[tuple[int, int, str]]:
    """Return (position, depth, kind) markers for ``|`` and ``[`` outside quotes.

    kind is ``"pipe"`` or ``"open"``. Quotes (double, single, backtick) are honoured, with
    backslash escapes, so regexes such as ``rex "a|b"`` are not split.
    """
    marks: list[tuple[int, int, str]] = []
    depth = 0
    quote: str | None = None
    i = 0
    while i < len(spl):
        ch = spl[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == quote:
                quote = None
        elif ch in "\"'`":
            quote = ch
        elif ch == "[":
            depth += 1
            marks.append((i, depth, "open"))
        elif ch == "]":
            depth = max(0, depth - 1)
        elif ch == "|":
            marks.append((i, depth, "pipe"))
        i += 1
    return marks


_WORD = re.compile(r"\s*([A-Za-z_][\w]*)")


def _first_word(spl: str, pos: int) -> str:
    m = _WORD.match(spl, pos)
    return m.group(1).lower() if m else ""


def _stage_text(spl: str, start: int) -> str:
    """Text from ``start`` up to the next pipe (any depth), i.e. the rest of this stage."""
    nxt = [p for p, _, k in _scan(spl) if p > start and k == "pipe"]
    return spl[start + 1 : nxt[0] if nxt else len(spl)]


def split_stages(spl: str) -> list[str]:
    """Split a search into its top-level pipeline stages (depth 0 pipes only)."""
    cuts = [p for p, d, k in _scan(spl) if k == "pipe" and d == 0]
    stages: list[str] = []
    prev = 0
    for c in cuts:
        stages.append(spl[prev:c])
        prev = c + 1
    stages.append(spl[prev:])
    return [s.strip() for s in stages if s.strip()]


def _commands(spl: str) -> list[tuple[str, str]]:
    """All (command, stage_text) pairs, including those inside subsearches."""
    found: list[tuple[str, str]] = []
    for pos, _depth, kind in _scan(spl):
        word = _first_word(spl, pos + 1)
        if word:
            found.append((word, _stage_text(spl, pos) if kind == "pipe" else spl[pos + 1 :]))
    return found


_REST_METHOD = re.compile(r"\bmethod\s*=\s*[\"']?(post|delete|put)\b", re.IGNORECASE)
_INDEX_EQ = re.compile(r"(?<![\w.])index\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s,()|\[\]]+))", re.I)
_INDEX_IN = re.compile(r"(?<![\w.])index\s+IN\s*\(([^)]*)\)", re.I)


def _referenced_indexes(spl: str) -> list[str]:
    refs: list[str] = []
    for m in _INDEX_EQ.finditer(spl):
        refs.append(next(g for g in m.groups() if g is not None).strip())
    for m in _INDEX_IN.finditer(spl):
        for part in re.split(r"[,\s]+", m.group(1)):
            part = part.strip().strip("\"'")
            if part:
                refs.append(part)
    return refs


def check_spl(spl: str, *, allowed_indexes: list[str] | None = None) -> str:
    """Validate ``spl`` and return the normalised search string, or raise ``UnsafeSPL``."""
    spl = (spl or "").strip()
    if not spl:
        raise UnsafeSPL("The search is empty.")

    if not spl.startswith("|"):
        spl = "search " + spl

    for command, stage in _commands(spl):
        if command in BLOCKED_COMMANDS:
            raise UnsafeSPL(f"The command '{command}' is blocked: this server is read-only.")
        if command == "map":
            raise UnsafeSPL("The command 'map' is blocked: it runs a search per result row.")
        if command == "rest" and _REST_METHOD.search(stage):
            raise UnsafeSPL("'| rest' with a write method (post, delete, put) is blocked.")

    if allowed_indexes:
        allowed = {a.lower() for a in allowed_indexes}
        refs = _referenced_indexes(spl)
        if not refs:
            raise UnsafeSPL(
                "This server only allows searches over specific indexes. Add an explicit "
                "index=<name> (allowed: " + ", ".join(allowed_indexes) + ")."
            )
        bad = sorted({r for r in refs if r.lower() not in allowed})
        if bad:
            raise UnsafeSPL(
                "Index not allowed: " + ", ".join(bad) + ". Allowed: "
                + ", ".join(allowed_indexes) + "."
            )
    return spl


_HEAD = re.compile(r"^(head|tail)\b\s*(?:limit\s*=\s*)?(\d+)?\s*$", re.IGNORECASE)


def ensure_head(spl: str, max_rows: int) -> str:
    """Append ``| head N`` unless the pipeline already ends with a small enough head/tail."""
    stages = split_stages(spl)
    if stages:
        m = _HEAD.match(stages[-1])
        if m:
            n = int(m.group(2)) if m.group(2) else 10  # Splunk's default for head/tail
            if n <= max_rows:
                return spl
    return f"{spl} | head {max_rows}"
