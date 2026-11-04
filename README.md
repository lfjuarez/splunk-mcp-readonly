# splunk-mcp-readonly

A standalone, read-only [Model Context Protocol](https://modelcontextprotocol.io) server that lets an LLM assistant (Claude Desktop, Claude Code, or any MCP client) query Splunk Enterprise and Splunk Cloud with nothing but a token. It exposes search, index, saved search, health and Enterprise Security notable tools behind a guard that refuses anything that could write, delete, export or execute, and writes an audit line for every call.

It is read-only by design: an assistant that can explore your data is useful, an assistant that can run `| delete` or `| outputlookup` on a typo or a prompt injection is an incident. Safety is enforced twice, by the server and by the Splunk role behind the token.

## When to use this, and when to use Splunk's own server

Splunk ships an official [Splunk MCP Server](https://splunkbase.splunk.com/app/7931) as a Splunk app: 25 tools including fired alerts, throttles, KV store, knowledge objects and SPL generation through Splunk AI Assistant, with a configurable allow-list of SPL commands. If you can install apps on the Splunk instance and want that breadth, use it.

This project exists for the other cases:

- **You cannot install anything on the Splunk you are querying.** Consultants, auditors and analysts often get a token and nothing else. This server runs on your side (laptop, jump host, container) and only needs the management port.
- **You want the smallest possible surface.** Seven tools, read-only, about 800 lines of Python you can review in an hour before pointing an LLM at production data.
- **You need the controls written down.** Index allow-list, forced row caps, default time window, command blocklist and a JSON Lines audit log of every call the model makes, so the SOC can answer "what did the assistant run last Tuesday".
- **You are evaluating.** It is a reference implementation of guardrails for LLM-driven SPL; the guard module is self-contained and reusable.

## Tools

| Tool | Purpose | Limits |
|------|---------|--------|
| `search` | Run a read-only SPL search | `| head N` always enforced; N <= `SPLUNK_MAX_ROWS` (default 200, hard cap 1000); default range `-24h` |
| `explain_spl` | Validate SPL against the guard without running it | No Splunk call |
| `list_indexes` | Indexes with event count, size and retention | All indexes visible to the role |
| `list_saved_searches` | Saved searches and alerts with SPL and cron | `filter` matches name substring; `limit` default 50 |
| `server_info` | Version, server name, product type, OS, CPU | - |
| `health` | splunkd health status per feature | - |
| `notables` | Recent Enterprise Security notables | Needs Splunk ES; `limit` default 50 |

Resource: `splunk://indexes`. Prompts: `triage_notable(rule_name)` and `coverage_question()`.

## Safety model

- **Command blocklist.** Any pipeline stage, including inside subsearches, that starts with `delete, outputlookup, outputcsv, outputtext, collect, mcollect, meventcollect, sendemail, sendalert, script, runshellscript, run, dbxquery, dbxoutput, crawl, input, savedsearch, loadjob` is refused, case-insensitively and regardless of spacing. `map` is refused, and `| rest` with `method=post|delete|put` is refused (plain GET is allowed). Pipes inside quoted strings, such as `rex "a|b"`, are not mistaken for commands.
- **Forced `head`.** Every search ends with `| head N` unless it already ends with `head` or `tail` of N or fewer rows.
- **Default time range.** `-24h` to `now` unless the caller says otherwise.
- **Index allow-list.** With `SPLUNK_ALLOWED_INDEXES=main,wineventlog`, every `index=` and `index IN (...)` reference must be on the list, and a search without an explicit index is refused.
- **Audit log.** With `SPLUNK_MCP_AUDIT_LOG=/var/log/splunk-mcp/audit.jsonl`, every tool call appends one JSON line: timestamp, tool, the arguments the model passed, the SPL actually run, row count or error, and duration. Credentials never reach the log. Ship the file to Splunk itself if you want the assistant's activity next to everything else.
- **No secrets in output.** Credentials are never logged or returned, including in error messages.
- **Least-privilege token (the real control).** The guard is defence in depth. Create a dedicated role with only the capabilities `search`, `list_indexes` and `rest_properties_get`, and no `edit_*` capabilities. Restrict it to the indexes you want to expose. Then, in Splunk Web, go to Settings -> Tokens, create a token for a user holding that role, and set a reasonable expiry.

## Install and configure

Environment variables:

| Variable | Default | Meaning |
|----------|---------|---------|
| `SPLUNK_URL` | required | Management URL, e.g. `https://splunk.example.com:8089` |
| `SPLUNK_TOKEN` | - | Bearer token (preferred) |
| `SPLUNK_USERNAME`, `SPLUNK_PASSWORD` | - | Basic auth, used when no token is set |
| `SPLUNK_VERIFY_TLS` | `true` | Verify the TLS certificate |
| `SPLUNK_DEFAULT_EARLIEST` | `-24h` | Default start of the time range |
| `SPLUNK_MAX_ROWS` | `200` | Row cap per search (hard cap 1000) |
| `SPLUNK_TIMEOUT_S` | `60` | HTTP timeout in seconds |
| `SPLUNK_ALLOWED_INDEXES` | unset | Comma list; searches may only reference these |
| `SPLUNK_MCP_AUDIT_LOG` | unset | Path of a JSON Lines file; one line per tool call when set |

Run it directly from GitHub with uv:

```bash
uvx --from git+https://github.com/lfjuarez/splunk-mcp-readonly splunk-mcp
```

Or with pipx, or from source:

```bash
pipx install git+https://github.com/lfjuarez/splunk-mcp-readonly

git clone https://github.com/lfjuarez/splunk-mcp-readonly
cd splunk-mcp-readonly
uv venv .venv && uv pip install -e ".[dev]"
.venv/bin/pytest -q
```

### Claude Desktop

Add to `claude_desktop_config.json` (see [`examples/claude_desktop_config.json`](examples/claude_desktop_config.json)):

```json
{
  "mcpServers": {
    "splunk": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/lfjuarez/splunk-mcp-readonly", "splunk-mcp"],
      "env": {
        "SPLUNK_URL": "https://splunk.example.com:8089",
        "SPLUNK_TOKEN": "<token>",
        "SPLUNK_VERIFY_TLS": "true"
      }
    }
  }
}
```

### Claude Code

```bash
claude mcp add splunk \
  -e SPLUNK_URL=https://splunk.example.com:8089 \
  -e SPLUNK_TOKEN=your-read-only-token \
  -- uvx --from git+https://github.com/lfjuarez/splunk-mcp-readonly splunk-mcp
```

More options, including a project `.mcp.json`, in [`examples/claude-code.md`](examples/claude-code.md).

## Example session

> **User:** Which hosts had failed logons followed by a success in the last 6 hours?
>
> **Assistant** calls `explain_spl`:
> ```
> index=wineventlog (EventCode=4625 OR EventCode=4624)
> | sort 0 _time
> | streamstats current=f last(EventCode) as prev by host, user
> | where EventCode=4624 AND prev=4625
> | stats count as recoveries, values(user) as users by host
> | sort - recoveries
> ```
> Result: `{"ok": true, "normalised": "search index=wineventlog ..."}`
>
> **Assistant** calls `search` with the same SPL, `earliest="-6h"`, `max_rows=20`.
> Result: 3 rows, e.g. `{"host": "WS-114", "recoveries": "7", "users": ["svc_backup", "jdoe"]}`.
>
> **Assistant:** Three hosts show a failed logon immediately followed by a success. WS-114 stands out with 7 occurrences across two accounts, including a service account. Want me to pull the source IPs for those events?

## Enterprise Security notables

The `notables` tool runs the ES `` `notable` `` macro and shows rule name, severity, urgency, status, owner, src, dest, user and risk score. Without Splunk Enterprise Security the macro does not exist and the tool returns an error message instead of data. The `triage_notable` prompt turns a rule name into a short investigation checklist that uses the other tools.

## Limitations

- One-shot searches only: the request blocks until Splunk finishes, bounded by `SPLUNK_TIMEOUT_S`. There is no job polling yet, so very long searches time out.
- At most 1000 rows per search.
- No write operations, ever: no saved search creation, no lookups updates, no alert management.
- The guard is a text-level check, not a full SPL parser. Use a least-privilege role as the authoritative control.

## Roadmap

- Job polling for long-running searches
- Splunk Cloud ACS support (index and token administration is out of scope; read-only discovery)
- Metrics index tools (`mstats`, `mcatalog` helpers)

## Author

Leandro F. Juárez, built from field work on SIEM platforms. [LinkedIn](https://www.linkedin.com/in/leandrofjuarez). MIT licensed.
