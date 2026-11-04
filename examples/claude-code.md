# Using splunk-mcp-readonly with Claude Code

Register the server for your user with one command:

```bash
claude mcp add splunk \
  -e SPLUNK_URL=https://splunk.example.com:8089 \
  -e SPLUNK_TOKEN=your-read-only-token \
  -- uvx --from git+https://github.com/lfjuarez/splunk-mcp-readonly splunk-mcp
```

Or share it with a project by committing a `.mcp.json` (keep the token out of the file by
letting Claude Code expand it from your environment):

```json
{
  "mcpServers": {
    "splunk": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/lfjuarez/splunk-mcp-readonly", "splunk-mcp"],
      "env": {
        "SPLUNK_URL": "https://splunk.example.com:8089",
        "SPLUNK_TOKEN": "${SPLUNK_TOKEN}",
        "SPLUNK_ALLOWED_INDEXES": "main,wineventlog,firewall"
      }
    }
  }
}
```

Verify with `claude mcp list`, then ask: "List my Splunk indexes".
