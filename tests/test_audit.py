import json

import httpx

from splunk_mcp import server
from splunk_mcp.client import SplunkClient
from splunk_mcp.config import Settings


def _wire(monkeypatch, tmp_path, handler):
    log = tmp_path / "audit.jsonl"
    settings = Settings(url="https://splunk.test:8089", token="s3cret-token", audit_log=str(log))
    client = SplunkClient(settings, transport=httpx.MockTransport(handler))
    monkeypatch.setattr(server, "settings_factory", lambda: settings)
    monkeypatch.setattr(server, "client_factory", lambda: client)
    return log


def _rows(req):
    return httpx.Response(200, json={"fields": [{"name": "host"}], "results": [{"host": "a"}, {"host": "b"}]})


def test_search_is_recorded_with_args_and_outcome(monkeypatch, tmp_path):
    log = _wire(monkeypatch, tmp_path, _rows)
    server.search("index=main | stats count by host", earliest="-2h", max_rows=5)
    lines = log.read_text().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["tool"] == "search"
    assert entry["args"] == {
        "spl": "index=main | stats count by host", "earliest": "-2h", "latest": "now", "max_rows": 5,
    }
    assert entry["outcome"] == "ok" and entry["count"] == 2
    assert entry["spl_run"].endswith("| head 5")
    assert entry["duration_ms"] >= 0 and entry["ts"].endswith("+00:00")
    assert "s3cret" not in lines[0]


def test_refused_search_is_recorded_as_error_without_http(monkeypatch, tmp_path):
    calls = []

    def handler(req):
        calls.append(req)
        return _rows(req)

    log = _wire(monkeypatch, tmp_path, handler)
    server.search("index=main | delete")
    entry = json.loads(log.read_text().splitlines()[0])
    assert entry["outcome"] == "error" and "delete" in entry["error"]
    assert calls == []


def test_other_tools_are_recorded(monkeypatch, tmp_path):
    def handler(req):
        if req.url.path == "/services/data/indexes":
            return httpx.Response(200, json={"entry": [{"name": "main", "content": {}}]})
        return _rows(req)

    log = _wire(monkeypatch, tmp_path, handler)
    server.list_indexes()
    server.notables(hours=6, limit=10)
    tools = [json.loads(line)["tool"] for line in log.read_text().splitlines()]
    assert tools == ["list_indexes", "notables"]
    assert json.loads(log.read_text().splitlines()[1])["args"] == {"limit": 10, "hours": 6}


def test_no_log_when_unset(monkeypatch, tmp_path):
    settings = Settings(url="https://splunk.test:8089", token="tok")
    client = SplunkClient(settings, transport=httpx.MockTransport(_rows))
    monkeypatch.setattr(server, "settings_factory", lambda: settings)
    monkeypatch.setattr(server, "client_factory", lambda: client)
    server.search("index=main")
    assert list(tmp_path.iterdir()) == []


def test_unwritable_path_does_not_break_the_tool(monkeypatch, tmp_path):
    missing = tmp_path / "missing" / "dir" / "a.jsonl"
    settings = Settings(url="https://splunk.test:8089", token="tok", audit_log=str(missing))
    client = SplunkClient(settings, transport=httpx.MockTransport(_rows))
    monkeypatch.setattr(server, "settings_factory", lambda: settings)
    monkeypatch.setattr(server, "client_factory", lambda: client)
    assert server.search("index=main")["count"] == 2
