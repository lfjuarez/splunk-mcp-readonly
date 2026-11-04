import asyncio
import json

import httpx
import pytest

from splunk_mcp import server
from splunk_mcp.client import SplunkClient
from splunk_mcp.config import ConfigError, Settings


@pytest.fixture
def wire(monkeypatch):
    calls = []

    def install(handler=None, **settings_kw):
        def default(req):
            calls.append(req)
            if req.url.path == "/services/search/v2/jobs":
                return httpx.Response(200, json={"fields": [{"name": "host"}],
                                                 "results": [{"host": "a"}, {"host": "b"}]})
            if req.url.path == "/services/data/indexes":
                return httpx.Response(200, json={"entry": [{"name": "main", "content": {}}]})
            return httpx.Response(500, json={})

        settings = Settings(url="https://splunk.test:8089", token="tok", **settings_kw)
        client = SplunkClient(settings, transport=httpx.MockTransport(handler or default))
        monkeypatch.setattr(server, "settings_factory", lambda: settings)
        monkeypatch.setattr(server, "client_factory", lambda: client)
        return calls

    return install


def test_search_refuses_delete(wire):
    calls = wire()
    out = server.search("index=main | delete")
    assert "error" in out and "delete" in out["error"]
    assert calls == []


def test_search_returns_rows_and_adds_head(wire):
    calls = wire()
    out = server.search("index=main | stats count by host", max_rows=5)
    assert out["results"] == [{"host": "a"}, {"host": "b"}]
    assert out["spl"] == "search index=main | stats count by host | head 5"
    assert out["truncated"] is False
    assert len(calls) == 1


def test_search_truncation_and_cap(wire):
    wire(max_rows=2)
    out = server.search("index=main", max_rows=900)
    assert out["spl"].endswith("| head 2")
    assert out["truncated"] is True and "limit" in out["note"]


def test_allowed_indexes(wire):
    wire(allowed_indexes=["main"])
    assert "error" in server.search("index=other")
    assert server.explain_spl("index=other")["ok"] is False
    assert server.explain_spl("index=main")["ok"] is True


def test_explain_spl(wire):
    wire()
    assert server.explain_spl("index=main")["normalised"] == "search index=main"
    bad = server.explain_spl("| outputlookup x")
    assert bad["ok"] is False and "outputlookup" in bad["reason"]


def test_http_error_becomes_error_dict(wire):
    wire(lambda r: httpx.Response(401, json={}))
    out = server.search("index=main")
    assert "401" in out["error"] and "tok" not in out["error"].replace("token", "")


def test_unexpected_exception_is_contained(monkeypatch):
    def broken():
        raise ConfigError("missing environment variables: SPLUNK_URL")

    monkeypatch.setattr(server, "settings_factory", broken)
    assert server.search("index=main") == {"error": "missing environment variables: SPLUNK_URL"}


def test_list_indexes_and_resource(wire):
    wire()
    assert server.list_indexes()["count"] == 1
    assert json.loads(server.indexes_resource())["indexes"][0]["name"] == "main"


def test_prompts():
    assert "R-1" in server.triage_notable("R-1")
    assert "list_saved_searches" in server.coverage_question()


def test_registered_tools():
    names = {t.name for t in asyncio.run(server.mcp.list_tools())}
    assert names == {"search", "explain_spl", "list_indexes", "list_saved_searches",
                     "server_info", "health", "notables"}
