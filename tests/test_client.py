from urllib.parse import parse_qs

import httpx
import pytest

from splunk_mcp.client import SplunkClient, SplunkError
from splunk_mcp.config import Settings


def make(handler, **kw):
    s = Settings(url="https://splunk.test:8089", token="tok123", **kw)
    return SplunkClient(s, transport=httpx.MockTransport(handler))


def test_oneshot_search():
    seen = {}

    def handler(req: httpx.Request):
        seen["req"] = req
        return httpx.Response(
            200,
            json={
                "fields": [{"name": "host"}, {"name": "count"}],
                "results": [{"host": "a", "count": "3"}],
            },
        )

    out = make(handler).oneshot_search("search index=main", "-1h", "now", 25)
    req = seen["req"]
    assert req.method == "POST"
    assert req.url.path == "/services/search/v2/jobs"
    assert req.headers["authorization"] == "Bearer tok123"
    form = {k: v[0] for k, v in parse_qs(req.content.decode()).items()}
    assert form == {
        "search": "search index=main",
        "exec_mode": "oneshot",
        "output_mode": "json",
        "earliest_time": "-1h",
        "latest_time": "now",
        "count": "25",
    }
    assert out == {
        "results": [{"host": "a", "count": "3"}],
        "fields": ["host", "count"],
        "count": 1,
        "spl": "search index=main",
    }


def test_basic_auth():
    seen = {}

    def handler(req):
        seen["auth"] = req.headers["authorization"]
        return httpx.Response(200, json={"entry": [{"content": {"version": "9.2.1"}}]})

    s = Settings(url="https://splunk.test:8089", username="u", password="p")
    SplunkClient(s, transport=httpx.MockTransport(handler)).server_info()
    assert seen["auth"].startswith("Basic ")


def test_list_indexes():
    def handler(req):
        assert req.method == "GET" and req.url.path == "/services/data/indexes"
        assert req.url.params["count"] == "0" and req.url.params["output_mode"] == "json"
        return httpx.Response(
            200,
            json={
                "entry": [
                    {"name": "main", "content": {"totalEventCount": "1200", "currentDBSizeMB": 12.7,
                                                   "frozenTimePeriodInSecs": 15552000}},
                    {"name": "_internal", "content": {"totalEventCount": "5", "currentDBSizeMB": 1,
                                                        "frozenTimePeriodInSecs": 2592000,
                                                        "isInternal": True}},
                ]
            },
        )

    out = make(handler).list_indexes()
    assert out[0] == {"name": "main", "events": 1200, "size_mb": 12, "retention_days": 180,
                      "is_internal": False}
    assert out[1]["is_internal"] is True and out[1]["retention_days"] == 30


def test_list_saved_searches():
    def handler(req):
        assert req.url.path == "/services/saved/searches"
        assert req.url.params["search"] == "brute" and req.url.params["count"] == "10"
        return httpx.Response(
            200,
            json={
                "entry": [
                    {
                        "name": "Brute Force Detected",
                        "acl": {"app": "SA-Threat", "owner": "admin"},
                        "content": {"search": "index=win EventCode=4625", "cron_schedule": "*/5 * * * *",
                                    "disabled": False, "next_scheduled_time": "2026-11-03 10:05:00 UTC"},
                    }
                ]
            },
        )

    out = make(handler).list_saved_searches("brute", 10)
    assert out == [{
        "name": "Brute Force Detected", "search": "index=win EventCode=4625",
        "cron": "*/5 * * * *", "disabled": False, "app": "SA-Threat", "owner": "admin",
        "next_scheduled_time": "2026-11-03 10:05:00 UTC",
    }]


def test_server_info():
    def handler(req):
        assert req.url.path == "/services/server/info"
        return httpx.Response(200, json={"entry": [{"content": {
            "version": "9.2.1", "serverName": "sh01", "product_type": "enterprise",
            "os_name": "Linux", "cpu_arch": "x86_64"}}]})

    assert make(handler).server_info() == {
        "version": "9.2.1", "server_name": "sh01", "product_type": "enterprise",
        "os": "Linux", "cpu_arch": "x86_64"}


def test_health_flatten_and_raw():
    def handler(req):
        assert req.url.path == "/services/server/health/splunkd/details"
        return httpx.Response(200, json={"entry": [{"content": {"health": "yellow", "features": {
            "Data Forwarding": {"health": "green", "features": {}},
            "Index Processor": {"health": "yellow", "features": {"Buckets": {
                "health": "yellow", "description": "Buckets are rolling too fast"}}},
        }}}]})

    out = make(handler).health()
    assert out["status"] == "yellow"
    assert out["features"][0] == {"name": "Data Forwarding", "status": "green", "reasons": []}
    assert out["features"][1]["reasons"] == ["Buckets are rolling too fast"]

    odd = make(lambda r: httpx.Response(200, json={"weird": 1})).health()
    assert odd == {"raw": {"weird": 1}}


def test_notables():
    seen = {}

    def handler(req):
        seen["form"] = {k: v[0] for k, v in parse_qs(req.content.decode()).items()}
        return httpx.Response(200, json={"fields": [], "results": [{"rule_name": "R1"}]})

    out = make(handler).notables(12, 5)
    assert out == [{"rule_name": "R1"}]
    assert seen["form"]["search"].startswith("`notable`")
    assert seen["form"]["search"].endswith("| head 5")
    assert seen["form"]["earliest_time"] == "-12h"


def test_error_mapping():
    with pytest.raises(SplunkError, match="401"):
        make(lambda r: httpx.Response(401, json={})).oneshot_search("search x")
    with pytest.raises(SplunkError, match="403"):
        make(lambda r: httpx.Response(403, json={})).list_indexes()
    bad = httpx.Response(400, json={"messages": [{"type": "FATAL", "text": "Unknown search command 'foo'."}]})
    with pytest.raises(SplunkError, match="Unknown search command 'foo'"):
        make(lambda r: bad).oneshot_search("search | foo")


def test_errors_never_leak_token():
    def boom(req):
        raise httpx.ConnectError("failed with Bearer tok123")

    with pytest.raises(SplunkError) as ei:
        make(boom).server_info()
    assert "tok123" not in str(ei.value)
