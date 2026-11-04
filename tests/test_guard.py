import pytest

from splunk_mcp.guard import BLOCKED_COMMANDS, UnsafeSPL, check_spl, ensure_head


@pytest.mark.parametrize("cmd", sorted(BLOCKED_COMMANDS))
def test_blocked_commands(cmd):
    with pytest.raises(UnsafeSPL):
        check_spl(f"index=main | {cmd} foo")


@pytest.mark.parametrize(
    "spl",
    [
        "index=main | DeLeTe",
        "index=main |   OUTPUTLOOKUP x.csv",
        "index=main|collect index=summary",
        "| savedsearch my_search",
        "index=main [ | inputlookup a.csv | delete ]",
        "index=main [search index=x | sendemail to=a@b.c]",
        "index=main | map search=\"search index=x\"",
        "| rest /services/saved/searches method=post",
        "| rest /services/x method=DELETE",
    ],
)
def test_blocked_variants(spl):
    with pytest.raises(UnsafeSPL):
        check_spl(spl)


@pytest.mark.parametrize(
    "spl",
    [
        "index=main error",
        "index=main | stats count by host",
        "| tstats count where index=main by host",
        "index=main | rex field=_raw \"user=(?<u>\\w+)\" | eval x=1",
        "index=main | lookup geo ip OUTPUT city",
        "| inputlookup assets.csv",
        "| rest /services/server/info",
        "| rest /services/server/info method=GET",
        "| makeresults count=3",
        "| datamodel Authentication search",
        'index=main | rex "delete|run|map" | stats count',
        'index=main message="please delete this"',
    ],
)
def test_allowed(spl):
    out = check_spl(spl)
    assert out.startswith(("search ", "|"))


def test_prefix_search_and_empty():
    assert check_spl("  index=main  ") == "search index=main"
    assert check_spl("| makeresults") == "| makeresults"
    with pytest.raises(UnsafeSPL):
        check_spl("   ")


@pytest.mark.parametrize(
    "spl,expected",
    [
        ("search index=main", "search index=main | head 50"),
        ("search index=main | head 10", "search index=main | head 10"),
        ("search index=main | head 500", "search index=main | head 500 | head 50"),
        ("search index=main | tail 20", "search index=main | tail 20"),
        ("search index=main | head limit=5", "search index=main | head limit=5"),
        ("search index=main | stats count by host", "search index=main | stats count by host | head 50"),
        ("search index=main | timechart count", "search index=main | timechart count | head 50"),
    ],
)
def test_ensure_head(spl, expected):
    assert ensure_head(spl, 50) == expected


ALLOWED = ["main", "wineventlog"]


@pytest.mark.parametrize(
    "spl",
    [
        "index=main error",
        'index="main" error',
        "index IN (main, wineventlog) error",
        "| tstats count where index=wineventlog by host",
    ],
)
def test_allowed_indexes_pass(spl):
    check_spl(spl, allowed_indexes=ALLOWED)


@pytest.mark.parametrize(
    "spl,fragment",
    [
        ("index=secret error", "secret"),
        ("index IN (main, secret) error", "secret"),
        ("index=* error", "not allowed"),
        ("error", "explicit"),
        ("| makeresults", "explicit"),
    ],
)
def test_allowed_indexes_reject(spl, fragment):
    with pytest.raises(UnsafeSPL, match=fragment):
        check_spl(spl, allowed_indexes=ALLOWED)
