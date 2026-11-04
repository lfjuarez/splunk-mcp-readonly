import pytest

from splunk_mcp.config import ConfigError, Settings


def test_defaults_and_caps():
    s = Settings.from_env({"SPLUNK_URL": "https://h:8089/", "SPLUNK_TOKEN": "t",
                           "SPLUNK_MAX_ROWS": "5000", "SPLUNK_ALLOWED_INDEXES": "a, b"})
    assert s.url == "https://h:8089" and s.max_rows == 1000
    assert s.verify_tls is True and s.default_earliest == "-24h" and s.timeout_s == 60
    assert s.allowed_indexes == ["a", "b"]


def test_missing_vars_listed():
    with pytest.raises(ConfigError, match="SPLUNK_URL.*SPLUNK_TOKEN"):
        Settings.from_env({})


def test_token_not_in_repr():
    assert "secret" not in repr(Settings.from_env({"SPLUNK_URL": "u", "SPLUNK_TOKEN": "secret"}))
