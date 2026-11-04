"""Thin synchronous Splunk REST client built on httpx."""

from __future__ import annotations

from typing import Any

import httpx

from .config import Settings


class SplunkError(RuntimeError):
    """A readable error from Splunk or the connection to it. Never contains credentials."""


NOTABLES_SPL = (
    '`notable` | eval _time=strftime(_time,"%Y-%m-%d %H:%M:%S") '
    "| table _time rule_name severity urgency status_label owner src dest user risk_score"
)


class SplunkClient:
    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None) -> None:
        self.settings = settings
        headers: dict[str, str] = {"Accept": "application/json"}
        auth: httpx.Auth | None = None
        if settings.token:
            headers["Authorization"] = f"Bearer {settings.token}"
        elif settings.username and settings.password:
            auth = httpx.BasicAuth(settings.username, settings.password)
        self._http = httpx.Client(
            base_url=settings.url,
            verify=settings.verify_tls,
            timeout=settings.timeout_s,
            transport=transport,
            headers=headers,
            auth=auth,
        )

    def close(self) -> None:
        self._http.close()

    # -- plumbing ---------------------------------------------------------------------------

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        try:
            resp = self._http.request(method, path, **kwargs)
        except httpx.TimeoutException:
            raise SplunkError(
                f"Splunk did not answer within {self.settings.timeout_s}s. "
                "Narrow the time range or the search."
            ) from None
        except httpx.HTTPError as exc:
            raise SplunkError(f"Could not reach Splunk ({type(exc).__name__}).") from None
        if resp.status_code == 401:
            raise SplunkError("Splunk rejected the credentials (401). Check SPLUNK_TOKEN.")
        if resp.status_code == 403:
            raise SplunkError(
                "Splunk denied access (403). The role behind this token lacks a capability."
            )
        if resp.status_code >= 400:
            raise SplunkError(f"Splunk returned {resp.status_code}: {self._message(resp)}")
        try:
            data = resp.json()
        except ValueError:
            raise SplunkError("Splunk returned a response that is not JSON.") from None
        return data if isinstance(data, dict) else {"raw": data}

    @staticmethod
    def _message(resp: httpx.Response) -> str:
        try:
            msgs = resp.json().get("messages") or []
            if msgs and msgs[0].get("text"):
                return str(msgs[0]["text"])
        except (ValueError, AttributeError, IndexError):
            pass
        return resp.text[:300] or resp.reason_phrase

    # -- search -----------------------------------------------------------------------------

    def oneshot_search(
        self, spl: str, earliest: str = "-24h", latest: str = "now", max_rows: int = 100
    ) -> dict[str, Any]:
        data = self._request(
            "POST",
            "/services/search/v2/jobs",
            data={
                "search": spl,
                "exec_mode": "oneshot",
                "output_mode": "json",
                "earliest_time": earliest,
                "latest_time": latest,
                "count": str(max_rows),
            },
        )
        results = data.get("results") or []
        fields = data.get("fields") or []
        names = [f["name"] if isinstance(f, dict) else str(f) for f in fields]
        return {"results": results, "fields": names, "count": len(results), "spl": spl}

    # -- metadata ---------------------------------------------------------------------------

    def list_indexes(self) -> list[dict[str, Any]]:
        data = self._request(
            "GET", "/services/data/indexes", params={"output_mode": "json", "count": "0"}
        )
        out = []
        for entry in data.get("entry", []):
            c = entry.get("content", {})
            frozen = c.get("frozenTimePeriodInSecs")
            out.append(
                {
                    "name": entry.get("name"),
                    "events": int(c.get("totalEventCount") or 0),
                    "size_mb": int(float(c.get("currentDBSizeMB") or 0)),
                    "retention_days": round(int(frozen) / 86400) if frozen else None,
                    "is_internal": bool(c.get("isInternal")) or str(entry.get("name", "")).startswith("_"),
                }
            )
        return out

    def list_saved_searches(self, filter: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        params = {"output_mode": "json", "count": str(limit)}
        if filter:
            params["search"] = filter
        data = self._request("GET", "/services/saved/searches", params=params)
        out = []
        for entry in data.get("entry", []):
            c = entry.get("content", {})
            acl = entry.get("acl", {})
            out.append(
                {
                    "name": entry.get("name"),
                    "search": c.get("search"),
                    "cron": c.get("cron_schedule"),
                    "disabled": bool(c.get("disabled")),
                    "app": acl.get("app"),
                    "owner": acl.get("owner"),
                    "next_scheduled_time": c.get("next_scheduled_time") or None,
                }
            )
        return out

    def server_info(self) -> dict[str, Any]:
        data = self._request("GET", "/services/server/info", params={"output_mode": "json"})
        c = (data.get("entry") or [{}])[0].get("content", {})
        return {
            "version": c.get("version"),
            "server_name": c.get("serverName"),
            "product_type": c.get("product_type"),
            "os": c.get("os_name"),
            "cpu_arch": c.get("cpu_arch"),
        }

    def health(self) -> dict[str, Any]:
        data = self._request(
            "GET", "/services/server/health/splunkd/details", params={"output_mode": "json"}
        )
        try:
            content = data["entry"][0]["content"]
            features = content["features"]
            flat = [
                {
                    "name": name,
                    "status": (info or {}).get("health"),
                    "reasons": _reasons(info),
                }
                for name, info in features.items()
            ]
            return {"status": content.get("health"), "features": flat}
        except (KeyError, IndexError, TypeError, AttributeError):
            return {"raw": data}

    def notables(self, hours: int = 24, limit: int = 50) -> list[dict[str, Any]]:
        spl = f"{NOTABLES_SPL} | head {limit}"
        return self.oneshot_search(spl, earliest=f"-{hours}h", latest="now", max_rows=limit)[
            "results"
        ]


def _reasons(info: dict[str, Any] | None) -> list[str]:
    """Collect unhealthy indicator descriptions found anywhere under a health feature."""
    reasons: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if node.get("health") in {"yellow", "red"} and node.get("description"):
                reasons.append(str(node["description"]))
            for v in node.values():
                walk(v)

    walk(info)
    return reasons
