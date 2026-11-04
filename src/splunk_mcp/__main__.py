"""Entry point: ``python -m splunk_mcp`` or the ``splunk-mcp`` console script (stdio)."""

from __future__ import annotations

import sys

from .config import ConfigError, Settings


def main() -> None:
    try:
        Settings.from_env()
    except ConfigError as exc:
        print(f"splunk-mcp: configuration error: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    from .server import mcp

    mcp.run()


if __name__ == "__main__":
    main()
