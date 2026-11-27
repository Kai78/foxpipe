"""Standalone Python 3.11 entry point for GitLab SSH Pipeline Runner."""

from __future__ import annotations

import os
import uvicorn

from app.config import load_config


def main() -> None:
    """Start Uvicorn using server host and port from config.yaml (with env overrides)."""
    cfg = load_config()
    port = int(os.environ.get("PYTHON_PORT") or os.environ.get("RUNNER_PORT") or cfg.server.port)
    host = os.environ.get("PYTHON_HOST") or os.environ.get("RUNNER_HOST") or cfg.server.host
    forwarded_allow_ips = os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1")
    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        workers=cfg.server.workers,
        log_level=cfg.logging.level.lower(),
        proxy_headers=True,
        forwarded_allow_ips=forwarded_allow_ips,
    )


if __name__ == "__main__":
    main()
