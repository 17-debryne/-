"""核心业务 HTTP（无认证路由）：python -m mcp_agent_safe_protecter.run_core_http"""

from __future__ import annotations

import logging
import os

import uvicorn

from mcp_agent_safe_protecter.api.factory import create_app
from mcp_agent_safe_protecter.config.external_settings import bootstrap_external_config

logging.basicConfig(level=os.environ.get("MASP_LOG_LEVEL", "INFO"))


def main() -> None:
    bootstrap_external_config()
    app = create_app(mode="core")
    uvicorn.run(
        app,
        host=os.environ.get("MASP_HOST", "127.0.0.1"),
        port=int(os.environ.get("MASP_PORT", "8765")),
        log_level=os.environ.get("MASP_LOG_LEVEL", "info"),
    )


if __name__ == "__main__":
    main()
