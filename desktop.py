"""桌面壳：内嵌 WebView，本地拉起 FastAPI。python -m mcp_agent_safe_protecter.desktop"""

from __future__ import annotations

import os
import threading
import time
import urllib.error
import urllib.request
from typing import Any

import uvicorn

try:
    import webview
except ImportError as e:
    raise SystemExit(
        "缺少依赖 pywebview，请执行: pip install pywebview"
    ) from e

from mcp_agent_safe_protecter.api.factory import create_app
from mcp_agent_safe_protecter.config.external_settings import bootstrap_external_config


def main() -> None:
    bootstrap_external_config()
    host = os.environ.get("MASP_HOST", "127.0.0.1")
    port = int(os.environ.get("MASP_PORT", "8765"))
    app = create_app()
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    holder: dict[str, Any] = {}

    def run_server() -> None:
        holder["server"] = server
        server.run()

    thread = threading.Thread(target=run_server, daemon=False)
    thread.start()

    deadline = time.time() + 15
    health = f"http://{host}:{port}/health"
    while time.time() < deadline:
        try:
            urllib.request.urlopen(health, timeout=0.35)
            break
        except (urllib.error.URLError, OSError):
            time.sleep(0.05)

    url = f"http://{host}:{port}/"
    webview.create_window("MASP · 控制台", url, width=1100, height=760)
    webview.start()
    server.should_exit = True
    thread.join(timeout=10)


if __name__ == "__main__":
    main()
