#!/usr/bin/env bash
# 一键启动 HTTP API（与 python -m mcp_agent_safe_protecter.run_http 等价）
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${MASP_PORT:-8765}"

_open_ui() {
  sleep 2
  local url="http://127.0.0.1:${PORT}/"
  if command -v xdg-open >/dev/null 2>&1; then xdg-open "$url"
  elif command -v open >/dev/null 2>&1; then open "$url"
  fi
}

_open_ui &

if [[ -x "${ROOT}/.venv/bin/python" ]]; then
  exec "${ROOT}/.venv/bin/python" -m mcp_agent_safe_protecter.run_http
elif command -v python3 >/dev/null 2>&1; then
  exec python3 -m mcp_agent_safe_protecter.run_http
else
  exec python -m mcp_agent_safe_protecter.run_http
fi
