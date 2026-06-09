@echo off
chcp 65001 >nul
setlocal

cd /d "%~dp0"

if not defined MASP_PORT set "MASP_PORT=8765"

rem 稍后尝试打开 API 文档（服务器在同目录启动）
start "" cmd /c "timeout /t 2 /nobreak >nul && start http://127.0.0.1:%MASP_PORT%/"

if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" -m mcp_agent_safe_protecter.run_http
) else (
  python -m mcp_agent_safe_protecter.run_http
)

if errorlevel 1 (
  echo.
  echo [MASP] 启动失败。请先在本目录执行:  pip install -e .
  echo.
  pause
)
