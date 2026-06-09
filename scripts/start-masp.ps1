#Requires -Version 5.0
<#
.SYNOPSIS
  一键启动 MASP HTTP（溯源等业务 API）

.DESCRIPTION
  优先使用项目目录下 .venv；否则使用当前 PATH 中的 python。
  约 2 秒后尝试打开控制台首页（重定向至浏览器壳 UI）：http://127.0.0.1:<MASP_PORT>/
#>
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)

if (-not $env:MASP_PORT) { $env:MASP_PORT = "8765" }
$port = $env:MASP_PORT
$url = "http://127.0.0.1:$port/"

Start-Process -FilePath "cmd.exe" -ArgumentList @(
  "/c", "timeout /t 2 /nobreak >nul && start `"$url`""
) -WindowStyle Hidden

$py = Join-Path $PWD ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $py)) {
  $py = "python"
}

& $py -m mcp_agent_safe_protecter.run_http
if ($LASTEXITCODE -ne 0) {
  Write-Host ""
  Write-Host "[MASP] 启动失败。请先在本目录执行: pip install -e ." -ForegroundColor Red
  Write-Host ""
  Read-Host "按 Enter 退出"
  exit $LASTEXITCODE
}
