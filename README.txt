MCP Agent Safe Protecter
========================

Python 包目录：mcp_agent_safe_protecter/

使用前（项目根）
--------------
  pip install -e .

本地 HTTP
---------
  Windows 一键启动：双击项目根目录 start-masp.bat（约 2 秒后尝试打开首页 → 浏览器壳 UI）
  前端静态页：/ （307 → /ui/browser-console.html）；OpenAPI：/docs；健康检查：/health
  安全防护评估 API：POST /api/v1/tenants/{tenant}/sessions/{sid}/protection/evaluate（JWT 或 X-API-Key）
  其它：scripts/start-masp.ps1、scripts/start-masp.sh（chmod +x）
  set MASP_API_KEY=你的密钥
  python -m mcp_agent_safe_protecter.run_http

Docker
------
  默认双容器（core + masp-auth）：docker compose build && docker compose up -d
  统一入口：docker compose --profile gateway up -d
  单体：docker compose --profile monolith up -d

HTTPS 反向代理、Vault / Nacos、邮箱/手机/微信/QQ 注册登录说明见 deploy/README.txt 与 deploy/auth-identity.env.example

数据目录（MASP_DATA_DIR）
------------------------
  masp_auth.sqlite3：认证库（用户/OAuth/验证码/JWT 吊销），可由 MASP_AUTH_DATABASE 覆盖；首次可从 auth/identity.sqlite3 自动复制迁移。
  masp_audit.sqlite3：审计库（每次 scan/evaluate 的发现与溯源快照），MASP_AUDIT_DATABASE 可覆盖。
  masp_app.sqlite3：配额与导出计数；tenants/*.sqlite3：按租户溯源。
  CLI：masp auth prune、masp cache clear [--tenant ID]、masp query --limit 20（需正确设置 MASP_DATA_DIR）。
  HTTP（需 JWT 或 X-API-Key）：GET /api/v1/admin/cache/stats、POST /api/v1/admin/cache/cleanup。
  可选 MASP_TRACE_STORE_CACHE_MAX 限制租户溯源连接缓存条数（FIFO 自动清理）。
  安全审计：security_audit/events.jsonl；Prometheus：/metrics（core/full）；详见 deploy/README.txt 第十一节。

运行演示
--------
  python -m mcp_agent_safe_protecter.demo_run
