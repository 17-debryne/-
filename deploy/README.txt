部署说明（Docker / HTTPS / 配置中心）
=====================================

一、本地 Python（项目根）
-------------------------
  pip install -e .
  set MASP_API_KEY=你的密钥
  python -m mcp_agent_safe_protecter.run_http

二、Docker Compose
------------------
  默认（双容器：core + 独立认证）：
    docker compose build && docker compose up -d

  - masp：溯源等业务 API，端口 MASP_PUBLISH_PORT（默认 8765）
  - masp-auth：登录/注册/OAuth，端口 MASP_AUTH_PUBLISH_PORT（默认 8766）
  - 二者共享卷 masp_data，须使用相同 MASP_JWT_SECRET（或共享 auth/.jwt_secret）

  统一 HTTP 入口（推荐）：
    docker compose --profile gateway up -d
  网关端口 MASP_GATEWAY_PORT（默认 8080），/api/v1/auth/* → masp-auth，其余 → masp（OpenAPI 见各服务 /docs）。
  OAuth 回调请设置 MASP_PUBLIC_BASE_URL=http://localhost:8080（或你的网关 HTTPS 地址）。

  单体模式（与旧版一致，单进程全功能）：
    docker compose --profile monolith up -d

三、HTTPS（Nginx 反向代理模板）
------------------------------
  1. 准备证书：见 deploy/certs/README.txt
  2. 生成 nginx 配置：
       - 快速：复制 deploy/nginx/default.conf.example 为 deploy/nginx/default.conf 并按需改 server_name
       - 或：用 deploy/nginx/default.conf.template + envsubst（见模板内注释）
  3. 启动：
       docker compose --profile https up -d

  对外只暴露 443；应用仍监听容器内 8765（HTTP），由 Nginx 终结 TLS。

四、HashiCorp Vault（KV v2）
---------------------------
  启动前设置：
    MASP_CONFIG_SOURCE=vault
    MASP_VAULT_ADDR=https://vault.example:8200
    MASP_VAULT_TOKEN=...
    MASP_VAULT_SECRET_PATH=secret/data/masp    （KV v2 路径）

  密钥 JSON 的 data.data 中为键值对，键名与 MASP_* 环境变量一致。
  仅当某变量在当前环境中「未设置或为空」时才写入（Compose/env 显式值优先）。

  自建 Vault 测试证书：MASP_VAULT_TLS_VERIFY=0（生产勿用）

五、Nacos（properties 文本）
-----------------------------
    MASP_CONFIG_SOURCE=nacos
    MASP_NACOS_SERVER=http://nacos:8848
    MASP_NACOS_DATA_ID=masp.properties
    MASP_NACOS_GROUP=DEFAULT_GROUP
    MASP_NACOS_NAMESPACE=          （可选）

  配置内容为 KEY=value 行；键名与 MASP_* 一致。合并规则同上。

六、严格模式
------------
  MASP_CONFIG_STRICT=1 时，Vault/Nacos 拉取失败将中止进程（默认仅打日志）。

七、登录 / 注册（邮箱·手机·微信·QQ）
-----------------------------------
  认证库默认：{MASP_DATA_DIR}/masp_auth.sqlite3（环境变量 MASP_AUTH_DATABASE 可覆盖）。
  若该文件不存在且仍存在旧路径 {MASP_DATA_DIR}/auth/identity.sqlite3，启动时会自动复制到新路径。
  详见 deploy/auth-identity.env.example（SMTP、OAuth、短信、OTP、邮箱魔法链接安全配置）。
  认证库体积：MASP_AUTH_SQLITE_MAX_SIZE_MIB（可选 PRAGMA max_page_count）；维护命令 masp auth prune（建议 cron）。

八、应用元数据库（配额 / 导出计数 / 防膨胀）
---------------------------------------------
  {MASP_DATA_DIR}/masp_app.sqlite3：租户配额、按租户按日的导出字节计数、兼容旧版的 JWT 口令用户表。
  若仅有 tenant_quotas.json 且库内配额表为空，启动时会一次性导入 JSON。
  溯源 append_event 的单条 payload 序列化后默认上限 512KB，可用 MASP_MAX_EVENT_PAYLOAD_BYTES 调整（设为 0 表示不限制）。

九、服务端缓存清理（租户溯源连接）
----------------------------------
  Core / Full 进程在内存中缓存各租户已打开的 SQLiteTraceStore。
  - CLI：masp cache clear（驱逐全部已缓存连接，默认 WAL checkpoint）；masp cache clear --tenant acme
  - API：GET /api/v1/admin/cache/stats、POST /api/v1/admin/cache/cleanup（需 Authorization 或 X-API-Key）
  请求体示例：{"tenant_ids": [], "checkpoint_wal": true, "scopes": ["trace_stores"]}（tenant_ids 空表示全部）。
  可选 ``MASP_TRACE_STORE_CACHE_MAX``（正整数）：限制进程内缓存的租户连接数，超出时按先入先出自动驱逐并 WAL checkpoint。

十、审计库（评估 / scan 留痕）
-----------------------------
  默认 {MASP_DATA_DIR}/masp_audit.sqlite3（MASP_AUDIT_DATABASE）。
  每次 HTTP POST .../sessions/{id}/scan 写入 evaluation_sessions、findings、protection_decisions、trace_artifacts。
  体量控制：MASP_AUDIT_MAX_SESSIONS（超出删最旧会话级联子表）、可选 MASP_AUDIT_SQLITE_MAX_SIZE_MIB。
  查询：masp query --limit 20（需 export MASP_DATA_DIR 与线上一致）。

十一、管理面加固 / 指标 / 策略完整性（优先落地项）
----------------------------------------------------
  安全审计（JSONL）：{MASP_DATA_DIR}/security_audit/events.jsonl
    记录登录成功/失败/锁定、注册与 OAuth、登出、admin cache cleanup 等（含 request_id、client_host）。

  限流（按 IP，可选信任代理）：
    MASP_RATE_LIMIT_AUTH_PER_MINUTE（默认 60，0 关闭）作用于 /api/v1/auth/login 与 /api/v1/auth/register*
    MASP_RATE_LIMIT_ADMIN_PER_MINUTE（默认 120）作用于 /api/v1/admin/
    MASP_TRUST_X_FORWARDED_FOR=1 时使用 X-Forwarded-For 首段作为客户端 IP

  登录暴力破解限制与账户锁定（masp_app.sqlite3 · login_throttle）：
    MASP_LOGIN_MAX_FAILS（默认 8）、MASP_LOGIN_FAIL_WINDOW_SEC（默认 900）、MASP_LOGIN_LOCKOUT_SEC（默认 900）

  管理接口 HMAC（可选，与 JWT/API Key 二选一）：
    MASP_ADMIN_HMAC_SECRET 设置后，/api/v1/admin/* 满足其一即可：
    （1）有效 HMAC：X-Masp-Timestamp（Unix 秒）、X-Masp-Signature=hex(HMAC-SHA256(secret, "{ts}\\n{METHOD}\\n{path}"))
    （2）或与现有接口相同：Authorization Bearer JWT / X-API-Key
    MASP_ADMIN_HMAC_MAX_SKEW_SEC（默认 120）

  Prometheus：Core/Full 暴露 GET /metrics（请在网络层限制采集端访问）
    masp_evaluate_*、masp_remote_config_fetch_failures_total（Vault/Nacos 拉取异常时递增）

  tenant_quotas.json 完整性（导入 SQLite 前校验）：
    MASP_POLICY_FILE_HMAC_SECRET + 并发生成 tenant_quotas.json.hmac（单行 hex，算法见 api/policy_integrity.py）

  健康检查：GET /health 返回 checks（app_database、audit_database、data_dir_disk）、health_status；
    MASP_HEALTH_STRICT=1 且 DB 报错时标记 unhealthy；MASP_HEALTH_MIN_DISK_FREE_RATIO 默认 0.02

  后续 roadmap（未实现）：JWT access/refresh 分离、mTLS、镜像 non-root、SBOM、策略版本写入审计库字段等。
