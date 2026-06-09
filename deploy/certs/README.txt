此目录挂载到 nginx 容器 /etc/nginx/certs/

请放置 TLS 文件（示例文件名）：
  fullchain.pem   — 完整证书链
  privkey.pem     — 私钥

自签测试（仅本地）示例：
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout privkey.pem -out fullchain.pem \
    -subj "/CN=localhost"

生产环境请使用正式 CA 或 ACME 签发的证书。
