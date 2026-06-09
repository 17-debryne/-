from __future__ import annotations

import logging
import os
import smtplib
from email.mime.text import MIMEText

_LOG = logging.getLogger(__name__)


def send_otp_email(to_addr: str, code: str, *, purpose: str = "注册") -> None:
    """发送邮箱验证码；未配置 SMTP 时根据 ``MASP_OTP_LOG_PLAINTEXT`` 决定是否打印明文（仅开发）。"""
    host = os.environ.get("MASP_SMTP_HOST", "").strip()
    port = int(os.environ.get("MASP_SMTP_PORT", "587"))
    user = os.environ.get("MASP_SMTP_USER", "").strip()
    password = os.environ.get("MASP_SMTP_PASSWORD", "").strip()
    mail_from = os.environ.get("MASP_SMTP_FROM", user).strip()
    use_tls = os.environ.get("MASP_SMTP_TLS", "1").strip() != "0"

    body = f"您的验证码（{purpose}）：{code}\n有效期见系统配置。\n如非本人操作请忽略。"

    if not host:
        if os.environ.get("MASP_OTP_LOG_PLAINTEXT", "").strip() == "1":
            _LOG.warning(
                "[邮箱 OTP 明文日志] to=%s purpose=%s code=%s（禁止在生产开启）",
                to_addr,
                purpose,
                code,
            )
        else:
            _LOG.info(
                "未配置 SMTP（MASP_SMTP_HOST），已向 %s 跳过发送；"
                "开发可设 MASP_OTP_LOG_PLAINTEXT=1 在日志查看验证码",
                to_addr,
            )
        return

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = f"MASP 验证码 — {purpose}"
    msg["From"] = mail_from
    msg["To"] = to_addr

    with smtplib.SMTP(host, port, timeout=30) as smtp:
        smtp.ehlo()
        if use_tls:
            smtp.starttls()
            smtp.ehlo()
        if user:
            smtp.login(user, password)
        smtp.sendmail(mail_from, [to_addr], msg.as_string())


def send_verification_link_email(to_addr: str, verify_url: str, *, purpose: str = "邮箱注册") -> None:
    """发送带验证链接的邮件；未配置 SMTP 时按 ``MASP_EMAIL_LINK_LOG_PLAINTEXT`` / ``MASP_OTP_LOG_PLAINTEXT`` 记日志。"""
    host = os.environ.get("MASP_SMTP_HOST", "").strip()
    port = int(os.environ.get("MASP_SMTP_PORT", "587"))
    user = os.environ.get("MASP_SMTP_USER", "").strip()
    password = os.environ.get("MASP_SMTP_PASSWORD", "").strip()
    mail_from = os.environ.get("MASP_SMTP_FROM", user).strip()
    use_tls = os.environ.get("MASP_SMTP_TLS", "1").strip() != "0"

    body = (
        f"请点击以下链接完成邮箱验证（{purpose}），随后在页面设置登录密码：\n\n"
        f"{verify_url}\n\n"
        "链接有效期见系统配置。如非本人操作请忽略。"
    )

    log_plain = (
        os.environ.get("MASP_EMAIL_LINK_LOG_PLAINTEXT", "").strip() == "1"
        or os.environ.get("MASP_OTP_LOG_PLAINTEXT", "").strip() == "1"
    )

    if not host:
        if log_plain:
            _LOG.warning(
                "[邮箱验证链接明文日志] to=%s purpose=%s url=%s（禁止在生产开启）",
                to_addr,
                purpose,
                verify_url,
            )
        else:
            _LOG.info(
                "未配置 SMTP，已向 %s 跳过发送验证链接；开发可设 MASP_EMAIL_LINK_LOG_PLAINTEXT=1 打印完整 URL",
                to_addr,
            )
        return

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = f"MASP 邮箱验证链接 — {purpose}"
    msg["From"] = mail_from
    msg["To"] = to_addr

    with smtplib.SMTP(host, port, timeout=30) as smtp:
        smtp.ehlo()
        if use_tls:
            smtp.starttls()
            smtp.ehlo()
        if user:
            smtp.login(user, password)
        smtp.sendmail(mail_from, [to_addr], msg.as_string())
