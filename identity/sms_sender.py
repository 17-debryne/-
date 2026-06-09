from __future__ import annotations

import logging
import os

_LOG = logging.getLogger(__name__)


def send_otp_sms(phone_e164_cn: str, code: str, *, purpose: str = "注册") -> None:
    """
    短信 OTP 占位实现。
    生产请对接阿里云 / 腾讯云短信 HTTP API（可在本函数内扩展分支）。
    """
    backend = os.environ.get("MASP_SMS_BACKEND", "console").strip().lower()
    text = f"[MASP]{purpose}验证码：{code}"

    if backend == "console":
        if os.environ.get("MASP_OTP_LOG_PLAINTEXT", "").strip() == "1":
            _LOG.warning(
                "[短信 OTP 明文日志] phone=%s purpose=%s code=%s",
                phone_e164_cn,
                purpose,
                code,
            )
        else:
            _LOG.info(
                "SMS_BACKEND=console，已向号码 %s 跳过真实发送；"
                "开发可设 MASP_OTP_LOG_PLAINTEXT=1 查看验证码",
                phone_e164_cn,
            )
        _LOG.debug("SMS body: %s", text)
        return

    raise RuntimeError(f"MASP_SMS_BACKEND={backend!r} 尚未实现，请使用 console 或扩展 sms_sender.py")
