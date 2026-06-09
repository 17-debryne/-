from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

_LOG = logging.getLogger(__name__)


def wechat_web_authorize_url(*, app_id: str, redirect_uri: str, state: str) -> str:
    q = urllib.parse.urlencode(
        {
            "appid": app_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "snsapi_login",
            "state": state,
        }
    )
    return f"https://open.weixin.qq.com/connect/qrconnect?{q}#wechat_redirect"


def wechat_exchange_code(app_id: str, secret: str, code: str) -> dict[str, Any]:
    q = urllib.parse.urlencode(
        {
            "appid": app_id,
            "secret": secret,
            "code": code,
            "grant_type": "authorization_code",
        }
    )
    url = f"https://api.weixin.qq.com/sns/oauth2/access_token?{q}"
    with urllib.request.urlopen(url, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if data.get("errcode"):
        raise RuntimeError(f"WeChat token 错误: {data}")
    return data


def wechat_userinfo(access_token: str, openid: str) -> dict[str, Any]:
    q = urllib.parse.urlencode({"access_token": access_token, "openid": openid})
    url = f"https://api.weixin.qq.com/sns/userinfo?{q}"
    with urllib.request.urlopen(url, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def qq_authorize_url(*, app_id: str, redirect_uri: str, state: str) -> str:
    q = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": app_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "scope": "get_user_info",
        }
    )
    return f"https://graph.qq.com/oauth2.0/authorize?{q}"


def _qq_parse_token_body(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in raw.split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k] = v
    return out


def qq_exchange_code(
    app_id: str, secret: str, code: str, redirect_uri: str
) -> dict[str, Any]:
    q = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "client_id": app_id,
            "client_secret": secret,
            "code": code,
            "redirect_uri": redirect_uri,
            "fmt": "json",
        }
    )
    url = f"https://graph.qq.com/oauth2.0/token?{q}"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"QQ token HTTP {e.code}: {body}") from e

    if body.strip().startswith("{"):
        data = json.loads(body)
        if "access_token" not in data:
            raise RuntimeError(f"QQ token 响应异常: {data}")
        return data
    parsed = _qq_parse_token_body(body)
    if "access_token" not in parsed:
        raise RuntimeError(f"QQ token 响应异常: {body[:200]}")
    return parsed


def qq_openid(access_token: str) -> str:
    url = f"https://graph.qq.com/oauth2.0/me?access_token={urllib.parse.quote(access_token)}"
    with urllib.request.urlopen(url, timeout=30) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    m = re.search(r"\{[\s\S]*\}", raw)
    if not m:
        raise RuntimeError(f"QQ openid 解析失败: {raw[:200]}")
    data = json.loads(m.group())
    oid = data.get("openid")
    if not oid:
        raise RuntimeError(f"QQ openid 缺失: {data}")
    return str(oid)


def qq_user_info(access_token: str, app_id: str, openid: str) -> dict[str, Any]:
    q = urllib.parse.urlencode(
        {
            "access_token": access_token,
            "oauth_consumer_key": app_id,
            "openid": openid,
            "fmt": "json",
        }
    )
    url = f"https://graph.qq.com/user/get_user_info?{q}"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        _LOG.warning("QQ get_user_info 失败: %s", e)
        return {}
