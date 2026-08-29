#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
多站点 New API 自动签到（纯 HTTP，零第三方依赖）。

设计参考 newapi-checkin 的 api 动作状态机：
  1. GET /api/user/self          验证凭据并记录签到前余额
  2. GET /api/user/checkin?month → checked_in_today，已签则短路
  3. POST /api/user/checkin      执行签到
  4. 奖励缺失时用「余额差 + 已签标记」交叉验证，绝不谎报成功

用法：
  python checkin.py                 # 执行 ACCOUNTS.json 中全部启用站点
  python checkin.py --validate      # 校验配置 + 探测各站认证是否有效
  python checkin.py --name tabitoken  # 只跑指定站点
环境变量：
  ACCOUNTS_FILE    配置文件路径（默认 ACCOUNTS.json）
  CHECKIN_PROXY    可选出站代理 http://host:port
  TG_BOT_TOKEN / TG_CHAT_ID  可选 Telegram 通知（二者齐备才启用）
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import ssl
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

# ────────────────────────── 常量 ──────────────────────────

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
QUOTA_PER_UNIT = 500000  # New API: quota / 500000 = 美元
MAX_RETRIES = 2          # 仅网络层错误重试（业务失败不重试，避免重复 POST）
RETRY_BACKOFF = 2.0

# 签到状态分类词表（源自 newapi-checkin providers/base.py 的实测沉淀）
ALREADY_DONE_PATTERNS = ["已签到", "今日已", "已领取", "明天再来", "already"]
NOT_OPEN_PATTERNS = [
    "签到功能未启用", "签到功能已关闭", "签到功能暂未开放", "签到未开放",
    "签到已关闭", "未开启签到", "活动未开始", "活动已结束", "活动未开放",
]
LOGIN_PATTERNS = ["登录", "unauthorized", "not logged in", "未登录", "无权", "权限不足"]
VERIFICATION_PATTERNS = [
    "turnstile", "captcha", "验证码", "人机验证", "请完成验证",
]

# 「HTTP 拿到的是防护页而不是业务响应」的特征。
# challenge = 可解挑战（需真浏览器执行 JS）；block = 出口 IP 被安全规则终局拒绝，
# 换浏览器也没用，只能换代理节点 —— 两者必须分开报告。
CF_CHALLENGE_PATTERNS = [
    "just a moment", "checking your browser", "cf-challenge", "cf_chl_opt",
]
CF_BLOCK_PATTERNS = [
    "sorry, you have been blocked", "attention required! | cloudflare",
    "you are unable to access", "error 1020", "access denied | cloudflare",
    "cf-error-details",
]
ALIYUN_WAF_PATTERNS = ["aliyun_waf", "acw_sc__", "slidecaptcha", "var arg1="]


# ────────────────────────── 数据结构 ──────────────────────────

@dataclass
class ApiError(Exception):
    message: str
    status: int | None = None
    payload: object = None
    transient: bool = False
    kind: str = ""  # waf_challenge / waf_block / html

    def __str__(self) -> str:
        return self.message


@dataclass
class SiteConfig:
    name: str
    base_url: str
    user_id: str = ""
    access_token: str = ""
    cookie: str = ""
    enabled: bool = True
    referer_path: str = "/profile"
    verify_ssl: bool = True
    proxy: str = ""
    quota_per_unit: int = QUOTA_PER_UNIT
    raw: dict = field(default_factory=dict)


@dataclass
class Outcome:
    name: str
    base_url: str
    status: str            # success / already_done / need_login / need_verification / not_open / network_error / error / need_config
    message: str
    quota_awarded_usd: float | None = None
    current_quota_usd: float | None = None
    username: str = ""


# ────────────────────────── 工具 ──────────────────────────

def mask(text: str, keep: int = 6) -> str:
    """脱敏：长凭据只保留头尾少量字符。"""
    text = str(text or "")
    if len(text) <= keep * 2:
        return "***" if text else ""
    return text[:keep] + "***" + text[-keep:]


def fmt_usd(value) -> str:
    return f"${float(value):.4f}".rstrip("0").rstrip(".") if value is not None else "N/A"


def contains_any(haystack: str, needles) -> bool:
    h = (haystack or "").lower()
    return any(str(n).lower() in h for n in needles)


def waf_page_kind(text: str) -> str:
    """判断 HTML 响应属于哪类防护页：challenge(可解) / block(IP被封) / ''。"""
    if not text:
        return ""
    if contains_any(text, CF_BLOCK_PATTERNS):
        return "waf_block"
    if contains_any(text, CF_CHALLENGE_PATTERNS) or contains_any(text, ALIYUN_WAF_PATTERNS):
        return "waf_challenge"
    return ""


def describe_html(text: str) -> str:
    """把 HTML 响应压成一句诊断（页面标题 + 长度），不倾倒整页。"""
    kind = waf_page_kind(text)
    title = re.search(r"<title[^>]*>(.*?)</title>", text or "", re.I | re.S)
    title_text = (title.group(1).strip()[:60] if title else "")
    ray = re.search(r"Ray ID:\s*(?:<[^>]+>\s*)*([0-9a-f]{8,32})", text or "", re.I)
    if kind == "waf_block":
        extra = f"，Ray ID={ray.group(1)}" if ray else ""
        return f"Cloudflare 已拒绝当前出口 IP{extra}（IP 被站点安全规则封禁，需更换代理节点）"
    if kind == "waf_challenge":
        return f"站点返回人机验证挑战页（{title_text or 'Cloudflare/WAF'}），纯 HTTP 无法通过，需浏览器执行 JS"
    if title_text:
        return f"接口返回 HTML 而非 JSON（title={title_text}，共 {len(text)} 字符）"
    return f"接口返回 HTML 而非 JSON（共 {len(text)} 字符）"


def log(msg: str) -> None:
    print(f"[{dt.datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


# ────────────────────────── HTTP 客户端 ──────────────────────────

class NewApiClient:
    """单个 New API 站点的最小 HTTP 客户端（stdlib urllib）。"""

    def __init__(self, site: SiteConfig):
        self.site = site
        self.base_url = site.base_url.rstrip("/")
        self.referer = self.base_url + (site.referer_path if site.referer_path.startswith("/") else "/" + site.referer_path)
        self.proxy = site.proxy or os.getenv("CHECKIN_PROXY", "")
        handlers: list = []
        if self.proxy:
            handlers.append(urllib.request.ProxyHandler({"http": self.proxy, "https": self.proxy}))
        if not site.verify_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        self._opener = urllib.request.build_opener(*handlers)

    # -- 底层请求 --
    def request(self, method: str, path: str, body: dict | None = None) -> object:
        url = self.base_url + path
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Origin": self.base_url,
            "Referer": self.referer,
            "Cache-Control": "no-store",
        }
        if self.site.user_id:
            headers["New-Api-User"] = str(self.site.user_id)
        if self.site.access_token:
            headers["Authorization"] = f"Bearer {self.site.access_token}"
        if self.site.cookie:
            headers["Cookie"] = self.site.cookie
        data = None
        if body is not None or method.upper() == "POST":
            data = json.dumps(body or {}).encode("utf-8")
            headers["Content-Type"] = "application/json;charset=UTF-8"

        attempts = MAX_RETRIES + 1
        last_exc: Exception | None = None
        for attempt in range(attempts):
            try:
                return self._open(method, url, headers, data)
            except urllib.error.HTTPError as exc:
                # 4xx/5xx 是服务端应答：不重试，读出响应体用于分类
                raw = exc.read().decode("utf-8", "replace")
                raise self._as_api_error(exc.code, raw) from exc
            except ApiError:
                raise
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_exc = exc
                if attempt + 1 >= attempts:
                    break
                sleep_s = RETRY_BACKOFF * (2 ** attempt)
                log(f"  [{self.site.name}] 网络错误，{sleep_s:.0f}s 后重试 ({attempt + 1}/{MAX_RETRIES}): {exc}")
                time.sleep(sleep_s)
        raise ApiError(f"网络错误: {last_exc}", transient=True)

    def _open(self, method: str, url: str, headers: dict, data: bytes | None) -> object:
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with self._opener.open(req, timeout=30) as resp:
            text = resp.read().decode("utf-8", "replace")
        return self._parse_json(text)

    def _parse_json(self, text: str) -> object:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            kind = waf_page_kind(text)
            raise ApiError(describe_html(text), payload=text[:300], kind=kind)

    def _as_api_error(self, status: int, raw: str) -> ApiError:
        try:
            payload = json.loads(raw)
            if isinstance(payload, dict):
                msg = payload.get("message") or payload.get("error") or f"HTTP {status}"
                return ApiError(str(msg), status=status, payload=payload)
        except json.JSONDecodeError:
            pass
        kind = waf_page_kind(raw)
        msg = describe_html(raw) if (kind or (raw or "").lstrip().startswith("<")) else f"HTTP {status}: {raw[:160]}"
        return ApiError(msg, status=status, payload=raw[:300], kind=kind)

    # -- 业务接口 --
    def fetch_user(self) -> dict:
        """GET /api/user/self → {quota, username}"""
        payload = self._require_success(self.request("GET", "/api/user/self"))
        data = payload.get("data") or {}
        return {
            "quota": data.get("quota"),
            "username": str(data.get("username") or data.get("display_name") or ""),
            "id": data.get("id"),
        }

    def fetch_status(self) -> dict:
        """GET /api/user/checkin?month= → {checked_in_today, enabled}"""
        month = dt.datetime.now().strftime("%Y-%m")
        payload = self._require_success(
            self.request("GET", f"/api/user/checkin?{urllib.parse.urlencode({'month': month})}")
        )
        data = payload.get("data") or {}
        stats = data.get("stats") or {}
        return {
            "enabled": bool(data.get("enabled", True)),
            "checked_in_today": stats.get("checked_in_today") if "checked_in_today" in stats else None,
            "raw": data,
        }

    def do_checkin(self) -> dict:
        """POST /api/user/checkin → {quota_awarded, ...}"""
        payload = self._require_success(self.request("POST", "/api/user/checkin", body={}))
        data = payload.get("data") or {}
        return {
            "quota_awarded": data.get("quota_awarded"),
            "checkin_date": data.get("checkin_date"),
            "raw": payload,
        }

    @staticmethod
    def _require_success(payload: object) -> dict:
        if not isinstance(payload, dict):
            raise ApiError("接口返回非 JSON 对象", payload=payload)
        if payload.get("success") is False:
            raise ApiError(str(payload.get("message") or "接口返回失败"), payload=payload)
        return payload


# ────────────────────────── 分类 ──────────────────────────

def classify_error(err: ApiError) -> str:
    """把 ApiError 归类为稳定状态（顺序即优先级，参考 newapi-checkin classify）。"""
    if err.kind == "waf_block" or err.kind == "waf_challenge":
        return "need_verification"
    if err.status == 401:
        return "need_login"
    msg = err.message or ""
    if contains_any(msg, NOT_OPEN_PATTERNS):
        return "not_open"
    if contains_any(msg, ALREADY_DONE_PATTERNS):
        return "already_done"
    if contains_any(msg, VERIFICATION_PATTERNS):
        return "need_verification"
    if err.transient:
        return "network_error"
    if contains_any(msg, LOGIN_PATTERNS):
        return "need_login"
    return "error"


STATUS_HINTS = {
    "need_login": "凭据失效或不被接受：请重新采集 access_token / user_id（GitHub 登录站点 → 控制台生成系统访问令牌）",
    "need_verification": "站点启用了 Cloudflare/Turnstile 防护，纯 HTTP 无法通过；需浏览器流程或更换代理出口 IP",
    "not_open": "站点未开放签到功能（非账号问题）",
    "network_error": "临时网络失败，下次运行会自动重试",
    "need_config": "配置缺失：user_id 与 access_token 必须同时提供",
}


# ────────────────────────── 签到状态机 ──────────────────────────

def run_site(site: SiteConfig, *, probe_only: bool = False) -> Outcome:
    tag = f"[{site.name}]"

    if not site.base_url or not site.access_token or not site.user_id:
        return Outcome(site.name, site.base_url, "need_config", STATUS_HINTS["need_config"])

    client = NewApiClient(site)
    log(f"{tag} 开始处理 {site.base_url}")

    try:
        # 1) 验证凭据 + 记录签到前余额（没有比余额差更可靠的发放证据）
        user = client.fetch_user()
        quota_before = user.get("quota")
        quota_before_usd = to_usd(quota_before, site)
        log(f"{tag} 认证有效 (用户: {user.get('username') or mask(site.user_id)}, 余额: {fmt_usd(quota_before_usd)})")
        if probe_only:
            return Outcome(site.name, site.base_url, "success", "认证有效", current_quota_usd=quota_before_usd, username=user.get("username") or "")

        # 2) 查签到状态：已签则短路
        status = client.fetch_status()
        if status.get("checked_in_today") is True:
            log(f"{tag} 今日已签到，跳过")
            return Outcome(site.name, site.base_url, "already_done", "今日已签到，无需重复签到",
                           current_quota_usd=quota_before_usd, username=user.get("username") or "")

        # 3) 执行签到
        result = client.do_checkin()
        awarded = result.get("quota_awarded")

        # 4) 结果确认：奖励字段缺失/为 0 时不轻信，用余额差与已签标记交叉验证
        awarded_usd = to_usd(awarded, site) if awarded else None
        current_usd = None
        if not awarded_usd:
            time.sleep(1)
            user_after = client.fetch_user()
            current_usd = to_usd(user_after.get("quota"), site)
            if quota_before_usd is not None and current_usd is not None and current_usd - quota_before_usd > 1e-9:
                awarded_usd = round(current_usd - quota_before_usd, 6)
                log(f"{tag} 接口未返回奖励字段，按余额差确认 +{fmt_usd(awarded_usd)}")
            else:
                st2 = client.fetch_status()
                if st2.get("checked_in_today") is True:
                    log(f"{tag} 接口未返回奖励，但站点已标记今日已签到")
                    return Outcome(site.name, site.base_url, "success", "签到成功（站点已标记今日已签到）",
                                   current_quota_usd=current_usd or quota_before_usd,
                                   username=user.get("username") or "")
                return Outcome(site.name, site.base_url, "error",
                               "签到接口返回成功但未发放额度，站点也未标记已签到；可能需要在网页手动签到或接口已变更",
                               current_quota_usd=current_usd or quota_before_usd)
        else:
            # 有奖励字段时也补一次当前余额，失败不致命
            try:
                current_usd = to_usd(client.fetch_user().get("quota"), site)
            except Exception:
                current_usd = quota_before_usd

        message = f"签到成功，获得额度：{fmt_usd(awarded_usd)}"
        log(f"{tag} ✓ {message}（当前: {fmt_usd(current_usd)}）")
        return Outcome(site.name, site.base_url, "success", message,
                       quota_awarded_usd=awarded_usd, current_quota_usd=current_usd,
                       username=user.get("username") or "")

    except ApiError as exc:
        kind = classify_error(exc)
        hint = STATUS_HINTS.get(kind, "")
        message = f"{exc.message}" + (f"；{hint}" if hint else "")
        log(f"{tag} ✗ {kind}: {exc.message}")
        return Outcome(site.name, site.base_url, kind, message)
    except Exception as exc:  # 兜底：未知异常不中断其他站点
        log(f"{tag} ✗ 未预期异常: {type(exc).__name__}: {exc}")
        return Outcome(site.name, site.base_url, "error", f"{type(exc).__name__}: {exc}")


def to_usd(quota, site: SiteConfig) -> float | None:
    if isinstance(quota, bool) or not isinstance(quota, (int, float)):
        return None
    return quota / (site.quota_per_unit or QUOTA_PER_UNIT)


# ────────────────────────── 配置加载 ──────────────────────────

def load_sites(path: str, only_name: str | None = None) -> list[SiteConfig]:
    if not os.path.exists(path):
        raise SystemExit(f"配置文件不存在: {path}（请参考 ACCOUNTS.example.json 或设置 ACCOUNTS_FILE）")
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    items = raw.get("accounts") if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        raise SystemExit("配置格式错误：应为 {\"accounts\": [...]} 或站点数组")
    sites = []
    for item in items:
        if not isinstance(item, dict):
            continue
        site = SiteConfig(
            name=str(item.get("name") or urllib.parse.urlparse(str(item.get("base_url", ""))).netloc or "未命名"),
            base_url=str(item.get("base_url") or "").rstrip("/"),
            user_id=str(item.get("user_id") or ""),
            access_token=str(item.get("access_token") or ""),
            cookie=str(item.get("cookie") or ""),
            enabled=bool(item.get("enabled", True)),
            referer_path=str(item.get("referer_path") or "/profile"),
            verify_ssl=bool(item.get("verify_ssl", True)),
            proxy=str(item.get("proxy") or ""),
            quota_per_unit=int(item.get("quota_per_unit") or QUOTA_PER_UNIT),
            raw=item,
        )
        if only_name and site.name != only_name:
            continue
        if not site.enabled:
            log(f"[{site.name}] 已禁用，跳过")
            continue
        sites.append(site)
    if only_name and not sites:
        raise SystemExit(f"未找到名为 {only_name!r} 的启用站点")
    return sites


# ────────────────────────── 通知与汇总 ──────────────────────────

def notify_telegram(outcomes: list[Outcome]) -> None:
    token = os.getenv("TG_BOT_TOKEN", "")
    chat_id = os.getenv("TG_CHAT_ID", "")
    if not token or not chat_id or not outcomes:
        return
    ok = sum(1 for o in outcomes if o.status in ("success", "already_done"))
    lines = [f"{'✅' if ok == len(outcomes) else '⚠️'} 多站签到 {ok}/{len(outcomes)}"]
    icon_map = {"success": "✅", "already_done": "🎁"}
    for o in outcomes:
        icon = icon_map.get(o.status, "❌")
        detail = ""
        if o.status == "success" and o.quota_awarded_usd:
            detail = f"；获得 {fmt_usd(o.quota_awarded_usd)}"
        if o.current_quota_usd is not None:
            detail += f"；余额 {fmt_usd(o.current_quota_usd)}"
        if o.status not in ("success", "already_done"):
            detail = f"；{o.message[:120]}"
        lines.append(f"{icon} [{o.name}] {o.status}{detail}")
    body = "\n".join(lines)
    try:
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=json.dumps({"chat_id": chat_id, "text": body}).encode(),
            headers={"Content-Type": "application/json"},
        )
        urllib.request.build_opener().open(req, timeout=15).read()
        log("Telegram 通知已发送")
    except Exception as exc:
        log(f"Telegram 通知失败: {exc}")


def write_summary(outcomes: list[Outcome]) -> None:
    """写 GitHub Actions Step Summary（存在 $GITHUB_STEP_SUMMARY 时）。"""
    path = os.getenv("GITHUB_STEP_SUMMARY")
    if not path:
        return
    rows = "\n".join(
        f"| {o.name} | `{o.status}` | {o.message[:80]} | "
        f"{fmt_usd(o.quota_awarded_usd) if o.quota_awarded_usd else '-'} | "
        f"{fmt_usd(o.current_quota_usd) if o.current_quota_usd is not None else '-'} |"
        for o in outcomes
    )
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(
            "## 签到结果\n\n| 站点 | 状态 | 说明 | 获得 | 余额 |\n|---|---|---|---|---|\n"
            + rows + "\n"
        )


# ────────────────────────── 入口 ──────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="多站点 New API 自动签到")
    parser.add_argument("--validate", action="store_true", help="校验配置并探测认证（不签到）")
    parser.add_argument("--name", help="只运行指定名称的站点")
    args = parser.parse_args()

    accounts_path = os.getenv("ACCOUNTS_FILE", "ACCOUNTS.json")
    sites = load_sites(accounts_path, args.name)
    if not sites:
        log("没有启用站点，退出")
        return 1

    log(f"共 {len(sites)} 个站点，模式: {'探测' if args.validate else '签到'}")
    outcomes = [run_site(s, probe_only=args.validate) for s in sites]

    print("\n" + "=" * 62)
    ok = 0
    for o in outcomes:
        good = o.status in ("success", "already_done")
        ok += good
        icon = "✅" if good else "❌"
        detail = o.message
        if o.status == "success" and o.quota_awarded_usd:
            detail += f"；当前余额 {fmt_usd(o.current_quota_usd)}"
        print(f"{icon} [{o.name}] {o.status} - {detail}")
        print(f"   站点地址: {o.base_url}")
    print("=" * 62)
    log(f"完成: {ok}/{len(outcomes)}")

    notify_telegram(outcomes)
    write_summary(outcomes)
    return 0 if ok == len(outcomes) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:
        log("未预期错误:")
        traceback.print_exc()
        sys.exit(2)
