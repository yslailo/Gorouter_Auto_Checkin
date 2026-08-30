---
name: cf-turnstile-bypass
description: Cloudflare Turnstile 人机验证自动绕过实战知识——当需要在纯 HTTP 签到/爬虫场景过 Turnstile、排查「Turnstile token 为空」「600010」「点击后静默不签发」、配置代理池多节点探测、或复用 New API 站点签到方案时使用。
---

# Cloudflare Turnstile 自动绕过（实测沉淀）

本仓库 `checkin.py` 已实现完整方案（Patchright + screenX 补丁 + 代理池），本文档沉淀其原理与踩坑，供复用到其他项目/站点。

## 1. 核心认知（先读这个）

- **令牌三元绑定**：Turnstile 令牌绑定 `(sitekey, hostname, 出口 IP)`。求解浏览器与最终提交必须同一出口 IP，否则服务端拒绝。
- **令牌一次性、短时效**（~5 分钟）：拿到就提交，不缓存不重放。
- **sitekey 是公开的**：`GET /api/status` 返回 `turnstile_check` + `turnstile_site_key`，无需登录。
- **提交格式**（New API legacy 接口）：`POST /api/user/checkin?turnstile=<token>`，带 `Authorization: Bearer <token>` + `New-Api-User: <id>`。
- **最优架构 = 混合模型**：浏览器只负责「渲染 widget → 等令牌」，拿到令牌后在**页面内** `fetch` 提交业务请求——UA/TLS 指纹/sec-ch 头/出口 IP 与签发环境天然一致，免疫服务端一致性校验。

## 2. 检测层与对策（全部实测验证）

| 检测层 | 症状 | 对策 |
|---|---|---|
| 自动化浏览器参数（`--disable-web-security`、`--enable-automation` 等） | 点击后 `error/600010` | Patchright（Playwright 反检测 fork）+ `ignore_default_args=["--enable-automation","--disable-extensions"]` + 系统真实 Chrome |
| **跨域 iframe 内 `screenX < ~120` 的点击事件被静默丢弃** | 点击后状态永远停在 `rendered`，无错误码 | `MouseEvent.prototype.screenX/screenY` getter 补丁（见 §3），`add_init_script` 导航前注入（覆盖所有后续 frame 含 challenges.cloudflare.com） |
| CDP `Runtime.enable` / Playwright 运行时痕迹 | 指纹层面被识别 | Patchright（C++ 层剔除）；裸 CDP 也可，但 Playwright 不行 |
| 机房/脏 IP 信誉 | 点击被采纳但 `600010`（显式拒绝）或永远 `rendered`（静默惩罚） | 代理池多节点探测（§5）或住宅代理 |
| headless 指纹 | 渲染/交互异常 | CI 用 `xvfb-run` + 有头模式；`--headless=new` 也不够可信 |

判定口诀：**`rendered` 静默 = 事件被丢或 IP 惩罚；`600010` = 环境被显式拒绝；整页 Just a moment = WAF 层**。同代码跨环境 A/B（本机 vs CI）即可归因。

## 3. screenX 补丁（本项目最关键一招）

来源 shield-bypass（MIT）。要点：CDP/XTEST 派发的点击在 Turnstile 跨域 iframe 内 `screenX` 退化为 clientX 或 widget 偏移（<120），真实鼠标相对显示器是数百像素——CF 以此判假。

```js
// add_init_script 注入（主世界，导航前生效，覆盖全部 frame）
(() => {
  if (globalThis.__cfTurnstileClickPatch) return;
  globalThis.__cfTurnstileClickPatch = 1;
  const rand = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
  const framed = (() => { try { return window.top !== window; } catch (_) { return true; } })();
  const originX = !framed && window.screenX > 50 ? window.screenX : rand(240, 960);
  const originY = !framed && window.screenY > 40 ? window.screenY : rand(80, 420);
  function needsPatch(native, client) {
    if (!Number.isFinite(native)) return true;
    if (native < 120 && Math.abs(native - client) < 2) return true;  // CDP 特征
    if (window.top !== window && native < 120) return true;          // iframe 小值
    return false;
  }
  for (const proto of [MouseEvent.prototype, window.PointerEvent?.prototype]) {
    if (!proto) continue;
    for (const name of ["screenX", "screenY"]) {
      const desc = Object.getOwnPropertyDescriptor(proto, name);
      const origGet = desc && desc.get;
      const axis = name.endsWith("X") ? "X" : "Y";
      const origin = axis === "X" ? originX : originY;
      Object.defineProperty(proto, name, { configurable: true, enumerable: !!(desc && desc.enumerable),
        get() { let n = 0; try { n = origGet ? origGet.call(this) : 0; } catch (_) {}
                const c = axis === "X" ? (Number(this.clientX || 0) || 0) : (Number(this.clientY || 0) || 0);
                return needsPatch(n, c) ? origin + c : n; } });
    }
  }
})();
```

注意：Chrome 会自动按窗口位置补算 screenX（无需手动传 CDP `screenX` 参数）；补丁拦截的是**事件对象读取**，CF 在 iframe 内读取时拿到的就是补丁值。

## 4. 求解流程（checkin.py 已实现）

1. 启动：Patchright `launch_persistent_context`（临时 profile、`no_viewport=True`、系统 Chrome），注入补丁
2. **直接导航真实 SPA**（不要用 Playwright 路由拦截/Fetch 域——可检测面）；整页挑战先等通过（≤15s）
3. 主世界注入 widget bootstrap：`window.turnstile.render(slot, {sitekey, callback, error-callback})`；令牌读两处——自写 callback 的 `data-token` 属性 + `input[name=cf-turnstile-response]`
4. 100ms 轮询：`rendered` 且未点过 → 元素级点击（`frame_locator` 探测 checkbox 可见性 → `handle.click(position={26,32}, delay=60, force=True)`）；10s 无令牌重试（≤3 次）
5. 令牌到手 → 页面内 fetch 提交 → 解析 `{success, message, data:{quota_awarded}}`
6. 兜底：Camoufox（`humanize=0.6, geoip=True, os="macos"`，Firefox 侧无 screenX 补丁，靠自身反检测）

闭环原则：**「拿到令牌」是唯一成功判据**，点击是否点中不用猜（closed shadow root 无法直查 checkbox，FakeShadowRoot 是 CloakBrowser 私有内核特性，普通 Chrome 没有）。

## 5. 代理池模式（机房 IP 的解法）

架构（适配 Clash 订阅 yaml，节点 100+）：

```
下载池 yaml → mihomo「预筛实例」加载全部节点
  → GET /group/GLOBAL/delay 一次测活全部节点（含劫持/死节点剔除）
  → 按延迟排序取前 N（默认 24）
  → K 个并发 worker（默认 3）：每个 worker 独立 mihomo（minimal config 钉死单节点）
    + 独立浏览器探测 → 出令牌 = 节点可用
  → 首个出令牌者独占提交（claim Event），成功/已签 → 全局停止
```

关键约束与坑：

- **solve 与 submit 必须同 worker 同节点**（令牌绑 IP）
- **探测不发业务 POST**，只有胜者提交一次（避免多 IP 打同一账号触发账号风控）
- mihomo 配置要**剔除池子自带的 proxy-groups/rules**（组间引用/重名是启动失败首因——实测池内有叫 `PASS` 的组），兜底组用随机唯一名
- 失败分类：`ERR_CONNECTION_CLOSED/TIMED_OUT`=死节点；`ERR_CERT_COMMON_NAME_INVALID`=SNI 劫持；`600010`=IP 拒绝；`rendered` 静默=信誉惩罚
- mihomo 启动失败必须**落盘 stderr 并回显日志尾部**，否则只有 rc=1 无法定位

## 6. 可复用清单

- 本仓库 `checkin.py`：`_SCREENX_PATCH_JS` / `_WIDGET_BOOTSTRAP_JS` / `_solve_and_submit_chrome` / `_pool_flow_async`（直接抄）
- `newapi-checkin/scripts/newapi_turnstile.py`：Camoufox 求解鼻祖
- `shield-bypass/bypass/ext/script.js` + `plugins/cf_turnstile.py`：screenX 规则与点击策略来源
- `CloudflareBypassForScraping`：FakeShadowRoot 内核 + curl_cffi TLS 镜像思路（重依赖路线）

## 7. 已知边界（不要浪费时间的方向）

- CF 把 IP 拉黑时任何代码都无效——唯一杠杆是换 IP（代理池/住宅代理）
- 补丁可被反检测（getter toString 特征）——猫鼠游戏，失效时先查 getter 是否被识破
- widget 布局改版会使 (26,32) 失效——用 checkbox 可见性探测 + 多候选坐标缓解
- 站点换验证体系（hCaptcha/自研）→ 需要新求解器，本方案不适用
