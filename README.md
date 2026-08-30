多站点 New API 自动签到（tabitoken / gorouter / api.justwoker.icu 等），**纯 HTTP 接口签到，零第三方依赖**。

GitHub OAuth 登录的账号无需账密：只需在站点控制台生成一次「系统访问令牌」，之后每日自动签到全自动。

站点启用 Cloudflare Turnstile 人机验证（如 gorouter.app）时，自动切换「**浏览器拿令牌 + HTTP 提交**」混合模型，无需人工介入。

## 工作原理

```
GET  /api/user/self              验证凭据 + 记录签到前余额
GET  /api/user/checkin?month=…   查询状态：今日已签 → 跳过
POST /api/user/checkin           执行签到
GET  /api/user/self              交叉验证（奖励字段缺失时用余额差确认，绝不谎报成功）
```

- 认证：`Authorization: Bearer <access_token>` + `New-Api-User: <user_id>`
- 站点返回 Cloudflare/WAF 页面时自动识别分类：可解挑战 → 提示需浏览器；IP 被封 → 提示换代理
- 额度换算：`quota ÷ 500000 = 美元`

### Turnstile 混合模型（签到被拒时自动触发）

```
POST /api/user/checkin           → 「Turnstile token 为空」
GET  /api/status                 → 取 turnstile_site_key
Camoufox 反检测浏览器             → 站点 origin 下打开最小承载页（不下载 SPA），
                                   注入 Turnstile widget，自动/真实鼠标点击，
                                   等待 Cloudflare 签发令牌
POST /api/user/checkin?turnstile=<token>   → 令牌签到，复用原认证
```

令牌绑定 (sitekey, hostname, 出口 IP)，浏览器与 HTTP 层共用同一代理出口。全程只消费 Cloudflare 正常签发的令牌，不伪造、不绕过。

## 使用方法

### 第一步：采集凭据（每站 3 分钟，一次性）

1. 浏览器正常 GitHub 登录站点（如 https://tabitoken.com）
2. 按 F12 打开控制台 → Console 标签
3. 粘贴 `collector.js` 全部内容并回车 → 自动输出 `user_id`
4. 打开站点控制台 → **个人设置 → 生成系统访问令牌**，复制 `access_token`

### 第二步：配置

复制 `ACCOUNTS.example.json` 为 `ACCOUNTS.json`，填入采集到的凭据：

```json
{
  "accounts": [
    {
      "name": "tabitoken",
      "base_url": "https://tabitoken.com",
      "user_id": "12345",
      "access_token": "生成的系统访问令牌",
      "enabled": true
    },
    {
      "name": "gorouter",
      "base_url": "https://gorouter.app",
      "user_id": "67890",
      "access_token": "生成的系统访问令牌",
      "turnstile": "auto",
      "enabled": true
    }
  ]
}
```

> `user_id` + `access_token` 必须同时提供（缺任一报 `need_config`）。
> `turnstile`: `auto`（默认，签到被拒时自动用浏览器求解令牌）/ `off`（关闭，报 `need_verification`）。

### 本地运行 Turnstile 求解（仅 Turnstile 站点需要）

```bash
pip install -r requirements.txt
python checkin.py --name gorouter
```

浏览器策略：**真实 Chrome + Patchright（反检测 Playwright fork）+ screenX 主世界补丁**为主路径（Cloudflare 会丢弃跨域 iframe 内 screenX 过小的点击事件，补丁改写该值）；**Camoufox 反检测 Firefox** 为兜底（需 `python -m camoufox fetch`）。CI 默认在 xvfb 虚拟显示下有头运行（`CHECKIN_HEADLESS` 可覆盖）。

### 第三步：本地运行（可选验证）

```bash
python checkin.py --validate    # 只探测认证，不签到
python checkin.py               # 执行签到
python checkin.py --name tabitoken   # 只跑一个站
```

### 第四步：GitHub Actions 自动运行

1. 仓库 **Settings → Secrets and variables → Actions → New repository secret**
2. 添加 `ACCOUNTS`：整个 `ACCOUNTS.json` 的内容（JSON 文本）
3. 可选：`TG_BOT_TOKEN` / `TG_CHAT_ID`（Telegram 通知）、`CHECKIN_PROXY`（出站代理）
4. 前往 **Actions** 启用 workflow，每天北京时间 09:30 自动运行，也可手动触发测试

运行结果会写入 Step Summary 表格（站点 / 状态 / 说明 / 获得 / 余额）。

## 状态说明

| 状态 | 含义 | 处理 |
|---|---|---|
| `success` | 签到成功，奖励已确认 | 无 |
| `already_done` | 今日已签，自动跳过 | 无 |
| `need_config` | 缺 user_id 或 access_token | 补全配置 |
| `need_login` | 令牌失效（401） | 重新生成系统访问令牌 |
| `need_verification` | Cloudflare/WAF 拦截 | Turnstile 已配自动求解仍失败 → 配置住宅代理重试；WAF 拦截页 → 更换代理出口 IP |
| `not_open` | 站点未开放签到 | 无（站点侧问题） |
| `network_error` | 临时网络失败 / 站点 5xx | 下次运行自动重试 |
| `error` | 业务拒绝或结果无法确认 | 查看日志详情 |

## 安全

- `ACCOUNTS.json` 已被 `.gitignore` 忽略，只通过 GitHub Secret 传递
- 日志中凭据自动脱敏
- workflow 运行结束立即删除落盘的凭据文件
