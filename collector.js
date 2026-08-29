// collector.js — 在已登录的 New API 站点控制台执行，采集签到所需凭据。
// 使用方法：浏览器 GitHub 登录站点后，F12 → Console → 粘贴本文件全部内容并回车。
(async () => {
  const ls = (k) => localStorage.getItem(k);
  const userRaw = ls("user");
  let userId = "";
  let username = "";
  try {
    const u = JSON.parse(userRaw || "{}");
    userId = String(u.id || "");
    username = u.username || u.display_name || "";
  } catch (_) {}

  // 兜底：直接调 self 接口确认身份（走浏览器 session）
  let selfData = null;
  try {
    const resp = await fetch("/api/user/self", {
      headers: { Accept: "application/json" },
      credentials: "include",
      cache: "no-store",
    });
    const payload = await resp.json();
    if (payload && payload.success) selfData = payload.data;
  } catch (_) {}
  if (selfData) {
    userId = String(selfData.id || userId);
    username = selfData.username || selfData.display_name || username;
  }

  console.log("%c== New API 站点凭据采集 ==", "color:#0af;font-weight:bold");
  console.log("站点地址   :", location.origin);
  console.log("用户名     :", username || "(未知)");
  console.log("user_id    :", userId || "(未获取到！请确认已登录)");
  console.log("");
  console.log("%c下一步：", "color:#f80;font-weight:bold");
  console.log("1. 打开控制台 → 个人设置/个人中心 → 找到「生成系统访问令牌 / Access Token」并复制");
  console.log("2. 把下面的 JSON 填进 ACCOUNTS.json（替换 <ACCESS_TOKEN> 占位符）：");
  console.log(JSON.stringify({
    name: location.hostname.replace(/\./g, "-"),
    base_url: location.origin,
    site_profile: "newapi",
    auth_method: "access_token",
    checkin_action: "api",
    user_id: userId || "<USER_ID>",
    access_token: "<ACCESS_TOKEN>",
    enabled: true,
  }, null, 2));
})();
