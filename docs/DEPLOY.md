# 部署到 msl-123ljc.top（Cloudflare）

## 一键方式（推荐）

```powershell
cd cloud_v3
powershell -ExecutionPolicy Bypass -File .\deploy_auto.ps1
```

如果你有 `ZoneId` 与 `ApiToken`，可自动绑定路由：

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy_auto.ps1 -ZoneId <ZONE_ID> -ApiToken <CF_API_TOKEN> -RoutePattern "msl-123ljc.top/*"
```

## 手动方式（备用）

1. 安装依赖

```powershell
cd cloud_v3
npm install
```

2. 首次创建 D1

```powershell
npx wrangler d1 create checkin_v3
```

把返回的 `database_id` 填入 `wrangler.toml`。

3. 初始化数据库

```powershell
npm run db:migrate
```

4. 设置 secret

```powershell
npx wrangler secret put ADMIN_PASSWORD
npx wrangler secret put WEB_UI_OTP_CODE
```

5. 部署

```powershell
npm run deploy
```

## 浏览器扩展步骤（必须手动）

以下两步因浏览器安全策略，不能由 Worker 自动点击：

1. 打开 `edge://extensions`，重载 `Checkin Browser Bridge`
2. 回控制台页面按 `Ctrl+F5`

## 上线后建议先做

1. 登录控制台
2. 用“自动接入并保存”接入一个站点
3. 验证“提取 Key / 创建 Key（分组）”
4. 验证“全站签到”
5. 验证“日志中心（系统日志 + usage 日志）”
6. 跑一次冒烟测试：

```powershell
powershell -ExecutionPolicy Bypass -File .\smoke_test.ps1 -BaseUrl "https://msl-123ljc.top" -Username "admin" -Password "你的密码" -OtpCode "你的验证码"
```
