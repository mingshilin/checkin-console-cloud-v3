# 云端签到控制台 v3（Cloudflare）

这是独立于本地 Python 版的云端实现，目标是：

- 电脑关机后仍可访问与签到
- 多账号/多工作区隔离
- Key 操作分离（提取 / 创建）+ 分组创建
- 双日志（系统调用日志 + 站点使用日志）
- 任务进度 SSE、定时签到 Cron

## 目录

- `src/worker.js`：Worker API + 定时任务 + Durable Object 锁
- `public/index.html`：中文控制台页面
- `migrations/0001_init.sql`：D1 表结构
- `wrangler.toml`：Cloudflare 配置
- `deploy_auto.ps1`：一键部署脚本
- `smoke_test.ps1`：一键冒烟测试脚本

## 一键部署（推荐）

```powershell
cd cloud_v3
powershell -ExecutionPolicy Bypass -File .\deploy_auto.ps1
```

可选参数：

```powershell
# 跳过 secrets 设置（仅部署）
powershell -ExecutionPolicy Bypass -File .\deploy_auto.ps1 -SkipSecrets

# 自动绑定域名路由（需要 ZoneId + ApiToken）
powershell -ExecutionPolicy Bypass -File .\deploy_auto.ps1 -ZoneId <ZONE_ID> -ApiToken <CF_API_TOKEN> -RoutePattern "msl-123ljc.top/*"
```

脚本会自动执行：

1. `npm install`
2. `wrangler` 登录检查（未登录会引导 login）
3. D1 创建（若 `database_id` 还是占位符）
4. D1 迁移
5. Worker 部署
6. 可选自动绑定域名路由

## 冒烟测试

```powershell
cd cloud_v3
powershell -ExecutionPolicy Bypass -File .\smoke_test.ps1 -BaseUrl "https://你的域名" -Username "admin" -Password "你的密码" -OtpCode "你的验证码"
```

## 首次登录

- 用户名：`ADMIN_USERNAME`（默认 `admin`）
- 密码：必须通过 `ADMIN_PASSWORD` secret 设置，未设置时不会自动创建管理员账号
- 二次验证码：`WEB_UI_OTP_CODE`（通过 secret 设置）

## 已实现 API（核心）

- `POST /api/onboarding/auto`
- `POST /api/onboarding/extract`
- `POST /api/onboarding/extract-credentials`
- `POST /api/onboarding/save-site`
- `GET /api/sites`
- `POST /api/sites`
- `PUT /api/sites/{site_id}`
- `DELETE /api/sites/{site_id}`
- `GET /api/site-capabilities/{site_id}`
- `GET /api/sites/{site_id}/keys`
- `POST /api/sites/{site_id}/keys/extract`
- `GET /api/sites/{site_id}/key-groups`
- `POST /api/sites/{site_id}/keys/create`
- `GET /api/api-url/{site_id}`
- `POST /api/channel/{site_id}/create`
- `POST /api/checkin/run`
- `GET /api/jobs/{job_id}/events`
- `GET /api/checkin/history`
- `GET /api/logs/system`
- `GET /api/logs/usage`
- `POST /api/logs/usage/refresh`
- `GET /api/logs/usage/export.csv`
- `GET /api/schedule`
- `PUT /api/schedule`
- `POST /api/schedule/run-now`

另外保留了旧路由兼容：

- `GET /api/token/{site_id}`
- `POST /api/token/{site_id}/create`
- `POST /api/token/{site_id}/ensure`
- `GET /api/request-log`

## 注意

- 当前凭据按你的要求是明文存储（D1）；后续可加密升级。
- 某些站点不提供签到接口时，控制台仍可接入并读取额度/日志。
- 使用日志抓取依赖各站点 API 是否开放对应日志端点。
- 浏览器安全限制下，以下两步不能由服务器强制自动点击：
  - `edge://extensions` 重载扩展
  - 控制台页面 `Ctrl+F5` 强刷
