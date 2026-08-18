param(
  [string]$DbName = "checkin_v3",
  [string]$RoutePattern = "msl-123ljc.top/*",
  [string]$ZoneId = "",
  [string]$ApiToken = "",
  [switch]$SkipSecrets,
  [switch]$SkipRouteBinding,
  [switch]$SkipRemoteMigrate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step([string]$msg) {
  Write-Host "`n=== $msg ===" -ForegroundColor Cyan
}

function Ensure-Tool([string]$name) {
  if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
    throw "缺少命令: $name"
  }
}

function Get-TomlValue([string]$toml, [string]$key) {
  $pattern = '{0}\s*=\s*"([^"]+)"' -f [regex]::Escape($key)
  $m = [regex]::Match($toml, $pattern)
  if ($m.Success) { return $m.Groups[1].Value }
  return ""
}

function Set-WranglerSecret([string]$name, [string]$value) {
  if ([string]::IsNullOrWhiteSpace($value)) { return }
  Write-Host "设置 secret: $name" -ForegroundColor Yellow
  $value | npx wrangler secret put $name | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "设置 secret 失败: $name"
  }
}

function Read-SecretText([string]$prompt) {
  $sec = Read-Host $prompt -AsSecureString
  if (-not $sec) { return "" }
  $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
  try {
    return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
  }
  finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
  }
}

Push-Location $PSScriptRoot
try {
  Write-Step "检查基础环境"
  Ensure-Tool "node"
  Ensure-Tool "npm"
  Ensure-Tool "npx"

  Write-Step "安装依赖"
  npm install
  if ($LASTEXITCODE -ne 0) { throw "npm install 失败" }

  Write-Step "检查 Wrangler 登录状态"
  $whoamiText = (npx wrangler whoami 2>&1 | Out-String)
  if ($LASTEXITCODE -ne 0 -or $whoamiText -match "not authenticated") {
    Write-Host "未登录 Cloudflare，开始执行 wrangler login ..." -ForegroundColor Yellow
    npx wrangler login
    if ($LASTEXITCODE -ne 0) { throw "wrangler login 失败" }
  }

  Write-Step "读取 wrangler.toml"
  $tomlPath = Join-Path $PSScriptRoot "wrangler.toml"
  if (-not (Test-Path $tomlPath)) { throw "未找到 wrangler.toml" }
  $toml = Get-Content $tomlPath -Raw

  $workerName = Get-TomlValue $toml "name"
  if ([string]::IsNullOrWhiteSpace($workerName)) { throw "wrangler.toml 缺少 name" }

  $databaseName = Get-TomlValue $toml "database_name"
  if ([string]::IsNullOrWhiteSpace($databaseName)) { $databaseName = $DbName }

  $databaseId = Get-TomlValue $toml "database_id"
  if ([string]::IsNullOrWhiteSpace($databaseId) -or $databaseId -eq "REPLACE_WITH_YOUR_D1_ID") {
    Write-Step "创建 D1 数据库"
    $createOut = (npx wrangler d1 create $databaseName 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
      throw "创建 D1 失败: `n$createOut"
    }

    $idMatch = [regex]::Match($createOut, 'database_id\s*=\s*"([0-9a-fA-F-]{36})"')
    if (-not $idMatch.Success) {
      $idMatch = [regex]::Match($createOut, "([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})")
    }
    if (-not $idMatch.Success) {
      throw "无法从输出中解析 database_id，请手动检查: `n$createOut"
    }

    $databaseId = $idMatch.Groups[1].Value
    $toml = [regex]::Replace($toml, 'database_id\s*=\s*"[^"]+"', "database_id = `"$databaseId`"")
    Set-Content -Encoding UTF8 $tomlPath $toml
    Write-Host "已写入 database_id: $databaseId" -ForegroundColor Green
  }

  if (-not $SkipSecrets) {
    Write-Step "设置 secrets（可回车跳过）"
    $adminPass = Read-SecretText "输入 ADMIN_PASSWORD"
    $otpCode = Read-SecretText "输入 WEB_UI_OTP_CODE（例如 123456）"
    if (-not [string]::IsNullOrWhiteSpace($adminPass)) { Set-WranglerSecret "ADMIN_PASSWORD" $adminPass }
    if (-not [string]::IsNullOrWhiteSpace($otpCode)) { Set-WranglerSecret "WEB_UI_OTP_CODE" $otpCode }
  }

  Write-Step "执行 D1 迁移"
  if ($SkipRemoteMigrate) {
    npx wrangler d1 migrations apply $databaseName --local
  } else {
    npx wrangler d1 migrations apply $databaseName --remote
  }
  if ($LASTEXITCODE -ne 0) { throw "D1 迁移失败" }

  Write-Step "部署 Worker"
  $deployOut = (npx wrangler deploy 2>&1 | Out-String)
  if ($LASTEXITCODE -ne 0) {
    throw "部署失败: `n$deployOut"
  }
  Write-Host $deployOut

  $workerUrl = ""
  $u = [regex]::Match($deployOut, "https://[^\s]+\.workers\.dev")
  if ($u.Success) { $workerUrl = $u.Value }

  if (-not $SkipRouteBinding) {
    if ([string]::IsNullOrWhiteSpace($ZoneId) -or [string]::IsNullOrWhiteSpace($ApiToken)) {
      Write-Host "未提供 ZoneId/ApiToken，跳过自动域名路由绑定（可手动在 Cloudflare Dashboard 绑定）" -ForegroundColor Yellow
    } else {
      Write-Step "自动绑定域名路由"
      $headers = @{ Authorization = "Bearer $ApiToken"; "Content-Type" = "application/json" }
      $listUrl = "https://api.cloudflare.com/client/v4/zones/$ZoneId/workers/routes"
      $existing = Invoke-RestMethod -Method Get -Uri $listUrl -Headers $headers
      $has = $false
      foreach ($r in ($existing.result | Where-Object { $_ })) {
        if ($r.pattern -eq $RoutePattern -and $r.script -eq $workerName) { $has = $true; break }
      }
      if (-not $has) {
        $body = @{ pattern = $RoutePattern; script = $workerName } | ConvertTo-Json
        $resp = Invoke-RestMethod -Method Post -Uri $listUrl -Headers $headers -Body $body
        if (-not $resp.success) { throw "路由绑定失败: $($resp | ConvertTo-Json -Depth 8)" }
        Write-Host "路由绑定成功: $RoutePattern -> $workerName" -ForegroundColor Green
      } else {
        Write-Host "路由已存在，无需重复绑定" -ForegroundColor Green
      }
    }
  }

  Write-Step "部署完成"
  Write-Host "Worker 名称: $workerName" -ForegroundColor Green
  Write-Host "D1 数据库: $databaseName ($databaseId)" -ForegroundColor Green
  if ($workerUrl) { Write-Host "Worker URL: $workerUrl" -ForegroundColor Green }
  Write-Host "提示：Edge 扩展重载 + Ctrl+F5 无法由服务器强制自动执行，需要你在浏览器点一次。" -ForegroundColor Yellow
}
finally {
  Pop-Location
}
