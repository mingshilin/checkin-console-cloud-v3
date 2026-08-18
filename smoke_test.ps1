param(
  [string]$BaseUrl = "http://127.0.0.1:8787",
  [string]$Username = "admin",
  [string]$Password = "",
  [string]$OtpCode = "123456"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Password)) {
  throw "请传入 -Password"
}

function Step([string]$m){ Write-Host "`n=== $m ===" -ForegroundColor Cyan }

$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

Step "health"
$health = Invoke-RestMethod -Uri "$BaseUrl/api/health" -Method Get -TimeoutSec 20
$health | ConvertTo-Json -Depth 6 | Write-Host

Step "login request"
$req = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/auth/login/request" -WebSession $session -ContentType 'application/json' -Body (@{username=$Username;password=$Password}|ConvertTo-Json)
$req | ConvertTo-Json -Depth 6 | Write-Host

$challengeId = $req.item.challenge_id
if ([string]::IsNullOrWhiteSpace($challengeId)) {
  throw "未拿到 challenge_id"
}

Step "login verify"
$verify = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/auth/login/verify" -WebSession $session -ContentType 'application/json' -Body (@{challenge_id=$challengeId;code=$OtpCode}|ConvertTo-Json)
$verify | ConvertTo-Json -Depth 6 | Write-Host

Step "auth me"
$me = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/auth/me" -WebSession $session
$me | ConvertTo-Json -Depth 6 | Write-Host

Step "sites"
$sites = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/sites" -WebSession $session
$sites | ConvertTo-Json -Depth 6 | Write-Host

Step "logs"
$sys = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/logs/system?limit=5" -WebSession $session
$usage = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/logs/usage?limit=5" -WebSession $session
Write-Host "system logs: $($sys.item.items.Count)"
Write-Host "usage logs: $($usage.item.items.Count)"

Step "done"
Write-Host "冒烟测试通过" -ForegroundColor Green
