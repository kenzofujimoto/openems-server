<#
.SYNOPSIS
  Create the .env that docker-compose.yml requires, with fresh random secrets.

.DESCRIPTION
  Prints the administrator password and the enrollment invitation once; store
  them in a password manager. Refuses to overwrite an existing file unless -Force.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File deploy\new-env.ps1
  powershell -ExecutionPolicy Bypass -File deploy\new-env.ps1 -BaseUrl https://ems.empresa.com.br -Uses 50
#>
param(
    [string]$Path = (Join-Path (Split-Path -Parent $PSScriptRoot) ".env"),
    [string]$AdminUser = "admin",
    [string]$BaseUrl = "http://localhost:8013",
    [ValidateRange(1, 10000)][int]$Uses = 10,
    [switch]$Force
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-Secret([int]$Length) {
    # Letters and digits only, so values never need URL or shell escaping.
    $alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789".ToCharArray()
    $bytes = New-Object byte[] $Length
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    -join ($bytes | ForEach-Object { $alphabet[$_ % $alphabet.Length] })
}

if ((Test-Path -LiteralPath $Path) -and -not $Force) {
    throw "$Path already exists; pass -Force to replace it (existing data keeps the old database password)."
}
if ($AdminUser -notmatch '^[A-Za-z0-9._-]{3,64}$') {
    throw "Administrator user names may contain letters, digits, dot, dash and underscore."
}

$dbPassword = New-Secret 32
$adminPassword = New-Secret 20
$invitation = New-Secret 48
$lines = @(
    "POSTGRES_PASSWORD=$dbPassword",
    "OPENEMS_DATABASE_URL=postgresql://postgres:$dbPassword@postgres:5432/openems",
    "OPENEMS_ADMIN=${AdminUser}:$adminPassword",
    "OPENEMS_SESSION_SECRET=$(New-Secret 64)",
    "OPENEMS_ENROLLMENT_TOKEN=$invitation",
    "OPENEMS_ENROLLMENT_VDOM=Default",
    "OPENEMS_ENROLLMENT_USES=$Uses",
    "OPENEMS_BASE_URL=$BaseUrl"
)
# UTF-8 without BOM: docker compose reads a BOM as part of the first variable name.
[IO.File]::WriteAllText($Path, ($lines -join "`n") + "`n", (New-Object Text.UTF8Encoding($false)))

Write-Host "Wrote $Path"
Write-Host ""
Write-Host "Panel login:          $AdminUser / $adminPassword"
Write-Host "Agent invitation:     $invitation  (valid for $Uses enrollments)"
Write-Host ""
Write-Host "Keep these values safe; they are not shown again."
