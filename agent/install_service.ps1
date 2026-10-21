#Requires -RunAsAdministrator
<#
  Installs the openems agent as an auto-start Windows service (LocalSystem).
  Run from an elevated (Administrator) PowerShell:
      .\install_service.ps1 -Server http://EMS_HOST:8013 -DevId MY-PC-01
#>
param(
  [string]$Server = "http://localhost:8013",
  [string]$DevId = $env:COMPUTERNAME,
  [string]$Vdom = "Default",
  [int]$Interval = 15
)
$ErrorActionPreference = "Stop"
$agentDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# 1. write config
$cfgDir = "C:\ProgramData\openems"
New-Item -ItemType Directory -Force $cfgDir | Out-Null
@{ server = $Server; devid = $DevId; vdom = $Vdom; interval = $Interval } |
  ConvertTo-Json | Set-Content "$cfgDir\agent.json" -Encoding utf8
Write-Host "config written: $cfgDir\agent.json"

# 2. dependency
python -m pip install --quiet pywin32

# 3. install + auto-start + start the service
python "$agentDir\service.py" install
sc.exe config openems-agent start= auto | Out-Null
python "$agentDir\service.py" start

Write-Host "openems-agent installed and running (LocalSystem, starts at boot)."
Write-Host "Logs: $cfgDir\agent.log   Uninstall: .\uninstall_service.ps1"
