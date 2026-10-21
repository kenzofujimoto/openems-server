#Requires -RunAsAdministrator
<#  Stops and removes the openems agent service, and clears its hosts block.
    Run from an elevated (Administrator) PowerShell:  .\uninstall_service.ps1  #>
$ErrorActionPreference = "Continue"
$agentDir = Split-Path -Parent $MyInvocation.MyCommand.Path

python "$agentDir\service.py" stop 2>$null
python "$agentDir\service.py" remove 2>$null

# remove any managed block the agent left in the hosts file
python -c "import sys; sys.path.insert(0, r'$agentDir'); import openems_agent as a; a.clear_hosts(a.DEFAULT_HOSTS); print('hosts block cleared')"

Write-Host "openems-agent removed."
