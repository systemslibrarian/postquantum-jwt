# Tears down the demo resource group. Idempotent - runs `az group delete` with
# `--yes --no-wait`. Costs stop accruing immediately even though the actual
# deletion takes a few minutes in the background.

[CmdletBinding()]
param(
    [string]$NamePrefix = 'pqjwt-demo',
    [string]$ResourceGroup = "$NamePrefix-rg"
)

$ErrorActionPreference = 'Stop'

if (-not (az group exists --name $ResourceGroup | ConvertFrom-Json)) {
    Write-Host "Resource group $ResourceGroup does not exist; nothing to delete." -ForegroundColor Yellow
    exit 0
}

Write-Host "==> Deleting resource group $ResourceGroup (background)" -ForegroundColor Cyan
az group delete --name $ResourceGroup --yes --no-wait
Write-Host "    Submitted. The group will disappear in a few minutes." -ForegroundColor Green
