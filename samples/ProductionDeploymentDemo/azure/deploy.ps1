# Deploys the ProductionDeploymentDemo to Azure Container Apps.
#
# Prereqs:
#   - Azure CLI: https://learn.microsoft.com/cli/azure/install-azure-cli
#   - `az login` already run, default subscription selected.
#
# Usage:
#   .\deploy.ps1                                        # default name/region
#   .\deploy.ps1 -Location westus3 -NamePrefix pqjwt-demo
#   .\deploy.ps1 -IssuerImage ghcr.io/myfork/...        # override image
#
# Cost shape: scale-to-zero on all three Container Apps. Idle cost rounds to
# $0. Tear down with `cleanup.ps1` when you're done.

[CmdletBinding()]
param(
    [string]$NamePrefix = 'pqjwt-demo',
    [string]$Location = 'eastus',
    [string]$ResourceGroup = "$NamePrefix-rg",
    [string]$IssuerImage = 'ghcr.io/systemslibrarian/pqjwt-demo-issuer:latest',
    [string]$OrdersImage = 'ghcr.io/systemslibrarian/pqjwt-demo-orders:latest',
    [string]$RedisImage = 'redis:7-alpine',
    [int]$IssuerRateLimitPermits = 10,
    [int]$OrdersRateLimitPermits = 20,
    [int]$RateLimitWindowSeconds = 60
)

$ErrorActionPreference = 'Stop'

Write-Host "==> Deploying PostQuantum.Jwt ProductionDeploymentDemo" -ForegroundColor Cyan
Write-Host "    Resource group: $ResourceGroup ($Location)"
Write-Host "    Name prefix:    $NamePrefix"
Write-Host "    Issuer image:   $IssuerImage"
Write-Host "    Orders image:   $OrdersImage"
Write-Host ""

# Ensure az is logged in and a subscription is selected.
$account = az account show --output json 2>$null | ConvertFrom-Json
if ($null -eq $account) {
    Write-Error "Not logged in. Run: az login"
    exit 1
}
Write-Host "    Subscription:   $($account.name) ($($account.id))" -ForegroundColor DarkGray
Write-Host ""

# Ensure the Container Apps + Operational Insights resource providers are registered.
$providers = @('Microsoft.App', 'Microsoft.OperationalInsights')
foreach ($p in $providers) {
    $state = az provider show --namespace $p --query 'registrationState' -o tsv
    if ($state -ne 'Registered') {
        Write-Host "Registering $p (this is a one-time per-subscription step)..." -ForegroundColor Yellow
        az provider register --namespace $p | Out-Null
    }
}

# Create the resource group if it doesn't exist.
az group create --name $ResourceGroup --location $Location --output none

Write-Host "==> az deployment group create (this will take ~4-6 minutes)" -ForegroundColor Cyan
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$bicep = Join-Path $scriptDir 'main.bicep'

$result = az deployment group create `
    --resource-group $ResourceGroup `
    --template-file $bicep `
    --parameters `
        namePrefix=$NamePrefix `
        location=$Location `
        issuerImage=$IssuerImage `
        ordersImage=$OrdersImage `
        redisImage=$RedisImage `
        issuerRateLimitPermits=$IssuerRateLimitPermits `
        ordersRateLimitPermits=$OrdersRateLimitPermits `
        rateLimitWindowSeconds=$RateLimitWindowSeconds `
    --output json | ConvertFrom-Json

if ($null -eq $result) {
    Write-Error "Deployment failed; see Azure portal Activity Log for $ResourceGroup."
    exit 1
}

$outputs = $result.properties.outputs
$issuerFqdn = $outputs.issuerFqdn.value
$ordersFqdn = $outputs.ordersFqdn.value

Write-Host ""
Write-Host "==> Deployed" -ForegroundColor Green
Write-Host ""
Write-Host "    Issuer landing page :  https://$issuerFqdn/"
Write-Host "    Issuer JWKS         :  https://$issuerFqdn/.well-known/pqjwt-keys"
Write-Host "    Orders health       :  https://$ordersFqdn/health"
Write-Host "    Orders endpoint     :  https://$ordersFqdn/orders/123"
Write-Host ""
Write-Host "    Tail logs           :  az containerapp logs show -g $ResourceGroup -n $NamePrefix-issuer --follow"
Write-Host "    Tear down           :  .\cleanup.ps1 -ResourceGroup $ResourceGroup"
Write-Host ""
Write-Host "    DEMO ONLY - keys are ephemeral and reset on cold start. Never trust these tokens." -ForegroundColor Yellow
