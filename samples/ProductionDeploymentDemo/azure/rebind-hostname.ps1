# Re-binds a custom domain to the issuer Container App after a Bicep redeploy.
#
# Why this exists: the Bicep template's `configuration.ingress` block does not
# include custom-domain bindings, so every `az deployment group create` against
# main.bicep wipes them. The managed certificate itself survives — only the
# binding is lost. This script restores the binding idempotently and re-uses the
# existing cert so we don't trigger a fresh ACME-style issuance every time.
#
# Usage:
#   .\rebind-hostname.ps1                                                 # uses defaults
#   .\rebind-hostname.ps1 -Hostname demo.pqjwt.systemslibrarian.dev       # explicit hostname
#   .\rebind-hostname.ps1 -AppName pqjwt-demo-issuer -Environment pqjwt-demo-env

[CmdletBinding()]
param(
    [string]$ResourceGroup = 'pqjwt-demo-rg',
    [string]$Environment = 'pqjwt-demo-env',
    [string]$AppName = 'pqjwt-demo-issuer',
    [string]$Hostname = 'demo.pqjwt.systemslibrarian.dev'
)

$ErrorActionPreference = 'Stop'

Write-Host "==> Looking up the existing managed certificate for $Hostname" -ForegroundColor Cyan
$certId = az containerapp env certificate list `
    -g $ResourceGroup `
    -n $Environment `
    --managed-certificates-only `
    --query "[?properties.subjectName=='$Hostname'].id" `
    -o tsv

if ([string]::IsNullOrWhiteSpace($certId)) {
    Write-Error "No managed certificate found for $Hostname in $Environment. Re-create it with: az containerapp hostname bind ... --validation-method CNAME"
    exit 1
}

Write-Host "    Cert id: $certId" -ForegroundColor DarkGray

Write-Host "==> az containerapp hostname add (idempotent)" -ForegroundColor Cyan
az containerapp hostname add -n $AppName -g $ResourceGroup --hostname $Hostname -o table

Write-Host "==> az containerapp hostname bind (re-uses existing cert)" -ForegroundColor Cyan
az containerapp hostname bind -n $AppName -g $ResourceGroup `
    --hostname $Hostname `
    --environment $Environment `
    --certificate $certId `
    -o table

Write-Host ""
Write-Host "==> Re-bound" -ForegroundColor Green
Write-Host "    Test:  curl -sS -o /dev/null -w '%{http_code}\n' https://$Hostname/health" -ForegroundColor DarkGray
