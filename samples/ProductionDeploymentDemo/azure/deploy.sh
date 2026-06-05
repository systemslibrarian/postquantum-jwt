#!/usr/bin/env bash
# Deploys the ProductionDeploymentDemo to Azure Container Apps.
#
# Prereqs:
#   - Azure CLI: https://learn.microsoft.com/cli/azure/install-azure-cli
#   - `az login` already run, default subscription selected.
#
# Usage:
#   ./deploy.sh                                       # default name/region
#   NAME_PREFIX=pqjwt-demo LOCATION=westus3 ./deploy.sh
#   ISSUER_IMAGE=ghcr.io/myfork/... ./deploy.sh
#
# Cost shape: scale-to-zero on all three Container Apps. Idle cost rounds to $0.
# Tear down with `cleanup.sh` when you're done.

set -euo pipefail

NAME_PREFIX="${NAME_PREFIX:-pqjwt-demo}"
LOCATION="${LOCATION:-eastus}"
RESOURCE_GROUP="${RESOURCE_GROUP:-${NAME_PREFIX}-rg}"
ISSUER_IMAGE="${ISSUER_IMAGE:-ghcr.io/systemslibrarian/pqjwt-demo-issuer:latest}"
ORDERS_IMAGE="${ORDERS_IMAGE:-ghcr.io/systemslibrarian/pqjwt-demo-orders:latest}"
REDIS_IMAGE="${REDIS_IMAGE:-redis:7-alpine}"
ISSUER_RATE_LIMIT_PERMITS="${ISSUER_RATE_LIMIT_PERMITS:-10}"
ORDERS_RATE_LIMIT_PERMITS="${ORDERS_RATE_LIMIT_PERMITS:-20}"
RATE_LIMIT_WINDOW_SECONDS="${RATE_LIMIT_WINDOW_SECONDS:-60}"

cyan()   { printf '\033[36m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }

cyan "==> Deploying PostQuantum.Jwt ProductionDeploymentDemo"
echo "    Resource group: $RESOURCE_GROUP ($LOCATION)"
echo "    Name prefix:    $NAME_PREFIX"
echo "    Issuer image:   $ISSUER_IMAGE"
echo "    Orders image:   $ORDERS_IMAGE"
echo

if ! az account show >/dev/null 2>&1; then
    echo "Not logged in. Run: az login" >&2
    exit 1
fi

# Register required providers if needed.
for p in Microsoft.App Microsoft.OperationalInsights; do
    state=$(az provider show --namespace "$p" --query 'registrationState' -o tsv)
    if [[ "$state" != "Registered" ]]; then
        yellow "Registering $p (this is a one-time per-subscription step)..."
        az provider register --namespace "$p" >/dev/null
    fi
done

az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --output none

cyan "==> az deployment group create (this will take ~4-6 minutes)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

result=$(az deployment group create \
    --resource-group "$RESOURCE_GROUP" \
    --template-file "$SCRIPT_DIR/main.bicep" \
    --parameters \
        namePrefix="$NAME_PREFIX" \
        location="$LOCATION" \
        issuerImage="$ISSUER_IMAGE" \
        ordersImage="$ORDERS_IMAGE" \
        redisImage="$REDIS_IMAGE" \
        issuerRateLimitPermits="$ISSUER_RATE_LIMIT_PERMITS" \
        ordersRateLimitPermits="$ORDERS_RATE_LIMIT_PERMITS" \
        rateLimitWindowSeconds="$RATE_LIMIT_WINDOW_SECONDS" \
    --output json)

issuer_fqdn=$(echo "$result" | jq -r '.properties.outputs.issuerFqdn.value')
orders_fqdn=$(echo "$result" | jq -r '.properties.outputs.ordersFqdn.value')

echo
green "==> Deployed"
echo
echo "    Issuer landing page :  https://$issuer_fqdn/"
echo "    Issuer JWKS         :  https://$issuer_fqdn/.well-known/pqjwt-keys"
echo "    Orders health       :  https://$orders_fqdn/health"
echo "    Orders endpoint     :  https://$orders_fqdn/orders/123"
echo
echo "    Tail logs           :  az containerapp logs show -g $RESOURCE_GROUP -n $NAME_PREFIX-issuer --follow"
echo "    Tear down           :  ./cleanup.sh"
echo
yellow "    DEMO ONLY — keys are ephemeral and reset on cold start. Never trust these tokens."
