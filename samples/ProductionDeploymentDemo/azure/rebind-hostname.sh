#!/usr/bin/env bash
# Re-binds a custom domain to the issuer Container App after a Bicep redeploy.
# See rebind-hostname.ps1 for the rationale; identical behaviour.
#
# Usage:
#   ./rebind-hostname.sh
#   HOSTNAME=demo.pqjwt.systemslibrarian.dev ./rebind-hostname.sh

set -euo pipefail

RESOURCE_GROUP="${RESOURCE_GROUP:-pqjwt-demo-rg}"
ENVIRONMENT="${ENVIRONMENT:-pqjwt-demo-env}"
APP_NAME="${APP_NAME:-pqjwt-demo-issuer}"
HOSTNAME_TO_BIND="${HOSTNAME:-demo.pqjwt.systemslibrarian.dev}"

printf '\033[36m==> Looking up the existing managed certificate for %s\033[0m\n' "$HOSTNAME_TO_BIND"
CERT_ID=$(az containerapp env certificate list \
    -g "$RESOURCE_GROUP" \
    -n "$ENVIRONMENT" \
    --managed-certificates-only \
    --query "[?properties.subjectName=='$HOSTNAME_TO_BIND'].id" \
    -o tsv)

if [[ -z "$CERT_ID" ]]; then
    echo "No managed certificate found for $HOSTNAME_TO_BIND in $ENVIRONMENT." >&2
    echo "Re-create it with: az containerapp hostname bind ... --validation-method CNAME" >&2
    exit 1
fi

echo "    Cert id: $CERT_ID"

printf '\033[36m==> az containerapp hostname add (idempotent)\033[0m\n'
az containerapp hostname add -n "$APP_NAME" -g "$RESOURCE_GROUP" --hostname "$HOSTNAME_TO_BIND" -o table

printf '\033[36m==> az containerapp hostname bind (re-uses existing cert)\033[0m\n'
az containerapp hostname bind -n "$APP_NAME" -g "$RESOURCE_GROUP" \
    --hostname "$HOSTNAME_TO_BIND" \
    --environment "$ENVIRONMENT" \
    --certificate "$CERT_ID" \
    -o table

echo
printf '\033[32m==> Re-bound\033[0m\n'
printf "    Test:  curl -sS -o /dev/null -w '%%{http_code}\\n' https://%s/health\n" "$HOSTNAME_TO_BIND"
