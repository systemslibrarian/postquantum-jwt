#!/usr/bin/env bash
# One-shot bootstrap: build the PqJwtPlayground image in ACR and deploy it to
# Azure Container Apps with scale-to-zero. Run from the REPOSITORY ROOT
# (the Dockerfile references ../../src, so the build context must be the root).
#
#   bash samples/PqJwtPlayground/deploy.sh
#
# Idempotent enough to re-run; resource creation is skipped if it already exists.
# To God be the glory - 1 Corinthians 10:31.
set -euo pipefail

# ---- variables (edit these) ------------------------------------------------
RESOURCE_GROUP="pqjwt-demos"
LOCATION="eastus"
ENVIRONMENT="pqjwt-env"
ACR_NAME="pqjwtdemoacr"          # must be globally unique
APP_NAME="pqjwt-playground"
IMAGE="pqjwt-playground:latest"
DOCKERFILE="samples/PqJwtPlayground/Dockerfile"
# ---------------------------------------------------------------------------

echo ">> Ensuring resource group, environment, and registry exist..."
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" -o none
az containerapp env create --name "$ENVIRONMENT" --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" -o none 2>/dev/null || true
az acr create --resource-group "$RESOURCE_GROUP" --name "$ACR_NAME" \
  --sku Basic --location "$LOCATION" -o none 2>/dev/null || true

echo ">> Building image in ACR (cloud build, repo root as context)..."
az acr build --registry "$ACR_NAME" --image "$IMAGE" --file "$DOCKERFILE" .

echo ">> Deploying / updating the container app..."
az containerapp up \
  --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --environment "$ENVIRONMENT" \
  --image "${ACR_NAME}.azurecr.io/${IMAGE}" \
  --registry-server "${ACR_NAME}.azurecr.io" \
  --ingress external \
  --target-port 8080

az containerapp update --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" \
  --min-replicas 0 --max-replicas 1 -o none

URL=$(az containerapp show -n "$APP_NAME" -g "$RESOURCE_GROUP" \
  --query "properties.configuration.ingress.fqdn" -o tsv)
echo ">> Live at: https://${URL}"
echo ">> Verify PQ crypto:  az containerapp exec -n $APP_NAME -g $RESOURCE_GROUP --command 'openssl version'"
