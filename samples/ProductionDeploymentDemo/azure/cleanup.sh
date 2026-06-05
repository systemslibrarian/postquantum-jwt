#!/usr/bin/env bash
# Tears down the demo resource group. Idempotent — runs `az group delete` with
# `--yes --no-wait`. Costs stop accruing immediately even though the actual
# deletion takes a few minutes in the background.

set -euo pipefail

NAME_PREFIX="${NAME_PREFIX:-pqjwt-demo}"
RESOURCE_GROUP="${RESOURCE_GROUP:-${NAME_PREFIX}-rg}"

if [[ "$(az group exists --name "$RESOURCE_GROUP")" != "true" ]]; then
    echo "Resource group $RESOURCE_GROUP does not exist; nothing to delete."
    exit 0
fi

printf '\033[36m==> Deleting resource group %s (background)\033[0m\n' "$RESOURCE_GROUP"
az group delete --name "$RESOURCE_GROUP" --yes --no-wait
printf '\033[32m    Submitted. The group will disappear in a few minutes.\033[0m\n'
