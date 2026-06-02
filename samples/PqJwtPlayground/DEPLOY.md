# Deploying the Playground live (Azure Container Apps)

The playground is a stateful Blazor Server app whose crypto runs server-side and
needs **OpenSSL 3.5+**, so it can't be a static GitHub Pages site. Azure
Container Apps (ACA) is the cheapest, simplest fit: it builds the existing
`Dockerfile` (Azure Linux 3.0 base → new-enough OpenSSL) and gives you a public
HTTPS URL with scale-to-zero so an idle demo costs almost nothing.

> **Build context is the repo root.** This Dockerfile references `../../src`, so
> every command below runs from the **repository root** and points at the
> Dockerfile with `-f`. Don't `cd` into the sample folder.

## One-time setup

```bash
# Install / update the CLI extension and register providers (once per subscription)
az extension add --name containerapp --upgrade
az provider register --namespace Microsoft.App
az provider register --namespace Microsoft.OperationalInsights
az login
```

## Option 1 — one command from local source (fastest)

From the **repository root**:

```bash
az containerapp up \
  --name pqjwt-playground \
  --resource-group pqjwt-demos \
  --location eastus \
  --source . \
  --ingress external

# Tip: `up` looks for a Dockerfile in the source root. Because ours lives at
# samples/PqJwtPlayground/Dockerfile, the simplest reliable path is to build the
# image yourself (Option 2) OR temporarily copy the Dockerfile to the repo root.
```

Because the Dockerfile isn't at the context root, the most predictable route is
to build-and-push explicitly, then deploy the image:

## Option 2 — build with ACR, then deploy the image (most reliable)

From the **repository root**:

```bash
# 1) Create the resource group + a registry (once)
az group create --name pqjwt-demos --location eastus
az acr create --resource-group pqjwt-demos --name pqjwtdemoacr --sku Basic --admin-enabled true

# 2) Build the image in the cloud, using our Dockerfile and the repo root as context
az acr build \
  --registry pqjwtdemoacr \
  --image pqjwt-playground:latest \
  --file samples/PqJwtPlayground/Dockerfile \
  .

# 3) Deploy the image to Container Apps (scale-to-zero keeps idle cost ~$0)
az containerapp up \
  --name pqjwt-playground \
  --resource-group pqjwt-demos \
  --environment pqjwt-env \
  --image pqjwtdemoacr.azurecr.io/pqjwt-playground:latest \
  --registry-server pqjwtdemoacr.azurecr.io \
  --ingress external \
  --target-port 8080

# 4) (optional) allow scale to zero when idle
az containerapp update \
  --name pqjwt-playground \
  --resource-group pqjwt-demos \
  --min-replicas 0 --max-replicas 1
```

The deploy prints the public URL (e.g. `https://pqjwt-playground.<region>.azurecontainerapps.io`).

## Verify OpenSSL inside the running container

If the PQ paths ever fail closed in the cloud, the base image's OpenSSL is the
first suspect:

```bash
az containerapp exec \
  --name pqjwt-playground --resource-group pqjwt-demos \
  --command "openssl version"
# expect: OpenSSL 3.5.x or newer
```

## Continuous deploy from GitHub (optional)

A ready workflow lives at `.github/workflows/deploy-playground.yml` (added at the
repo root). It builds with ACR and updates the container app on every push to
`main` that touches the playground. Set these repository secrets:

- `AZURE_CREDENTIALS` — output of `az ad sp create-for-rbac --sdk-auth ...`
- `ACR_NAME` — e.g. `pqjwtdemoacr`

## Tear down

```bash
az group delete --name pqjwt-demos --yes --no-wait
```

## Cost note

With `--min-replicas 0`, ACA scales the demo to zero when no one is using it, so
you pay only for actual request time plus the small ACR storage. A low-traffic
public demo typically costs a few dollars a month or less.

---

*To God be the glory — 1 Corinthians 10:31.*

## Recommended: managed identity for ACR pull (no admin credentials)

The quickstart above lets Container Apps pull with registry admin credentials.
For anything you keep around, prefer a system-assigned managed identity with the
`AcrPull` role — no stored secrets:

```bash
# 1) Give the app a system-assigned identity
PRINCIPAL_ID=$(az containerapp identity assign \
  --name pqjwt-playground --resource-group pqjwt-demos \
  --system-assigned --query principalId -o tsv)

# 2) Grant it pull rights on the registry
ACR_ID=$(az acr show --name pqjwtdemoacr --query id -o tsv)
az role assignment create \
  --assignee "$PRINCIPAL_ID" --role AcrPull --scope "$ACR_ID"

# 3) Point the app at the registry via that identity (no --registry-password)
az containerapp registry set \
  --name pqjwt-playground --resource-group pqjwt-demos \
  --server pqjwtdemoacr.azurecr.io --identity system
```

## Custom domain

To serve the playground at `pqjwt.systemslibrarian.dev` with a free managed
certificate (Cloudflare DNS), see **[CUSTOM-DOMAIN.md](CUSTOM-DOMAIN.md)**.
