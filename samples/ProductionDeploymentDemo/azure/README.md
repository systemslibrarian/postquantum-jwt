# Azure Container Apps deployment

This folder deploys the `ProductionDeploymentDemo` to Azure as three
Container Apps in one managed Environment:

```
┌─ Container Apps Environment (Log Analytics attached) ────────────────────┐
│                                                                          │
│  ┌─────────────┐         ┌─────────────┐         ┌─────────────────┐     │
│  │ issuerapi   │ ──HTTP─►│ ordersapi   │ ──TCP──►│ redis (sidecar) │     │
│  │ public      │         │ public      │  6379   │ internal only   │     │
│  │ scale 0→1   │         │ scale 0→1   │         │ scale 0→1       │     │
│  └─────────────┘         └─────────────┘         └─────────────────┘     │
│        ▲                       ▲                                          │
└────────┼───────────────────────┼──────────────────────────────────────────┘
         │ HTTPS (rate-limited)  │ HTTPS (rate-limited)
         │                       │
       internet                internet
```

Both public apps are HTTPS-only with per-IP rate limiting at the app level
(default 10 and 20 permits per 60-second window). The Redis sidecar is
internal-only on port 6379 (no public ingress). All three scale to zero.

> **DEMO ONLY.** The IssuerApi uses ephemeral keys regenerated on every cold
> start. Tokens this deployment issues are not trustworthy for anything that
> matters. The whole point is for reviewers to poke at a real running
> deployment, not for production use.

## Files

| File | Purpose |
|---|---|
| `main.bicep` | Container Apps Environment, Log Analytics, the 3 Container Apps |
| `deploy.ps1` / `deploy.sh` | One-shot `az group create` + `az deployment group create` |
| `cleanup.ps1` / `cleanup.sh` | `az group delete --yes --no-wait` |

## Prereqs

- An Azure subscription.
- Azure CLI: <https://learn.microsoft.com/cli/azure/install-azure-cli>
- `az login` already run; default subscription set
  (`az account set --subscription <sub-id-or-name>`).
- A Bicep-capable Azure CLI (built-in since Azure CLI 2.20+, no separate
  install needed).

## Deploy

```powershell
# from samples/ProductionDeploymentDemo/azure/
.\deploy.ps1
# or with overrides:
.\deploy.ps1 -Location westus3 -NamePrefix pqjwt-demo
```

```bash
# from samples/ProductionDeploymentDemo/azure/
chmod +x deploy.sh && ./deploy.sh
# or with overrides:
NAME_PREFIX=pqjwt-demo LOCATION=westus3 ./deploy.sh
```

The script prints the public URLs on success:

```
==> Deployed

    Issuer landing page :  https://pqjwt-demo-issuer.<env-default-domain>/
    Issuer JWKS         :  https://pqjwt-demo-issuer.<env-default-domain>/.well-known/pqjwt-keys
    Orders health       :  https://pqjwt-demo-orders.<env-default-domain>/health
    Orders endpoint     :  https://pqjwt-demo-orders.<env-default-domain>/orders/123
```

Open the Issuer landing page — it's an interactive HTML UI hosted by the
Issuer container itself, with buttons for every demo step. Run-demo scripts
in the parent folder work against the same URLs (set `ISSUER_URL` and
`ORDERS_URL`).

## What it costs

Scale-to-zero on all three Container Apps means **idle cost rounds to zero**:

| Resource | At rest | With ~hundreds of requests/day |
|---|---|---|
| Container Apps (3 apps, min 0 replicas) | $0 | ~$0 (under the free tier ceiling of 180k vCPU-sec + 360k GiB-sec / month) |
| Log Analytics workspace | $0 | $0 (under the 5 GB / month free tier) |
| Egress | $0 | $0 to ~$0.05 |

Cold start hits the first request after idle: ~30–60 seconds for the
issuer + orders apps because the conda OpenSSL 3.5+ image is large, plus
internal warm-up (`IssuerKeyRing` fetching the issuer's JWKS).

> The Container Apps free-tier ceilings are per subscription. If you run
> several Container Apps demos in the same subscription, they share the
> ceiling. Past it, traffic is billed at ~$0.000024 / vCPU-second + ~$0.000003
> / GiB-second. Check current pricing at
> <https://azure.microsoft.com/pricing/details/container-apps/>.

## Custom domain (optional)

After the initial deploy, you can bind a custom domain (e.g.
`demo.pqjwt.systemslibrarian.dev`) to the Issuer Container App via the
portal: **Container App → Custom domains → Add custom domain**. You'll need
a `CNAME` and a `TXT` validation record in your DNS provider; Container
Apps issues a managed TLS certificate for free.

## Logs

```bash
# Live tail
az containerapp logs show -g pqjwt-demo-rg -n pqjwt-demo-issuer --follow
az containerapp logs show -g pqjwt-demo-rg -n pqjwt-demo-orders --follow

# Query historical logs via the Log Analytics workspace
az monitor log-analytics query \
  --workspace $(az monitor log-analytics workspace show -g pqjwt-demo-rg -n pqjwt-demo-logs --query customerId -o tsv) \
  --analytics-query "ContainerAppConsoleLogs_CL | where ContainerAppName_s == 'pqjwt-demo-issuer' | take 100"
```

## Update an existing deployment

A new image push to `ghcr.io` triggers neither a rebuild nor a redeploy.
To pull the latest images after the GitHub Action publishes them:

```bash
az containerapp revision restart -g pqjwt-demo-rg -n pqjwt-demo-issuer
az containerapp revision restart -g pqjwt-demo-rg -n pqjwt-demo-orders
```

Or to deploy a specific image tag (recommended for production-shape
reproducibility, even on a demo):

```powershell
.\deploy.ps1 -IssuerImage ghcr.io/systemslibrarian/pqjwt-demo-issuer:abc1234 `
             -OrdersImage ghcr.io/systemslibrarian/pqjwt-demo-orders:abc1234
```

## Tear down

```powershell
.\cleanup.ps1
```
```bash
./cleanup.sh
```

Both are idempotent. `az group delete --yes --no-wait` returns immediately;
the actual deletion runs in the background and bills stop accruing as soon
as Azure receives the delete request.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Deploy fails on `Microsoft.App` registration | First-time per-subscription registration. The script registers automatically, but it can take a few minutes — re-run the deploy. |
| Cold start &gt;60s | The OpenSSL 3.5+ conda layer makes the image large. Expected for the first request after scale-to-zero idle. |
| 429 from issuer or orders | Per-IP rate limit hit. Defaults: issuer 10/min, orders 20/min. Loosen via Bicep params (`issuerRateLimitPermits`, `ordersRateLimitPermits`) or redeploy. |
| `/health` returns 503 with `warming-up` | OrdersApi has not yet fetched the issuer's JWKS. Resolves in ~5 seconds after both apps are alive. |
| First token call from Issuer fails with 5xx | Orders is cold-starting from zero — its `/.well-known/pqjwt-recipient-key` returns 503 until ready. Wait 30s and retry. |
| Logs show `using InMemoryReplayCache` warning | `REDIS_CONNECTION` env wasn't set on Orders. The Bicep sets it; double-check the Orders Container App's env. |
