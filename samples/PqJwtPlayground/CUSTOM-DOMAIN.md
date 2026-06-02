# Custom domain: pqjwt.systemslibrarian.dev (Cloudflare DNS + Azure managed cert)

Do this **after** the app is live and working on its default
`*.azurecontainerapps.io` URL (see `DEPLOY.md`). You own `systemslibrarian.dev`
on Cloudflare, so this is DNS + two Azure commands + a free managed certificate.

> **Two things that trip people up — handled below:**
> 1. The TXT validation value is **your app's `customDomainVerificationId`** —
>    not a value you can guess or copy from a guide. We read the real one.
> 2. Bind can fail with `RequireCustomHostnameInEnvironment` if the cert is
>    requested before the hostname is registered and the TXT record is live.
>    The order below (add hostname → create both DNS records → confirm with
>    `dig` → bind) avoids it.

## At a glance

The whole flow, in order — each step is detailed below:

1. **Deploy** the app so its default `*.azurecontainerapps.io` URL works (`DEPLOY.md`).
2. **Read** the two values you'll need: the app's FQDN (CNAME target) and its
   `customDomainVerificationId` (TXT value). — *step 1*
3. **Register** the hostname on the app: `az containerapp hostname add`. — *step 2*
4. **Create** two Cloudflare records: `CNAME pqjwt` → FQDN (grey cloud) and
   `TXT asuid.pqjwt` → verification id (grey cloud). — *step 3*
5. **Confirm** both records resolve with `dig` before going further. — *step 4*
6. **Bind** + provision the managed cert: `az containerapp hostname bind … --validation-method CNAME`. — *step 5*
7. **Verify** the binding and certificate status, then open the URL. — *step 6*

The single most important ordering rule: **don't bind (step 6) until `dig`
confirms both records (step 5).** Binding early is the usual cause of the
`RequireCustomHostnameInEnvironment` failure.

## Variables

```bash
RESOURCE_GROUP="pqjwt-demos"
APP_NAME="pqjwt-playground"
ENVIRONMENT="pqjwt-env"
CUSTOM_DOMAIN="pqjwt.systemslibrarian.dev"
SUBDOMAIN="pqjwt"   # the label only, for Cloudflare record names
```

## 1. Get the two values you'll put in Cloudflare

```bash
# (a) The CNAME target: your app's current default FQDN
az containerapp show -n "$APP_NAME" -g "$RESOURCE_GROUP" \
  --query "properties.configuration.ingress.fqdn" -o tsv
# e.g. pqjwt-playground.politegrass-abc123.eastus.azurecontainerapps.io

# (b) The domain-ownership token for the TXT record (THIS is the real
#     validation value — not a guessed string)
az containerapp show -n "$APP_NAME" -g "$RESOURCE_GROUP" \
  --query "properties.customDomainVerificationId" -o tsv
# e.g. A1B2C3...long-hex-string
```

## 2. Register the hostname on the app (before requesting a cert)

```bash
az containerapp hostname add \
  --hostname "$CUSTOM_DOMAIN" \
  -g "$RESOURCE_GROUP" \
  -n "$APP_NAME"
```

## 3. Create the two Cloudflare DNS records

In the Cloudflare dashboard for `systemslibrarian.dev`:

| Type  | Name                | Content / Target                          | Proxy        |
| ----- | ------------------- | ----------------------------------------- | ------------ |
| CNAME | `pqjwt`             | *(the FQDN from step 1a)*                 | **DNS only** |
| TXT   | `asuid.pqjwt`       | *(the verification id from step 1b)*      | **DNS only** |

**Critical:** the CNAME must be **DNS only (grey cloud)**, not proxied (orange).
Azure provisions the managed certificate by reaching your app directly; with
Cloudflare's proxy on, validation and cert issuance fail. You can turn the proxy
on later only if you front it with Cloudflare's own certificate, which is a
different setup — leave it grey for the managed-cert path.

(Cloudflare appends the zone automatically, so the TXT **Name** is just
`asuid.pqjwt`, which becomes `asuid.pqjwt.systemslibrarian.dev`.)

## 4. Wait for DNS, then confirm both records resolve

```bash
# CNAME should point at the azurecontainerapps.io FQDN
dig +short CNAME pqjwt.systemslibrarian.dev
# TXT should return your customDomainVerificationId
dig +short TXT  asuid.pqjwt.systemslibrarian.dev
```

Give it 1–5 minutes. Don't bind until both return the expected values — binding
early is the usual cause of the `RequireCustomHostnameInEnvironment` error.

## 5. Bind + provision the free managed certificate

```bash
az containerapp hostname bind \
  --hostname "$CUSTOM_DOMAIN" \
  -g "$RESOURCE_GROUP" \
  -n "$APP_NAME" \
  --environment "$ENVIRONMENT" \
  --validation-method CNAME
```

Certificate issuance can take several minutes. If this command errors with
`RequireCustomHostnameInEnvironment`, the hostname/TXT weren't ready — re-check
step 4 and run it again (it's idempotent).

## 6. Verify

```bash
az containerapp hostname list -n "$APP_NAME" -g "$RESOURCE_GROUP" -o table
# look for pqjwt.systemslibrarian.dev with a bound certificate

# managed certs live on the ENVIRONMENT:
az containerapp env certificate list \
  -g "$RESOURCE_GROUP" -n "$ENVIRONMENT" \
  --managed-certificates-only -o table
# status should be Succeeded
```

Then open <https://pqjwt.systemslibrarian.dev> — valid cert, your Playground.

## Troubleshooting

- **`RequireCustomHostnameInEnvironment` on bind** — the most common error. The
  hostname must be added (step 2) and the `asuid.` TXT must be live (step 4)
  before the cert is requested. Wait for `dig` to show the TXT, then re-run bind.
- **Cert stuck / fails** — confirm the CNAME is **grey-cloud** in Cloudflare.
  A proxied record blocks DigiCert from validating.
- **TXT name** — it is `asuid.pqjwt` in Cloudflare (zone auto-appended), giving
  `asuid.pqjwt.systemslibrarian.dev`. Wrong prefix = failed validation.
- **Wrong TXT value** — it must be the app's `customDomainVerificationId`
  (step 1b), nothing else.

---

*To God be the glory — 1 Corinthians 10:31.*
