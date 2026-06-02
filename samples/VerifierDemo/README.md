# PostQuantum.Jwt — Verifier Demo (cross-service rotation)

A **second** service that validates tokens minted by `WebApiDemo` **without
sharing a signing key**. It fetches the issuer's public keys from
`/.well-known/pqjwt-keys` over HTTP via `HttpPqJwtKeyRing` and resolves each
token's `kid` against them.

This is the real multi-service story: the issuer can rotate its key + `kid` and
publish both old and new during an overlap window; this verifier picks up the
new key on its next refresh — no redeploy, no shared secret.

## Run it with the issuer (recommended)

Use the two-service compose file from the repo root:

```bash
docker compose -f samples/docker-compose.yml up --build

# mint a token from the issuer
TOKEN=$(curl -s -X POST "http://localhost:5080/token?sub=alice&role=admin" | jq -r .token)
# verify it on the SEPARATE verifier (which never saw the signing key)
curl -s http://localhost:5090/verify -H "Authorization: Bearer $TOKEN" | jq
```

## Run it locally (issuer must be running on :5080)

```bash
cd samples/VerifierDemo
dotnet run    # reads ISSUER_KEYS_URL, defaults to http://localhost:5080/.well-known/pqjwt-keys
```

## Notes

- No signing key lives in this process — only public verification keys it fetched.
- The key ring refreshes every 30s here so rotation is visible quickly in a demo;
  use a longer interval in production.
- The `http://localhost` key URL works only because it's loopback —
  `HttpPqJwtKeyRing` **rejects a non-loopback `http://` endpoint** (the key
  directory is the trust root). In production point `ISSUER_KEYS_URL` at an
  `https://` URL.
- Preview software, not audited; non-IANA identifiers; non-interoperable tokens.

---

*To God be the glory — 1 Corinthians 10:31.*
