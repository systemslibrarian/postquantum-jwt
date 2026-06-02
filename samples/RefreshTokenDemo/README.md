# Refresh-token rotation demo

The library issues the **access token** — a short-lived, signed ML-DSA-65 JWT.
But an access token alone can't be revoked and shouldn't be long-lived. This
demo shows the architecture that surrounds it: the **access/refresh split** with
**rotation** and **reuse detection** — the pattern that gives you working logout
and revocation.

| Token | What | Lifetime | Storage | Sent |
| ----- | ---- | -------- | ------- | ---- |
| Access | ML-DSA-65 JWT, carries only `sub` | 15 min | client memory (NOT localStorage) | every API request |
| Refresh | opaque 64-byte random (not a JWT) | 30 days | server stores only its SHA-256 hash; client holds an HttpOnly cookie | only to `/auth/refresh` |

## What this defends against

The "JWT & Token Exploitation — Advanced API Attacks" guides frame two attacks
that the *token itself* can't answer — they're properties of the surrounding
architecture, which is exactly what this demo supplies:

- **Token replay / "session never invalidated"** — the bug-bounty test is: log
  out, replay the old token, and if it still works the session was never really
  killed. Here, every refresh **rotates** the refresh token and marks the old one
  used; replaying a used token triggers **reuse detection** and revokes the whole
  family. See the runnable "See reuse detection fire" walkthrough below.
- **No revocation** (a stateless JWT lives until it expires) — logout deletes the
  refresh token server-side, so it can mint no more access tokens. The current
  access token still works until expiry (≤15 min); that bounded window is the
  point of keeping it short-lived.

The token-level attacks from those same guides — `alg:none`, algorithm
confusion, weak-secret cracking, role manipulation by editing the payload,
missing signature verification — are demonstrated failing closed in
`../ConsoleDemo` (Attack Mode) and `../SpecByExample`, and mapped row-by-row in
`../HARDENING-CHECKLIST.md`. This demo deliberately covers the architectural half
that those don't.

## Run it

```bash
cd samples/RefreshTokenDemo
dotnet run
```

## Walkthrough (curl)

A cookie jar (`-c`/`-b`) stands in for the browser holding the HttpOnly cookie.

```bash
# 1. Log in -> get an access token + a refresh cookie (saved to jar.txt)
curl -sk -c jar.txt -X POST "https://localhost:7110/auth/login?user=alice" | jq

# 2. Call the protected resource with the access token
ACCESS=$(curl -sk -c jar.txt -X POST "https://localhost:7110/auth/login?user=alice" | jq -r .accessToken)
curl -sk https://localhost:7110/me -H "Authorization: Bearer $ACCESS" | jq

# 3. Refresh -> the refresh cookie is rotated, a new access token comes back
curl -sk -b jar.txt -c jar.txt -X POST https://localhost:7110/auth/refresh | jq
```

### See reuse detection fire

Rotation means the OLD refresh token is now used. Present it again and the whole
family is revoked — exactly what happens if a thief replays a stolen token:

```bash
# Capture a refresh token, use it once (rotates), then try the OLD one again.
curl -sk -c a.txt -X POST "https://localhost:7110/auth/login?user=alice" >/dev/null
cp a.txt old.txt
curl -sk -b a.txt -c a.txt -X POST https://localhost:7110/auth/refresh >/dev/null  # old.txt now stale
curl -sk -b old.txt -X POST https://localhost:7110/auth/refresh | jq
# -> {"error":"Refresh token reuse detected — family revoked."}
```

### Logout

```bash
curl -sk -b jar.txt -X POST https://localhost:7110/auth/logout -i   # 204; refresh revoked server-side
```

The current access token still validates until it expires (≤15 min). That
bounded window is the entire point of short-lived access tokens.

## What's demo-grade vs production

- The refresh store is an in-memory `ConcurrentDictionary` — use a durable,
  shared store in production (and persist the access-token signing key; see
  `../WebApiDemo/FileBackedSigningKey.cs`).
- `/auth/login` trusts the `user` query param instead of checking a password.
- No expired-entry sweeper; rely on the store's TTL/eviction in a real system.

---

*To God be the glory — 1 Corinthians 10:31.*
