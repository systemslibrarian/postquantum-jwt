# Secure usage: getting the architecture around the token right

`PostQuantum.Jwt` makes the *token* sound — fail-closed validation, no `alg:none`,
no algorithm confusion, required `exp`. But a sound token can still sit inside an
unsound system. These are the surrounding decisions that matter, drawn from
current web-auth guidance and adapted to this library.

## 0. Authentication is not authorization (the boundary that matters most)

This library answers exactly one question: **is this token authentic, and who
does it say the caller is?** It does *not* — and cannot — answer **what is that
caller allowed to do?** That second question is your application's job, and it
is where the #1 bug class lives: **broken access control**.

A perfectly validated PostQuantum.Jwt token tells you the caller is user `123`.
It tells you nothing about whether user `123` may read order `456`, edit another
user's profile, or reach an admin route. If your server skips those checks, the
strongest token in the world doesn't save you:

- **IDOR / horizontal escalation** — `GET /api/user/123` works; the attacker
  tries `/api/user/124` with the *same valid token* and reads someone else's
  data. The token was never the problem; the missing ownership check was.
- **Vertical escalation** — a valid non-admin token reaches `/api/admin` because
  the route only checked *authentication*, not *role*.
- **Hidden-parameter / mass-assignment escalation** — a request adds
  `role=admin` and the server trusts the body over the token's identity.
- **Frontend-only restrictions** — the UI hides a button; the backend still
  honors the request. Never trust the client to enforce access.

What this means in practice:

1. **Derive identity from the token, authority from the server.** Take `sub`
   from the validated token, then look up that user's roles/permissions and the
   target resource's owner server-side, and check them on every protected route.
2. **Check ownership, not just authentication.** "Is the caller logged in?" is
   not "may the caller touch *this* object?" Compare the resource's owner to the
   token's `sub` before returning or mutating it.
3. **Enforce authorization on the backend, every time.** Hiding an action in the
   UI is not enforcement.

The `WebApiDemo`'s `/admin` policy shows the *role* half of this (authorization
on top of a valid token), but no token library can supply your per-resource
ownership checks — those are yours to write. Treat a green validation result as
the *start* of an authorization decision, never the end of one.

## 1. Put only `sub` in the access token

A signed JWT payload is **readable by anyone holding the token** — it's base64,
not encrypted. (Encrypt-for a recipient if you need confidentiality; see the
`EncryptFor` path. But even then, minimize.) Don't pack `role`, `email`,
`org`, or internal IDs into the access token. Carry `sub` and look up everything
else server-side, from a fresh query, on the routes that care.

- A leaked access token then reveals nothing an attacker didn't already know to ask for.
- Authorization decisions reflect *current* server state, not whatever was true when the token was minted.

```csharp
// Good: minimal access token.
new PqJwtBuilder()
    .WithIssuer(issuer).WithAudience(audience)
    .WithSubject(userId)                 // <- and essentially nothing else
    .WithLifetime(TimeSpan.FromMinutes(15))
    .SignWith(signingKey)
    .Build();
```

## 2. Keep the access token in memory, never in localStorage

Anything in `localStorage` is readable by any JavaScript on the page — your code,
every npm dependency, every analytics snippet, every extension. One XSS anywhere
in that tree and the token walks. Keep the access token in a JS variable / auth
context in memory. On tab refresh it's gone; bootstrap a new one from the refresh
endpoint.

## 3. Make the access token short-lived, and add a refresh token for revocation

A stateless JWT can't be revoked — logout doesn't truly invalidate it. The fix is
the access/refresh split (runnable in `RefreshTokenDemo/`):

- **Access token**: this library, ≤15 min, in memory.
- **Refresh token**: opaque random string (not a JWT), long-lived, stored
  server-side **as a hash**, delivered in an `HttpOnly; Secure; SameSite=Strict`
  cookie scoped to the refresh path so it never rides normal requests. Rotate it
  on every use and revoke the family on reuse. That's what makes logout real.

## 4. Always pin issuer and audience on the validator

Set `ValidIssuer` and `ValidAudience`. They stop a token minted for one service
from being accepted by another — free if you're single-service today, essential
the day you aren't.

## 5. Turn on replay protection where one-time use matters

For tokens that should be used once (e.g. a sensitive action), set
`RequireReplayProtection = true` and supply a `ReplayCache` — distributed if you
run more than one node (see `DistributedReplayCache/`).

## 6. Persist and protect the signing key

An ephemeral key invalidates every token on restart. Persist it (encrypted
PKCS#8 at minimum; HSM / key vault in production). See
`WebApiDemo/FileBackedSigningKey.cs`. Never log or return private key material —
only the public key is shareable.

## 7. Step up authentication for sensitive actions

A short-lived access token still has a blast radius: if it's stolen, the attacker
can do anything it authorizes until it expires. Shrink that radius — don't let the
ordinary session token authorize your most destructive operations. For actions
like changing a password, updating billing, or moving money, demand a fresh proof
of presence *at that moment*: a re-entered password, an OTP, or a passkey/
biometric. Keep that elevated state out of the ordinary access token — issue a
separate short-lived, single-use token for the sensitive step (pair it with replay
protection, §5) or track a server-side "recently re-authenticated" flag. Low-risk
reads stay seamless; high-risk writes cost the attacker a second factor they
don't have.

## 8. Protect the token in transit and in logs

A validated token is a **bearer credential** — whoever holds it *is* the user
until it expires. So:

- **TLS only.** Never send tokens over plain HTTP. Terminate HTTPS (and HSTS for
  browsers) so a token can't be sniffed in transit.
- **Never log the token.** Keep `Authorization` and `Cookie` values out of logs,
  traces, and error reports; redact them in any request-logging middleware. (This
  library logs *nothing*; the ASP.NET Core handler logs only the validation
  *failure* — its reason — never the token or key bytes. The `pqjwt.validations`
  metric is the safe way to watch failures; see `HARDENING-CHECKLIST.md`.)
- **Never put a token in a URL.** Query strings leak into browser history, proxy
  and server access logs, and `Referer` headers. Tokens belong in the
  `Authorization` header or an `HttpOnly` cookie — never `?token=`.

## 9. Bind the token to its client (advanced, optional)

§7 limits what a stolen token can *do*; binding limits *who can use it at all*.
The OWASP "token sidejacking" defense: when you issue the token, generate a high-
entropy random value, put its **hash** in a claim, and hand the **raw** value to
the client in a separate hardened `HttpOnly; Secure; SameSite=Strict` cookie. On
each request, re-hash the cookie value and compare it to the claim. A token lifted
from a log or an `Authorization` header is then useless without the matching
cookie, which `HttpOnly` keeps out of JavaScript's reach.

```csharp
// Issue: fingerprint hash travels in the token, raw value in a hardened cookie.
var raw = RandomNumberGenerator.GetHexString(64);
var fpt = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));
var token = new PqJwtBuilder()
    .WithSubject(userId).WithLifetime(TimeSpan.FromMinutes(15))
    .WithClaim("fpt", fpt)            // hash only — never the raw value
    .SignWith(signingKey).Build();
// Validate: after PqJwtValidator succeeds, compare result.GetString("fpt")
// to SHA-256 of the fingerprint cookie; reject on mismatch.
```

This is an application-level control the library *enables* (it's just a claim) but
does not enforce for you. It's worth the complexity for high-value sessions; for
most apps, §2 (in-memory) + §3 (short-lived + refresh) + §8 already cover the
common theft paths.

---

*To God be the glory — 1 Corinthians 10:31.*
