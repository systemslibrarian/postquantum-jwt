# Changelog

All notable changes to the **PostQuantum.Jwt for VS Code** extension. This
extension does no cryptography; it helps you write and understand
PostQuantum.Jwt code. It sends no telemetry and makes no network calls.

## 0.2.1

A redesign and major expansion of the 0.2.0 visual inspector: the single panel
becomes a tabbed tool (Token · Hybrid construction · Validation flow), and the
token analysis is refactored into one pure, well-tested model shared by every
surface.

- **New — Visual Token Inspector.** A sandboxed webview (strict CSP, no network)
  that color-codes each segment, decodes the header, lists claims as a table,
  shows algorithm badges, and clearly distinguishes 3-segment **signed** from
  5-segment **encrypted** tokens. Open it with **Inspect Token (Visual)** or the
  **🔍 Inspect PQ-JWT** CodeLens.
- **New — Hybrid Construction view.** A step-by-step diagram of sign → X-Wing
  encapsulate → AES-256-GCM, including the X-Wing combiner formula, so
  sign-then-encrypt is intuitive. Jump to it with **Show Hybrid Construction
  Diagram**.
- **New — Validation Flow view.** The validator's 8 fail-closed checks, in order,
  each with the reasons it rejects. Steps annotate themselves against the loaded
  token. Jump to it with **Show Validation Flow**.
- **New — smarter playground link.** *Open in Playground* reconstructs the build
  form (issuer, audience, subject, lifetime, jti, custom claims) from a signed
  token and deep-links it. No key material is ever encoded.
- **New — walkthrough.** "Understand post-quantum JWTs" in *Get Started*.
- **New — settings:** `pqjwt.codeLens.enabled`, `pqjwt.inspector.openToSide`.
- **New — richer hovers** with a short concept note per API symbol.
- **Internal:** token analysis refactored into a pure, well-tested `model`
  (single source of truth for the text decode, inspector, hovers, and deep-link);
  added unit tests for the model, the HTML renderer (incl. injection-escaping),
  and the playground share encoding. Still no cryptography, no telemetry, no
  network calls.

## 0.2.0

The first visual release. Adds an **Inspect PQ-JWT** webview panel that lays a
token out as labelled layers (header / payload / signature, or header /
encrypted-key / IV / ciphertext / tag) with colour-coded header-field chips and
expandable explanations of ML-DSA-65, the X-Wing hybrid KEM, sign-then-encrypt,
the validation path, and fail-closed behaviour — auto-expanded for the inspected
token. The text **Decode Token** command is kept (labelled *Text*) as a fallback.
Sandboxed (strict CSP), no cryptography, no telemetry, no network calls.
(Superseded by the tabbed redesign in 0.2.1.)

## 0.1.7

- **Fixed:** the `pqjwt-aspnetcore` and `pqjwt-keyring` snippets now use the
  `PostQuantum.AspNetCore` package's real identifiers (`PostQuantumJwtBearerDefaults`,
  `HttpPostQuantumJwtKeyRing`) instead of stale legacy names, and the key-ring
  snippet imports its namespace — so pasted code compiles.
- **Fixed:** decoded-output documents are now released when their tab closes
  (the content store no longer grows for the host's lifetime).
- **Improved:** **Decode Token** also strips a leading `Authorization:` /
  `Bearer ` prefix, so selecting a header line from an `.http` file works.
- **Improved:** the API-docs CodeLens skips comment-only lines (less noise;
  symbols inside string literals are still matched — a full fix needs semantic
  tokens).

## 0.1.6

- **Fixed:** hovering an inherited Object property (`constructor`, `toString`,
  …) no longer renders a broken hover with `undefined` details.
- **Fixed:** a token whose header decodes to JSON `null` (or a primitive/array)
  no longer throws and crash the inline-token CodeLens for the document.
- **Fixed:** a valid 3-part token immediately followed by `.word.word` is now
  detected (the greedy match no longer voids it as a 5-part token).
- **Fixed:** the **Decode Token** command now strips surrounding quotes/backticks
  (and a trailing `,`/`;`) so highlighting a string literal still decodes.
- **Changed:** decoded output opens in a titled, read-only tab.
- **Added:** Marketplace badges and a Privacy section in the README; banner color.
- **Internal:** stopped shipping the dev-only `MONOREPO-SETUP.md` in the VSIX;
  added integration smoke tests for command registration and the CodeLens.

## 0.1.5

- **Added:** inline **🔍 Inspect PQ-JWT** CodeLens — when a token appears in a
  `.cs`/`.json`/`.http` file, decode it with one click. Detection is strict
  (3/5 segments whose header `alg` is `ML-DSA-65`/`X-Wing`).

## 0.1.4

- **Internal:** split into pure, testable modules; added a `node:test` suite,
  eslint + stricter TypeScript, and a push/PR CI lane.
- **Improved:** clearer decoder errors (empty vs. not-base64url vs. not-JSON).
- **Fixed:** README install instructions (`code --install-extension`, not the
  Quick Open `ext install` form).

## 0.1.3

- **Internal:** stateless symbol-matching regex; de-duplicated docs links;
  typed the decoded header; surface `kid` in the decoder notes.

## 0.1.2

- **Docs:** added an Install section to the Marketplace page.

## 0.1.1

- **Added:** bundled the MIT license in the package.

## 0.1.0

- Initial release: C# snippets, a structure-only token decoder, hover/CodeLens
  docs links, and quick links to the playground, docs, NuGet, and GitHub.
