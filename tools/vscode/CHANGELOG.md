# Changelog

All notable changes to the **PostQuantum.Jwt for VS Code** extension. This
extension does no cryptography; it helps you write and understand
PostQuantum.Jwt code. It sends no telemetry and makes no network calls.

## 0.2.0

- **Added:** a visual **PQ-JWT Inspector** panel. The inline **🔍 Inspect PQ-JWT**
  CodeLens (and the new **Inspect Token (Visual)** command) now opens a webview
  that lays out the token as labelled layers — header / payload / signature for
  the signed form, or header / encrypted-key / IV / ciphertext / tag for the
  encrypted form — with colour-coded header-field chips (`✓` ML-DSA-65, `✗`
  `alg:none`, etc.). It is also a *teacher*: expandable sections explain
  ML-DSA-65, the X-Wing hybrid KEM, sign-then-encrypt, the cheap-checks-first
  validation path, and fail-closed behaviour — auto-expanded for the token in
  front of you, so you don't need the browser playground to understand it.
  Still **no cryptography**: it renders the same structure-and-header inspection
  as the text decoder (shared, unit-tested logic), never decrypting anything.
- **Kept:** the text **Decode Token** command (now labelled *Text*) as a
  lightweight fallback.

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
