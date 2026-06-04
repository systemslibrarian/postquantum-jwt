// Single source of truth for the PostQuantum.Jwt API symbols the hover and
// CodeLens providers surface: each symbol's README anchor and one-line blurb.
// No vscode dependency.
export interface ApiDocEntry {
  anchor: string;
  blurb: string;
  /** Optional second paragraph: a short conceptual explanation for the hover. */
  concept?: string;
}

export const API_DOCS: Record<string, ApiDocEntry> = {
  PqJwtBuilder: {
    anchor: "#usage",
    blurb: "Fluent builder for signed (3-part) or signed-then-encrypted (5-part) tokens.",
    concept:
      "Adding a recipient X-Wing key switches the output from a 3-segment signed token to a 5-segment encrypted one (sign-then-encrypt).",
  },
  PqJwtValidator: {
    anchor: "#sign-and-validate",
    blurb: "Fail-closed validator. Thread-safe and reusable.",
    concept:
      "Runs 8 ordered checks (bounds → segments → decrypt → algorithm → key → signature → claims → replay) and throws on the first failure. No unsigned path; exactly one suite accepted.",
  },
  PqJwtValidationParameters: {
    anchor: "#sign-and-validate",
    blurb: "Validation configuration: keys, issuer/audience, lifetime, replay cache.",
    concept: "exp is required by default; iss/aud are enforced when set; jti uniqueness is enforced when a replay cache is wired.",
  },
  PqJwtValidationResult: {
    anchor: "#public-api-at-a-glance",
    blurb: "The validated claims; only returned when every check passed.",
  },
  XWingPrivateKey: {
    anchor: "#sign-and-encrypt",
    blurb: "X-Wing hybrid KEM private key (X25519 + ML-KEM-768).",
    concept:
      "X-Wing combines a classical (X25519) and a post-quantum (ML-KEM-768) KEM. An attacker must break both to recover the key, so it stays safe even if one is later broken.",
  },
  XWingPublicKey: {
    anchor: "#sign-and-encrypt",
    blurb: "X-Wing hybrid KEM public key. Generate(), Import(), Export().",
    concept: "Encoded as ek_ML-KEM ‖ pk_X25519 (1216 bytes). The recipient holds the matching private key.",
  },
  InMemoryReplayCache: {
    anchor: "#key-rotation-and-replay-protection",
    blurb: "Default single-process jti replay cache. Use a distributed store in clusters.",
    concept: "Tracks seen jti values so a captured token can't be replayed. In a cluster, back it with a shared store (e.g. Redis).",
  },
  HttpPqJwtKeyRing: {
    anchor: "#aspnet-core-integration",
    blurb: "JWKS-equivalent: fetch verification keys from a trusted HTTPS endpoint (legacy PostQuantum.Jwt.AspNetCore).",
  },
  HttpPostQuantumJwtKeyRing: {
    anchor: "#aspnet-core-integration",
    blurb: "JWKS-equivalent: fetch verification keys from a trusted HTTPS endpoint (PostQuantum.AspNetCore).",
  },
};

// A fresh global regex per call — `matchAll` requires the `g` flag, and a new
// instance avoids the shared-`lastIndex` state a module-level regex would carry.
export const apiRegex = (): RegExp =>
  new RegExp(`\\b(${Object.keys(API_DOCS).join("|")})\\b`, "g");

// Look up a symbol's docs entry. Uses an own-property check so inherited Object
// members (`constructor`, `toString`, `__proto__`, …) never resolve to a truthy
// native function and produce a broken hover.
export function lookupApiDoc(word: string): ApiDocEntry | undefined {
  return Object.prototype.hasOwnProperty.call(API_DOCS, word) ? API_DOCS[word] : undefined;
}
