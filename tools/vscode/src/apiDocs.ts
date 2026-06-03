// Single source of truth for the PostQuantum.Jwt API symbols the hover and
// CodeLens providers surface: each symbol's README anchor and one-line blurb.
// No vscode dependency.
export interface ApiDocEntry {
  anchor: string;
  blurb: string;
}

export const API_DOCS: Record<string, ApiDocEntry> = {
  PqJwtBuilder: {
    anchor: "#usage",
    blurb: "Fluent builder for signed (3-part) or signed-then-encrypted (5-part) tokens.",
  },
  PqJwtValidator: {
    anchor: "#sign-and-validate",
    blurb: "Fail-closed validator. Thread-safe and reusable.",
  },
  PqJwtValidationParameters: {
    anchor: "#sign-and-validate",
    blurb: "Validation configuration: keys, issuer/audience, lifetime, replay cache.",
  },
  PqJwtValidationResult: {
    anchor: "#public-api-at-a-glance",
    blurb: "The validated claims; only returned when every check passed.",
  },
  XWingPrivateKey: {
    anchor: "#sign-and-encrypt",
    blurb: "X-Wing hybrid KEM private key (X25519 + ML-KEM-768).",
  },
  XWingPublicKey: {
    anchor: "#sign-and-encrypt",
    blurb: "X-Wing hybrid KEM public key. Generate(), Import(), Export().",
  },
  InMemoryReplayCache: {
    anchor: "#key-rotation-and-replay-protection",
    blurb: "Default single-process jti replay cache. Use a distributed store in clusters.",
  },
  HttpPqJwtKeyRing: {
    anchor: "#aspnet-core-integration",
    blurb: "JWKS-equivalent: fetch verification keys from a trusted HTTPS endpoint.",
  },
};

// A fresh global regex per call — `matchAll` requires the `g` flag, and a new
// instance avoids the shared-`lastIndex` state a module-level regex would carry.
export const apiRegex = (): RegExp =>
  new RegExp(`\\b(${Object.keys(API_DOCS).join("|")})\\b`, "g");
