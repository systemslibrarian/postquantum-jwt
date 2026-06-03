// Static educational content and inline SVG icons for the inspector webview.
// Pure data + string builders — no vscode and no cryptography. Everything here is
// sourced from the PostQuantum.Jwt v1 profile (docs/SPEC.md) and docs/design.md so
// the visuals stay authoritative.

/** Minimal, theme-aware inline SVG icons (they inherit `currentColor`). */
export const ICONS = {
  sign: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 17.25V21h3.75L18 9.75 14.25 6 3 17.25z"/><path d="M14.25 6L18 9.75"/></svg>`,
  key: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="8" cy="8" r="4"/><path d="M11 11l8 8M16 16l2-2M19 19l2-2"/></svg>`,
  lock: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4.5" y="10.5" width="15" height="10" rx="2"/><path d="M8 10.5V7a4 4 0 0 1 8 0v3.5"/></svg>`,
  combine: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 3v6a6 6 0 0 0 6 6 6 6 0 0 0 6-6V3"/><path d="M12 15v6"/><path d="M8 21h8"/></svg>`,
  shield: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6l7-3z"/></svg>`,
  arrowDown: `<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 4v16M6 14l6 6 6-6"/></svg>`,
} as const;

/** Color "lane" per segment field — wired to CSS classes, not hard-coded colors. */
export const SEGMENT_LANE: Record<string, string> = {
  header: "lane-header",
  payload: "lane-payload",
  signature: "lane-signature",
  kem_ct: "lane-kem",
  iv: "lane-iv",
  ciphertext: "lane-ciphertext",
  tag: "lane-tag",
};

/** A stage in the sign-then-encrypt construction (outer = encrypted form). */
export interface HybridStage {
  icon: string;
  title: string;
  body: string;
  /** Optional monospace detail (e.g. the combiner formula). */
  detail?: string;
  /** Output produced by this stage, shown on the connector. */
  produces?: string;
}

export const HYBRID_STAGES: HybridStage[] = [
  {
    icon: ICONS.sign,
    title: "1 · Sign — ML-DSA-65",
    body: "The issuer signs the claims with its ML-DSA-65 private key (FIPS 204). The result is a complete 3-segment signed JWT: <code>header.payload.signature</code>.",
    produces: "Inner signed JWT (3 segments)",
  },
  {
    icon: ICONS.combine,
    title: "2 · Encapsulate — X-Wing",
    body: "To a recipient's X-Wing public key, the issuer runs the hybrid KEM. X25519 and ML-KEM-768 each produce a shared secret; the X-Wing combiner binds them into one 32-byte key.",
    detail: "ss = SHA3-256( ss_ML-KEM ‖ ss_X25519 ‖ ct_X25519 ‖ pk_X25519 ‖ label )",
    produces: "32-byte shared secret  +  kem_ct (1120 B)",
  },
  {
    icon: ICONS.lock,
    title: "3 · Encrypt — AES-256-GCM",
    body: "The shared secret is the AES-256-GCM key. The <em>entire inner signed JWT</em> becomes the plaintext; the protected header is the AAD. GCM yields the ciphertext, a 12-byte IV, and a 16-byte tag.",
    produces: "Outer encrypted JWT (5 segments)",
  },
];

/** Hybrid one-liner facts surfaced beside the diagram. */
export const XWING_FACTS: string[] = [
  "X-Wing = X25519 (classical ECDH) + ML-KEM-768 (FIPS 203 post-quantum KEM).",
  "Hybrid means an attacker must break <em>both</em> to recover the key — safe even if one is later broken.",
  "kem_ct is 1120 bytes: the 1088-byte ML-KEM-768 ciphertext concatenated with the 32-byte X25519 ephemeral public key.",
  "The signed JWT is encrypted whole, so the signature is confidential too — observers can't even see who signed it.",
];

/** A check in the fail-closed validation pipeline (docs/SPEC.md §Validation). */
export interface ValidationStep {
  n: number;
  title: string;
  /** What the verifier does at this step. */
  does: string;
  /** Why it rejects — the matching "explicitly rejected" reasons. */
  rejectsWhen: string[];
  /** Only runs for the encrypted (5-segment) form. */
  encryptedOnly?: boolean;
}

export const VALIDATION_STEPS: ValidationStep[] = [
  {
    n: 1,
    title: "Pre-parse bounds",
    does: "Reject input longer than the maximum accepted length (128 KiB) before any split, decode, or parse.",
    rejectsWhen: ["Oversized or truncated input."],
  },
  {
    n: 2,
    title: "Segment count",
    does: "Require exactly 3 (signed) or 5 (encrypted) dot-separated segments.",
    rejectsWhen: ["Any other segment count."],
  },
  {
    n: 3,
    title: "Decrypt",
    does: "A decryption key must be configured; check alg/enc, X-Wing decapsulate, then AES-256-GCM decrypt with the header as AAD. The plaintext must be a 3-segment signed token.",
    rejectsWhen: ["No decryption key configured.", "alg ≠ X-Wing or enc ≠ A256GCM.", "GCM tag mismatch (tampering)."],
    encryptedOnly: true,
  },
  {
    n: 4,
    title: "Algorithm",
    does: "alg MUST equal ML-DSA-65. The verifier never uses the header alg to select a path — it accepts exactly one suite.",
    rejectsWhen: ["alg = none, missing, or anything other than ML-DSA-65."],
  },
  {
    n: 5,
    title: "Key selection",
    does: "When a kid is present, resolve it through the configured key ring / resolver. Key selection never bypasses the algorithm allowlist.",
    rejectsWhen: ["A kid that does not resolve (when rotation is in use)."],
  },
  {
    n: 6,
    title: "Signature",
    does: "Verify the ML-DSA-65 signature over ASCII(header.payload).",
    rejectsWhen: ["Signature verification fails."],
  },
  {
    n: 7,
    title: "Claims",
    does: "Validate exp (required by default) and nbf within the configured clock skew (default 60s); validate iss/aud when configured.",
    rejectsWhen: ["Missing exp (unless explicitly disabled).", "Expired, or nbf too far in the future.", "iss/aud mismatch.", "A present-but-malformed time claim."],
  },
  {
    n: 8,
    title: "Replay",
    does: "When a replay cache is configured, the jti must be present and not previously seen.",
    rejectsWhen: ["Missing jti or a repeated jti (with a replay cache configured)."],
  },
];
