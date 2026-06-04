// Pure, crypto-free token model — the single source of truth for everything the
// extension shows about a PostQuantum.Jwt token (text decode, webview inspector,
// hovers, and the playground deep-link). It has NO vscode dependency, so it is
// fully unit-testable off the extension host.
//
// This module does NO cryptography. It inspects the compact-serialization
// structure and the (unencrypted) protected header only. Encrypted payloads stay
// encrypted; we never claim a signature is "valid" — only that the structure is
// well-formed and the headers say what the profile expects.
//
// Authoritative references (PostQuantum.Jwt Token Profile v1, docs/SPEC.md):
//   • Signed     = 3 segments: header.payload.signature                (alg ML-DSA-65)
//   • Encrypted  = 5 segments: header.kem_ct.iv.ciphertext.tag         (alg X-Wing, enc A256GCM)
//   • Sign-then-encrypt: the plaintext of the JWE is a complete signed token.

// ---------------------------------------------------------------------------
// JOSE header + base64url primitives
// ---------------------------------------------------------------------------

/** The subset of JOSE header fields this tooling inspects. */
export interface JoseHeader {
  alg?: string;
  enc?: string;
  cty?: string;
  typ?: string;
  kid?: string;
}

// JSON.parse can return null, a primitive, or an array — none of which is a JOSE
// header. Coerce anything that isn't a plain object to an empty header so field
// access never throws (a header decoding to `null` must not crash detection).
export function asHeader(value: unknown): JoseHeader {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as JoseHeader)
    : {};
}

// base64url uses the URL-safe alphabet with no padding.
export const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

export function base64UrlDecode(segment: string): string {
  let b64 = segment.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) {
    b64 += "=";
  }
  return Buffer.from(b64, "base64").toString("utf8");
}

/** Decoded byte length of a base64url segment (0 if it isn't base64url). */
export function base64UrlByteLength(segment: string): number {
  if (segment.length === 0 || !BASE64URL_RE.test(segment)) {
    return 0;
  }
  let b64 = segment.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) {
    b64 += "=";
  }
  return Buffer.from(b64, "base64").length;
}

// The outcome of decoding a single compact segment, distinguishing the failure
// modes so output can be precise about *why* a segment didn't read.
export type SegmentDecode =
  | { kind: "json"; pretty: string; value: unknown }
  | { kind: "empty" }
  | { kind: "not-base64url" }
  | { kind: "not-json"; text: string };

export function decodeSegment(segment: string): SegmentDecode {
  if (segment.length === 0) {
    return { kind: "empty" };
  }
  if (!BASE64URL_RE.test(segment)) {
    return { kind: "not-base64url" };
  }
  const text = base64UrlDecode(segment);
  try {
    const value: unknown = JSON.parse(text);
    return { kind: "json", pretty: JSON.stringify(value, null, 2), value };
  } catch {
    return { kind: "not-json", text };
  }
}

// The protected-header `alg`, or undefined if the segment isn't JSON-object-shaped.
export function headerAlg(segment: string): string | undefined {
  const header = decodeSegment(segment);
  return header.kind === "json" ? asHeader(header.value).alg : undefined;
}

// ---------------------------------------------------------------------------
// In-editor token detection (for the inline "Inspect PQ-JWT" CodeLens)
// ---------------------------------------------------------------------------

// A maximal compact-serialization run: a long-ish first segment followed by one
// or more dot-separated base64url segments. We match greedily and then decide
// how many segments are actually the token so trailing ".word.word" doesn't
// swallow a valid 3-part token into a rejected 5-part one. A fresh regex per
// call keeps `lastIndex` from leaking across scans.
const tokenRunRegex = (): RegExp => /[A-Za-z0-9_-]{16,}(?:\.[A-Za-z0-9_-]{2,})+/g;

/** The canonical algorithm identifiers this profile produces and accepts. */
export const SUITE = {
  signature: "ML-DSA-65",
  keyManagement: "X-Wing",
  contentEncryption: "A256GCM",
} as const;

// Tight gate against false positives (version strings, hashes, base64 blobs):
// only treat a candidate as a PostQuantum.Jwt token if it has exactly 3 or 5
// segments AND its protected header decodes to this suite's `alg`.
export function looksLikePqJwt(candidate: string): boolean {
  const parts = candidate.split(".");
  if (parts.length !== 3 && parts.length !== 5) {
    return false;
  }
  const alg = headerAlg(parts[0]);
  return parts.length === 3 ? alg === SUITE.signature : alg === SUITE.keyManagement;
}

export interface FoundToken {
  value: string;
  start: number;
  end: number;
}

/** Find PostQuantum.Jwt tokens within a single line of text. */
export function findPqJwtTokens(text: string): FoundToken[] {
  const found: FoundToken[] = [];
  for (const match of text.matchAll(tokenRunRegex())) {
    if (match.index === undefined) {
      continue;
    }
    const segments = match[0].split(".");
    const alg = headerAlg(segments[0]);
    // Take only as many segments as the detected form needs: a signed token is
    // the first 3, an encrypted token the first 5. Anything trailing is junk.
    let take = 0;
    if (segments.length >= 3 && alg === SUITE.signature) {
      take = 3;
    } else if (segments.length >= 5 && alg === SUITE.keyManagement) {
      take = 5;
    }
    if (take === 0) {
      continue;
    }
    const value = segments.slice(0, take).join(".");
    found.push({ value, start: match.index, end: match.index + value.length });
  }
  return found;
}

// ---------------------------------------------------------------------------
// Structured token model
// ---------------------------------------------------------------------------

export type TokenForm = "signed" | "encrypted" | "unknown";

/** A header/identifier assertion rendered as a badge in the inspector. */
export interface AlgoBadge {
  /** Field this badge speaks to: `alg`, `enc`, `typ`, `cty`, `kid`. */
  field: string;
  /** The value found in the header (or `(missing)`). */
  value: string;
  /** Does it match the profile's expectation? `warn` = present but unexpected. */
  status: "ok" | "warn" | "bad";
  /** Plain-language explanation. */
  note: string;
}

/** One compact-serialization segment, described for display. */
export interface SegmentInfo {
  index: number;
  /** Human name, e.g. "Protected header", "Ciphertext", "Authentication tag". */
  name: string;
  /** The JOSE/profile field name, e.g. "header", "kem_ct", "iv", "tag". */
  field: string;
  /** Is the content meant to be human-readable JSON (vs opaque bytes)? */
  readable: boolean;
  /** Decoded byte length (for opaque segments this is the useful measure). */
  byteLength: number;
  /** Expected byte length when the profile fixes it (iv=12, tag=16, kem_ct=1120). */
  expectedBytes?: number;
  /** Pretty-printed JSON when `readable` and decodable. */
  json?: string;
  /** A short descriptor of what lives here. */
  note: string;
  /** The raw base64url text of the segment. */
  raw: string;
  decode: SegmentDecode;
}

export interface ClaimRow {
  name: string;
  value: string;
  /** A registered JWT claim (iss/sub/aud/exp/nbf/iat/jti) vs a custom claim. */
  reserved: boolean;
}

/** Registered claim names the validator and profile give meaning to. */
export const RESERVED_CLAIMS = new Set(["iss", "sub", "aud", "exp", "nbf", "iat", "jti"]);

export interface TokenModel {
  form: TokenForm;
  /** Number of dot-separated segments actually found. */
  segmentCount: number;
  /** Structurally consistent with the PostQuantum.Jwt v1 profile. */
  wellFormed: boolean;
  /** The decoded protected header (empty object if unreadable). */
  header: JoseHeader;
  headerJson?: string;
  badges: AlgoBadge[];
  segments: SegmentInfo[];
  /** Readable claims (signed form only); undefined when the payload is encrypted. */
  claims?: ClaimRow[];
  /** True when the payload is ciphertext (encrypted form). */
  encryptedPayload: boolean;
  /** One-line human summary. */
  summary: string;
  /** Non-fatal mismatches worth surfacing (unexpected alg, odd sizes). */
  warnings: string[];
  /** Hard structural problems (wrong segment count, alg none, unreadable header). */
  errors: string[];
  /** The cleaned token text the model was built from. */
  token: string;
}

/**
 * Strip the wrapping noise users grab when selecting a token from source: quotes,
 * a trailing comma/semicolon, an `Authorization: Bearer` prefix, and whitespace.
 */
export function cleanToken(token: string): string {
  return token
    .trim()
    .replace(/^['"`]+/, "")
    .replace(/['"`,;]+$/, "")
    .replace(/^authorization\s*:\s*/i, "")
    .replace(/^bearer\s+/i, "")
    .replace(/\s+/g, "");
}

// Per-form segment metadata. Sizes/notes come from docs/SPEC.md and docs/design.md.
const SIGNED_SEGMENTS = [
  { name: "Protected header", field: "header", readable: true, note: "JOSE header — alg, typ, optional kid." },
  { name: "Payload", field: "payload", readable: true, note: "The JWT claims set (a JSON object)." },
  { name: "Signature", field: "signature", readable: false, note: "ML-DSA-65 signature over ASCII(header.payload)." },
] as const;

const ENCRYPTED_SEGMENTS = [
  { name: "Protected header", field: "header", readable: true, note: "JOSE header — alg, enc, typ, cty." },
  {
    name: "Encrypted key",
    field: "kem_ct",
    readable: false,
    note: "X-Wing encapsulation: ML-KEM-768 ciphertext ‖ X25519 ephemeral public key.",
    expectedBytes: 1120,
  },
  { name: "Initialization vector", field: "iv", readable: false, note: "12-byte AES-256-GCM nonce.", expectedBytes: 12 },
  {
    name: "Ciphertext",
    field: "ciphertext",
    readable: false,
    note: "AES-256-GCM-encrypted inner signed JWT (sign-then-encrypt).",
  },
  { name: "Authentication tag", field: "tag", readable: false, note: "16-byte AES-256-GCM tag.", expectedBytes: 16 },
] as const;

function buildSegment(
  meta: { name: string; field: string; readable: boolean; note: string; expectedBytes?: number },
  index: number,
  raw: string
): SegmentInfo {
  const decode = decodeSegment(raw);
  return {
    index,
    name: meta.name,
    field: meta.field,
    readable: meta.readable,
    byteLength: base64UrlByteLength(raw),
    expectedBytes: meta.expectedBytes,
    json: meta.readable && decode.kind === "json" ? decode.pretty : undefined,
    note: meta.note,
    raw,
    decode,
  };
}

function badge(field: string, value: string | undefined, expected: string): AlgoBadge {
  const shown = value ?? "(missing)";
  if (value === expected) {
    return { field, value: shown, status: "ok", note: expectedNote(field, expected) };
  }
  if (value === undefined) {
    return { field, value: shown, status: "bad", note: `Expected ${field} = ${expected}.` };
  }
  // `none` for alg is the one value we call out as a hard rejection, not a warn.
  if (field === "alg" && value === "none") {
    return {
      field,
      value: shown,
      status: "bad",
      note: "PostQuantum.Jwt has NO unsigned path — a verifier rejects alg=none outright.",
    };
  }
  return { field, value: shown, status: "warn", note: `Expected ${field} = ${expected}; this profile accepts only that.` };
}

function expectedNote(field: string, value: string): string {
  switch (`${field}:${value}`) {
    case "alg:ML-DSA-65":
      return "Post-quantum signature (FIPS 204; JOSE id RFC 9964).";
    case "alg:X-Wing":
      return "Hybrid key management: X25519 + ML-KEM-768.";
    case "enc:A256GCM":
      return "AES-256-GCM content encryption.";
    case "cty:JWT":
      return "Content type JWT — a signed JWT is nested inside.";
    case "typ:JWT":
      return "Token type JWT.";
    default:
      return `${field} = ${value}.`;
  }
}

function stringifyClaim(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  return JSON.stringify(value);
}

function buildClaims(payloadValue: unknown): ClaimRow[] | undefined {
  if (typeof payloadValue !== "object" || payloadValue === null || Array.isArray(payloadValue)) {
    return undefined;
  }
  return Object.entries(payloadValue as Record<string, unknown>).map(([name, value]) => ({
    name,
    value: stringifyClaim(value),
    reserved: RESERVED_CLAIMS.has(name),
  }));
}

/**
 * Build the structured model for a token. Accepts raw (possibly quote/Bearer-
 * wrapped) text; cleans it first. Never throws on malformed input — every failure
 * mode is reported through `errors` / `warnings` and the `unknown` form.
 */
export function buildTokenModel(rawToken: string): TokenModel {
  const token = cleanToken(rawToken);
  const parts = token.split(".");
  const warnings: string[] = [];
  const errors: string[] = [];

  if (token.length === 0) {
    return emptyModel(token, ["No token provided."]);
  }

  if (parts.length !== 3 && parts.length !== 5) {
    return {
      ...emptyModel(token, [
        `Found ${parts.length} segment(s); a PostQuantum.Jwt token has 3 (signed) or 5 (encrypted).`,
      ]),
      segmentCount: parts.length,
    };
  }

  const form: TokenForm = parts.length === 3 ? "signed" : "encrypted";
  const headerDecode = decodeSegment(parts[0]);
  const header = headerDecode.kind === "json" ? asHeader(headerDecode.value) : {};
  if (headerDecode.kind !== "json") {
    errors.push("Protected header did not decode to a JSON object.");
  }

  const metas = form === "signed" ? SIGNED_SEGMENTS : ENCRYPTED_SEGMENTS;
  const segments = metas.map((meta, i) => buildSegment(meta, i, parts[i]));

  // Size sanity for the fixed-length opaque segments.
  for (const seg of segments) {
    if (seg.expectedBytes !== undefined && seg.byteLength !== seg.expectedBytes && seg.byteLength > 0) {
      warnings.push(`${seg.name} is ${seg.byteLength} bytes; the profile expects ${seg.expectedBytes}.`);
    }
  }

  const badges: AlgoBadge[] = [];
  let claims: ClaimRow[] | undefined;

  if (form === "signed") {
    badges.push(badge("alg", header.alg, SUITE.signature));
    if (header.typ) {
      badges.push(badge("typ", header.typ, "JWT"));
    }
    const payloadDecode = segments[1].decode;
    if (payloadDecode.kind === "json") {
      claims = buildClaims(payloadDecode.value);
      if (claims === undefined) {
        warnings.push("Payload decoded but is not a JSON object.");
      }
    } else {
      warnings.push("Payload did not decode to readable JSON.");
    }
  } else {
    badges.push(badge("alg", header.alg, SUITE.keyManagement));
    badges.push(badge("enc", header.enc, SUITE.contentEncryption));
    badges.push(badge("cty", header.cty, "JWT"));
    if (header.typ) {
      badges.push(badge("typ", header.typ, "JWT"));
    }
  }

  if (header.kid) {
    badges.push({
      field: "kid",
      value: header.kid,
      status: "ok",
      note: "Key id — resolved at validation to support key rotation.",
    });
  }

  const wellFormed = errors.length === 0 && badges.every((b) => b.status === "ok");

  return {
    form,
    segmentCount: parts.length,
    wellFormed,
    header,
    headerJson: headerDecode.kind === "json" ? headerDecode.pretty : undefined,
    badges,
    segments,
    claims,
    encryptedPayload: form === "encrypted",
    summary: summarize(form, header),
    warnings,
    errors,
    token,
  };
}

function summarize(form: TokenForm, header: JoseHeader): string {
  if (form === "signed") {
    return `Signed token (3 segments) — ${header.alg ?? "?"} over header.payload.`;
  }
  return `Encrypted token (5 segments) — a ${header.alg ?? "?"}/${header.enc ?? "?"} JWE wrapping a signed JWT.`;
}

function emptyModel(token: string, errors: string[]): TokenModel {
  return {
    form: "unknown",
    segmentCount: token.length === 0 ? 0 : token.split(".").length,
    wellFormed: false,
    header: {},
    badges: [],
    segments: [],
    claims: undefined,
    encryptedPayload: false,
    summary: errors[0] ?? "Not a PostQuantum.Jwt token.",
    warnings: [],
    errors,
    token,
  };
}
