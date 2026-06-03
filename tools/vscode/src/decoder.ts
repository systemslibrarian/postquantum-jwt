// Pure token-decoding logic — no vscode dependency, so it is fully unit-testable
// off the extension host. This does NO cryptography: it inspects the compact
// serialization structure and the (unencrypted) protected header only.
import { LINKS } from "./links";

// The subset of JOSE header fields this decoder inspects.
export interface JoseHeader {
  alg?: string;
  enc?: string;
  cty?: string;
  kid?: string;
}

// JSON.parse can return null, a primitive, or an array — none of which is a JOSE
// header. Coerce anything that isn't a plain object to an empty header so field
// access never throws (a header decoding to `null` must not crash detection).
function asHeader(value: unknown): JoseHeader {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as JoseHeader)
    : {};
}

// base64url uses the URL-safe alphabet with no padding.
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

export function base64UrlDecode(segment: string): string {
  let b64 = segment.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) {
    b64 += "=";
  }
  return Buffer.from(b64, "base64").toString("utf8");
}

// The outcome of decoding a single compact segment, distinguishing the failure
// modes so the output can be precise about *why* a segment didn't read.
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

function renderSegment(decode: SegmentDecode, label: string): string[] {
  switch (decode.kind) {
    case "json":
      return [decode.pretty];
    case "empty":
      return [`(${label} segment is empty)`];
    case "not-base64url":
      return [`(${label} segment is not valid base64url — cannot decode)`];
    case "not-json": {
      const preview = decode.text.length > 200 ? decode.text.slice(0, 200) + "…" : decode.text;
      return [`(${label} decoded but is not valid JSON):`, preview];
    }
  }
}

// ---------------------------------------------------------------------------
// In-editor token detection (for the inline "Inspect PQ-JWT" CodeLens)
// ---------------------------------------------------------------------------

// A maximal compact-serialization run: a long-ish first segment followed by one
// or more dot-separated base64url segments. We match greedily and then decide
// how many segments are actually the token (see findPqJwtTokens) so trailing
// ".word.word" doesn't swallow a valid 3-part token into a rejected 5-part one.
// A fresh regex per call keeps `lastIndex` from leaking across scans.
const tokenRunRegex = (): RegExp =>
  /[A-Za-z0-9_-]{16,}(?:\.[A-Za-z0-9_-]{2,})+/g;

// The protected-header `alg`, or undefined if the segment isn't JSON-object-shaped.
function headerAlg(segment: string): string | undefined {
  const header = decodeSegment(segment);
  return header.kind === "json" ? asHeader(header.value).alg : undefined;
}

// Tight gate against false positives (version strings, hashes, base64 blobs):
// only treat a candidate as a PostQuantum.Jwt token if it has exactly 3 or 5
// segments AND its protected header decodes to this suite's `alg`.
export function looksLikePqJwt(candidate: string): boolean {
  const parts = candidate.split(".");
  if (parts.length !== 3 && parts.length !== 5) {
    return false;
  }
  const alg = headerAlg(parts[0]);
  return parts.length === 3 ? alg === "ML-DSA-65" : alg === "X-Wing";
}

export interface FoundToken {
  value: string;
  start: number;
  end: number;
}

// Find PostQuantum.Jwt tokens within a single line of text.
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
    if (segments.length >= 3 && alg === "ML-DSA-65") {
      take = 3;
    } else if (segments.length >= 5 && alg === "X-Wing") {
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

export function decodeToken(token: string): string {
  const trimmed = token
    .trim()
    // Users often grab the wrapping quotes/backticks (and a trailing , or ;)
    // when highlighting a string literal — strip them so the token still reads.
    .replace(/^['"`]+/, "")
    .replace(/['"`,;]+$/, "")
    // …or grab a whole "Authorization: Bearer <token>" line from an .http file.
    .replace(/^authorization\s*:\s*/i, "")
    .replace(/^bearer\s+/i, "")
    .replace(/\s+/g, "");
  const parts = trimmed.split(".");
  const lines: string[] = [];

  if (trimmed.length === 0) {
    return "No token provided.";
  }

  if (parts.length === 3) {
    lines.push("Form: SIGNED (3 segments)  —  header.payload.signature");
  } else if (parts.length === 5) {
    lines.push("Form: ENCRYPTED (5 segments)  —  header.encryptedKey.iv.ciphertext.tag");
    lines.push("(Sign-then-encrypt: a signed JWT nested inside a JWE.)");
  } else {
    lines.push(
      `Not a PostQuantum.Jwt compact token: found ${parts.length} segment(s), expected 3 (signed) or 5 (encrypted).`
    );
    return lines.join("\n");
  }

  lines.push("");
  lines.push("=== Protected header ===");
  const headerDecode = decodeSegment(parts[0]);
  lines.push(...renderSegment(headerDecode, "header"));
  const header: JoseHeader = headerDecode.kind === "json" ? asHeader(headerDecode.value) : {};

  // Algorithm sanity notes
  lines.push("");
  lines.push("=== Notes ===");
  if (header.kid) {
    lines.push(`• kid = ${header.kid} (key id — resolved at validation for rotation).`);
  }
  if (parts.length === 3) {
    if (header.alg === "ML-DSA-65") {
      lines.push("✓ alg = ML-DSA-65 (post-quantum signature, FIPS 204).");
    } else if (header.alg === "none") {
      lines.push("✗ alg = none — PostQuantum.Jwt has NO unsigned path; it would reject this.");
    } else {
      lines.push(`• alg = ${header.alg ?? "(missing)"} — not the expected ML-DSA-65 suite.`);
    }
    lines.push("");
    lines.push("=== Payload (claims) ===");
    lines.push(...renderSegment(decodeSegment(parts[1]), "payload"));
  } else {
    if (header.enc === "A256GCM") {
      lines.push("✓ enc = A256GCM (AES-256-GCM content encryption).");
    } else {
      lines.push(`• enc = ${header.enc ?? "(missing)"} — expected A256GCM.`);
    }
    if (header.alg === "X-Wing") {
      lines.push("✓ alg = X-Wing (hybrid key management: X25519 + ML-KEM-768).");
    } else {
      lines.push(`• alg = ${header.alg ?? "(missing)"} — expected X-Wing.`);
    }
    if (header.cty === "JWT") {
      lines.push("✓ cty = JWT (a signed JWT is nested inside).");
    }
    lines.push("");
    lines.push("Payload is encrypted — claims are not readable without the X-Wing private key.");
    lines.push("This decoder does no cryptography; it only inspects structure and headers.");
  }

  lines.push("");
  lines.push("─".repeat(60));
  lines.push("PostQuantum.Jwt is for controlled issuer/verifier systems.");
  lines.push("These tokens do not interop with generic JWT tooling.");
  lines.push(`Docs: ${LINKS.docs}`);

  return lines.join("\n");
}
