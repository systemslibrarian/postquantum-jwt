// Build an intelligent deep-link into the live playground from a decoded token.
//
// The playground restores a build form from a `?c=<base64url(json)>` "share" param
// (samples/PqJwtPlayground — ShareState, camelCase JSON). For a *signed* token we
// can reconstruct that form from its readable claims and pre-populate issuer,
// audience, subject, lifetime, jti, and any custom claims. Encrypted tokens have
// an opaque payload, so we fall back to opening the playground plainly.
//
// No cryptography and no key material ever leaves the machine: the share form
// carries claims and options only (the playground regenerates its own keys).
import { LINKS } from "./links";
import { RESERVED_CLAIMS, type TokenModel } from "./model";

interface ShareClaim {
  name: string;
  value: string;
}

// Mirrors samples/PqJwtPlayground ShareState (System.Text.Json camelCase).
interface ShareState {
  sub: string | null;
  iss: string | null;
  aud: string | null;
  minutes: number;
  encrypt: boolean;
  jti: boolean;
  claims: ShareClaim[];
}

function base64UrlEncode(bytes: Buffer): string {
  return bytes.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function asString(value: unknown): string | null {
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value === "string") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(String).join(" ");
  }
  return String(value);
}

/**
 * Reconstruct the playground share form from a signed token's claims, or
 * `undefined` when the token isn't a readable signed token.
 */
export function buildShareState(model: TokenModel): ShareState | undefined {
  if (model.form !== "signed") {
    return undefined;
  }
  const payload = model.segments[1]?.decode;
  if (!payload || payload.kind !== "json") {
    return undefined;
  }
  const value = payload.value;
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return undefined;
  }
  const obj = value as Record<string, unknown>;

  // Lifetime: prefer exp − (iat | nbf); clamp to the playground's 1..1440 minutes.
  const exp = typeof obj.exp === "number" ? obj.exp : undefined;
  const start = typeof obj.iat === "number" ? obj.iat : typeof obj.nbf === "number" ? obj.nbf : undefined;
  let minutes = 15;
  if (exp !== undefined && start !== undefined && exp > start) {
    minutes = Math.round((exp - start) / 60);
  }
  minutes = Math.min(1440, Math.max(1, minutes));

  const claims: ShareClaim[] = Object.entries(obj)
    .filter(([name]) => !RESERVED_CLAIMS.has(name))
    .map(([name, v]) => ({ name, value: typeof v === "string" ? v : JSON.stringify(v) }));

  return {
    sub: asString(obj.sub),
    iss: asString(obj.iss),
    aud: asString(obj.aud),
    minutes,
    encrypt: false,
    jti: obj.jti !== undefined,
    claims,
  };
}

/**
 * A playground URL pre-populated from the token when possible, otherwise the
 * plain playground. Falls back to plain if the encoded form would exceed the
 * playground's accepted share length (8 KiB).
 */
export function buildPlaygroundUrl(model: TokenModel): string {
  const base = LINKS.playground.replace(/\/+$/, "");
  const state = buildShareState(model);
  if (!state) {
    return LINKS.playground;
  }
  const code = base64UrlEncode(Buffer.from(JSON.stringify(state), "utf8"));
  if (code.length > 8000) {
    return LINKS.playground;
  }
  return `${base}/?c=${code}`;
}
