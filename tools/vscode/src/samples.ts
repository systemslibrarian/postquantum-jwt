// A representative (non-cryptographic) sample token, used when the educational
// commands are invoked without a token in the editor. The header and claims are
// real, decodable JSON; the signature segment is illustrative placeholder bytes
// (no signing happens anywhere in this extension).
import { SUITE } from "./model";

function seg(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj), "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/** A realistic 3-segment signed token for demos and the walkthrough. */
export function sampleSignedToken(): string {
  const header = { alg: SUITE.signature, typ: "JWT", kid: "2026-06" };
  const now = 1_780_000_000; // fixed instant so the sample is deterministic
  const payload = {
    iss: "https://issuer.example",
    sub: "user-7f3a",
    aud: "orders-api",
    iat: now,
    nbf: now,
    exp: now + 900,
    jti: "b2c1a0e4-9f1d-4c3a-8b77-2a1e5d6c7f80",
    role: "operator",
  };
  // Illustrative signature bytes (base64url). Not a real ML-DSA-65 signature.
  const signature = "c2FtcGxlLXNpZ25hdHVyZS1ub3QtcmVhbC1NTC1EU0EtNjUtcGxhY2Vob2xkZXI";
  return `${seg(header)}.${seg(payload)}.${signature}`;
}
