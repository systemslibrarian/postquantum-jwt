// The plain-text token decode (the "PostQuantum.Jwt: Decode Token" output and the
// virtual read-only tab). It builds on the pure model in `model.ts` and renders a
// compact textual report. No vscode dependency; no cryptography — structure and
// the unencrypted protected header only.
import { LINKS } from "./links";
import { asHeader, decodeSegment, cleanToken, type JoseHeader, type SegmentDecode } from "./model";

// Re-export the primitives and detection helpers that other modules and tests
// have historically imported from `./decoder`, so this stays the stable surface.
export {
  base64UrlDecode,
  decodeSegment,
  findPqJwtTokens,
  looksLikePqJwt,
  type JoseHeader,
  type SegmentDecode,
  type FoundToken,
} from "./model";

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

export function decodeToken(token: string): string {
  const trimmed = cleanToken(token);
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
