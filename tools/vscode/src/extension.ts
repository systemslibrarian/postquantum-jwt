import * as vscode from "vscode";

// ---------------------------------------------------------------------------
// Shared links
// ---------------------------------------------------------------------------
const LINKS = {
  playground: "https://pqjwt.systemslibrarian.dev",
  docs: "https://github.com/systemslibrarian/postquantum-jwt#readme",
  nuget: "https://www.nuget.org/packages/PostQuantum.Jwt",
  repo: "https://github.com/systemslibrarian/postquantum-jwt",
};

// Map of API symbols -> README anchor for hover/CodeLens links.
const API_DOCS: Record<string, { anchor: string; blurb: string }> = {
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

// Base docs URL without the README fragment, plus a helper to anchor into it.
const DOCS_BASE = LINKS.docs.replace("#readme", "");
const docUrl = (anchor: string): string => `${DOCS_BASE}${anchor}`;

// A fresh global regex per call — `matchAll` requires the `g` flag, and a new
// instance avoids the shared-`lastIndex` state a module-level regex would carry.
const apiRegex = (): RegExp =>
  new RegExp(`\\b(${Object.keys(API_DOCS).join("|")})\\b`, "g");

// The subset of JOSE header fields this decoder inspects (structure only).
interface JoseHeader {
  alg?: string;
  enc?: string;
  cty?: string;
  kid?: string;
}

// ---------------------------------------------------------------------------
// Token decoder (pure string work, no crypto)
// ---------------------------------------------------------------------------
function base64UrlDecode(segment: string): string {
  let b64 = segment.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) {
    b64 += "=";
  }
  return Buffer.from(b64, "base64").toString("utf8");
}

function prettyJson(raw: string): string {
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw; // not JSON (e.g. an encrypted/binary segment) — show as-is
  }
}

function decodeToken(token: string): string {
  const trimmed = token.trim().replace(/\s+/g, "");
  const parts = trimmed.split(".");
  const lines: string[] = [];

  if (parts.length === 3) {
    lines.push("Form: SIGNED (3 segments)  —  header.payload.signature");
  } else if (parts.length === 5) {
    lines.push(
      "Form: ENCRYPTED (5 segments)  —  header.encryptedKey.iv.ciphertext.tag"
    );
    lines.push("(Sign-then-encrypt: a signed JWT nested inside a JWE.)");
  } else {
    lines.push(
      `Not a PostQuantum.Jwt compact token: found ${parts.length} segment(s), expected 3 (signed) or 5 (encrypted).`
    );
    return lines.join("\n");
  }

  lines.push("");
  lines.push("=== Protected header ===");
  let header: JoseHeader = {};
  try {
    const headerRaw = base64UrlDecode(parts[0]);
    header = JSON.parse(headerRaw) as JoseHeader;
    lines.push(prettyJson(headerRaw));
  } catch {
    lines.push("(could not decode header)");
  }

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
    try {
      lines.push(prettyJson(base64UrlDecode(parts[1])));
    } catch {
      lines.push("(could not decode payload)");
    }
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

async function runDecode(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  let candidate = "";
  if (editor && !editor.selection.isEmpty) {
    candidate = editor.document.getText(editor.selection);
  }
  if (!candidate.trim()) {
    const input = await vscode.window.showInputBox({
      prompt: "Paste a PostQuantum.Jwt token to decode (header/structure only — no crypto).",
      placeHolder: "eyJhbGciOiJNTC1EU0EtNjUi...",
    });
    if (!input) {
      return;
    }
    candidate = input;
  }

  const output = decodeToken(candidate);
  const doc = await vscode.workspace.openTextDocument({
    content: output,
    language: "plaintext",
  });
  await vscode.window.showTextDocument(doc, { preview: true });
}

// ---------------------------------------------------------------------------
// Hover provider
// ---------------------------------------------------------------------------
class PqJwtHoverProvider implements vscode.HoverProvider {
  provideHover(
    document: vscode.TextDocument,
    position: vscode.Position
  ): vscode.ProviderResult<vscode.Hover> {
    const range = document.getWordRangeAtPosition(position, /[A-Za-z_][A-Za-z0-9_]*/);
    if (!range) {
      return;
    }
    const word = document.getText(range);
    const entry = API_DOCS[word];
    if (!entry) {
      return;
    }
    const md = new vscode.MarkdownString(
      `**${word}** — PostQuantum.Jwt\n\n${entry.blurb}\n\n` +
        `[Docs](${docUrl(entry.anchor)}) · ` +
        `[Playground](${LINKS.playground}) · [NuGet](${LINKS.nuget})`
    );
    md.isTrusted = true;
    return new vscode.Hover(md, range);
  }
}

// ---------------------------------------------------------------------------
// CodeLens provider
// ---------------------------------------------------------------------------
class PqJwtCodeLensProvider implements vscode.CodeLensProvider {
  provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
    const lenses: vscode.CodeLens[] = [];
    for (let line = 0; line < document.lineCount; line++) {
      const text = document.lineAt(line).text;
      const seenOnLine = new Set<string>();
      for (const match of text.matchAll(apiRegex())) {
        const symbol = match[1];
        if (seenOnLine.has(symbol)) {
          continue; // one lens per distinct symbol per line
        }
        seenOnLine.add(symbol);
        const range = new vscode.Range(line, 0, line, 0);
        lenses.push(
          new vscode.CodeLens(range, {
            title: `📖 PostQuantum.Jwt: ${symbol} docs`,
            command: "vscode.open",
            arguments: [vscode.Uri.parse(docUrl(API_DOCS[symbol].anchor))],
          })
        );
      }
    }
    return lenses;
  }
}

// ---------------------------------------------------------------------------
// Activation
// ---------------------------------------------------------------------------
export function activate(context: vscode.ExtensionContext) {
  const open = (url: string) => () =>
    vscode.env.openExternal(vscode.Uri.parse(url));

  context.subscriptions.push(
    vscode.commands.registerCommand("pqjwt.decodeToken", runDecode),
    vscode.commands.registerCommand("pqjwt.openPlayground", open(LINKS.playground)),
    vscode.commands.registerCommand("pqjwt.openDocs", open(LINKS.docs)),
    vscode.commands.registerCommand("pqjwt.openNuget", open(LINKS.nuget)),
    vscode.commands.registerCommand("pqjwt.openRepo", open(LINKS.repo)),
    vscode.commands.registerCommand("pqjwt.generateKeyPair", open(LINKS.playground)),
    vscode.languages.registerHoverProvider("csharp", new PqJwtHoverProvider()),
    vscode.languages.registerCodeLensProvider("csharp", new PqJwtCodeLensProvider())
  );
}

export function deactivate() {}
