import * as vscode from "vscode";
import { LINKS, docUrl } from "./links";
import { API_DOCS, apiRegex } from "./apiDocs";
import { decodeToken, findPqJwtTokens } from "./decoder";

// Languages where we look for inline tokens to offer an "Inspect" CodeLens.
const TOKEN_LENS_LANGUAGES = ["csharp", "json", "jsonc", "http"];

// ---------------------------------------------------------------------------
// Decode commands (the only pieces that touch the vscode host)
// ---------------------------------------------------------------------------
async function showDecodedToken(token: string): Promise<void> {
  const output = decodeToken(token);
  const doc = await vscode.workspace.openTextDocument({
    content: output,
    language: "plaintext",
  });
  await vscode.window.showTextDocument(doc, { preview: true });
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

  await showDecodedToken(candidate);
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
// Inline token CodeLens — detects PostQuantum.Jwt tokens in source/config and
// offers a one-click "Inspect" without selecting + invoking the command.
// ---------------------------------------------------------------------------
class PqJwtTokenLensProvider implements vscode.CodeLensProvider {
  provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
    const lenses: vscode.CodeLens[] = [];
    for (let line = 0; line < document.lineCount; line++) {
      const text = document.lineAt(line).text;
      for (const token of findPqJwtTokens(text)) {
        const range = new vscode.Range(line, token.start, line, token.end);
        lenses.push(
          new vscode.CodeLens(range, {
            title: "🔍 Inspect PQ-JWT",
            command: "pqjwt.inspectToken",
            arguments: [token.value],
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
    vscode.commands.registerCommand("pqjwt.inspectToken", (token: string) => showDecodedToken(token)),
    vscode.commands.registerCommand("pqjwt.openPlayground", open(LINKS.playground)),
    vscode.commands.registerCommand("pqjwt.openDocs", open(LINKS.docs)),
    vscode.commands.registerCommand("pqjwt.openNuget", open(LINKS.nuget)),
    vscode.commands.registerCommand("pqjwt.openRepo", open(LINKS.repo)),
    vscode.commands.registerCommand("pqjwt.generateKeyPair", open(LINKS.playground)),
    vscode.languages.registerHoverProvider("csharp", new PqJwtHoverProvider()),
    vscode.languages.registerCodeLensProvider("csharp", new PqJwtCodeLensProvider()),
    vscode.languages.registerCodeLensProvider(TOKEN_LENS_LANGUAGES, new PqJwtTokenLensProvider())
  );
}

export function deactivate() {}
