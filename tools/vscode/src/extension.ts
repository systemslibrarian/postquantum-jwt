import * as vscode from "vscode";
import { LINKS, docUrl } from "./links";
import { API_DOCS, apiRegex, lookupApiDoc } from "./apiDocs";
import { decodeToken, findPqJwtTokens } from "./decoder";
import { PqJwtInspectorPanel } from "./panel";

// Languages where we look for inline tokens to offer an "Inspect" CodeLens.
const TOKEN_LENS_LANGUAGES = ["csharp", "json", "jsonc", "http"];

// Virtual scheme for decode output — gives a titled, read-only tab (documents
// of a content-provider scheme are not editable) instead of an untitled buffer.
const DECODE_SCHEME = "pqjwt-decode";

class DecodeContentProvider implements vscode.TextDocumentContentProvider {
  private readonly store = new Map<string, string>();
  private counter = 0;

  provideTextDocumentContent(uri: vscode.Uri): string {
    return this.store.get(uri.toString()) ?? "";
  }

  // Stash content under a uniquely-keyed URI whose path is the (stable) tab title.
  add(content: string): vscode.Uri {
    const uri = vscode.Uri.parse(`${DECODE_SCHEME}:PQ-JWT decode.txt`).with({
      query: String(this.counter++),
    });
    this.store.set(uri.toString(), content);
    return uri;
  }

  // Drop a closed document's content so the store doesn't grow unbounded.
  remove(uri: vscode.Uri): void {
    if (uri.scheme === DECODE_SCHEME) {
      this.store.delete(uri.toString());
    }
  }
}

const decodeContent = new DecodeContentProvider();

// ---------------------------------------------------------------------------
// Decode commands (the only pieces that touch the vscode host)
// ---------------------------------------------------------------------------
async function showDecodedToken(token: string): Promise<void> {
  const uri = decodeContent.add(decodeToken(token));
  const doc = await vscode.workspace.openTextDocument(uri);
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

// Open the visual inspector for the active selection, or prompt for a token.
async function runVisualInspect(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  let candidate = "";
  if (editor && !editor.selection.isEmpty) {
    candidate = editor.document.getText(editor.selection);
  }
  if (!candidate.trim()) {
    const input = await vscode.window.showInputBox({
      prompt: "Paste a PostQuantum.Jwt token to inspect (structure + header only — no crypto).",
      placeHolder: "eyJhbGciOiJNTC1EU0EtNjUi...",
    });
    if (!input) {
      return;
    }
    candidate = input;
  }
  PqJwtInspectorPanel.show(candidate);
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
    const entry = lookupApiDoc(word);
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
      // Cheap noise filter: skip comment-only lines (`// PqJwtBuilder`, block
      // comment bodies). Symbols inside string literals or trailing comments are
      // still matched — a full fix needs semantic tokens.
      const lead = text.trimStart();
      if (lead.startsWith("//") || lead.startsWith("*") || lead.startsWith("/*")) {
        continue;
      }
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
            command: "pqjwt.inspectVisual",
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
    vscode.workspace.registerTextDocumentContentProvider(DECODE_SCHEME, decodeContent),
    vscode.workspace.onDidCloseTextDocument((doc) => decodeContent.remove(doc.uri)),
    vscode.commands.registerCommand("pqjwt.decodeToken", runDecode),
    // Visual inspector: a string arg (from the inline CodeLens) opens directly;
    // no arg (from the palette/context menu) falls back to selection/prompt.
    vscode.commands.registerCommand("pqjwt.inspectVisual", (token?: string) =>
      typeof token === "string" ? PqJwtInspectorPanel.show(token) : runVisualInspect()
    ),
    // Back-compat: the old text-decode command still works from the palette.
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
