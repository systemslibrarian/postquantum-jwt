import * as vscode from "vscode";
import { LINKS, docUrl } from "./links";
import { API_DOCS, apiRegex, lookupApiDoc } from "./apiDocs";
import { decodeToken } from "./decoder";
import { findPqJwtTokens } from "./model";
import { InspectorPanel } from "./inspector/panel";
import { sampleSignedToken } from "./samples";
import type { TabName } from "./inspector/html";

// Languages where we look for inline tokens to offer an "Inspect" CodeLens.
const TOKEN_LENS_LANGUAGES = ["csharp", "json", "jsonc", "http"];

// Virtual scheme for the plain-text decode output — gives a titled, read-only tab.
const DECODE_SCHEME = "pqjwt-decode";

// ---------------------------------------------------------------------------
// Configuration helpers
// ---------------------------------------------------------------------------
const config = () => vscode.workspace.getConfiguration("pqjwt");
const openToSide = (): boolean => config().get<boolean>("inspector.openToSide", true);
const codeLensEnabled = (): boolean => config().get<boolean>("codeLens.enabled", true);

class DecodeContentProvider implements vscode.TextDocumentContentProvider {
  private readonly store = new Map<string, string>();
  private counter = 0;

  provideTextDocumentContent(uri: vscode.Uri): string {
    return this.store.get(uri.toString()) ?? "";
  }

  add(content: string): vscode.Uri {
    const uri = vscode.Uri.parse(`${DECODE_SCHEME}:PQ-JWT decode.txt`).with({
      query: String(this.counter++),
    });
    this.store.set(uri.toString(), content);
    return uri;
  }

  remove(uri: vscode.Uri): void {
    if (uri.scheme === DECODE_SCHEME) {
      this.store.delete(uri.toString());
    }
  }
}

const decodeContent = new DecodeContentProvider();

// ---------------------------------------------------------------------------
// Token acquisition (selection → token under cursor → input box)
// ---------------------------------------------------------------------------
async function pickToken(prompt: string): Promise<string | undefined> {
  const editor = vscode.window.activeTextEditor;
  if (editor && !editor.selection.isEmpty) {
    const selected = editor.document.getText(editor.selection);
    if (selected.trim()) {
      return selected;
    }
  }
  // Try a token on the current line (so the user can just place the cursor on it).
  if (editor) {
    const line = editor.document.lineAt(editor.selection.active.line).text;
    const onLine = findPqJwtTokens(line);
    if (onLine.length === 1) {
      return onLine[0].value;
    }
  }
  return vscode.window.showInputBox({
    prompt,
    placeHolder: "eyJhbGciOiJNTC1EU0EtNjUi...",
  });
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------
async function showDecodedText(token: string): Promise<void> {
  const uri = decodeContent.add(decodeToken(token));
  const doc = await vscode.workspace.openTextDocument(uri);
  await vscode.window.showTextDocument(doc, { preview: true });
}

async function runDecodeText(): Promise<void> {
  const token = await pickToken("Paste a PostQuantum.Jwt token to decode (header/structure only — no crypto).");
  if (token) {
    await showDecodedText(token);
  }
}

function openInspector(extensionUri: vscode.Uri) {
  return async (token?: string): Promise<void> => {
    const value = token ?? (await pickToken("Paste a PostQuantum.Jwt token to inspect (header/structure only — no crypto)."));
    if (value) {
      InspectorPanel.show(extensionUri, value, { toSide: openToSide() });
    }
  };
}

// Educational commands: open the inspector focused on a concept tab, using the
// current selection if it's a token, otherwise a representative sample.
function showConcept(extensionUri: vscode.Uri, tab: TabName) {
  return async (): Promise<void> => {
    const editor = vscode.window.activeTextEditor;
    let token = sampleSignedToken();
    if (editor && !editor.selection.isEmpty) {
      const selected = editor.document.getText(editor.selection).trim();
      if (selected) {
        token = selected;
      }
    }
    InspectorPanel.show(extensionUri, token, { toSide: openToSide(), activeTab: tab });
  };
}

// ---------------------------------------------------------------------------
// Hover provider
// ---------------------------------------------------------------------------
class PqJwtHoverProvider implements vscode.HoverProvider {
  provideHover(document: vscode.TextDocument, position: vscode.Position): vscode.ProviderResult<vscode.Hover> {
    const range = document.getWordRangeAtPosition(position, /[A-Za-z_][A-Za-z0-9_]*/);
    if (!range) {
      return;
    }
    const word = document.getText(range);
    const entry = lookupApiDoc(word);
    if (!entry) {
      return;
    }
    const concept = entry.concept ? `\n\n${entry.concept}` : "";
    const md = new vscode.MarkdownString(
      `**${word}** — PostQuantum.Jwt\n\n${entry.blurb}${concept}\n\n` +
        `[Docs](${docUrl(entry.anchor)}) · ` +
        `[Playground](${LINKS.playground}) · [NuGet](${LINKS.nuget})`
    );
    md.isTrusted = true;
    md.supportHtml = false;
    return new vscode.Hover(md, range);
  }
}

// ---------------------------------------------------------------------------
// CodeLens providers (config-gated, refreshable)
// ---------------------------------------------------------------------------
class PqJwtCodeLensProvider implements vscode.CodeLensProvider {
  private readonly emitter = new vscode.EventEmitter<void>();
  readonly onDidChangeCodeLenses = this.emitter.event;
  refresh(): void {
    this.emitter.fire();
  }

  provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
    if (!codeLensEnabled()) {
      return [];
    }
    const lenses: vscode.CodeLens[] = [];
    for (let line = 0; line < document.lineCount; line++) {
      const text = document.lineAt(line).text;
      const lead = text.trimStart();
      if (lead.startsWith("//") || lead.startsWith("*") || lead.startsWith("/*")) {
        continue;
      }
      const seenOnLine = new Set<string>();
      for (const match of text.matchAll(apiRegex())) {
        const symbol = match[1];
        if (seenOnLine.has(symbol)) {
          continue;
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

class PqJwtTokenLensProvider implements vscode.CodeLensProvider {
  private readonly emitter = new vscode.EventEmitter<void>();
  readonly onDidChangeCodeLenses = this.emitter.event;
  refresh(): void {
    this.emitter.fire();
  }

  provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
    if (!codeLensEnabled()) {
      return [];
    }
    const lenses: vscode.CodeLens[] = [];
    for (let line = 0; line < document.lineCount; line++) {
      const text = document.lineAt(line).text;
      for (const token of findPqJwtTokens(text)) {
        const range = new vscode.Range(line, token.start, line, token.end);
        // Primary: the rich visual inspector. Secondary: the plain-text decode.
        lenses.push(
          new vscode.CodeLens(range, {
            title: "🔍 Inspect PQ-JWT",
            command: "pqjwt.inspectToken",
            arguments: [token.value],
          })
        );
        lenses.push(
          new vscode.CodeLens(range, {
            title: "≡ Text decode",
            command: "pqjwt.decodeToken",
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
export function activate(context: vscode.ExtensionContext): void {
  const open = (url: string) => () => vscode.env.openExternal(vscode.Uri.parse(url));
  const inspect = openInspector(context.extensionUri);

  const apiLens = new PqJwtCodeLensProvider();
  const tokenLens = new PqJwtTokenLensProvider();

  context.subscriptions.push(
    vscode.workspace.registerTextDocumentContentProvider(DECODE_SCHEME, decodeContent),
    vscode.workspace.onDidCloseTextDocument((doc) => decodeContent.remove(doc.uri)),

    // Decode / inspect
    vscode.commands.registerCommand("pqjwt.decodeToken", (token?: string) =>
      typeof token === "string" ? showDecodedText(token) : runDecodeText()
    ),
    vscode.commands.registerCommand("pqjwt.inspectToken", inspect),
    vscode.commands.registerCommand("pqjwt.openInspector", () => inspect()),
    vscode.commands.registerCommand("pqjwt.showHybridConstruction", showConcept(context.extensionUri, "hybrid")),
    vscode.commands.registerCommand("pqjwt.showValidationFlow", showConcept(context.extensionUri, "validation")),

    // Quick links
    vscode.commands.registerCommand("pqjwt.openPlayground", open(LINKS.playground)),
    vscode.commands.registerCommand("pqjwt.openDocs", open(LINKS.docs)),
    vscode.commands.registerCommand("pqjwt.openNuget", open(LINKS.nuget)),
    vscode.commands.registerCommand("pqjwt.openRepo", open(LINKS.repo)),
    vscode.commands.registerCommand("pqjwt.generateKeyPair", open(LINKS.playground)),

    // Providers
    vscode.languages.registerHoverProvider("csharp", new PqJwtHoverProvider()),
    vscode.languages.registerCodeLensProvider("csharp", apiLens),
    vscode.languages.registerCodeLensProvider(TOKEN_LENS_LANGUAGES, tokenLens),

    // Refresh CodeLenses when the relevant settings change.
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("pqjwt.codeLens")) {
        apiLens.refresh();
        tokenLens.refresh();
      }
    })
  );
}

export function deactivate(): void {}
