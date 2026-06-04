// WebviewPanel controller for the visual inspector. This is the only inspector
// file that touches the vscode host: it manages a single reusable panel, resolves
// resource URIs, sets a strict nonce-based CSP, and bridges webview messages to
// host actions (open external link, copy header). All rendering is delegated to
// the pure renderer in `html.ts`.
import * as vscode from "vscode";
import { buildTokenModel, type TokenModel } from "../model";
import { buildPlaygroundUrl } from "../playground";
import { renderInspectorHtml, type TabName } from "./html";

function makeNonce(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let value = "";
  for (let i = 0; i < 32; i++) {
    value += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return value;
}

interface ShowOptions {
  toSide?: boolean;
  activeTab?: TabName;
}

export class InspectorPanel {
  private static current: InspectorPanel | undefined;
  private static readonly viewType = "pqjwt.inspector";

  private model: TokenModel;
  private activeTab: TabName;
  private readonly disposables: vscode.Disposable[] = [];

  /** Open (or reuse) the inspector for a token. */
  static show(extensionUri: vscode.Uri, rawToken: string, options: ShowOptions = {}): void {
    const model = buildTokenModel(rawToken);
    const tab = options.activeTab ?? "token";
    const column = options.toSide ? vscode.ViewColumn.Beside : vscode.ViewColumn.Active;

    if (InspectorPanel.current) {
      InspectorPanel.current.update(model, tab);
      InspectorPanel.current.panel.reveal(column, true);
      return;
    }

    const panel = vscode.window.createWebviewPanel(
      InspectorPanel.viewType,
      "PQ-JWT Inspector",
      { viewColumn: column, preserveFocus: true },
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: [vscode.Uri.joinPath(extensionUri, "media")],
      }
    );
    InspectorPanel.current = new InspectorPanel(panel, extensionUri, model, tab);
  }

  private constructor(
    private readonly panel: vscode.WebviewPanel,
    private readonly extensionUri: vscode.Uri,
    model: TokenModel,
    activeTab: TabName
  ) {
    this.model = model;
    this.activeTab = activeTab;
    this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
    this.panel.webview.onDidReceiveMessage((m) => this.onMessage(m), null, this.disposables);
    this.render();
  }

  private update(model: TokenModel, activeTab: TabName): void {
    this.model = model;
    this.activeTab = activeTab;
    this.render();
  }

  private render(): void {
    const webview = this.panel.webview;
    const cssUri = webview
      .asWebviewUri(vscode.Uri.joinPath(this.extensionUri, "media", "inspector.css"))
      .toString();

    this.panel.title =
      this.model.form === "encrypted"
        ? "PQ-JWT Inspector — encrypted"
        : this.model.form === "signed"
          ? "PQ-JWT Inspector — signed"
          : "PQ-JWT Inspector";

    webview.html = renderInspectorHtml(this.model, {
      nonce: makeNonce(),
      cssUri,
      cspSource: webview.cspSource,
      playgroundUrl: buildPlaygroundUrl(this.model),
      activeTab: this.activeTab,
    });
  }

  private async onMessage(message: unknown): Promise<void> {
    if (typeof message !== "object" || message === null) {
      return;
    }
    const msg = message as { type?: string; url?: string };
    switch (msg.type) {
      case "openExternal":
        // Defense-in-depth: the webview is our own nonce'd script and only ever
        // posts the host-computed playground URL, but never hand an arbitrary
        // posted string to openExternal — restrict to http(s).
        if (typeof msg.url === "string") {
          let parsed: vscode.Uri | undefined;
          try {
            parsed = vscode.Uri.parse(msg.url, true);
          } catch {
            parsed = undefined;
          }
          if (parsed && (parsed.scheme === "https" || parsed.scheme === "http")) {
            await vscode.env.openExternal(parsed);
          }
        }
        break;
      case "copyHeader": {
        const json = this.model.headerJson ?? JSON.stringify(this.model.header, null, 2);
        await vscode.env.clipboard.writeText(json);
        vscode.window.setStatusBarMessage("PQ-JWT: protected header JSON copied", 2500);
        break;
      }
    }
  }

  private dispose(): void {
    InspectorPanel.current = undefined;
    this.panel.dispose();
    while (this.disposables.length) {
      this.disposables.pop()?.dispose();
    }
  }
}
