// The visual "PQ-JWT Inspector" webview. It renders the structured output of
// decoder.inspectToken() — it does NO cryptography and never re-parses a token
// itself; the tested pure decoder is the single source of truth. The panel is
// also the teacher: the concept sections (ML-DSA-65, X-Wing, sign-then-encrypt,
// validation path, fail-closed) are embedded inline so a user who never opens
// the browser playground still gets the full explanation in the editor.
import * as vscode from "vscode";
import { inspectToken, TokenInspection, SegmentInfo, HeaderField, FieldStatus, Topic } from "./decoder";
import { LINKS } from "./links";

// Map a field status to a VS Code theme chart colour (works in light + dark).
const STATUS_COLOR: Record<FieldStatus, string> = {
  ok: "var(--vscode-charts-green)",
  info: "var(--vscode-charts-blue)",
  warn: "var(--vscode-charts-yellow)",
  bad: "var(--vscode-charts-red)",
};

const STATUS_MARK: Record<FieldStatus, string> = { ok: "✓", info: "•", warn: "▲", bad: "✗" };

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// A non-cryptographic nonce is fine here: it only scopes the inline <style>/<script>
// in the page's CSP, it is not a security boundary. Date/Math.random are avoided
// to stay deterministic; a per-show counter gives a fresh value each render.
let nonceCounter = 0;
function makeNonce(): string {
  nonceCounter += 1;
  return `pqjwt${nonceCounter.toString(36)}${(nonceCounter * 2654435761 % 0xffffffff).toString(36)}`;
}

export class PqJwtInspectorPanel {
  public static readonly viewType = "pqjwt.inspector";
  private static current: PqJwtInspectorPanel | undefined;

  private readonly panel: vscode.WebviewPanel;
  private readonly disposables: vscode.Disposable[] = [];

  private constructor(panel: vscode.WebviewPanel) {
    this.panel = panel;
    this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
    this.panel.webview.onDidReceiveMessage(
      (msg: { command?: string; token?: string; url?: string }) => {
        if (msg.command === "inspect" && typeof msg.token === "string") {
          this.render(msg.token);
        } else if (msg.command === "openExternal" && typeof msg.url === "string") {
          vscode.env.openExternal(vscode.Uri.parse(msg.url));
        }
      },
      null,
      this.disposables
    );
  }

  // Show the inspector for a token, reusing the existing panel if one is open.
  public static show(token: string): void {
    const column = vscode.window.activeTextEditor?.viewColumn ?? vscode.ViewColumn.One;
    if (PqJwtInspectorPanel.current) {
      PqJwtInspectorPanel.current.panel.reveal(column, true);
      PqJwtInspectorPanel.current.render(token);
      return;
    }
    const panel = vscode.window.createWebviewPanel(
      PqJwtInspectorPanel.viewType,
      "PQ-JWT Inspector",
      { viewColumn: column, preserveFocus: true },
      { enableScripts: true, retainContextWhenHidden: true, localResourceRoots: [] }
    );
    PqJwtInspectorPanel.current = new PqJwtInspectorPanel(panel);
    PqJwtInspectorPanel.current.render(token);
  }

  private render(token: string): void {
    const inspection = inspectToken(token);
    this.panel.webview.html = renderHtml(inspection, this.panel.webview);
  }

  private dispose(): void {
    PqJwtInspectorPanel.current = undefined;
    while (this.disposables.length) {
      this.disposables.pop()?.dispose();
    }
    this.panel.dispose();
  }
}

// ---------------------------------------------------------------------------
// Pure HTML rendering
// ---------------------------------------------------------------------------
function renderHtml(i: TokenInspection, webview: vscode.Webview): string {
  const nonce = makeNonce();
  const csp =
    `default-src 'none'; ` +
    `style-src 'nonce-${nonce}'; ` +
    `script-src 'nonce-${nonce}'; ` +
    `img-src ${webview.cspSource};`;

  const body =
    i.form === "invalid" ? renderInvalid(i) : renderSummary(i) + renderSegments(i) + renderHeaderFields(i) + renderNotes(i);

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta http-equiv="Content-Security-Policy" content="${csp}" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<style nonce="${nonce}">${STYLE}</style>
<title>PQ-JWT Inspector</title>
</head>
<body>
<h1>🔐 PQ-JWT Inspector</h1>
${body}
${renderTeaching(i.topics)}
${renderInputBox()}
<footer>
  This panel does <strong>no cryptography</strong> — it inspects structure and the
  (unencrypted) protected header only. PostQuantum.Jwt is for controlled
  issuer/verifier systems; these tokens do not interop with generic JWT tooling.
  <div class="links">
    <a href="#" data-href="${LINKS.docs}">Docs</a> ·
    <a href="#" data-href="${LINKS.playground}">Playground</a> ·
    <a href="#" data-href="${LINKS.nuget}">NuGet</a> ·
    <a href="#" data-href="${LINKS.repo}">GitHub</a>
  </div>
  <div class="glory">To God be the glory — 1 Corinthians 10:31.</div>
</footer>
<script nonce="${nonce}">${SCRIPT}</script>
</body>
</html>`;
}

function renderInvalid(i: TokenInspection): string {
  return `<div class="card invalid">
    <div class="card-title">Not a PostQuantum.Jwt token</div>
    <p>${escapeHtml(i.error ?? i.summary)}</p>
  </div>`;
}

function renderSummary(i: TokenInspection): string {
  const badge = i.form === "signed" ? "SIGNED · 3 segments" : "ENCRYPTED · 5 segments";
  const cls = i.form === "signed" ? "badge-signed" : "badge-encrypted";
  return `<div class="summary">
    <span class="badge ${cls}">${badge}</span>
    <span class="summary-text">${escapeHtml(i.summary)}</span>
  </div>`;
}

function segmentBody(s: SegmentInfo): string {
  if (s.json !== undefined) {
    return `<pre class="seg-json">${escapeHtml(s.json)}</pre>`;
  }
  if (s.opaque) {
    return `<div class="seg-opaque">opaque bytes — binary / ciphertext, not human-readable</div>`;
  }
  const problem = s.problem ? `<div class="seg-problem">${escapeHtml(s.problem)}</div>` : "";
  const text = s.text ? `<pre class="seg-json">${escapeHtml(s.text)}</pre>` : "";
  return problem + text;
}

function renderSegments(i: TokenInspection): string {
  const rows = i.segments
    .map(
      (s) => `<div class="seg">
        <div class="seg-head"><span class="seg-index">${s.index + 1}</span>
          <span class="seg-label">${escapeHtml(s.label)}</span></div>
        <div class="seg-role">${escapeHtml(s.role)}</div>
        ${segmentBody(s)}
      </div>`
    )
    .join("\n");
  return `<section><h2>Layers</h2><div class="segments">${rows}</div></section>`;
}

function fieldChip(f: HeaderField): string {
  const color = STATUS_COLOR[f.status];
  return `<div class="chip" style="border-left:3px solid ${color}">
    <div class="chip-head"><span class="chip-mark" style="color:${color}">${STATUS_MARK[f.status]}</span>
      <code>${escapeHtml(f.name)}</code> = <code>${escapeHtml(f.value)}</code></div>
    <div class="chip-note">${escapeHtml(f.note)}</div>
  </div>`;
}

function renderHeaderFields(i: TokenInspection): string {
  if (i.headerFields.length === 0) {
    return "";
  }
  return `<section><h2>Header fields</h2><div class="chips">${i.headerFields.map(fieldChip).join("\n")}</div></section>`;
}

function renderNotes(i: TokenInspection): string {
  if (i.notes.length === 0) {
    return "";
  }
  return `<section><h2>Notes</h2><ul class="notes">${i.notes.map((n) => `<li>${escapeHtml(n)}</li>`).join("")}</ul></section>`;
}

// ---------------------------------------------------------------------------
// Embedded teaching content (the "full teacher" part). Static, honest, and
// auto-expanded for the topics relevant to the inspected token.
// ---------------------------------------------------------------------------
interface TeachingSection {
  topic: Topic;
  title: string;
  html: string;
}

const TEACHING: TeachingSection[] = [
  {
    topic: "ml-dsa",
    title: "ML-DSA-65 — the post-quantum signature",
    html: `<p>The signature is <strong>ML-DSA-65</strong> (FIPS 204), a lattice-based scheme
      believed secure against quantum attack. It signs <code>header.payload</code>.</p>
      <p>Crucially, the verifier does <em>not</em> trust the token's <code>alg</code>/<code>kid</code>
      to choose a key — the public key comes from a <strong>trusted internal key ring</strong>.
      The header only tells you which ring entry to <em>look up</em>, never what to trust.</p>`,
  },
  {
    topic: "x-wing",
    title: "X-Wing — the hybrid key exchange",
    html: `<p><strong>X-Wing</strong> combines two key-encapsulation mechanisms:</p>
      <ul>
        <li><strong>X25519</strong> — classical elliptic-curve Diffie–Hellman.</li>
        <li><strong>ML-KEM-768</strong> — lattice-based, post-quantum (FIPS 203).</li>
      </ul>
      <p>The two shared secrets are combined into one. The result stays secure as long as
      <em>either</em> primitive holds — so a future break of ECC alone doesn't expose the key,
      and a flaw found in the newer lattice scheme is still backstopped by X25519. That combined
      secret wraps the AES-256 content key.</p>`,
  },
  {
    topic: "sign-then-encrypt",
    title: "Sign-then-encrypt — why the order matters",
    html: `<p>An encrypted PQ-JWT is built in two steps:</p>
      <ol>
        <li><strong>Sign</strong> the claims → an inner ML-DSA-65 JWT.</li>
        <li><strong>Encrypt</strong> that whole JWT → the outer JWE (<code>cty: JWT</code>).</li>
      </ol>
      <p>On receipt the verifier reverses it: <strong>decrypt, then verify the signature.</strong>
      Signing first means the signer's assertion is itself confidential, and the signature covers
      exactly the claims — not attacker-malleable ciphertext.</p>`,
  },
  {
    topic: "validation-path",
    title: "Validation path — cheap checks first, crypto last",
    html: `<p>The validator rejects in increasing order of cost, so a bad token never reaches
      the expensive verify:</p>
      <ol>
        <li>Format &amp; size — malformed or oversized tokens are rejected up front.</li>
        <li>Unknown <code>kid</code> — not in the key ring → reject.</li>
        <li>Lifetime — <code>exp</code> required and enforced (and other time claims).</li>
        <li>Audience — must match the expected recipient.</li>
        <li><strong>Then</strong> the ML-DSA-65 signature verify (and, for the encrypted form,
          decrypt-then-verify the inner JWT).</li>
      </ol>`,
  },
  {
    topic: "fail-closed",
    title: "Fail-closed — no unsigned path, ever",
    html: `<p>Every validation or decryption failure <strong>throws</strong>. There is:</p>
      <ul>
        <li>no <code>alg: none</code> and no unsigned path;</li>
        <li>no silent downgrade and no "best-effort" result;</li>
        <li>no trusting the token header to pick the verification key.</li>
      </ul>
      <p>If anything is off, you get an exception — never a partially-trusted token.</p>`,
  },
];

function renderTeaching(topics: Topic[]): string {
  // Show every section so the panel teaches the whole model; auto-expand the
  // ones relevant to the inspected token.
  const set = new Set(topics);
  const items = TEACHING.map((sec) => {
    const open = set.has(sec.topic) ? " open" : "";
    return `<details class="teach"${open}>
      <summary>${escapeHtml(sec.title)}</summary>
      <div class="teach-body">${sec.html}</div>
    </details>`;
  }).join("\n");
  return `<section class="teaching"><h2>How it works</h2>${items}</section>`;
}

function renderInputBox(): string {
  return `<section class="inputbox">
    <h2>Inspect another token</h2>
    <textarea id="token-input" rows="3" placeholder="Paste a PQ-JWT (eyJhbGciOiJNTC1EU0EtNjUi…)"></textarea>
    <button id="inspect-btn">Inspect</button>
  </section>`;
}

const STYLE = `
:root { color-scheme: light dark; }
body { font-family: var(--vscode-font-family); color: var(--vscode-foreground);
  padding: 0 16px 32px; line-height: 1.5; }
h1 { font-size: 1.4em; margin: 16px 0 8px; }
h2 { font-size: 1.0em; text-transform: uppercase; letter-spacing: .04em;
  opacity: .8; margin: 24px 0 8px; border-bottom: 1px solid var(--vscode-panel-border); padding-bottom: 4px; }
code, pre { font-family: var(--vscode-editor-font-family, monospace); }
.summary { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin: 8px 0; }
.badge { font-weight: 600; font-size: .8em; padding: 3px 10px; border-radius: 10px; white-space: nowrap; }
.badge-signed { background: var(--vscode-charts-green); color: var(--vscode-editor-background); }
.badge-encrypted { background: var(--vscode-charts-purple); color: var(--vscode-editor-background); }
.summary-text { opacity: .85; }
.segments { display: flex; flex-direction: column; gap: 8px; }
.seg { border: 1px solid var(--vscode-panel-border); border-radius: 6px; padding: 8px 10px;
  background: var(--vscode-editor-background); }
.seg-head { display: flex; align-items: center; gap: 8px; }
.seg-index { background: var(--vscode-badge-background); color: var(--vscode-badge-foreground);
  border-radius: 50%; width: 20px; height: 20px; display: inline-flex; align-items: center;
  justify-content: center; font-size: .75em; flex: none; }
.seg-label { font-weight: 600; }
.seg-role { opacity: .7; font-size: .9em; margin: 2px 0 0 28px; }
.seg-json { margin: 8px 0 0 28px; padding: 8px; background: var(--vscode-textCodeBlock-background);
  border-radius: 4px; overflow-x: auto; white-space: pre; font-size: .9em; }
.seg-opaque { margin: 6px 0 0 28px; opacity: .6; font-style: italic; font-size: .9em; }
.seg-problem { margin: 6px 0 0 28px; color: var(--vscode-charts-yellow); font-size: .9em; }
.chips { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 8px; }
.chip { background: var(--vscode-editor-background); border: 1px solid var(--vscode-panel-border);
  border-radius: 4px; padding: 6px 10px; }
.chip-head { font-size: .95em; }
.chip-mark { font-weight: 700; margin-right: 4px; }
.chip-note { opacity: .75; font-size: .85em; margin-top: 2px; }
.notes { margin: 0; padding-left: 20px; }
.notes li { margin: 4px 0; }
.teaching details.teach { border: 1px solid var(--vscode-panel-border); border-radius: 6px;
  margin: 6px 0; padding: 0 12px; background: var(--vscode-editor-background); }
.teach summary { cursor: pointer; padding: 10px 0; font-weight: 600; }
.teach-body { padding: 0 0 12px; }
.teach-body ul, .teach-body ol { padding-left: 22px; }
.card.invalid { border: 1px solid var(--vscode-charts-yellow); border-radius: 6px; padding: 12px 14px;
  background: var(--vscode-inputValidation-warningBackground, transparent); }
.card-title { font-weight: 600; margin-bottom: 4px; }
.inputbox { margin-top: 24px; }
textarea { width: 100%; box-sizing: border-box; font-family: var(--vscode-editor-font-family, monospace);
  background: var(--vscode-input-background); color: var(--vscode-input-foreground);
  border: 1px solid var(--vscode-input-border, var(--vscode-panel-border)); border-radius: 4px; padding: 8px; }
button { margin-top: 8px; background: var(--vscode-button-background); color: var(--vscode-button-foreground);
  border: none; padding: 6px 16px; border-radius: 4px; cursor: pointer; }
button:hover { background: var(--vscode-button-hoverBackground); }
footer { margin-top: 32px; padding-top: 12px; border-top: 1px solid var(--vscode-panel-border);
  font-size: .85em; opacity: .8; }
footer .links { margin-top: 8px; }
footer a { color: var(--vscode-textLink-foreground); cursor: pointer; text-decoration: none; }
footer a:hover { text-decoration: underline; }
.glory { margin-top: 10px; font-style: italic; opacity: .7; }
`;

const SCRIPT = `
const vscode = acquireVsCodeApi();
document.getElementById('inspect-btn')?.addEventListener('click', () => {
  const token = document.getElementById('token-input').value;
  if (token && token.trim()) { vscode.postMessage({ command: 'inspect', token }); }
});
document.querySelectorAll('a[data-href]').forEach((a) => {
  a.addEventListener('click', (e) => {
    e.preventDefault();
    vscode.postMessage({ command: 'openExternal', url: a.getAttribute('data-href') });
  });
});
`;
