// Pure renderer for the inspector webview. Takes a TokenModel (and the resolved
// resource URIs / nonce the host supplies) and returns a complete HTML document
// string. No vscode import and no cryptography, so the markup is unit-testable
// without launching the extension host.
import {
  HYBRID_STAGES,
  ICONS,
  SEGMENT_LANE,
  VALIDATION_STEPS,
  XWING_FACTS,
  type HybridStage,
  type ValidationStep,
} from "../content";
import { type AlgoBadge, type ClaimRow, type SegmentInfo, type TokenModel } from "../model";

export type TabName = "token" | "hybrid" | "validation";

export interface RenderOptions {
  /** CSP nonce shared by the inline <style>/<script>. */
  nonce: string;
  /** Webview URI of the stylesheet (media/inspector.css). */
  cssUri: string;
  /** `webview.cspSource` for the content security policy. */
  cspSource: string;
  /** Tab to show first (defaults to "token"). */
  activeTab?: TabName;
}

// ---------------------------------------------------------------------------
// Escaping — every piece of token-derived text goes through one of these.
// The only HTML interpolated *without* escaping is trusted static content from
// content.ts (stage.body, XWING_FACTS, ICONS), which intentionally contains
// markup. Never route token-derived data through those paths.
// ---------------------------------------------------------------------------
function esc(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function attr(text: string): string {
  return esc(text);
}

// ---------------------------------------------------------------------------
// Small building blocks
// ---------------------------------------------------------------------------
function badgePill(b: AlgoBadge): string {
  const icon = b.status === "ok" ? "✓" : b.status === "warn" ? "!" : "✗";
  return `<span class="badge badge-${b.status}" title="${attr(b.note)}">
    <span class="badge-mark">${icon}</span>
    <span class="badge-field">${esc(b.field)}</span>
    <span class="badge-value">${esc(b.value)}</span>
  </span>`;
}

function bytes(n: number): string {
  return n === 1 ? "1 byte" : `${n.toLocaleString("en-US")} bytes`;
}

// The raw token, segment-colored so the structure is visible at a glance.
function tokenStrip(model: TokenModel): string {
  const parts = model.token.split(".");
  const lanes = model.segments.map((s) => SEGMENT_LANE[s.field] ?? "");
  const spans = parts.map((p, i) => {
    const lane = lanes[i] ?? "";
    const dot = i < parts.length - 1 ? `<span class="tok-dot">.</span>` : "";
    return `<span class="tok-seg ${lane}" title="${attr(model.segments[i]?.name ?? `segment ${i + 1}`)}">${esc(p)}</span>${dot}`;
  });
  return `<div class="token-strip" role="img" aria-label="token, segment-colored">${spans.join("")}</div>`;
}

function segmentCard(seg: SegmentInfo): string {
  const lane = SEGMENT_LANE[seg.field] ?? "";
  const sizeLabel =
    seg.expectedBytes !== undefined
      ? `${bytes(seg.byteLength)} <span class="muted">(expects ${bytes(seg.expectedBytes)})</span>`
      : bytes(seg.byteLength);

  let body: string;
  if (seg.readable && seg.json) {
    body = `<pre class="json"><code>${esc(seg.json)}</code></pre>`;
  } else if (seg.readable) {
    body = `<p class="muted">This segment did not decode to readable JSON.</p>`;
  } else {
    body = `<p class="opaque">Opaque bytes — not human-readable. ${esc(seg.note)}</p>`;
  }

  const open = seg.readable ? " open" : "";
  return `<details class="seg-card"${open}>
    <summary>
      <span class="seg-lane ${lane}" aria-hidden="true"></span>
      <span class="seg-index">${seg.index + 1}</span>
      <span class="seg-name">${esc(seg.name)}</span>
      <code class="seg-field">${esc(seg.field)}</code>
      <span class="seg-size">${sizeLabel}</span>
    </summary>
    <div class="seg-body">
      <p class="seg-note">${esc(seg.note)}</p>
      ${body}
    </div>
  </details>`;
}

function claimsTable(claims: ClaimRow[]): string {
  if (claims.length === 0) {
    return `<p class="muted">The payload is an empty claims set.</p>`;
  }
  const rows = claims
    .map(
      (c) => `<tr class="${c.reserved ? "claim-reserved" : "claim-custom"}">
        <td class="claim-name">${esc(c.name)}${c.reserved ? `<span class="tag">registered</span>` : ""}</td>
        <td class="claim-value"><code>${esc(c.value)}</code></td>
      </tr>`
    )
    .join("");
  return `<table class="claims">
    <thead><tr><th>Claim</th><th>Value</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

function noticeList(kind: "warn" | "error", items: string[]): string {
  if (items.length === 0) {
    return "";
  }
  const li = items.map((t) => `<li>${esc(t)}</li>`).join("");
  const label = kind === "error" ? "Problems" : "Notes";
  return `<div class="notice notice-${kind}"><strong>${label}</strong><ul>${li}</ul></div>`;
}

// ---------------------------------------------------------------------------
// Tab: Token
// ---------------------------------------------------------------------------
function tokenTab(model: TokenModel): string {
  if (model.form === "unknown") {
    return `<div class="empty">
      <h2>Not a PostQuantum.Jwt token</h2>
      <p>${esc(model.summary)}</p>
      <p class="muted">A token has 3 segments (signed) or 5 (signed-then-encrypted), and its header declares
      <code>ML-DSA-65</code> or <code>X-Wing</code>.</p>
      ${noticeList("error", model.errors)}
    </div>`;
  }

  const badges = model.badges.map(badgePill).join("");
  const segments = model.segments.map(segmentCard).join("");

  const payloadSection =
    model.form === "signed" && model.claims
      ? `<section class="block">
           <h3>Claims</h3>
           ${claimsTable(model.claims)}
         </section>`
      : model.form === "encrypted"
        ? `<section class="block encrypted-note">
             <h3>${ICONS.lock} Payload is encrypted</h3>
             <p>The claims live inside the ciphertext segment and are unreadable without the recipient's
             X-Wing private key. This inspector does <strong>no cryptography</strong> — it never attempts to
             decrypt. Use the playground with a private key to see decrypted claims.</p>
           </section>`
        : "";

  // The playground link encodes this token's decoded claims so the playground can
  // pre-fill its form — so the button says so plainly when that will happen.
  const sharesClaims = model.form === "signed" && (model.claims?.length ?? 0) > 0;
  const playgroundLabel = sharesClaims ? "Open in Playground (sends decoded claims) ▸" : "Open in Playground ▸";
  const playgroundTitle = sharesClaims
    ? "Opens the live playground with this token's decoded claims encoded in the link"
    : "Opens the live playground";

  return `<div class="tab-panel">
    <section class="block">
      <div class="strip-head">
        <span class="form-chip form-${model.form}">${model.form === "signed" ? "SIGNED · 3 segments" : "ENCRYPTED · 5 segments"}</span>
        <div class="actions">
          <button class="btn primary" data-cmd="playground" title="${attr(playgroundTitle)}">${esc(playgroundLabel)}</button>
          <button class="btn" data-cmd="copyHeader">Copy header JSON</button>
        </div>
      </div>
      ${tokenStrip(model)}
      <div class="badges">${badges}</div>
    </section>

    <section class="block">
      <h3>Structure</h3>
      <p class="muted">${model.form === "signed" ? "header.payload.signature" : "header.kem_ct.iv.ciphertext.tag — a JWE wrapping a signed JWT."}</p>
      <div class="segments">${segments}</div>
    </section>

    ${payloadSection}
    ${noticeList("warn", model.warnings)}
    ${noticeList("error", model.errors)}
  </div>`;
}

// ---------------------------------------------------------------------------
// Tab: Hybrid construction
// ---------------------------------------------------------------------------
function hybridStageEl(stage: HybridStage, isLast: boolean): string {
  const detail = stage.detail ? `<pre class="formula"><code>${esc(stage.detail)}</code></pre>` : "";
  const connector = isLast
    ? ""
    : `<div class="connector">${ICONS.arrowDown}<span class="produces">${esc(stage.produces ?? "")}</span></div>`;
  return `<div class="stage">
    <div class="stage-card">
      <div class="stage-icon">${stage.icon}</div>
      <div class="stage-text">
        <h4>${esc(stage.title)}</h4>
        <p>${stage.body}</p>
        ${detail}
      </div>
    </div>
    ${connector}
  </div>`;
}

function hybridTab(model: TokenModel): string {
  const here =
    model.form === "encrypted"
      ? `<p class="you-are-here">This token is the <strong>outer encrypted result</strong> (step 3 output).</p>`
      : model.form === "signed"
        ? `<p class="you-are-here">This token is the <strong>inner signed JWT</strong> (step 1 output) — the part that gets encrypted.</p>`
        : "";
  const stages = HYBRID_STAGES.map((s, i) => hybridStageEl(s, i === HYBRID_STAGES.length - 1)).join("");
  const facts = XWING_FACTS.map((f) => `<li>${f}</li>`).join("");
  return `<div class="tab-panel hybrid">
    <section class="block">
      <h2>Sign-then-encrypt</h2>
      <p class="lead">A PostQuantum.Jwt encrypted token is built in three steps. The signature is applied
      <em>first</em>, then the whole signed token is encrypted — so the signature is confidential too.</p>
      ${here}
      <div class="stage-flow">${stages}</div>
      <div class="result-card">${ICONS.shield} <code>header.kem_ct.iv.ciphertext.tag</code> — the 5-segment encrypted JWT.</div>
    </section>
    <aside class="block facts">
      <h3>${ICONS.combine} About X-Wing</h3>
      <ul>${facts}</ul>
    </aside>
  </div>`;
}

// ---------------------------------------------------------------------------
// Tab: Validation flow
// ---------------------------------------------------------------------------
function stepRelevance(step: ValidationStep, model: TokenModel): string {
  if (step.encryptedOnly && model.form === "signed") {
    return `<span class="step-tag skip">not for signed tokens</span>`;
  }
  if (step.encryptedOnly && model.form === "encrypted") {
    return `<span class="step-tag apply">applies here</span>`;
  }
  if (step.n === 8) {
    const hasJti = model.claims?.some((c) => c.name === "jti");
    return hasJti
      ? `<span class="step-tag apply">jti present</span>`
      : `<span class="step-tag info">needs jti + a replay cache</span>`;
  }
  return "";
}

function validationStepEl(step: ValidationStep, model: TokenModel): string {
  const rejects = step.rejectsWhen.map((r) => `<li>${esc(r)}</li>`).join("");
  const enc = step.encryptedOnly ? `<span class="step-tag enc">encrypted only</span>` : "";
  return `<details class="vstep">
    <summary>
      <span class="vnum">${step.n}</span>
      <span class="vtitle">${esc(step.title)}</span>
      ${enc}
      ${stepRelevance(step, model)}
    </summary>
    <div class="vbody">
      <p>${esc(step.does)}</p>
      <p class="rejects-label">Rejects when:</p>
      <ul class="rejects">${rejects}</ul>
    </div>
  </details>`;
}

function validationTab(model: TokenModel): string {
  const steps = VALIDATION_STEPS.map((s) => validationStepEl(s, model)).join("");
  return `<div class="tab-panel validation">
    <section class="block">
      <h2>${ICONS.shield} Validation is fail-closed and ordered</h2>
      <p class="lead">PqJwtValidator applies these checks <strong>in order</strong> and <strong>throws</strong> rather
      than degrade on any failure. There is no unsigned path and no algorithm negotiation — exactly one suite is
      accepted. This view is educational; the extension performs none of these checks.</p>
      <div class="vflow">${steps}</div>
    </section>
  </div>`;
}

// ---------------------------------------------------------------------------
// Document
// ---------------------------------------------------------------------------
export function renderInspectorHtml(model: TokenModel, opts: RenderOptions): string {
  const csp = [
    `default-src 'none'`,
    // Only the extension's own bundled assets (cspSource) and inline data: URIs —
    // no remote origins, so the panel can make no network requests.
    `img-src ${opts.cspSource} data:`,
    `style-src ${opts.cspSource} 'nonce-${opts.nonce}'`,
    `script-src 'nonce-${opts.nonce}'`,
    `font-src ${opts.cspSource}`,
  ].join("; ");

  const active: TabName = opts.activeTab ?? "token";
  const tabBtn = (name: TabName, label: string) =>
    `<button class="tab${name === active ? " active" : ""}" data-tab="${name}" role="tab" aria-selected="${name === active}">${label}</button>`;
  const viewEl = (name: TabName, inner: string) =>
    `<div class="view${name === active ? "" : " hidden"}" data-view="${name}">${inner}</div>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta http-equiv="Content-Security-Policy" content="${csp}" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<link href="${attr(opts.cssUri)}" rel="stylesheet" />
<title>PQ-JWT Inspector</title>
</head>
<body data-form="${attr(model.form)}">
  <header class="topbar">
    <div class="brand">
      <span class="brand-mark">${ICONS.shield}</span>
      <div>
        <h1>PostQuantum.Jwt Inspector</h1>
        <p class="summary">${esc(model.summary)}</p>
      </div>
    </div>
  </header>

  <nav class="tabs" role="tablist">
    ${tabBtn("token", "Token")}
    ${tabBtn("hybrid", "Hybrid construction")}
    ${tabBtn("validation", "Validation flow")}
  </nav>

  <main>
    ${viewEl("token", tokenTab(model))}
    ${viewEl("hybrid", hybridTab(model))}
    ${viewEl("validation", validationTab(model))}
  </main>

  <footer class="disclaimer">
    No cryptography happens in this panel — it inspects structure and the unencrypted header only.
    PostQuantum.Jwt tokens are for controlled issuer/verifier systems and do not interoperate with generic JWT tooling.
  </footer>

  <script nonce="${attr(opts.nonce)}">
    const vscode = acquireVsCodeApi();

    // Tab switching
    document.querySelectorAll('.tab').forEach((tab) => {
      tab.addEventListener('click', () => {
        const name = tab.getAttribute('data-tab');
        document.querySelectorAll('.tab').forEach((t) => {
          const on = t === tab;
          t.classList.toggle('active', on);
          t.setAttribute('aria-selected', String(on));
        });
        document.querySelectorAll('.view').forEach((v) => {
          v.classList.toggle('hidden', v.getAttribute('data-view') !== name);
        });
      });
    });

    // Action buttons → host
    document.body.addEventListener('click', (e) => {
      const el = e.target instanceof Element ? e.target : null;
      const btn = el && el.closest('[data-cmd]');
      if (!btn) return;
      const cmd = btn.getAttribute('data-cmd');
      if (cmd === 'playground') {
        // The host opens its own trusted, pre-computed playground link.
        vscode.postMessage({ type: 'openPlayground' });
      } else if (cmd === 'copyHeader') {
        vscode.postMessage({ type: 'copyHeader' });
      }
    });
  </script>
</body>
</html>`;
}
