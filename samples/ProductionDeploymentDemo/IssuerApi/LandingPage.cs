namespace PostQuantum.Jwt.Samples.ProductionDeploymentDemo.IssuerApi;

/// <summary>
/// The interactive demo landing page served at <c>/</c>. A self-contained
/// single-file HTML+CSS+JS app — no SPA framework, no build step. Drives the
/// full cross-service demo from a single browser session by calling Issuer's
/// own endpoints (relative paths) and OrdersApi cross-origin (CORS allowed
/// for this Issuer hostname).
/// </summary>
internal static class LandingPage
{
    public static string Render(string ordersBaseUrl) =>
        Template.Replace("{{ORDERS_BASE_URL}}", ordersBaseUrl);

    private const string Template = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>PostQuantum.Jwt — Live Production-Shape Demo</title>
  <link rel="icon" href="data:," />
  <style>
    :root {
      --bg: #0a0d1c;
      --bg-2: #0d1226;
      --panel: #151b35;
      --panel-2: #1e2647;
      --ink: #e8ecf6;
      --ink-dim: #8d97b8;
      --ink-mid: #b7c0dd;
      --accent: #7aa2ff;
      --accent-2: #5db4d8;
      --good: #5dd39e;
      --good-bg: rgba(93,211,158,0.10);
      --warn: #ffb86b;
      --warn-bg: rgba(255,184,107,0.10);
      --bad: #ff7a7a;
      --bad-bg: rgba(255,122,122,0.10);
      --line: #2a335c;
      --line-soft: #1f2750;
      --mono: ui-monospace, "JetBrains Mono", SFMono-Regular, Menlo, Consolas, monospace;
    }
    *, *::before, *::after { box-sizing: border-box; }
    html, body { margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: radial-gradient(1200px 600px at 20% -10%, #16213f 0%, var(--bg) 60%) fixed;
      color: var(--ink);
      min-height: 100vh;
      line-height: 1.5;
    }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
    code, .mono { font-family: var(--mono); }

    /* --------- demo-only banner --------- */
    .banner {
      background: linear-gradient(90deg, rgba(255,184,107,0.10), rgba(255,184,107,0.05));
      border-bottom: 1px solid rgba(255,184,107,0.30);
      color: var(--warn);
      padding: 10px 24px;
      font-size: 13px;
      text-align: center;
      letter-spacing: 0.15px;
    }
    .banner b { color: var(--warn); }
    .banner a { color: var(--warn); text-decoration: underline; }

    /* --------- hero --------- */
    header.hero {
      max-width: 1320px;
      margin: 0 auto;
      padding: 36px 32px 8px;
    }
    .hero-row {
      display: flex;
      align-items: flex-end;
      justify-content: space-between;
      gap: 24px;
      flex-wrap: wrap;
    }
    h1 {
      font-size: 28px;
      margin: 0 0 8px;
      font-weight: 700;
      letter-spacing: 0.2px;
    }
    h1 .tag {
      color: var(--accent);
      font-weight: 400;
      font-size: 22px;
      margin-left: 6px;
    }
    .lede {
      color: var(--ink-mid);
      font-size: 15px;
      max-width: 720px;
      margin: 8px 0 0;
    }
    .lede b { color: var(--ink); }
    .crumbs {
      display: flex;
      gap: 14px;
      flex-wrap: wrap;
      font-size: 12px;
      color: var(--ink-dim);
      margin-top: 12px;
    }
    .crumbs a {
      color: var(--accent-2);
      border-bottom: 1px dashed transparent;
    }
    .crumbs a:hover { border-bottom-color: var(--accent-2); text-decoration: none; }
    .status-tray {
      display: flex;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
    }
    .chip {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: var(--panel);
      border: 1px solid var(--line);
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 11.5px;
      color: var(--ink-mid);
    }
    .chip .dot {
      width: 6px; height: 6px; border-radius: 50%;
      background: var(--ink-dim);
    }
    .chip.alive .dot { background: var(--good); box-shadow: 0 0 0 3px rgba(93,211,158,0.18); }
    .chip.warn .dot { background: var(--warn); }
    .chip.bad .dot  { background: var(--bad);  }

    /* --------- main grid --------- */
    main {
      max-width: 1320px;
      margin: 0 auto;
      padding: 24px 32px 80px;
      display: grid;
      grid-template-columns: 340px 1fr 320px;
      gap: 20px;
    }
    @media (max-width: 1180px) { main { grid-template-columns: 1fr; } }

    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 14px;
      overflow: hidden;
    }
    .panel-head {
      padding: 14px 18px;
      border-bottom: 1px solid var(--line-soft);
      color: var(--ink-dim);
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 1.4px;
      text-transform: uppercase;
    }
    .panel-body { padding: 14px 18px; }
    .panel-body.tight { padding: 4px 4px; }

    /* --------- left rail: numbered steps --------- */
    .step {
      display: grid;
      grid-template-columns: 28px 1fr;
      column-gap: 12px;
      align-items: start;
      padding: 12px 14px;
      border-radius: 10px;
      border: 1px solid transparent;
      background: transparent;
      color: var(--ink);
      text-align: left;
      cursor: pointer;
      width: 100%;
      margin-bottom: 4px;
      font-family: inherit;
      font-size: 13px;
      transition: background 0.12s, border-color 0.12s, transform 0.04s;
    }
    .step:hover { background: var(--panel-2); border-color: var(--line); }
    .step:active { transform: translateY(1px); }
    .step.active {
      background: linear-gradient(180deg, rgba(122,162,255,0.12) 0%, rgba(122,162,255,0.05) 100%);
      border-color: rgba(122,162,255,0.35);
    }
    .step-num {
      width: 24px; height: 24px;
      border-radius: 50%;
      background: var(--panel-2);
      border: 1px solid var(--line);
      color: var(--ink-mid);
      font-weight: 700;
      font-size: 11px;
      display: flex;
      align-items: center;
      justify-content: center;
      letter-spacing: 0;
    }
    .step.done .step-num { background: var(--good-bg); border-color: var(--good); color: var(--good); }
    .step.bad .step-num  { background: var(--bad-bg);  border-color: var(--bad);  color: var(--bad); }
    .step-title { font-weight: 600; line-height: 1.35; color: var(--ink); margin-bottom: 2px; }
    .step-sub   { color: var(--ink-dim); font-size: 11.5px; line-height: 1.4; }
    .step .verb {
      display: inline-block;
      font-family: var(--mono);
      font-size: 10.5px;
      color: var(--accent);
      background: rgba(122,162,255,0.10);
      padding: 1px 6px;
      border-radius: 4px;
      margin-right: 6px;
    }

    /* --------- center: output --------- */
    .verdict {
      display: flex;
      gap: 12px;
      align-items: center;
      padding: 18px;
      border-bottom: 1px solid var(--line-soft);
    }
    .pill {
      padding: 5px 12px;
      border-radius: 999px;
      font-size: 11.5px;
      font-weight: 700;
      letter-spacing: 0.6px;
      text-transform: uppercase;
      background: var(--panel-2);
      color: var(--ink-mid);
      border: 1px solid var(--line);
    }
    .pill.good { background: var(--good-bg); color: var(--good); border-color: rgba(93,211,158,0.4); }
    .pill.bad  { background: var(--bad-bg);  color: var(--bad);  border-color: rgba(255,122,122,0.4); }
    .pill.warn { background: var(--warn-bg); color: var(--warn); border-color: rgba(255,184,107,0.4); }
    .verdict-text { color: var(--ink-mid); font-size: 13.5px; line-height: 1.45; }
    .verdict-text b { color: var(--ink); }

    .section { border-bottom: 1px solid var(--line-soft); }
    .section:last-child { border-bottom: none; }
    .section-head {
      padding: 12px 18px 6px;
      color: var(--ink-dim);
      font-size: 10.5px;
      font-weight: 700;
      letter-spacing: 1.3px;
      text-transform: uppercase;
    }
    .section-body {
      padding: 8px 18px 16px;
      font-size: 13px;
      color: var(--ink-mid);
    }
    pre {
      margin: 0;
      padding: 12px 14px;
      background: var(--bg-2);
      border: 1px solid var(--line-soft);
      border-radius: 8px;
      font-family: var(--mono);
      font-size: 12px;
      line-height: 1.55;
      white-space: pre-wrap;
      word-break: break-all;
      color: var(--ink);
      overflow-x: auto;
    }
    pre.dim { color: var(--ink-mid); }
    .token-grid {
      display: grid;
      grid-template-columns: 90px 1fr;
      gap: 6px 14px;
      align-items: baseline;
      font-size: 12.5px;
    }
    .token-grid .k { color: var(--ink-dim); }
    .token-grid .v { color: var(--ink); font-family: var(--mono); word-break: break-all; }
    .seg {
      display: inline-block;
      padding: 1px 6px;
      margin-right: 4px;
      border-radius: 4px;
      background: rgba(122,162,255,0.08);
      color: var(--accent-2);
      font-family: var(--mono);
      font-size: 11px;
    }
    .explain {
      background: var(--panel-2);
      border-left: 3px solid var(--accent);
      border-radius: 6px;
      padding: 10px 14px;
      color: var(--ink-mid);
      font-size: 13px;
    }
    .explain b { color: var(--ink); }
    .explain code { color: var(--accent-2); background: rgba(122,162,255,0.10); padding: 1px 6px; border-radius: 4px; }

    /* --------- right: state sidebar --------- */
    .state-row {
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      padding: 8px 0;
      font-size: 13px;
      border-bottom: 1px dashed var(--line-soft);
    }
    .state-row:last-child { border-bottom: none; }
    .state-row .k { color: var(--ink-dim); }
    .state-row .v { color: var(--ink); font-family: var(--mono); font-size: 12px; }
    .kid {
      display: inline-flex;
      gap: 6px;
      align-items: center;
      background: var(--panel-2);
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 2px 10px;
      font-family: var(--mono);
      font-size: 11.5px;
      color: var(--ink);
      margin: 3px 4px 0 0;
    }
    .kid.active { border-color: rgba(93,211,158,0.5); }
    .kid.previous { border-color: rgba(255,184,107,0.5); }
    .kid .role {
      font-family: -apple-system, sans-serif;
      font-size: 9.5px;
      letter-spacing: 0.4px;
      text-transform: uppercase;
      color: var(--ink-dim);
    }
    .kid.active .role { color: var(--good); }
    .kid.previous .role { color: var(--warn); }

    .reasons li {
      list-style: none;
      display: flex;
      justify-content: space-between;
      padding: 4px 0;
      font-size: 12.5px;
      color: var(--ink-mid);
    }
    .reasons li .k { color: var(--ink); }
    .reasons li .v { font-family: var(--mono); font-size: 11.5px; }

    /* --------- footer --------- */
    footer {
      max-width: 1320px;
      margin: 0 auto;
      padding: 8px 32px 36px;
      color: var(--ink-dim);
      font-size: 12px;
      line-height: 1.65;
    }
    footer a { color: var(--accent-2); }
    footer .pillrow { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 4px; }
    footer .ref {
      padding: 3px 9px;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 999px;
      font-family: var(--mono);
      font-size: 11px;
      color: var(--ink);
    }
    footer .ref:hover { border-color: var(--accent-2); text-decoration: none; }

    .spinner {
      width: 12px; height: 12px;
      border: 2px solid var(--line);
      border-top-color: var(--accent);
      border-radius: 50%;
      display: inline-block;
      animation: spin 0.7s linear infinite;
      vertical-align: -2px;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .muted { color: var(--ink-dim); }
  </style>
</head>
<body>
  <div class="banner">
    <b>DEMO ONLY.</b> Ephemeral keys reset on cold start, public ingress is rate-limited
    (10/min issuer, 20/min orders, per IP), Redis sidecar has no persistence.
    <b>Never trust tokens issued here.</b> This deployment exists so security reviewers can
    poke at a real running <a href="https://github.com/systemslibrarian/postquantum-jwt">PostQuantum.Jwt</a>
    instance, not for production use.
  </div>

  <header class="hero">
    <div class="hero-row">
      <div>
        <h1>PostQuantum.Jwt <span class="tag">/ live production-shape demo</span></h1>
        <p class="lede">
          Two real services on Azure Container Apps. <b>IssuerApi</b> mints
          <code class="mono">ML-DSA-65</code>-signed (and optionally
          <code class="mono">X-Wing</code>-encrypted) tokens. <b>OrdersApi</b> validates them fail-closed against a
          JWKS-equivalent it polls, a Redis-backed replay cache it owns, and a typed failure-reason
          taxonomy that never silently downgrades. Click a numbered step on the left and watch the
          full chain run — issue, decode, validate, replay-reject, tamper-reject, key-rotate.
        </p>
        <div class="crumbs">
          <a href="https://github.com/systemslibrarian/postquantum-jwt/blob/main/docs/SPEC.md">SPEC.md</a>
          <span>·</span>
          <a href="https://github.com/systemslibrarian/postquantum-jwt/blob/main/SECURITY.md">SECURITY.md</a>
          <span>·</span>
          <a href="https://github.com/systemslibrarian/postquantum-jwt/blob/main/KNOWN-GAPS.md">KNOWN-GAPS.md</a>
          <span>·</span>
          <a href="https://github.com/systemslibrarian/postquantum-jwt/blob/main/docs/TESTING.md">TESTING.md</a>
          <span>·</span>
          <a href="https://github.com/systemslibrarian/postquantum-jwt/tree/main/samples/ProductionDeploymentDemo">Source for this demo</a>
        </div>
      </div>
      <div class="status-tray">
        <span class="chip" id="chip-issuer"><span class="dot"></span><span>issuer</span></span>
        <span class="chip" id="chip-orders"><span class="dot"></span><span>orders</span></span>
        <span class="chip" id="chip-redis"><span class="dot"></span><span>redis</span></span>
      </div>
    </div>
  </header>

  <main>
    <!-- ============= LEFT: STEP RAIL ============= -->
    <section class="panel">
      <div class="panel-head">The tour — 8 steps</div>
      <div class="panel-body tight">
        <button class="step" data-step="1">
          <span class="step-num">1</span>
          <div>
            <div class="step-title"><span class="verb">GET</span>See the verification keys</div>
            <div class="step-sub">JWKS-equivalent the verifier polls. Header-trust is impossible because keys come from <i>here</i>, not the token.</div>
          </div>
        </button>
        <button class="step" data-step="2">
          <span class="step-num">2</span>
          <div>
            <div class="step-title"><span class="verb">POST</span>Issue an encrypted token</div>
            <div class="step-sub">5-part envelope: <code>X-Wing</code> KEM + <code>A256GCM</code> wrapping a <code>ML-DSA-65</code>-signed inner JWT.</div>
          </div>
        </button>
        <button class="step" data-step="3">
          <span class="step-num">3</span>
          <div>
            <div class="step-title"><span class="verb">GET</span>Validate at Orders</div>
            <div class="step-sub">Decrypt → verify sig → check iss/aud/exp/nbf → register jti in Redis → return claims.</div>
          </div>
        </button>
        <button class="step" data-step="4">
          <span class="step-num">4</span>
          <div>
            <div class="step-title"><span class="verb">GET</span>Replay the same token</div>
            <div class="step-sub">Redis <code>SET NX</code> already holds the <code>jti</code> → <b>ReplayDetected</b>.</div>
          </div>
        </button>
        <button class="step" data-step="5">
          <span class="step-num">5</span>
          <div>
            <div class="step-title"><span class="verb">GET</span>Tamper one byte of the signature</div>
            <div class="step-sub">Flip a base64url character → <b>SignatureMismatch</b>, fail-closed.</div>
          </div>
        </button>
        <button class="step" data-step="6">
          <span class="step-num">6</span>
          <div>
            <div class="step-title"><span class="verb">POST</span>Wrong-audience token</div>
            <div class="step-sub">Signed under the same key but aimed at a different <code>aud</code> → <b>AudienceMismatch</b>.</div>
          </div>
        </button>
        <button class="step" data-step="7">
          <span class="step-num">7</span>
          <div>
            <div class="step-title"><span class="verb">POST</span>Expired token</div>
            <div class="step-sub"><code>exp</code> in the past → <b>Expired</b>, after signature verifies.</div>
          </div>
        </button>
        <button class="step" data-step="8">
          <span class="step-num">8</span>
          <div>
            <div class="step-title"><span class="verb">POST</span>Rotate &amp; retire keys</div>
            <div class="step-sub">Mint a new active <code>kid</code>, then retire the previous one. Old tokens under the retired <code>kid</code> → <b>UnknownKid</b>.</div>
          </div>
        </button>
        <div class="explain" style="margin: 10px 6px;">
          <b>Reading the output:</b> each step shows the verdict pill, the actual JOSE shape we sent or got back (decoded from base64url where possible), and a one-paragraph explanation of <b>which security property</b> the step proved. The state sidebar on the right updates live.
        </div>
      </div>
    </section>

    <!-- ============= CENTER: OUTPUT ============= -->
    <section class="panel">
      <div class="panel-head" id="out-title">Pick a step on the left</div>
      <div class="verdict">
        <span class="pill" id="verdict-pill">idle</span>
        <span class="verdict-text" id="verdict-text">Click <b>step 1</b> to start the tour, or jump in anywhere.</span>
      </div>

      <div class="section">
        <div class="section-head">Token shape (decoded)</div>
        <div class="section-body" id="token-decoded">
          <span class="muted">No token in flight yet.</span>
        </div>
      </div>

      <div class="section">
        <div class="section-head">What just happened</div>
        <div class="section-body">
          <div class="explain" id="explain">Click any step to see the validator's reasoning, the typed <code>PqJwtFailureReason</code> on a rejection, and the wire-level evidence.</div>
        </div>
      </div>

      <div class="section">
        <div class="section-head">Raw responses</div>
        <div class="section-body">
          <pre id="raw" class="dim">// Network requests + JSON responses will print here as the demo runs.</pre>
        </div>
      </div>
    </section>

    <!-- ============= RIGHT: STATE ============= -->
    <section>
      <div class="panel" style="margin-bottom: 14px;">
        <div class="panel-head">Issuer key ring</div>
        <div class="panel-body">
          <div id="key-state" class="muted">Step 1 will load the published keys.</div>
        </div>
      </div>
      <div class="panel" style="margin-bottom: 14px;">
        <div class="panel-head">Last token issued</div>
        <div class="panel-body">
          <div id="last-token" class="muted">No token yet.</div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-head">Validation outcomes</div>
        <div class="panel-body">
          <ul class="reasons" id="reasons">
            <li><span class="k">— pick a step —</span></li>
          </ul>
        </div>
      </div>
    </section>
  </main>

  <footer>
    <p>
      <b>Where this demo lives in the standards:</b>
    </p>
    <p class="pillrow">
      <a class="ref" href="https://datatracker.ietf.org/doc/rfc9964/">RFC 9964 — ML-DSA in JOSE</a>
      <a class="ref" href="https://csrc.nist.gov/pubs/fips/204/final">FIPS 204 — ML-DSA</a>
      <a class="ref" href="https://csrc.nist.gov/pubs/fips/203/final">FIPS 203 — ML-KEM</a>
      <a class="ref" href="https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/">draft-connolly-cfrg-xwing-kem</a>
      <a class="ref" href="https://datatracker.ietf.org/doc/html/rfc7515">RFC 7515 — JWS</a>
      <a class="ref" href="https://datatracker.ietf.org/doc/html/rfc7516">RFC 7516 — JWE</a>
      <a class="ref" href="https://datatracker.ietf.org/doc/html/rfc7518">RFC 7518 — A256GCM</a>
      <a class="ref" href="https://datatracker.ietf.org/doc/html/rfc7748">RFC 7748 — X25519</a>
    </p>
    <p>
      ML-DSA-65 and A256GCM are registered JOSE identifiers. The X-Wing key-management profile is
      <b>not</b> currently a standardized JOSE/JWE profile — tokens this library produces are
      intended for controlled issuer/verifier systems, not generic JWT interop. See
      <a href="https://github.com/systemslibrarian/postquantum-jwt#readme">README</a>.
    </p>
    <p class="muted" style="margin-top:14px;">To God be the glory — 1 Corinthians 10:31.</p>
  </footer>

  <script>
    const ORDERS_BASE = "{{ORDERS_BASE_URL}}";
    const ISSUER_BASE = "";  // relative — we're served by issuer

    // ---- tiny helpers ----
    const $ = (id) => document.getElementById(id);
    const verdictPill = $('verdict-pill');
    const verdictText = $('verdict-text');
    const outTitle = $('out-title');
    const tokenDecoded = $('token-decoded');
    const explain = $('explain');
    const raw = $('raw');
    const keyState = $('key-state');
    const lastToken = $('last-token');
    const reasons = $('reasons');
    const reasonCounts = {};

    function setVerdict(kind, label, text) {
      verdictPill.className = 'pill ' + (kind || '');
      verdictPill.textContent = label;
      verdictText.innerHTML = text;
    }
    function setExplain(html) { explain.innerHTML = html; }
    function setRaw(s) { raw.textContent = s; raw.classList.remove('dim'); }
    function setStepStatus(n, status) {
      document.querySelectorAll('.step').forEach(b => {
        if (b.dataset.step === String(n)) {
          b.classList.remove('done', 'bad');
          if (status === 'good') b.classList.add('done');
          if (status === 'bad')  b.classList.add('bad');
        }
      });
    }
    function activateStep(n, title) {
      document.querySelectorAll('.step').forEach(b => b.classList.toggle('active', b.dataset.step === String(n)));
      outTitle.textContent = `Step ${n} — ${title}`;
    }
    function bumpReason(reason) {
      reasonCounts[reason] = (reasonCounts[reason] || 0) + 1;
      reasons.innerHTML = Object.entries(reasonCounts)
        .map(([k, v]) => `<li><span class="k">${k}</span><span class="v">${v}</span></li>`)
        .join('') || '<li><span class="k">— pick a step —</span></li>';
    }
    function b64urlToBytes(s) {
      s = s.replace(/-/g, '+').replace(/_/g, '/');
      while (s.length % 4) s += '=';
      const bin = atob(s);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return bytes;
    }
    function b64urlToText(s) {
      try { return new TextDecoder().decode(b64urlToBytes(s)); } catch { return null; }
    }
    function tryParseJson(s) { try { return JSON.parse(s); } catch { return null; } }

    function decodeTokenShape(token) {
      const parts = token.split('.');
      if (parts.length === 3) {
        const headerJson = tryParseJson(b64urlToText(parts[0]) || '');
        const payloadJson = tryParseJson(b64urlToText(parts[1]) || '');
        const sigBytes = b64urlToBytes(parts[2]);
        return {
          kind: 'JWS (signed only) — 3 parts',
          parts: 3,
          header: headerJson,
          payload: payloadJson,
          sigLen: sigBytes.length,
          tokenLen: token.length,
        };
      } else if (parts.length === 5) {
        const headerJson = tryParseJson(b64urlToText(parts[0]) || '');
        return {
          kind: 'JWE (sign-then-encrypt) — 5 parts',
          parts: 5,
          header: headerJson,
          kemCiphertextLen: b64urlToBytes(parts[1]).length,
          nonceLen: b64urlToBytes(parts[2]).length,
          ciphertextLen: b64urlToBytes(parts[3]).length,
          tagLen: b64urlToBytes(parts[4]).length,
          tokenLen: token.length,
          note: 'Inner JWT is encrypted — only the outer protected header is readable client-side.',
        };
      }
      return { kind: `Unrecognised shape (${parts.length} parts)`, tokenLen: token.length };
    }

    function renderTokenShape(shape) {
      if (!shape) {
        tokenDecoded.innerHTML = '<span class="muted">No token in flight yet.</span>';
        return;
      }
      let html = `<div class="token-grid">`;
      html += `<div class="k">shape</div><div class="v">${shape.kind}, ${shape.tokenLen} bytes</div>`;
      if (shape.header) {
        html += `<div class="k">protected header</div><div class="v"><pre>${escapeHtml(JSON.stringify(shape.header, null, 2))}</pre></div>`;
      }
      if (shape.parts === 3) {
        if (shape.payload) {
          html += `<div class="k">payload</div><div class="v"><pre>${escapeHtml(JSON.stringify(shape.payload, null, 2))}</pre></div>`;
        }
        html += `<div class="k">signature</div><div class="v">${shape.sigLen} bytes (ML-DSA-65 signature is ~3293 bytes)</div>`;
      } else if (shape.parts === 5) {
        html += `<div class="k">KEM ciphertext</div><div class="v">${shape.kemCiphertextLen} bytes (X-Wing KEM = ML-KEM-768 ct + X25519 ephemeral pubkey)</div>`;
        html += `<div class="k">AES-GCM nonce</div><div class="v">${shape.nonceLen} bytes (96-bit, AEAD-bound to the protected header as AAD)</div>`;
        html += `<div class="k">AES-GCM ciphertext</div><div class="v">${shape.ciphertextLen} bytes (the inner signed JWT, encrypted)</div>`;
        html += `<div class="k">AES-GCM tag</div><div class="v">${shape.tagLen} bytes (16-byte tag pinned by the profile, no truncation accepted)</div>`;
      }
      html += `</div>`;
      tokenDecoded.innerHTML = html;
    }
    function escapeHtml(s) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

    function updateLastToken(token, kid, parts) {
      if (!token) { lastToken.innerHTML = '<span class="muted">No token yet.</span>'; return; }
      const head = token.substring(0, 32);
      const tail = token.substring(token.length - 12);
      lastToken.innerHTML = `
        <div class="state-row"><span class="k">kid</span><span class="v">${kid || '(none)'}</span></div>
        <div class="state-row"><span class="k">parts</span><span class="v">${parts}</span></div>
        <div class="state-row"><span class="k">bytes</span><span class="v">${token.length}</span></div>
        <div style="margin-top:8px; word-break: break-all; font-family: var(--mono); font-size: 11px; color: var(--ink-mid);">${head}…${tail}</div>
      `;
    }

    function updateKeyState(jwks) {
      if (!jwks || !jwks.keys) { keyState.innerHTML = '<span class="muted">No JWKS yet.</span>'; return; }
      let html = '';
      for (const k of jwks.keys) {
        // Server emits `status` ('active' | 'previous'); accept `role` for compat.
        const status = (k.status || k.role || '').toLowerCase();
        const cls = status === 'active' ? 'active' : (status === 'previous' ? 'previous' : '');
        html += `<span class="kid ${cls}">${k.kid || k.Kid}<span class="role">${status}</span></span>`;
      }
      keyState.innerHTML = html || '<span class="muted">No keys published.</span>';
    }

    let lastIssuedToken = null;
    let lastIssuedKid = null;
    let lastIssuedParts = 0;

    async function safeJson(res) {
      const t = await res.text();
      try { return { json: JSON.parse(t), text: t }; } catch { return { json: null, text: t }; }
    }

    async function callIssuer(method, path, body) {
      const opts = { method, headers: {} };
      if (body !== undefined) {
        opts.headers['Content-Type'] = 'application/json';
        opts.body = JSON.stringify(body);
      }
      const t0 = performance.now();
      const res = await fetch(ISSUER_BASE + path, opts);
      const elapsed = Math.round(performance.now() - t0);
      const { json, text } = await safeJson(res);
      return { res, json, text, elapsed, method, path: ISSUER_BASE + path };
    }
    async function callOrders(method, path, opts = {}) {
      const t0 = performance.now();
      const res = await fetch(ORDERS_BASE + path, {
        method,
        headers: {
          ...(opts.bearer ? { 'Authorization': 'Bearer ' + opts.bearer } : {}),
        },
      });
      const elapsed = Math.round(performance.now() - t0);
      const { json, text } = await safeJson(res);
      return { res, json, text, elapsed, method, path: ORDERS_BASE + path };
    }
    function appendRaw(label, call) {
      const line = `// ${label}\n${call.method} ${call.path}\n${call.res.status} ${call.res.statusText} - ${call.elapsed}ms\n\n${tryPretty(call.text)}\n`;
      raw.textContent = (raw.textContent && !raw.classList.contains('dim') ? raw.textContent + '\n' : '') + line;
      raw.classList.remove('dim');
    }
    function tryPretty(s) { try { return JSON.stringify(JSON.parse(s), null, 2); } catch { return s; } }

    function tamperFirstSigChar(token) {
      const parts = token.split('.');
      if (parts.length === 0) return token;
      const sigIdx = parts.length - 1;
      const sig = parts[sigIdx];
      if (!sig.length) return token;
      const orig = sig[0];
      const flip = orig === 'A' ? 'B' : 'A';
      parts[sigIdx] = flip + sig.slice(1);
      return parts.join('.');
    }

    // ---- step handlers ----
    const STEPS = {
      1: async () => {
        activateStep(1, 'See the verification keys');
        setVerdict('warn', 'GET', 'Asking the issuer for its published verification keys…');
        const call = await callIssuer('GET', '/.well-known/pqjwt-keys');
        appendRaw('Fetch JWKS', call);
        if (call.res.ok && call.json) {
          updateKeyState(call.json);
          setVerdict('good', 'JWKS PUBLISHED', `The verifier polls <code>/.well-known/pqjwt-keys</code> and resolves <code>kid</code> against this list. The validator never reads the token's <code>alg</code>/<code>jwk</code>/<code>jku</code>/<code>x5u</code>/<code>x5c</code>.`);
          setExplain(`<b>Property proved:</b> the verification key comes from the trusted key directory, not the token. This is what makes <i>header-trust</i> algorithm-confusion attacks (e.g. <code>alg: none</code>, <code>jku</code> pointing at attacker keys) structurally impossible — they cannot influence which key the verifier uses.`);
          setStepStatus(1, 'good');
        } else {
          setVerdict('bad', `HTTP ${call.res.status}`, 'Failed to fetch the JWKS. The issuer may be cold-starting; try again in 30 seconds.');
          setStepStatus(1, 'bad');
        }
      },

      2: async () => {
        activateStep(2, 'Issue an encrypted token');
        setVerdict('warn', 'POST', 'Asking the issuer to mint a fresh encrypted token…');
        const call = await callIssuer('POST', '/token', {});
        appendRaw('Issue token', call);
        if (call.res.ok && call.json) {
          lastIssuedToken = call.json.access_token;
          lastIssuedKid = call.json.kid;
          lastIssuedParts = call.json.parts;
          updateLastToken(lastIssuedToken, lastIssuedKid, lastIssuedParts);
          renderTokenShape(decodeTokenShape(lastIssuedToken));
          setVerdict('good', '200 — TOKEN ISSUED', `<b>${lastIssuedParts}-part</b> envelope under <code>kid=${lastIssuedKid}</code>, ${lastIssuedToken.length} bytes. ML-DSA-65 signature inside, X-Wing + AES-256-GCM outside.`);
          setExplain(`<b>What you're seeing:</b> the outer protected header is the only part readable client-side — it pins <code>alg=X-Wing</code>, <code>enc=A256GCM</code>, <code>typ=JWT</code>, <code>cty=JWT</code>. The inner JWT (header + claims + ML-DSA signature) is encrypted into the ciphertext segment, AEAD-bound to the protected header as AAD. A 16-byte tag is required — truncation is rejected by the validator.`);
          setStepStatus(2, 'good');
        } else {
          setVerdict('bad', `HTTP ${call.res.status}`, 'Token issuance failed. Likely a cold-start delay — try again.');
          setStepStatus(2, 'bad');
        }
      },

      3: async () => {
        if (!lastIssuedToken) { await STEPS[2](); }
        activateStep(3, 'Validate at Orders');
        setVerdict('warn', 'GET', 'Sending the encrypted token to Orders for full validation…');
        const call = await callOrders('GET', '/orders/123', { bearer: lastIssuedToken });
        appendRaw('Validate at Orders', call);
        if (call.res.ok && call.json) {
          setVerdict('good', '200 — ACCEPTED', `Orders decrypted with its X-Wing key, verified the ML-DSA-65 signature, checked iss/aud/exp/nbf, resolved <code>kid=${lastIssuedKid}</code>, and registered <code>jti</code> in Redis. Returned: <b>${call.json.sub}</b> (${call.json.role}, ${call.json.scope}).`);
          setExplain(`<b>Property proved:</b> the signed-before-claims ordering. Orders <i>verifies the ML-DSA signature first</i>, then evaluates <code>iss</code>/<code>aud</code>/<code>exp</code>/<code>nbf</code>. An attacker who tampers any claim breaks the signature; an attacker who steals a token can still only act within its <code>exp</code> + <code>jti</code> budget. The acceptance message lists every gate the token passed.`);
          bumpReason('Accepted');
          setStepStatus(3, 'good');
        } else {
          setVerdict('bad', `HTTP ${call.res.status}`, 'Orders rejected the token. Inspect the raw response below for the typed reason.');
          if (call.json && call.json.detail) bumpReason(call.json.title || 'Rejected');
          setStepStatus(3, 'bad');
        }
      },

      4: async () => {
        if (!lastIssuedToken) { await STEPS[2](); }
        activateStep(4, 'Replay the same token');
        setVerdict('warn', 'GET', 'Sending the SAME token to Orders a second time. Redis should reject it…');
        const call = await callOrders('GET', '/orders/123', { bearer: lastIssuedToken });
        appendRaw('Replay attempt', call);
        if (call.res.status === 401) {
          setVerdict('bad', '401 — REPLAY DETECTED', `Orders ran the same validation pipeline, but Redis' <code>SET NX</code> for this <code>jti</code> failed because the previous validation already registered it. The validator fails closed — same token, different request, rejected.`);
          setExplain(`<b>Property proved:</b> replay defense survives a stolen token. Even with a perfectly valid signature and current <code>exp</code>, the second presentation of the same <code>jti</code> is rejected with <b>ReplayDetected</b>. The replay store is a real Redis sidecar in this deployment (not in-memory) — multi-node deployments share the same TTL'd seen-jti set.`);
          bumpReason('ReplayDetected');
          setStepStatus(4, 'good');
        } else {
          setVerdict('bad', `HTTP ${call.res.status}`, `Unexpected status — replay should have produced a 401 ReplayDetected. Check the raw response.`);
          setStepStatus(4, 'bad');
        }
      },

      5: async () => {
        if (!lastIssuedToken) { await STEPS[2](); }
        activateStep(5, 'Tamper one byte of the signature');
        setVerdict('warn', 'GET', 'Flipping one base64url character in the signature/tag segment and resending…');
        const tampered = tamperFirstSigChar(lastIssuedToken);
        const call = await callOrders('GET', '/orders/123', { bearer: tampered });
        appendRaw('Tampered token', call);
        if (call.res.status === 401) {
          setVerdict('bad', '401 — TAMPER REJECTED', `One flipped character is enough. For a 5-part envelope, this corrupts the AES-GCM tag and decryption fails closed (<b>DecryptionFailed</b>). For a 3-part token it surfaces as <b>SignatureMismatch</b>.`);
          setExplain(`<b>Property proved:</b> ciphertext + tag malleability is non-existent. AEAD construction binds the protected header into the AAD, and the 16-byte tag is pinned by the profile (no truncation accepted). For signed-only tokens the equivalent guarantee is ML-DSA-65 itself — any byte changed on the wire breaks verification.`);
          bumpReason(call.json && call.json.title ? call.json.title : 'Rejected');
          setStepStatus(5, 'good');
        } else {
          setVerdict('bad', `HTTP ${call.res.status}`, `Unexpected — tampered tokens should always be rejected.`);
          setStepStatus(5, 'bad');
        }
      },

      6: async () => {
        activateStep(6, 'Wrong-audience token');
        setVerdict('warn', 'POST', 'Asking the issuer to mint a token whose aud is wrong on purpose…');
        const mint = await callIssuer('POST', '/token/wrong-audience', {});
        appendRaw('Mint wrong-aud token', mint);
        if (!mint.res.ok || !mint.json) {
          setVerdict('bad', `HTTP ${mint.res.status}`, 'Could not mint the wrong-audience token.');
          setStepStatus(6, 'bad');
          return;
        }
        const tok = mint.json.access_token;
        renderTokenShape(decodeTokenShape(tok));
        setVerdict('warn', 'GET', 'Sending it to Orders — should fail with AudienceMismatch…');
        const call = await callOrders('GET', '/orders/123', { bearer: tok });
        appendRaw('Validate wrong-aud at Orders', call);
        if (call.res.status === 401) {
          setVerdict('bad', '401 — AUDIENCE MISMATCH', `The signature verifies (same issuer, same kid), but the <code>aud</code> doesn't match what Orders is configured to accept. Fail-closed.`);
          setExplain(`<b>Property proved:</b> claim validation is bound to the verifier's configuration, not the token. The token is honestly signed by the legitimate issuer — it just isn't <i>for Orders</i>. A misrouted (or maliciously redirected) token cannot impersonate a valid one across services.`);
          bumpReason(call.json && call.json.title ? call.json.title : 'AudienceMismatch');
          setStepStatus(6, 'good');
        } else {
          setVerdict('bad', `HTTP ${call.res.status}`, 'Unexpected status.');
          setStepStatus(6, 'bad');
        }
      },

      7: async () => {
        activateStep(7, 'Expired token');
        setVerdict('warn', 'POST', 'Asking the issuer to mint a token with exp in the past…');
        const mint = await callIssuer('POST', '/token/expired', {});
        appendRaw('Mint expired token', mint);
        if (!mint.res.ok || !mint.json) {
          setVerdict('bad', `HTTP ${mint.res.status}`, 'Could not mint the expired token.');
          setStepStatus(7, 'bad');
          return;
        }
        const tok = mint.json.access_token;
        renderTokenShape(decodeTokenShape(tok));
        setVerdict('warn', 'GET', 'Sending to Orders — should fail with Expired after the signature verifies…');
        const call = await callOrders('GET', '/orders/123', { bearer: tok });
        appendRaw('Validate expired at Orders', call);
        if (call.res.status === 401) {
          setVerdict('bad', '401 — EXPIRED', `The signature verifies; the <code>exp</code> claim is in the past. Fail-closed with the <b>Expired</b> reason.`);
          setExplain(`<b>Property proved:</b> lifetime checks live after signature verification — which is the right order for fail-closed totality. An unauthenticated payload claim is never trusted; only after the signature confirms the issuer minted exactly these bytes does the validator look at <code>exp</code>/<code>nbf</code>. See <code>docs/SPEC.md</code> steps 6→7.`);
          bumpReason('Expired');
          setStepStatus(7, 'good');
        } else {
          setVerdict('bad', `HTTP ${call.res.status}`, 'Unexpected status.');
          setStepStatus(7, 'bad');
        }
      },

      8: async () => {
        activateStep(8, 'Rotate & retire keys');
        setVerdict('warn', 'POST', 'Rotating the active signing key (previous stays valid for overlap)…');
        const rot = await callIssuer('POST', '/keys/rotate', {});
        appendRaw('Rotate', rot);

        const jwks1 = await callIssuer('GET', '/.well-known/pqjwt-keys');
        appendRaw('JWKS after rotate', jwks1);
        if (jwks1.json) updateKeyState(jwks1.json);

        setVerdict('warn', 'POST', 'Minting a token under the new active kid…');
        const newTok = await callIssuer('POST', '/token', {});
        appendRaw('Issue under new kid', newTok);

        setVerdict('warn', 'POST', 'Retiring the previous kid. Any token still signed by it must now be rejected…');
        const retire = await callIssuer('POST', '/keys/retire-previous', {});
        appendRaw('Retire previous', retire);

        const jwks2 = await callIssuer('GET', '/.well-known/pqjwt-keys');
        appendRaw('JWKS after retire', jwks2);
        if (jwks2.json) updateKeyState(jwks2.json);

        // Try the OLD lastIssuedToken — its kid is now retired.
        if (lastIssuedToken) {
          const call = await callOrders('GET', '/orders/123', { bearer: lastIssuedToken });
          appendRaw('Validate retired-kid token at Orders', call);
          if (call.res.status === 401) {
            setVerdict('bad', '401 — UNKNOWN KID', `After retirement the previous kid is no longer in the JWKS. A token still signed by it cannot be verified — fail-closed with <b>UnknownKid</b> (the validator never tries the wrong key).`);
            setExplain(`<b>Property proved:</b> structural key rotation. A signed-only key change works the same way as a TLS certificate rollover — overlap window so live tokens keep working, then a hard cutoff. Crucially, no <code>kid</code> means no verification attempt; the validator does not silently fall back to another published key.`);
            bumpReason('UnknownKid');
            setStepStatus(8, 'good');
          } else {
            setVerdict('warn', `HTTP ${call.res.status}`, 'Unexpected — retired kid should have produced 401 UnknownKid.');
            setStepStatus(8, 'bad');
          }
        }
      },
    };

    document.querySelectorAll('.step').forEach(btn => {
      btn.addEventListener('click', async () => {
        const n = parseInt(btn.dataset.step, 10);
        try { await STEPS[n](); }
        catch (err) {
          setVerdict('bad', 'error', String(err));
          appendRaw('JS error', { method: '(client)', path: '-', res: { status: 0, statusText: 'error' }, elapsed: 0, text: String(err) });
        }
      });
    });

    // ---- status chips ----
    async function pingChip(id, baseUrl, path) {
      const chip = $(id);
      try {
        const res = await fetch(baseUrl + path, { method: 'GET' });
        if (res.ok) {
          chip.classList.add('alive');
          const body = await res.json().catch(() => null);
          if (body && body.replay) {
            const r = $('chip-redis');
            r.classList.remove('warn', 'bad');
            r.classList.add(body.replay === 'redis' ? 'alive' : 'warn');
            r.querySelector('span:last-child').textContent = 'redis (' + body.replay + ')';
          }
        } else {
          chip.classList.add('warn');
        }
      } catch {
        chip.classList.add('bad');
      }
    }
    pingChip('chip-issuer', ISSUER_BASE, '/health');
    pingChip('chip-orders', ORDERS_BASE, '/health');
  </script>
</body>
</html>
""";
}
