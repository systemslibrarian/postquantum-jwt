namespace PostQuantum.Jwt.Samples.ProductionDeploymentDemo.IssuerApi;

/// <summary>
/// Self-contained interactive landing page served at <c>/</c>. No SPA
/// framework, no build step, no asset pipeline — just vanilla HTML/CSS/JS
/// that fetches the existing JSON endpoints and shows the results.
/// Demo-only banner is mandatory and unconditional.
/// </summary>
internal static class LandingPage
{
    public const string Html = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1" />
          <title>PostQuantum.Jwt — ProductionDeploymentDemo Issuer</title>
          <link rel="icon" href="data:," />
          <style>
            :root {
              --bg: #0b1020;
              --panel: #141a30;
              --panel-2: #1c2440;
              --ink: #e8ecf6;
              --ink-dim: #97a0bf;
              --accent: #7aa2ff;
              --good: #5dd39e;
              --warn: #ffb86b;
              --bad: #ff6b6b;
              --line: #2a335c;
              --mono: ui-monospace, 'JetBrains Mono', SFMono-Regular, Menlo, Consolas, monospace;
            }
            * { box-sizing: border-box; }
            body {
              margin: 0;
              font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
              background: linear-gradient(180deg, #0b1020 0%, #0a0e1c 100%);
              color: var(--ink);
              min-height: 100vh;
            }
            header {
              padding: 28px 32px 8px;
              max-width: 1080px;
              margin: 0 auto;
            }
            h1 { font-size: 22px; margin: 0 0 6px; font-weight: 600; letter-spacing: 0.2px; }
            h1 .tag { color: var(--accent); font-weight: 400; }
            .subtitle { color: var(--ink-dim); font-size: 14px; margin: 0 0 18px; }
            .banner {
              background: rgba(255, 184, 107, 0.08);
              border: 1px solid rgba(255, 184, 107, 0.35);
              color: var(--warn);
              padding: 12px 16px;
              border-radius: 10px;
              font-size: 13px;
              line-height: 1.55;
              margin: 14px 32px 0;
              max-width: 1080px;
              margin-left: auto;
              margin-right: auto;
            }
            .banner b { color: var(--warn); }
            main {
              max-width: 1080px;
              margin: 0 auto;
              padding: 24px 32px 64px;
              display: grid;
              grid-template-columns: 320px 1fr;
              gap: 20px;
            }
            @media (max-width: 880px) { main { grid-template-columns: 1fr; } }
            .panel {
              background: var(--panel);
              border: 1px solid var(--line);
              border-radius: 12px;
              padding: 18px;
            }
            .panel h2 {
              font-size: 12px;
              text-transform: uppercase;
              letter-spacing: 1.4px;
              color: var(--ink-dim);
              margin: 0 0 14px;
              font-weight: 600;
            }
            .actions { display: flex; flex-direction: column; gap: 8px; }
            button {
              text-align: left;
              padding: 10px 12px;
              border-radius: 8px;
              border: 1px solid var(--line);
              background: var(--panel-2);
              color: var(--ink);
              font-size: 13px;
              line-height: 1.4;
              cursor: pointer;
              transition: background 0.12s, border-color 0.12s, transform 0.04s;
            }
            button:hover { background: #232c52; border-color: #3a4480; }
            button:active { transform: translateY(1px); }
            button .verb { color: var(--accent); font-weight: 600; }
            button.good .verb { color: var(--good); }
            button.warn .verb { color: var(--warn); }
            button.bad .verb { color: var(--bad); }
            button .why { color: var(--ink-dim); font-size: 11.5px; display: block; margin-top: 2px; }
            .output {
              background: var(--panel);
              border: 1px solid var(--line);
              border-radius: 12px;
              padding: 0;
              overflow: hidden;
              min-height: 360px;
              display: flex;
              flex-direction: column;
            }
            .output-head {
              padding: 14px 18px;
              border-bottom: 1px solid var(--line);
              display: flex;
              align-items: center;
              gap: 12px;
              font-size: 13px;
            }
            .pill {
              padding: 2px 9px;
              border-radius: 999px;
              font-size: 11px;
              font-weight: 600;
              letter-spacing: 0.4px;
            }
            .pill.good { background: rgba(93, 211, 158, 0.14); color: var(--good); }
            .pill.bad  { background: rgba(255, 107, 107, 0.14); color: var(--bad); }
            .pill.warn { background: rgba(255, 184, 107, 0.14); color: var(--warn); }
            .pill.dim  { background: rgba(151, 160, 191, 0.14); color: var(--ink-dim); }
            pre {
              flex: 1;
              margin: 0;
              padding: 14px 18px;
              font-family: var(--mono);
              font-size: 12.5px;
              line-height: 1.55;
              white-space: pre-wrap;
              word-break: break-all;
              color: var(--ink);
              overflow-y: auto;
            }
            .footer {
              max-width: 1080px;
              margin: 0 auto;
              padding: 4px 32px 36px;
              color: var(--ink-dim);
              font-size: 12px;
              line-height: 1.6;
            }
            .footer a { color: var(--accent); text-decoration: none; }
            .footer a:hover { text-decoration: underline; }
            .endpoints { font-family: var(--mono); font-size: 11.5px; color: var(--ink-dim); }
            .endpoints code { color: var(--ink); }
            .kbd {
              font-family: var(--mono); font-size: 11px; padding: 1px 6px;
              border: 1px solid var(--line); border-radius: 4px; background: var(--panel-2);
            }
          </style>
        </head>
        <body>
          <div class="banner">
            <b>DEMO ONLY.</b> The tokens this service issues use ephemeral keys that
            reset on every cold start. Public ingress is rate-limited. Never trust
            these tokens for anything that matters — they are here so reviewers can
            poke at a real <a style="color:var(--warn);text-decoration:underline" href="https://github.com/systemslibrarian/postquantum-jwt">PostQuantum.Jwt</a> deployment, not for production use.
          </div>
          <header>
            <h1>PostQuantum.Jwt <span class="tag">/ ProductionDeploymentDemo / Issuer</span></h1>
            <p class="subtitle">ML-DSA-65 signed tokens, optional X-Wing sign-then-encrypt, key rotation. Click a button on the left, watch the response on the right.</p>
          </header>
          <main>
            <section class="panel">
              <h2>Issue</h2>
              <div class="actions">
                <button class="good" data-action="issue">
                  <span class="verb">POST</span> /token
                  <span class="why">A real ML-DSA-65 signed (and X-Wing encrypted) token Orders will accept.</span>
                </button>
                <button class="warn" data-action="wrong-audience">
                  <span class="verb">POST</span> /token/wrong-audience
                  <span class="why">Token aimed at a different aud — Orders must reject it.</span>
                </button>
                <button class="warn" data-action="expired">
                  <span class="verb">POST</span> /token/expired
                  <span class="why">Token whose exp is in the past — Orders must reject it.</span>
                </button>
              </div>
              <h2 style="margin-top:22px">Keys</h2>
              <div class="actions">
                <button data-action="keys-status">
                  <span class="verb">GET</span> /keys/status
                  <span class="why">Active kid, previous kid, count of published verification keys.</span>
                </button>
                <button data-action="keys-jwks">
                  <span class="verb">GET</span> /.well-known/pqjwt-keys
                  <span class="why">Published verification keys, what Orders fetches to verify signatures.</span>
                </button>
                <button class="bad" data-action="rotate">
                  <span class="verb">POST</span> /keys/rotate
                  <span class="why">Mint a new active key; previous key stays valid for overlap.</span>
                </button>
                <button class="bad" data-action="retire">
                  <span class="verb">POST</span> /keys/retire-previous
                  <span class="why">Retire the previous key. Any token signed under it now fails-closed.</span>
                </button>
              </div>
              <h2 style="margin-top:22px">Service</h2>
              <div class="actions">
                <button data-action="health">
                  <span class="verb">GET</span> /health
                  <span class="why">Issuer status, audience, encryption default.</span>
                </button>
              </div>
            </section>
            <section class="output">
              <div class="output-head">
                <span class="pill dim" id="status-pill">idle</span>
                <span id="status-text">Pick a button to fire a call.</span>
              </div>
              <pre id="output">// Output appears here. The page calls these endpoints with fetch() and shows the JSON. You can do the same with curl, e.g. `curl -X POST https://&lt;host&gt;/token`. Every failure path returns a typed PqJwtFailureReason — the library never silently downgrades.</pre>
            </section>
          </main>
          <div class="footer">
            <p><b>Endpoints:</b> <span class="endpoints">
              <code>POST /token</code> · <code>POST /token/wrong-audience</code> · <code>POST /token/expired</code> ·
              <code>POST /keys/rotate</code> · <code>POST /keys/retire-previous</code> · <code>GET /keys/status</code> ·
              <code>GET /.well-known/pqjwt-keys</code> · <code>GET /health</code>
            </span></p>
            <p>This page is served by the same minimal API process that mints the tokens.
            To verify a token end-to-end, take a <code>POST /token</code> response's
            <code>access_token</code> and call OrdersApi with
            <code>Authorization: Bearer &lt;token&gt;</code>. The repository's
            <code>run-demo.sh</code> / <code>run-demo.ps1</code> scripts do this for you.</p>
            <p>Source &amp; full docs: <a href="https://github.com/systemslibrarian/postquantum-jwt/tree/main/samples/ProductionDeploymentDemo">github.com/systemslibrarian/postquantum-jwt</a></p>
            <p style="margin-top:14px; opacity:0.7">To God be the glory — 1 Corinthians 10:31.</p>
          </div>
          <script>
            const out = document.getElementById('output');
            const pill = document.getElementById('status-pill');
            const text = document.getElementById('status-text');
            const setStatus = (kind, label) => {
              pill.className = 'pill ' + kind;
              pill.textContent = label;
            };
            const calls = {
              'issue':           { method: 'POST', path: '/token' },
              'wrong-audience':  { method: 'POST', path: '/token/wrong-audience' },
              'expired':         { method: 'POST', path: '/token/expired' },
              'keys-status':     { method: 'GET',  path: '/keys/status' },
              'keys-jwks':       { method: 'GET',  path: '/.well-known/pqjwt-keys' },
              'rotate':          { method: 'POST', path: '/keys/rotate' },
              'retire':          { method: 'POST', path: '/keys/retire-previous' },
              'health':          { method: 'GET',  path: '/health' },
            };
            for (const btn of document.querySelectorAll('button[data-action]')) {
              btn.addEventListener('click', async () => {
                const action = btn.dataset.action;
                const spec = calls[action];
                setStatus('warn', spec.method);
                text.textContent = 'calling ' + spec.path + ' …';
                out.textContent = '';
                const t0 = performance.now();
                try {
                  const res = await fetch(spec.path, {
                    method: spec.method,
                    headers: spec.method === 'POST' ? { 'Content-Type': 'application/json' } : undefined,
                    body: spec.method === 'POST' ? '{}' : undefined,
                  });
                  const elapsed = Math.round(performance.now() - t0);
                  const text2 = await res.text();
                  let pretty = text2;
                  try { pretty = JSON.stringify(JSON.parse(text2), null, 2); } catch {}
                  out.textContent = `// ${spec.method} ${spec.path}\n// ${res.status} ${res.statusText} — ${elapsed}ms\n\n${pretty}`;
                  if (res.ok) {
                    setStatus(res.status === 200 ? 'good' : 'warn', String(res.status));
                    text.textContent = `${spec.method} ${spec.path} — ${elapsed}ms`;
                  } else {
                    setStatus(res.status === 429 ? 'warn' : 'bad', String(res.status));
                    text.textContent = `${spec.method} ${spec.path} — ${res.statusText} in ${elapsed}ms`;
                  }
                } catch (err) {
                  setStatus('bad', 'error');
                  text.textContent = String(err);
                  out.textContent = String(err);
                }
              });
            }
          </script>
        </body>
        </html>
        """;
}
