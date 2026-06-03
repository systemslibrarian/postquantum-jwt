import test from "node:test";
import assert from "node:assert/strict";
import { buildTokenModel } from "../model";
import { renderInspectorHtml, type RenderOptions } from "./html";

const opts: RenderOptions = {
  nonce: "nonce123",
  cssUri: "https://example/inspector.css",
  cspSource: "vscode-resource:",
  playgroundUrl: "https://pqjwt.systemslibrarian.dev/?c=abc",
};

function seg(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}
function signed(payload: object): string {
  return [seg({ alg: "ML-DSA-65", typ: "JWT" }), seg(payload), "c2lnbmF0dXJl"].join(".");
}

test("renders a complete document with CSP, nonce, and all three tabs", () => {
  const html = renderInspectorHtml(buildTokenModel(signed({ sub: "u" })), opts);
  assert.match(html, /^<!DOCTYPE html>/);
  assert.match(html, /Content-Security-Policy/);
  assert.match(html, /nonce-nonce123/);
  assert.match(html, /script-src 'nonce-nonce123'/);
  assert.match(html, /data-tab="token"/);
  assert.match(html, /data-tab="hybrid"/);
  assert.match(html, /data-tab="validation"/);
  // No inline event handlers or unsafe-inline.
  assert.doesNotMatch(html, /unsafe-inline/);
});

test("activeTab selects the initial view", () => {
  const html = renderInspectorHtml(buildTokenModel(signed({ sub: "u" })), { ...opts, activeTab: "validation" });
  assert.match(html, /class="tab active" data-tab="validation"/);
  assert.match(html, /class="view" data-view="validation"/);
  assert.match(html, /class="view hidden" data-view="token"/);
});

test("escapes token-derived content (no HTML/script injection)", () => {
  const evil = "<img src=x onerror=alert(1)>";
  const html = renderInspectorHtml(buildTokenModel(signed({ sub: evil })), opts);
  assert.ok(!html.includes("<img src=x"), "raw HTML must not appear");
  assert.match(html, /&lt;img src=x/);
});

test("encrypted token shows the 'payload is encrypted' notice and no claims table", () => {
  const token = [seg({ alg: "X-Wing", enc: "A256GCM", cty: "JWT" }), "encKey", "iv", "ct", "tag"].join(".");
  const html = renderInspectorHtml(buildTokenModel(token), opts);
  assert.match(html, /Payload is encrypted/);
  assert.doesNotMatch(html, /<table class="claims"/);
});

test("validation flow lists all 8 ordered steps", () => {
  const html = renderInspectorHtml(buildTokenModel(signed({ sub: "u" })), opts);
  for (let n = 1; n <= 8; n++) {
    assert.match(html, new RegExp(`<span class="vnum">${n}</span>`));
  }
});

test("hybrid view exposes the X-Wing combiner formula", () => {
  const html = renderInspectorHtml(buildTokenModel(signed({ sub: "u" })), opts);
  assert.match(html, /SHA3-256\(/);
});

test("unknown input renders the friendly empty state, still a full doc", () => {
  const html = renderInspectorHtml(buildTokenModel("a.b"), opts);
  assert.match(html, /Not a PostQuantum\.Jwt token/);
  assert.match(html, /^<!DOCTYPE html>/);
});
