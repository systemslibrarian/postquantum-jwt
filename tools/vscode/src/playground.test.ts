import test from "node:test";
import assert from "node:assert/strict";
import { buildTokenModel } from "./model";
import { buildShareState, buildPlaygroundUrl } from "./playground";

function seg(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}
function signed(payload: object): string {
  return [seg({ alg: "ML-DSA-65", typ: "JWT" }), seg(payload), "c2ln"].join(".");
}

// Decode a ?c= share back into its JSON, mirroring the playground's DecodeShare.
function decodeShare(url: string): Record<string, unknown> {
  const code = new URL(url).searchParams.get("c");
  assert.ok(code, "expected a ?c= share code");
  let b64 = code!.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) {
    b64 += "=";
  }
  return JSON.parse(Buffer.from(b64, "base64").toString("utf8"));
}

test("buildShareState pulls registered + custom claims from a signed token", () => {
  const now = 1_700_000_000;
  const state = buildShareState(
    buildTokenModel(
      signed({ iss: "iss-x", sub: "sub-y", aud: "aud-z", iat: now, exp: now + 600, jti: "abc", role: "admin" })
    )
  );
  assert.ok(state);
  assert.equal(state!.iss, "iss-x");
  assert.equal(state!.sub, "sub-y");
  assert.equal(state!.aud, "aud-z");
  assert.equal(state!.minutes, 10); // (exp-iat)/60
  assert.equal(state!.jti, true);
  assert.equal(state!.encrypt, false);
  assert.deepEqual(state!.claims, [{ name: "role", value: "admin" }]);
});

test("buildShareState returns undefined for encrypted/unknown tokens", () => {
  const enc = [seg({ alg: "X-Wing", enc: "A256GCM", cty: "JWT" }), "k", "iv", "ct", "tag"].join(".");
  assert.equal(buildShareState(buildTokenModel(enc)), undefined);
  assert.equal(buildShareState(buildTokenModel("a.b")), undefined);
});

test("buildPlaygroundUrl round-trips through the playground's camelCase share schema", () => {
  const url = buildPlaygroundUrl(buildTokenModel(signed({ iss: "i", sub: "s", aud: "a", role: "ops" })));
  assert.match(url, /\/\?c=/);
  const decoded = decodeShare(url);
  assert.equal(decoded.iss, "i");
  assert.equal(decoded.sub, "s");
  assert.equal(decoded.aud, "a");
  assert.equal(decoded.encrypt, false);
  assert.ok(Array.isArray(decoded.claims));
  assert.deepEqual(decoded.claims, [{ name: "role", value: "ops" }]);
});

test("aud given as an array is flattened to a space-joined string", () => {
  const state = buildShareState(buildTokenModel(signed({ aud: ["a", "b"] })));
  assert.equal(state!.aud, "a b");
});

test("non-string custom claim values are JSON-stringified", () => {
  const state = buildShareState(buildTokenModel(signed({ scopes: ["read", "write"], admin: true })));
  assert.deepEqual(
    state!.claims,
    [
      { name: "scopes", value: '["read","write"]' },
      { name: "admin", value: "true" },
    ]
  );
});

test("encrypted/unknown tokens fall back to the plain playground URL", () => {
  const enc = [seg({ alg: "X-Wing", enc: "A256GCM", cty: "JWT" }), "k", "iv", "ct", "tag"].join(".");
  assert.equal(buildPlaygroundUrl(buildTokenModel(enc)), "https://pqjwt.systemslibrarian.dev");
  assert.equal(buildPlaygroundUrl(buildTokenModel("a.b")), "https://pqjwt.systemslibrarian.dev");
});
