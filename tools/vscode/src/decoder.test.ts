import test from "node:test";
import assert from "node:assert/strict";
import { decodeToken, decodeSegment, base64UrlDecode } from "./decoder";

// Helper: encode an object as a base64url segment (no padding), like JOSE.
function seg(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

test("signed token: 3 segments, ML-DSA-65 header + kid + payload", () => {
  const token = [seg({ alg: "ML-DSA-65", kid: "k1" }), seg({ sub: "user-1" }), "sig"].join(".");
  const out = decodeToken(token);
  assert.match(out, /Form: SIGNED \(3 segments\)/);
  assert.match(out, /alg = ML-DSA-65/);
  assert.match(out, /kid = k1/);
  assert.match(out, /"sub": "user-1"/);
});

test("encrypted token: 5 segments, X-Wing / A256GCM / cty=JWT", () => {
  const token = [seg({ alg: "X-Wing", enc: "A256GCM", cty: "JWT" }), "encKey", "iv", "ct", "tag"].join(".");
  const out = decodeToken(token);
  assert.match(out, /Form: ENCRYPTED \(5 segments\)/);
  assert.match(out, /enc = A256GCM/);
  assert.match(out, /alg = X-Wing/);
  assert.match(out, /cty = JWT/);
  assert.match(out, /Payload is encrypted/);
});

test("alg: none is flagged as the no-unsigned-path rejection", () => {
  const token = [seg({ alg: "none" }), seg({}), "sig"].join(".");
  assert.match(decodeToken(token), /alg = none .* NO unsigned path/);
});

test("unexpected signature alg is noted, not accepted", () => {
  const token = [seg({ alg: "RS256" }), seg({}), "sig"].join(".");
  assert.match(decodeToken(token), /alg = RS256 — not the expected ML-DSA-65 suite/);
});

test("wrong segment count is reported", () => {
  assert.match(decodeToken("a.b"), /found 2 segment\(s\), expected 3 \(signed\) or 5 \(encrypted\)/);
});

test("empty / whitespace input is handled", () => {
  assert.equal(decodeToken("   "), "No token provided.");
});

test("non-base64url header is reported as not decodable", () => {
  const token = ["@@bad@@", seg({}), "sig"].join(".");
  assert.match(decodeToken(token), /header segment is not valid base64url/);
});

test("header that decodes but is not JSON is reported distinctly", () => {
  const notJson = Buffer.from("hello, not json").toString("base64url");
  const token = [notJson, seg({}), "sig"].join(".");
  assert.match(decodeToken(token), /header decoded but is not valid JSON/);
});

test("decodeSegment classifies the failure modes", () => {
  assert.equal(decodeSegment("").kind, "empty");
  assert.equal(decodeSegment("a@b").kind, "not-base64url");
  assert.equal(decodeSegment(Buffer.from("nope").toString("base64url")).kind, "not-json");
  assert.equal(decodeSegment(seg({ ok: true })).kind, "json");
});

test("base64UrlDecode round-trips JSON (no padding in input)", () => {
  const encoded = Buffer.from('{"a":1}').toString("base64url");
  assert.equal(base64UrlDecode(encoded), '{"a":1}');
});
