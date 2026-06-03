import test from "node:test";
import assert from "node:assert/strict";
import {
  decodeToken,
  decodeSegment,
  base64UrlDecode,
  looksLikePqJwt,
  findPqJwtTokens,
} from "./decoder";

// Helper: encode an object as a base64url segment (no padding), like JOSE.
function seg(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

// A realistic-length signed token (first segment must be >= 16 base64url chars).
function signedToken(): string {
  return [seg({ alg: "ML-DSA-65", kid: "k1" }), seg({ sub: "user-1" }), "c2lnbmF0dXJl"].join(".");
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

test("looksLikePqJwt accepts a real signed/encrypted token", () => {
  assert.equal(looksLikePqJwt(signedToken()), true);
  const enc = [seg({ alg: "X-Wing", enc: "A256GCM", cty: "JWT" }), "encKey", "iv", "ct", "tag"].join(".");
  assert.equal(looksLikePqJwt(enc), true);
});

test("looksLikePqJwt rejects look-alikes (wrong alg, version strings, hashes)", () => {
  // Right shape, wrong alg — not our suite.
  assert.equal(looksLikePqJwt([seg({ alg: "RS256" }), seg({}), "sig"].join(".")), false);
  // Version string — first segment too short and header not JSON.
  assert.equal(looksLikePqJwt("1.0.0"), false);
  // A 4-segment base64url blob is not a 3/5-part token.
  assert.equal(looksLikePqJwt("aaaaaaaaaaaaaaaa.bbbb.cccc.dddd"), false);
});

test("findPqJwtTokens locates a token embedded in a line and reports its span", () => {
  const token = signedToken();
  const line = `    var jwt = "${token}";`;
  const found = findPqJwtTokens(line);
  assert.equal(found.length, 1);
  assert.equal(found[0].value, token);
  assert.equal(line.slice(found[0].start, found[0].end), token);
});

test("findPqJwtTokens ignores lines with no PostQuantum.Jwt token", () => {
  assert.equal(findPqJwtTokens('const version = "1.0.0-preview.5";').length, 0);
  assert.equal(findPqJwtTokens("just some prose with words.and.dots here").length, 0);
});

// --- Regression: bugs reported in bugsgeminifound.md ---

test("bug 2: a header that JSON-parses to null does not throw", () => {
  // base64url of '      null      ' decodes to a valid JSON null, >= 16 chars.
  const nullHeader = Buffer.from("      null      ").toString("base64url");
  const token = [nullHeader, seg({}), "sigsigsig"].join(".");
  assert.doesNotThrow(() => looksLikePqJwt(token));
  assert.equal(looksLikePqJwt(token), false);
  assert.doesNotThrow(() => findPqJwtTokens("var x = " + token));
  assert.equal(findPqJwtTokens("var x = " + token).length, 0);
  assert.doesNotThrow(() => decodeToken(token));
});

test("bug 3: a 3-part token followed by .word.word is still detected", () => {
  const token = signedToken();
  const found = findPqJwtTokens(token + ".word1.word2");
  assert.equal(found.length, 1);
  assert.equal(found[0].value, token); // trailing junk is not included
});

test("bug 4: surrounding quotes are stripped before decoding", () => {
  const out = decodeToken('"' + signedToken() + '"');
  assert.match(out, /Form: SIGNED/);
  assert.match(out, /kid = k1/);
  assert.doesNotMatch(out, /not valid base64url/);
});
