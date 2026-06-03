import test from "node:test";
import assert from "node:assert/strict";
import { buildTokenModel } from "./model";

function seg(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}
function signed(payload: object, header: object = { alg: "ML-DSA-65", typ: "JWT", kid: "k1" }): string {
  return [seg(header), seg(payload), "c2lnbmF0dXJlLWJ5dGVz"].join(".");
}

test("signed token: form, segment count, badges, claims", () => {
  const m = buildTokenModel(signed({ sub: "user-1", iss: "iss", role: "admin" }));
  assert.equal(m.form, "signed");
  assert.equal(m.segmentCount, 3);
  assert.equal(m.encryptedPayload, false);
  assert.equal(m.segments.length, 3);
  assert.deepEqual(
    m.segments.map((s) => s.field),
    ["header", "payload", "signature"]
  );
  const alg = m.badges.find((b) => b.field === "alg");
  assert.equal(alg?.status, "ok");
  assert.ok(m.claims);
  const sub = m.claims!.find((c) => c.name === "sub");
  assert.equal(sub?.value, "user-1");
  assert.equal(sub?.reserved, true);
  assert.equal(m.claims!.find((c) => c.name === "role")?.reserved, false);
});

test("encrypted token: form, opaque payload, identifiers, segment names", () => {
  const token = [seg({ alg: "X-Wing", enc: "A256GCM", typ: "JWT", cty: "JWT" }), "encKey", "iv", "ct", "tag"].join(".");
  const m = buildTokenModel(token);
  assert.equal(m.form, "encrypted");
  assert.equal(m.segmentCount, 5);
  assert.equal(m.encryptedPayload, true);
  assert.equal(m.claims, undefined);
  assert.deepEqual(
    m.segments.map((s) => s.field),
    ["header", "kem_ct", "iv", "ciphertext", "tag"]
  );
  for (const f of ["alg", "enc", "cty"]) {
    assert.equal(m.badges.find((b) => b.field === f)?.status, "ok", f);
  }
});

test("alg=none is a hard 'bad' badge, not a warning", () => {
  const m = buildTokenModel(signed({ sub: "x" }, { alg: "none" }));
  const alg = m.badges.find((b) => b.field === "alg");
  assert.equal(alg?.status, "bad");
  assert.match(alg!.note, /no unsigned path/i);
  assert.equal(m.wellFormed, false);
});

test("unexpected signature alg is a 'warn' badge", () => {
  const m = buildTokenModel(signed({ sub: "x" }, { alg: "RS256" }));
  assert.equal(m.badges.find((b) => b.field === "alg")?.status, "warn");
});

test("wrong segment count yields unknown form with an error", () => {
  const m = buildTokenModel("a.b");
  assert.equal(m.form, "unknown");
  assert.equal(m.segmentCount, 2);
  assert.equal(m.segments.length, 0);
  assert.match(m.errors[0], /2 segment/);
});

test("empty input is reported, not thrown", () => {
  const m = buildTokenModel("   ");
  assert.equal(m.form, "unknown");
  assert.match(m.summary, /No token/);
});

test("fixed-size opaque segments warn when the byte length is off", () => {
  // iv expects 12 bytes; give it 3 bytes ("abc" decodes to 3 bytes via base64url).
  const ivThreeBytes = Buffer.from("abc").toString("base64url");
  const token = [seg({ alg: "X-Wing", enc: "A256GCM", cty: "JWT" }), "encKey", ivThreeBytes, "ct", "tag"].join(".");
  const m = buildTokenModel(token);
  assert.ok(m.warnings.some((w) => /Initialization vector/.test(w) && /expects 12/.test(w)));
});

test("byte lengths are reported for segments", () => {
  const m = buildTokenModel(signed({ sub: "x" }));
  assert.ok(m.segments[0].byteLength > 0);
  assert.equal(m.segments[2].field, "signature");
  assert.equal(m.segments[2].readable, false);
});

test("quote/Bearer wrapped input is cleaned before modelling", () => {
  const m = buildTokenModel('"Bearer ' + signed({ sub: "x" }) + '"');
  assert.equal(m.form, "signed");
});
