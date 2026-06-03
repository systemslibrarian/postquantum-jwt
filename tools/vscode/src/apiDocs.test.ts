import test from "node:test";
import assert from "node:assert/strict";
import { lookupApiDoc, API_DOCS } from "./apiDocs";

test("lookupApiDoc resolves real API symbols", () => {
  const entry = lookupApiDoc("PqJwtValidator");
  assert.ok(entry);
  assert.equal(entry.anchor, API_DOCS["PqJwtValidator"].anchor);
  assert.ok(entry.blurb.length > 0);
});

test("bug 1: inherited Object properties never resolve to an entry", () => {
  for (const word of ["constructor", "toString", "hasOwnProperty", "valueOf", "__proto__"]) {
    assert.equal(lookupApiDoc(word), undefined, `${word} should not resolve`);
  }
});

test("lookupApiDoc returns undefined for unknown words", () => {
  assert.equal(lookupApiDoc("SomeRandomType"), undefined);
});
