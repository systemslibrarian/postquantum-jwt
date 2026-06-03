import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";

// Load the shipped snippets file (compiled tests live in out/, snippets in ../snippets).
const snippetsPath = path.resolve(__dirname, "../snippets/csharp.json");
const raw = fs.readFileSync(snippetsPath, "utf8");

test("snippets file is valid JSON", () => {
  assert.doesNotThrow(() => JSON.parse(raw));
});

test("ASP.NET snippets use the PostQuantum.AspNetCore identifiers (chatbugs 1 & 2)", () => {
  // The legacy PostQuantum.Jwt.AspNetCore names must not reappear in the snippets.
  assert.doesNotMatch(raw, /PqJwtBearerDefaults/, "use PostQuantumJwtBearerDefaults");
  assert.doesNotMatch(raw, /\bHttpPqJwtKeyRing\b/, "use HttpPostQuantumJwtKeyRing");
  // The correct successor-package names must be present.
  assert.match(raw, /PostQuantumJwtBearerDefaults\.AuthenticationScheme/);
  assert.match(raw, /HttpPostQuantumJwtKeyRing/);
});

test("the key-ring snippet imports its namespace (chatbug 2)", () => {
  const snippets = JSON.parse(raw) as Record<string, { prefix: string; body: string[] }>;
  const keyring = Object.values(snippets).find((s) => s.prefix === "pqjwt-keyring");
  assert.ok(keyring, "pqjwt-keyring snippet exists");
  assert.ok(
    keyring.body.some((line) => line.includes("using PostQuantum.AspNetCore;")),
    "key-ring snippet should bring in the PostQuantum.AspNetCore namespace"
  );
});
