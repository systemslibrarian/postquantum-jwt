import assert from "node:assert/strict";
import * as vscode from "vscode";

const EXT_ID = "systemslibrarian.postquantum-jwt";

function seg(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

const SIGNED_TOKEN = [
  seg({ alg: "ML-DSA-65", kid: "k1" }),
  seg({ sub: "u1" }),
  "c2lnbmF0dXJl",
].join(".");

export interface IntegrationTest {
  name: string;
  fn: () => Promise<void>;
}

// Plain exported cases run by the tiny harness in ./suite/index.ts inside a real
// VS Code host. No mocha (its serialize-javascript dep has an unfixed advisory)
// and no node:test (it isolates files in subprocesses where `vscode` is absent).
export const tests: IntegrationTest[] = [
  {
    name: "activates and registers all contributed commands",
    fn: async () => {
      const ext = vscode.extensions.getExtension(EXT_ID);
      assert.ok(ext, `extension ${EXT_ID} should be present in the host`);
      await ext.activate();
      const commands = await vscode.commands.getCommands(true);
      for (const id of [
        "pqjwt.decodeToken",
        "pqjwt.inspectToken",
        "pqjwt.openPlayground",
        "pqjwt.openDocs",
        "pqjwt.openNuget",
        "pqjwt.openRepo",
        "pqjwt.generateKeyPair",
      ]) {
        assert.ok(commands.includes(id), `command ${id} should be registered`);
      }
    },
  },
  {
    name: "offers an Inspect CodeLens for an embedded token",
    fn: async () => {
      const doc = await vscode.workspace.openTextDocument({
        language: "csharp",
        content: `var jwt = "${SIGNED_TOKEN}";`,
      });
      await vscode.window.showTextDocument(doc);
      const lenses = await vscode.commands.executeCommand<vscode.CodeLens[]>(
        "vscode.executeCodeLensProvider",
        doc.uri
      );
      assert.ok(
        lenses?.some((l) => l.command?.command === "pqjwt.inspectToken"),
        "an Inspect PQ-JWT CodeLens should be present"
      );
    },
  },
  {
    name: "provides a hover for a known API symbol",
    fn: async () => {
      const doc = await vscode.workspace.openTextDocument({
        language: "csharp",
        content: "PqJwtValidator validator;",
      });
      await vscode.window.showTextDocument(doc);
      const hovers = await vscode.commands.executeCommand<vscode.Hover[]>(
        "vscode.executeHoverProvider",
        doc.uri,
        new vscode.Position(0, 2)
      );
      assert.ok(hovers && hovers.length > 0, "a hover should be returned");
    },
  },
  {
    name: "does NOT add an API docs CodeLens on a comment-only line (chatbug 5)",
    fn: async () => {
      const doc = await vscode.workspace.openTextDocument({
        language: "csharp",
        content: "// PqJwtValidator is the validator\nPqJwtValidator validator;",
      });
      await vscode.window.showTextDocument(doc);
      const lenses =
        (await vscode.commands.executeCommand<vscode.CodeLens[]>(
          "vscode.executeCodeLensProvider",
          doc.uri
        )) ?? [];
      // Identify the API-docs lens by its title (its command id resolves to an
      // internal handler), not by "vscode.open".
      const summary = lenses.map((l) => `${l.range.start.line}:${l.command?.title}`).join(", ");
      const docLensLines = lenses
        .filter((l) => l.command?.title?.includes("docs"))
        .map((l) => l.range.start.line);
      assert.ok(!docLensLines.includes(0), `no docs CodeLens on the comment line — got [${summary}]`);
      assert.ok(docLensLines.includes(1), `docs CodeLens on the real code line — got [${summary}]`);
    },
  },
  {
    name: "does NOT hover inherited Object members (bug 1 regression)",
    fn: async () => {
      const doc = await vscode.workspace.openTextDocument({
        language: "csharp",
        content: "constructor toString;",
      });
      await vscode.window.showTextDocument(doc);
      const hovers = await vscode.commands.executeCommand<vscode.Hover[]>(
        "vscode.executeHoverProvider",
        doc.uri,
        new vscode.Position(0, 2)
      );
      const ours = (hovers ?? []).filter((h) =>
        h.contents.some((c) => {
          const value = typeof c === "object" && "value" in c ? c.value : String(c);
          return value.includes("PostQuantum.Jwt");
        })
      );
      assert.equal(ours.length, 0, "no PostQuantum.Jwt hover for an inherited member");
    },
  },
];
