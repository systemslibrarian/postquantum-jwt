import { tests } from "../extension.itest";

// Entry point invoked by @vscode/test-electron inside the VS Code host.
// A minimal sequential runner — no test framework needed for four smoke checks.
export async function run(): Promise<void> {
  let failures = 0;
  for (const t of tests) {
    try {
      await t.fn();
      console.log(`  ✓ ${t.name}`);
    } catch (err) {
      failures += 1;
      console.error(`  ✗ ${t.name}`);
      console.error(err instanceof Error ? err.stack : String(err));
    }
  }
  console.log(`\n${tests.length - failures}/${tests.length} integration tests passed`);
  if (failures > 0) {
    throw new Error(`${failures} integration test(s) failed`);
  }
}
