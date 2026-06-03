// Shared external links and the docs-anchor helper. No vscode dependency, so
// this module is safe to import from pure (testable) code.
export const LINKS = {
  playground: "https://pqjwt.systemslibrarian.dev",
  docs: "https://github.com/systemslibrarian/postquantum-jwt#readme",
  nuget: "https://www.nuget.org/packages/PostQuantum.Jwt",
  repo: "https://github.com/systemslibrarian/postquantum-jwt",
} as const;

// Base docs URL without the README fragment, plus a helper to anchor into it.
export const DOCS_BASE = LINKS.docs.replace("#readme", "");
export const docUrl = (anchor: string): string => `${DOCS_BASE}${anchor}`;
