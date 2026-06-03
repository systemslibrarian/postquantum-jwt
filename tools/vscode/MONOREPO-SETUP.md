# Adding the VS Code extension to the postquantum-jwt monorepo

## File placement

Two pieces go to two different places in the repo:

```
postquantum-jwt/                          (your existing repo root)
├─ .github/
│  └─ workflows/
│     └─ vscode-release.yml               ← from this bundle's .github/workflows/
├─ tools/
│  └─ vscode/                             ← everything ELSE from this bundle
│     ├─ package.json
│     ├─ tsconfig.json
│     ├─ README.md
│     ├─ .vscodeignore
│     ├─ .gitignore
│     ├─ images/icon.png
│     ├─ snippets/csharp.json
│     ├─ src/extension.ts
│     └─ .vscode/{launch.json,tasks.json}
└─ ... (your .NET library, samples, docs, etc. — untouched)
```

GitHub Actions only runs workflows from the **repo-root** `.github/workflows/`.
It cannot run a workflow stored in `tools/vscode/`. The `vscode-release.yml`
workflow is path/tag-scoped so it never interferes with your NuGet pipeline.

## One-time setup

```bash
cd path/to/postquantum-jwt          # your existing clone
mkdir -p tools/vscode

# copy the extension files in (everything except the .github folder)
# then move the workflow to the repo root:
#   tools/vscode/.github/workflows/vscode-release.yml  ->  .github/workflows/

git add tools/vscode .github/workflows/vscode-release.yml
git commit -m "Add VS Code companion extension (tools/vscode)"
git push
```

Add two repo secrets (Settings → Secrets and variables → Actions):
- `VSCE_PAT`   — your Azure DevOps Marketplace→Manage token (for VS Code Marketplace)
- `OVSX_PAT`   — an Open VSX token from https://open-vsx.org (optional)

Both publish steps are guarded by `if: env.X != ''`, so a missing secret just
skips that registry — the GitHub Release + .vsix attachment still happen.

## Releasing the extension

The extension versions independently from the library. Bump
`tools/vscode/package.json` "version", then:

```bash
git tag vscode-v0.1.0       # note the vscode- prefix; NOT v1.0.0 (that's NuGet)
git push origin vscode-v0.1.0
```

CI then: installs → compiles → packages the .vsix → publishes to Marketplace
and Open VSX (if secrets present) → creates a GitHub Release with the .vsix
attached.

## Local dev (unchanged by the move)

```bash
cd tools/vscode
npm install
code .            # F5 to launch the Extension Development Host
```

---

*To God be the glory — 1 Corinthians 10:31.*
