#!/usr/bin/env bash
# Verifies that the package version is in sync across all the places it lives.
# Fails fast in CI if csproj / README / CHANGELOG drift apart.
#
# Sources of truth (in priority order):
#   1. <Version> in src/PostQuantum.Jwt/PostQuantum.Jwt.csproj
#   2. README install snippet: "dotnet add package PostQuantum.Jwt --version X"
#   3. README PackageReference: <PackageReference Include="..." Version="X" />
#   4. CHANGELOG.md heading: ## [X] — YYYY-MM-DD
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
csproj=$repo_root/src/PostQuantum.Jwt/PostQuantum.Jwt.csproj
readme=$repo_root/README.md
changelog=$repo_root/CHANGELOG.md

csproj_version=$(grep -oE '<Version>[^<]+</Version>' "$csproj" | head -1 | sed -E 's|</?Version>||g')
if [[ -z $csproj_version ]]; then
  echo "::error::Could not parse <Version> from $csproj"
  exit 1
fi
echo "csproj version:    $csproj_version"

errors=0

readme_install=$(grep -oE -- '--version [0-9A-Za-z.\-]+' "$readme" | head -1 | awk '{print $2}')
if [[ -z $readme_install ]]; then
  echo "::error::README is missing 'dotnet add package ... --version X' line"
  errors=$((errors + 1))
elif [[ $readme_install != "$csproj_version" ]]; then
  echo "::error::README install snippet version ($readme_install) does not match csproj ($csproj_version)"
  errors=$((errors + 1))
else
  echo "README install:    $readme_install OK"
fi

readme_pkgref=$(grep -oE 'PackageReference Include="PostQuantum\.Jwt" Version="[^"]+"' "$readme" | head -1 | sed -E 's|.*Version="([^"]+)".*|\1|')
if [[ -z $readme_pkgref ]]; then
  echo "::warning::README does not show a <PackageReference> snippet — skipping that check"
elif [[ $readme_pkgref != "$csproj_version" ]]; then
  echo "::error::README PackageReference version ($readme_pkgref) does not match csproj ($csproj_version)"
  errors=$((errors + 1))
else
  echo "README PackageRef: $readme_pkgref OK"
fi

# CHANGELOG must contain a heading for the current csproj version (and not as
# part of [Unreleased]).
if ! grep -qE "^## \[$csproj_version\]" "$changelog"; then
  echo "::error::CHANGELOG.md has no '## [$csproj_version]' section"
  errors=$((errors + 1))
else
  echo "CHANGELOG entry:   $csproj_version OK"
fi

# The dotnet-new template package, and the PostQuantum.Jwt* PackageReferences in
# the scaffolded template content, reference the PUBLISHED library version. Keep
# them in lockstep so `dotnet new pqjwt-*` never scaffolds against a stale version.
templates_csproj=$repo_root/templates/PostQuantum.Jwt.Templates.csproj
if [[ -f $templates_csproj ]]; then
  tpl_version=$(grep -oE '<Version>[^<]+</Version>' "$templates_csproj" | head -1 | sed -E 's|</?Version>||g')
  if [[ $tpl_version != "$csproj_version" ]]; then
    echo "::error::Templates package version ($tpl_version) does not match csproj ($csproj_version)"
    errors=$((errors + 1))
  else
    echo "Templates package: $tpl_version OK"
  fi

  ref_mismatch=0
  while IFS= read -r ref_version; do
    [[ -z $ref_version ]] && continue
    if [[ $ref_version != "$csproj_version" ]]; then
      echo "::error::Template content has a PostQuantum.Jwt PackageReference at $ref_version, expected $csproj_version"
      ref_mismatch=$((ref_mismatch + 1))
    fi
  done < <(grep -rhoE 'PackageReference Include="PostQuantum\.Jwt[^"]*" Version="[^"]+"' "$repo_root/templates/content" \
             | sed -E 's|.*Version="([^"]+)".*|\1|')
  if [[ $ref_mismatch -gt 0 ]]; then
    errors=$((errors + ref_mismatch))
  else
    echo "Template content refs: all PostQuantum.Jwt references at $csproj_version OK"
  fi
fi

# The analyzer companion package ships in lockstep with the library.
analyzers_csproj=$repo_root/src/Analyzers/PostQuantum.Jwt.Analyzers/PostQuantum.Jwt.Analyzers.csproj
if [[ -f $analyzers_csproj ]]; then
  analyzers_version=$(grep -oE '<Version>[^<]+</Version>' "$analyzers_csproj" | head -1 | sed -E 's|</?Version>||g')
  if [[ $analyzers_version != "$csproj_version" ]]; then
    echo "::error::Analyzers package version ($analyzers_version) does not match csproj ($csproj_version)"
    errors=$((errors + 1))
  else
    echo "Analyzers package: $analyzers_version OK"
  fi
fi

if [[ $errors -gt 0 ]]; then
  echo "::error::version-sync check failed with $errors error(s)"
  exit 1
fi

echo "All version strings are in sync at $csproj_version."
