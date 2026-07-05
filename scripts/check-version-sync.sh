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

# The dotnet-new template package, and the PostQuantum.Jwt PackageReferences in
# the scaffolded template content, reference the PUBLISHED library version. Keep
# them in lockstep so `dotnet new pqjwt-*` never scaffolds against a stale version.
#
# Two AspNetCore-related rules on top of that:
#   * PostQuantum.Jwt.AspNetCore is retired (frozen at 1.0.0, deprecated and
#     unlisted on nuget.org). Templates must NOT reference it at all.
#   * Its successor PostQuantum.AspNetCore lives in its own repo and releases
#     on its own cadence, so its version cannot track this repo's — instead it
#     is pinned here and in the template csproj; bump both together when the
#     successor releases (check https://www.nuget.org/packages/PostQuantum.AspNetCore).
expected_pq_aspnetcore_version="1.0.0"
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
  done < <(grep -rhoE 'PackageReference Include="PostQuantum\.Jwt" Version="[^"]+"' "$repo_root/templates/content" \
             | sed -E 's|.*Version="([^"]+)".*|\1|')
  if [[ $ref_mismatch -gt 0 ]]; then
    errors=$((errors + ref_mismatch))
  else
    echo "Template content refs: all PostQuantum.Jwt references at $csproj_version OK"
  fi

  retired_refs=$(grep -rlE 'PackageReference Include="PostQuantum\.Jwt\.AspNetCore"' "$repo_root/templates/content" || true)
  if [[ -n $retired_refs ]]; then
    echo "::error::Template content references the retired PostQuantum.Jwt.AspNetCore (frozen at 1.0.0, unlisted). Use PostQuantum.AspNetCore instead. Found in:"
    echo "$retired_refs"
    errors=$((errors + 1))
  else
    echo "Template content refs: no references to retired PostQuantum.Jwt.AspNetCore OK"
  fi

  successor_mismatch=0
  successor_found=0
  while IFS= read -r ref_version; do
    [[ -z $ref_version ]] && continue
    successor_found=$((successor_found + 1))
    if [[ $ref_version != "$expected_pq_aspnetcore_version" ]]; then
      echo "::error::Template content references PostQuantum.AspNetCore at $ref_version, expected the pinned $expected_pq_aspnetcore_version (update expected_pq_aspnetcore_version here if the successor released)"
      successor_mismatch=$((successor_mismatch + 1))
    fi
  done < <(grep -rhoE 'PackageReference Include="PostQuantum\.AspNetCore" Version="[^"]+"' "$repo_root/templates/content" \
             | sed -E 's|.*Version="([^"]+)".*|\1|')
  if [[ $successor_found -eq 0 ]]; then
    echo "::error::Template content has no PostQuantum.AspNetCore reference — pqjwt-webapi should scaffold the successor authentication package"
    errors=$((errors + 1))
  elif [[ $successor_mismatch -gt 0 ]]; then
    errors=$((errors + successor_mismatch))
  else
    echo "Template content refs: PostQuantum.AspNetCore pinned at $expected_pq_aspnetcore_version OK"
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
