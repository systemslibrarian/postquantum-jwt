#!/usr/bin/env bash
# Build, instrument, and run the SharpFuzz coverage-guided fuzz target.
# Prereqs (one-time): clang, `dotnet tool install --global SharpFuzz.CommandLine`,
# and a built `libfuzzer-dotnet` driver (see PostQuantum.Jwt.Fuzz/README.md).
#
# Usage:
#   LD_LIBRARY_PATH=/opt/conda/lib  fuzz/run.sh  [/path/to/libfuzzer-dotnet]
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
out="$repo_root/fuzz/bin"
driver="${1:-libfuzzer-dotnet}"
corpus="$repo_root/fuzz/corpus"

if ! command -v sharpfuzz >/dev/null 2>&1; then
  echo "error: 'sharpfuzz' not found. Run: dotnet tool install --global SharpFuzz.CommandLine" >&2
  exit 1
fi
if ! command -v "$driver" >/dev/null 2>&1 && [[ ! -x "$driver" ]]; then
  echo "error: libfuzzer-dotnet driver '$driver' not found (build it with clang; see README.md)." >&2
  exit 1
fi

echo "==> publish"
dotnet publish "$repo_root/fuzz/PostQuantum.Jwt.Fuzz" -c Release -o "$out"

echo "==> instrument PostQuantum.Jwt.dll"
sharpfuzz "$out/PostQuantum.Jwt.dll"

echo "==> fuzz (Ctrl-C to stop; crashes are written as crash-* files)"
"$driver" --target_path="$out/PostQuantum.Jwt.Fuzz" "$corpus" -timeout=10 -rss_limit_mb=4096
