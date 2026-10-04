#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN=${SPARKBRIDGE_BIN:-"$ROOT/target/release/sparkbridge"}
[[ -x "$BIN" ]] || { echo "SKIP: build sparkbridge CLI first" >&2; exit 77; }
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/source/state" "$TMP/source/config"
printf 'alpha\n' > "$TMP/source/state/state.txt"
printf 'beta\n' > "$TMP/source/config/server.toml"
if [[ "$(uname -s)" != MINGW* && "$(uname -s)" != CYGWIN* ]]; then chmod 600 "$TMP/source/config/server.toml"; fi
"$BIN" backup create --root "$TMP/source" --output "$TMP/backup" --include state --include config >/dev/null
"$BIN" backup verify --backup "$TMP/backup" >/dev/null
"$BIN" backup restore --backup "$TMP/backup" --target "$TMP/restored" >/dev/null
cmp "$TMP/source/state/state.txt" "$TMP/restored/state/state.txt"
cmp "$TMP/source/config/server.toml" "$TMP/restored/config/server.toml"
if command -v stat >/dev/null 2>&1 && [[ "$(uname -s)" != MINGW* && "$(uname -s)" != CYGWIN* ]]; then
  if stat -c '%a' "$TMP/restored/config/server.toml" >/dev/null 2>&1; then
    [[ "$(stat -c '%a' "$TMP/restored/config/server.toml")" == "600" ]]
  elif stat -f '%Lp' "$TMP/restored/config/server.toml" >/dev/null 2>&1; then
    [[ "$(stat -f '%Lp' "$TMP/restored/config/server.toml")" == "600" ]]
  fi
fi
# Corruption must be detected rather than restored silently.
cp -a "$TMP/backup" "$TMP/corrupt"
first_file=$(find "$TMP/corrupt" -type f ! -name manifest.json | head -n 1 || true)
if [[ -n "$first_file" ]]; then
  printf 'corruption\n' >> "$first_file"
  if "$BIN" backup verify --backup "$TMP/corrupt" >/dev/null 2>&1; then
    echo "FAIL: corrupted backup verified successfully" >&2
    exit 1
  fi
fi
echo "PASS backup/restore integrity + mode drill"
