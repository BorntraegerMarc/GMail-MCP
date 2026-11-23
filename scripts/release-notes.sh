#!/usr/bin/env bash
# Print the CHANGELOG.md section for one version, without its heading.
# Fails (non-zero) if the section is missing or empty, so a release cannot ship
# without release notes.
#
# Usage: scripts/release-notes.sh <version> [changelog-file]
set -euo pipefail

version="${1:?usage: release-notes.sh <version> [changelog-file]}"
file="${2:-CHANGELOG.md}"

notes="$(awk -v v="$version" '
  BEGIN { gsub(/\./, "\\.", v) }
  $0 ~ ("^## \\[" v "\\]") { found = 1; next }
  found && /^## \[/ { exit }
  found { print }
' "$file")"

if [ -z "$(printf '%s' "$notes" | tr -d '[:space:]')" ]; then
  echo "no CHANGELOG section (or it is empty) for version $version in $file" >&2
  exit 1
fi

printf '%s\n' "$notes"
