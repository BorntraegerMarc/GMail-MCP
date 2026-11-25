#!/usr/bin/env bash
#
# Looks for plaintext copies of Google OAuth secrets in the places where one could be left
# behind: this project, ~/.config, the temporary folder and ~/Downloads (where Google's client
# secret file lands). Run it after `gmail-mcp auth`, and once more after you delete the client
# secret file, to see that nothing but the Keychain holds your credentials.
# Why: docs/decisions/0006-credentials-in-os-credential-store.md
#
# It prints the PATHS of suspicious files and never what is inside them.
# Other tools keep their own Google tokens (the Google Cloud CLI does, under ~/.config), so a
# hit is a reason to look, not proof that gmail-mcp left it.
# It never reports "nothing found" for a place it could not read: that is an error.
#
# Usage: scripts/verify-no-plaintext-secrets.sh [folder ...]
#   With folders, only those are scanned (a name that is not a folder is an error); without,
#   the four places above, and one that does not exist is skipped.
# Exit status: 0 nothing found and everything read, 1 something found,
#              2 could not run, or could not read everything.

set -u

# Bytes, not characters: in a UTF-8 locale grep treats a file with one stray byte as binary and
# skips it, which would hide a secret in an otherwise plain text file.
export LC_ALL=C

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  sed -n '3,18p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
fi

for tool in find grep mktemp; do
  if ! command -v "$tool" > /dev/null 2>&1; then
    echo "Cannot run: $tool is not installed or not on the PATH."
    exit 2
  fi
done

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)" || exit 2
project="$(dirname "$script_dir")"

if [ "$#" -gt 0 ]; then
  explicit=1
  folders=("$@")
else
  explicit=0
  folders=("$project" "${HOME:-/nonexistent}/.config" "${TMPDIR:-/tmp}" "${HOME:-/nonexistent}/Downloads")
fi

# What Google issues: a client secret (GOCSPX-...), a refresh token (1//...), an access token
# (ya29....) and a client id (...apps.googleusercontent.com). The length minimums keep prose
# that merely mentions a prefix from matching.
content='(GOCSPX-[A-Za-z0-9_-]{20,}|1//[A-Za-z0-9_-]{40,}|ya29\.[A-Za-z0-9_-]{40,}|[0-9]{6,}-[a-z0-9]{10,}\.apps\.googleusercontent\.com)'

# Error messages of find and grep (paths and reasons, never file contents) are collected here
# so that a place that could not be read is reported, not silently counted as clean.
errors="$(mktemp)" || exit 2
trap 'rm -f "$errors"' EXIT

found=0
unread=0
scanned=()

# Skips what is not worth reading: `.git` and `target` folders inside the scanned folder, files
# over 1 MiB (tokens are short) and, through grep -I, binary files. `-mindepth 1` keeps the
# scanned folder itself out of the tests, so one that is called "target" or sits below a folder
# of that name is still read; `-H` follows a symbolic link that was named on the command line
# (a dotfiles setup often links ~/.config), and links found inside are not followed.
for folder in "${folders[@]}"; do
  if [ ! -d "$folder" ]; then
    if [ "$explicit" -eq 1 ]; then
      echo "CANNOT SCAN (not a folder): $folder"
      unread=1
    else
      echo "Skipped (not there): $folder"
    fi
    continue
  fi
  scanned+=("$folder")
  : > "$errors"
  while IFS= read -r path; do
    printf 'FOUND (file name of a Google OAuth download or token file): %s\n' "$path"
    found=1
  done < <(find -H "$folder" -mindepth 1 \
    \( -type d \( -name .git -o -name target \) -prune \) -o \
    \( -type f \( -name 'client_secret*.json' -o -name 'credentials.json' -o -name 'token.json' -o -name 'tokens.json' \) -print \) 2>> "$errors")
  while IFS= read -r path; do
    printf 'FOUND (text that looks like a Google OAuth secret): %s\n' "$path"
    found=1
  done < <(find -H "$folder" -mindepth 1 \
    \( -type d \( -name .git -o -name target \) -prune \) -o \
    \( -type f -size -1025k -exec grep -lIE "$content" {} + \) 2>> "$errors")
  if [ -s "$errors" ]; then
    echo "COULD NOT READ PART OF: $folder"
    head -n 5 "$errors" | sed 's/^/    /'
    unread=1
  fi
done

if [ "$found" -ne 0 ]; then
  echo "Review the files above. Delete the ones you do not need, starting with a downloaded"
  echo "client secret file: gmail-mcp auth has already copied what it needs to the credential store."
  echo "A file deleted in Finder is in the Trash, which this script does not read: empty it."
  if [ "$unread" -ne 0 ]; then
    echo "Some places could not be read (see above), so this list may be incomplete."
  fi
  exit 1
fi

if [ "$unread" -ne 0 ]; then
  echo "Nothing found in what could be read, but not everything could be read (see above)."
  echo "That is not a clean result: fix the problem and run the script again."
  exit 2
fi

echo "Nothing found in: ${scanned[*]:-no folder}"
exit 0
