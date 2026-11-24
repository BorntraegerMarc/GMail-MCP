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
#
# Usage: scripts/verify-no-plaintext-secrets.sh [folder ...]
#   With folders, only those are scanned; without, the four places above.
# Exit status: 0 nothing found, 1 something found, 2 could not run.

set -u

# Bytes, not characters: in a UTF-8 locale grep treats a file with one stray byte as binary and
# skips it, which would hide a secret in an otherwise plain text file.
export LC_ALL=C

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  sed -n '3,15p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
fi

script_dir="$(cd "$(dirname "$0")" && pwd -P)" || exit 2
project="$(dirname "$script_dir")"

if [ "$#" -gt 0 ]; then
  folders=("$@")
else
  folders=("$project" "${HOME:-/nonexistent}/.config" "${TMPDIR:-/tmp}" "${HOME:-/nonexistent}/Downloads")
fi

# What Google issues: a client secret (GOCSPX-...), a refresh token (1//...), an access token
# (ya29....) and a client id (...apps.googleusercontent.com). The length minimums keep prose
# that merely mentions a prefix from matching.
content='(GOCSPX-[A-Za-z0-9_-]{20,}|1//[A-Za-z0-9_-]{40,}|ya29\.[A-Za-z0-9_-]{40,}|[0-9]{6,}-[a-z0-9]{10,}\.apps\.googleusercontent\.com)'

found=0

# Skips what is not worth reading: `.git` and `target` folders inside the scanned folder, files
# over 1 MiB (tokens are short) and, through grep -I, binary files. `-mindepth 1` keeps the
# scanned folder itself out of the tests, so one that is called "target" or sits below a folder
# of that name is still read; `-H` follows a symbolic link that was named on the command line
# (a dotfiles setup often links ~/.config), and links found inside are not followed.
for folder in "${folders[@]}"; do
  if [ ! -d "$folder" ]; then
    continue
  fi
  while IFS= read -r path; do
    printf 'FOUND (file name of a Google OAuth download or token file): %s\n' "$path"
    found=1
  done < <(find -H "$folder" -mindepth 1 \
    \( -type d \( -name .git -o -name target \) -prune \) -o \
    \( -type f \( -name 'client_secret*.json' -o -name 'credentials.json' -o -name 'token.json' -o -name 'tokens.json' \) -print \) 2>/dev/null)
  while IFS= read -r path; do
    printf 'FOUND (text that looks like a Google OAuth secret): %s\n' "$path"
    found=1
  done < <(find -H "$folder" -mindepth 1 \
    \( -type d \( -name .git -o -name target \) -prune \) -o \
    \( -type f -size -1025k -exec grep -lIE "$content" {} + \) 2>/dev/null)
done

if [ "$found" -eq 0 ]; then
  echo "Nothing found in: ${folders[*]}"
  exit 0
fi

echo "Review the files above. Delete the ones you do not need, starting with a downloaded"
echo "client secret file: gmail-mcp auth has already copied what it needs to the credential store."
exit 1
