#!/usr/bin/env bash
# Print the CHANGELOG section for a version, for use as GitHub release notes.
#
#   scripts/release_notes.sh <version> [changelog]     e.g. scripts/release_notes.sh 0.1.0
#
# Fails when the `## [<version>]` section is missing, empty, or still marked Unreleased, so a
# release can't go out without its notes (or with a placeholder date).
set -euo pipefail

[ "$#" -ge 1 ] || { echo "usage: $0 <version> [changelog]" >&2; exit 2; }
version="$1"
changelog="${2:-CHANGELOG.md}"

# First line that starts with `## [<version>]` (anchored, so `### [x]` or `## [x-rc1]` don't match).
heading="$(awk -v h="## [$version]" 'index($0, h) == 1 { print; exit }' "$changelog")"
[ -n "$heading" ] || { echo "no '## [$version]' section in $changelog" >&2; exit 1; }
case "$heading" in
    *[Uu]nreleased*) echo "$changelog: '$heading' is still Unreleased; set the release date" >&2; exit 1 ;;
esac

# Body: lines after the heading, up to the next `## ` heading.
body="$(awk -v h="$heading" '
    $0 == h { on = 1; next }
    on && /^## / { exit }
    on { print }
' "$changelog" | sed -e '/./,$!d')"
[ -n "$(printf '%s' "$body" | tr -d '[:space:]')" ] || { echo "'$heading' has no content" >&2; exit 1; }
printf '%s\n' "$body"
