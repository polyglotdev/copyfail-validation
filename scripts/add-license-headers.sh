#!/usr/bin/env bash
# add-license-headers.sh — sweep every Go source file under the module root
# and prepend the standard 2-line SPDX copyright + license header to any file
# that does not already start with it.
#
# This script is idempotent — re-running it does nothing on files that already
# carry the header. Vendor directories and build artifacts under ./dist are
# skipped.
#
# Usage:
#   ./scripts/add-license-headers.sh              # sweep ./
#   ROOT=./preset ./scripts/add-license-headers.sh  # sweep a subtree
#
# A companion CI check in .github/workflows/test.yml fails the build if any
# file is missing the header, so the script is a developer convenience rather
# than the source of truth for enforcement.

set -euo pipefail

ROOT="${ROOT:-.}"
HEADER_LINE_1='// Copyright 2026 Dom Hallan'
HEADER_LINE_2='// SPDX-License-Identifier: Apache-2.0'
MARKER='SPDX-License-Identifier: Apache-2.0'

added=0
skipped=0

while IFS= read -r -d '' file; do
    if head -2 "$file" | grep -q -F "$MARKER"; then
        skipped=$((skipped + 1))
        continue
    fi

    tmp=$(mktemp)
    {
        printf '%s\n' "$HEADER_LINE_1"
        printf '%s\n' "$HEADER_LINE_2"
        printf '\n'
        cat "$file"
    } >"$tmp"
    mv "$tmp" "$file"
    added=$((added + 1))
    printf 'added header: %s\n' "$file"
done < <(find "$ROOT" \
    -type f \
    -name '*.go' \
    -not -path '*/vendor/*' \
    -not -path '*/dist/*' \
    -print0)

printf '\nsummary: added=%d skipped=%d\n' "$added" "$skipped"
