#!/bin/bash
# Add or update copyright header in Go files

set -euo pipefail

CURRENT_YEAR=$(date +%Y)
COPYRIGHT_REGEX="Copyright [0-9]{4} Gosayram Contributors"

# Go file copyright header (using // comments)
GO_HEADER="// Copyright ${CURRENT_YEAR} Gosayram Contributors
//
// Licensed under the Apache License, Version 2.0 (the \"License\");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an \"AS IS\" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License."

has_full_go_header() {
    local file="$1"
    local header
    header=$(head -n 20 "$file" 2>/dev/null || true)

    echo "$header" | grep -Eq "^// ${COPYRIGHT_REGEX}$" &&
        echo "$header" | grep -q "Licensed under the Apache License, Version 2.0" &&
        echo "$header" | grep -q "http://www.apache.org/licenses/LICENSE-2.0"
}

# Find all Go files
find . -name "*.go" -not -path "./vendor/*" -not -path "./.git/*" -not -path "./hack/*" -not -path "./logo/*" | while read -r file; do
    # Skip files that already have a complete Apache header block.
    if has_full_go_header "$file"; then
        echo "✓ $file (already has full copyright header)"
        continue
    fi

    # If a project copyright line exists but full header is missing,
    # do not prepend another block to avoid duplicates.
    if grep -Eq "^// ${COPYRIGHT_REGEX}$" "$file" 2>/dev/null; then
        echo "⚠️  $file has project copyright line but incomplete header (skipped to avoid duplicate)"
        continue
    fi

    # Check if file has package declaration
    if ! grep -q "^package " "$file" 2>/dev/null; then
        echo "⊘ Skipping $file (no package declaration)"
        continue
    fi

    # Add copyright before package declaration
    tmpfile=$(mktemp)
    echo "$GO_HEADER" > "$tmpfile"
    echo "" >> "$tmpfile"
    cat "$file" >> "$tmpfile"
    mv "$tmpfile" "$file"
    echo "✓ Added copyright to $file"
done

echo ""
echo "Copyright headers check completed"
