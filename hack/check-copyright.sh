#!/bin/bash
# Check that all Go files have correct copyright header

set -euo pipefail

COPYRIGHT_REGEX="Copyright [0-9]{4} Gosayram Contributors"
ERRORS=0

has_full_go_header() {
    local file="$1"
    local header
    header=$(head -n 20 "$file" 2>/dev/null || true)

    echo "$header" | grep -Eq "^// ${COPYRIGHT_REGEX}$" &&
        echo "$header" | grep -q "Licensed under the Apache License, Version 2.0" &&
        echo "$header" | grep -q "http://www.apache.org/licenses/LICENSE-2.0"
}

# Find all Go files and check copyright
while IFS= read -r -d '' file; do
    if ! has_full_go_header "$file"; then
        echo "❌ Missing or incomplete copyright header in $file"
        ERRORS=$((ERRORS + 1))
    fi
done < <(find . -name "*.go" -not -path "./vendor/*" -not -path "./.git/*" -not -path "./hack/*" -not -path "./logo/*" -print0)

if [ $ERRORS -eq 0 ]; then
    echo "✅ All files have correct copyright"
    exit 0
else
    echo ""
    echo "❌ Found $ERRORS files with missing or incorrect copyright"
    exit 1
fi
