#!/bin/bash
# Check that all Go files have correct copyright header

set -euo pipefail

COPYRIGHT="Copyright 2025 Gosayram Contributors"
ERRORS=0

# Find all Go files and check copyright
while IFS= read -r -d '' file; do
    # Check if file has copyright
    if ! grep -q "Copyright.*Gosayram" "$file" 2>/dev/null; then
        echo "❌ Missing copyright in $file"
        ERRORS=$((ERRORS + 1))
    else
        # Check if copyright is correct
        if ! grep -q "$COPYRIGHT" "$file" 2>/dev/null; then
            echo "⚠️  Wrong copyright in $file"
            ERRORS=$((ERRORS + 1))
        fi
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

