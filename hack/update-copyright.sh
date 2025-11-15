#!/bin/bash
# Update copyright year in all files

set -euo pipefail

CURRENT_YEAR=$(date +%Y)
OLD_COPYRIGHT="Copyright [0-9]\{4\} Gosayram Contributors"
NEW_COPYRIGHT="Copyright $CURRENT_YEAR Gosayram Contributors"
UPDATED=0

# Find all files that might have copyright
while IFS= read -r -d '' file; do
    # Check if file has copyright
    if grep -q "Copyright.*Gosayram" "$file" 2>/dev/null; then
        # Check if year needs updating
        if ! grep -q "$NEW_COPYRIGHT" "$file" 2>/dev/null; then
            # Update copyright year (handle both // and # comment styles)
            if [[ "$file" == *.go ]]; then
                # Go files use // comments
                sed -i.bak "s|// Copyright [0-9]\{4\} Gosayram|// Copyright $CURRENT_YEAR Gosayram|g" "$file"
            else
                # Other files use # comments
                sed -i.bak "s|# Copyright [0-9]\{4\} Gosayram|# Copyright $CURRENT_YEAR Gosayram|g" "$file"
            fi
            rm -f "${file}.bak"
            echo "✓ Updated copyright in $file"
            UPDATED=$((UPDATED + 1))
        fi
    fi
done < <(find . -type f \( -name "*.go" -o -name "*.sh" -o -name "*.yaml" -o -name "*.yml" -o -name "Dockerfile" -o -name "Makefile" \) \
    -not -path "./vendor/*" \
    -not -path "./.git/*" \
    -not -path "./hack/*" \
    -not -path "./bin/*" \
    -not -path "./logo/*" \
    -print0)

if [ $UPDATED -eq 0 ]; then
    echo "✓ All copyrights are up to date ($CURRENT_YEAR)"
else
    echo ""
    echo "✓ Updated $UPDATED files to copyright year $CURRENT_YEAR"
fi

