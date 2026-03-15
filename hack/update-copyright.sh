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
                # Remove duplicated Apache header blocks if present (keep a single block).
                perl -0777 -i -pe 's@\A// Copyright [0-9]{4} Gosayram Contributors\n//\n// Licensed under the Apache License, Version 2\.0 \(the "License"\);\n// you may not use this file except in compliance with the License\.\n// You may obtain a copy of the License at\n//\n//     http://www\.apache\.org/licenses/LICENSE-2\.0\n//\n// Unless required by applicable law or agreed to in writing, software\n// distributed under the License is distributed on an "AS IS" BASIS,\n// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied\.\n// See the License for the specific language governing permissions and\n// limitations under the License\.\n\n(?=// Copyright [0-9]{4} Gosayram Contributors\n)@@s' "$file"
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
