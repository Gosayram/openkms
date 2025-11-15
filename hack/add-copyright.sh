#!/bin/bash
# Add or update copyright header in Go files

set -euo pipefail

COPYRIGHT="Copyright 2025 Gosayram Contributors"

# Go file copyright header (using // comments)
GO_HEADER="// Copyright 2025 Gosayram Contributors
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

# Find all Go files
find . -name "*.go" -not -path "./vendor/*" -not -path "./.git/*" -not -path "./hack/*" -not -path "./logo/*" | while read -r file; do
    # Check if file already has correct copyright
    if grep -q "$COPYRIGHT" "$file" 2>/dev/null; then
        echo "✓ $file (already has correct copyright)"
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

