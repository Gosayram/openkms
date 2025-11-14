#!/usr/bin/env bash
# Copyright 2025 Gosayram Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Script to update Go dependencies and create a commit in Dependabot format
# Only commits go.mod and go.sum files

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo "Error: Not in a git repository" >&2
    exit 1
fi

# Check if there are uncommitted changes (excluding go.mod and go.sum)
if ! git diff --quiet --exit-code -- ':!go.mod' ':!go.sum' 2>/dev/null; then
    echo "Warning: You have uncommitted changes in files other than go.mod/go.sum"
    echo "The commit will only include go.mod and go.sum files"
    # Skip interactive prompt if CI environment or AUTO_YES is set
    if [ -z "${CI:-}" ] && [ -z "${AUTO_YES:-}" ]; then
        read -p "Continue? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        echo "Continuing automatically (CI/AUTO_YES mode)"
    fi
fi

# Create temporary files to store current state
TMPDIR=$(mktemp -d)
OLD_GO_MOD="${TMPDIR}/go.mod.old"
OLD_GO_SUM="${TMPDIR}/go.sum.old"

# Save current state
cp go.mod "${OLD_GO_MOD}" 2>/dev/null || touch "${OLD_GO_MOD}"
cp go.sum "${OLD_GO_SUM}" 2>/dev/null || touch "${OLD_GO_SUM}"

echo "Updating dependencies..."
go get -u ./...
go mod tidy

# Check if anything changed
if cmp -s go.mod "${OLD_GO_MOD}" && cmp -s go.sum "${OLD_GO_SUM}"; then
    echo "No dependency updates found"
    rm -rf "${TMPDIR}"
    exit 0
fi

# Analyze changes in go.mod
UPDATES=()
ADDITIONS=()
REMOVALS=()

# Get repository URL for links
REPO_URL=$(git remote get-url origin 2>/dev/null || echo "")
if [[ "${REPO_URL}" =~ ^git@ ]]; then
    REPO_URL=$(echo "${REPO_URL}" | sed -E 's|git@([^:]+):([^/]+)/(.+)\.git|https://\1/\2/\3|')
    REPO_URL=$(echo "${REPO_URL}" | sed -E 's|git@([^:]+):(.+)\.git|https://\1/\2|')
fi
REPO_URL="${REPO_URL%.git}"

# Parse go.mod to extract dependency changes
# Use go list -m to get accurate dependency information
if command -v go >/dev/null 2>&1; then
    # Get dependencies from new go.mod (current state)
    NEW_DEPS_FILE="${TMPDIR}/new_deps.txt"
    go list -m -f '{{.Path}} {{.Version}}' all 2>/dev/null | grep -v "^github.com/Gosayram/openkms" > "${NEW_DEPS_FILE}" || true
    
    # For old go.mod, we need to parse it directly since go list might not work with old module
    # Parse old go.mod file directly
    OLD_DEPS_MAP="${TMPDIR}/old_deps_map.txt"
    touch "${OLD_DEPS_MAP}"
    
    # Extract require statements from old go.mod
    in_require_block=0
    while IFS= read -r line; do
        # Check if we're entering a require block
        if [[ "$line" =~ ^require[[:space:]]*\( ]]; then
            in_require_block=1
            continue
        fi
        # Check if we're leaving a require block
        if [[ "$line" =~ ^\) ]]; then
            in_require_block=0
            continue
        fi
        # Check if it's a single-line require
        # Pattern: require module/path v1.2.3 or require module/path v1.2.3 // indirect
        if [[ "$line" =~ ^require[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)([[:space:]]|//) ]]; then
            module="${BASH_REMATCH[1]}"
            version="${BASH_REMATCH[2]}"
            echo "${module}|${version}" >> "${OLD_DEPS_MAP}"
        # Check if it's a line inside require block
        # Pattern: module/path v1.2.3 or module/path v1.2.3 // indirect
        elif [ $in_require_block -eq 1 ] && [[ "$line" =~ ^[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)([[:space:]]|//) ]]; then
            module="${BASH_REMATCH[1]}"
            version="${BASH_REMATCH[2]}"
            # Skip comments
            if [[ ! "$module" =~ ^// ]]; then
                echo "${module}|${version}" >> "${OLD_DEPS_MAP}"
            fi
        fi
    done < "${OLD_GO_MOD}"
    
    # Build map from new dependencies
    NEW_DEPS_MAP="${TMPDIR}/new_deps_map.txt"
    touch "${NEW_DEPS_MAP}"
    
    while IFS=' ' read -r module version; do
        if [ -n "$module" ] && [ -n "$version" ]; then
            echo "${module}|${version}" >> "${NEW_DEPS_MAP}"
        fi
    done < "${NEW_DEPS_FILE}"
    
    # Compare and find updates
    while IFS='|' read -r module new_version; do
        if [ -z "$module" ] || [ -z "$new_version" ]; then
            continue
        fi
        
        old_line=$(grep "^${module}|" "${OLD_DEPS_MAP}" 2>/dev/null | head -1 || echo "")
        if [ -n "$old_line" ]; then
            old_version=$(echo "$old_line" | cut -d'|' -f2)
            if [ "$old_version" != "$new_version" ]; then
                UPDATES+=("${module}|${old_version}|${new_version}")
            fi
        else
            # New dependency
            ADDITIONS+=("${module}|${new_version}")
        fi
    done < "${NEW_DEPS_MAP}"
    
    # Find removed dependencies
    while IFS='|' read -r module old_version; do
        if [ -z "$module" ]; then
            continue
        fi
        
        if ! grep -q "^${module}|" "${NEW_DEPS_MAP}" 2>/dev/null; then
            REMOVALS+=("${module}")
        fi
    done < "${OLD_DEPS_MAP}"
fi

# Function to format module link
format_module_link() {
    local module="$1"
    # Convert module path to GitHub URL if possible
    if [[ "$module" =~ ^github\.com/(.+)$ ]]; then
        local repo="${BASH_REMATCH[1]}"
        echo "[\`${module}\`](https://${repo})"
    elif [[ "$module" =~ ^golang\.org/x/(.+)$ ]]; then
        local pkg="${BASH_REMATCH[1]}"
        echo "[\`${module}\`](https://pkg.go.dev/${module})"
    else
        echo "\`${module}\`"
    fi
}

# Build commit message
COMMIT_MSG="chore(deps): update dependencies"

if [ ${#UPDATES[@]} -gt 0 ] || [ ${#ADDITIONS[@]} -gt 0 ] || [ ${#REMOVALS[@]} -gt 0 ]; then
    COMMIT_MSG="${COMMIT_MSG}\n\n"
    
    if [ ${#UPDATES[@]} -gt 0 ]; then
        COMMIT_MSG="${COMMIT_MSG}**Updated:**\n"
        for update in "${UPDATES[@]}"; do
            # Format: module|old_version|new_version
            IFS='|' read -r module old_ver new_ver <<< "$update"
            module_link=$(format_module_link "$module")
            COMMIT_MSG="${COMMIT_MSG}- ${module_link}: \`${old_ver}\` => \`${new_ver}\`\n"
        done
        COMMIT_MSG="${COMMIT_MSG}\n"
    fi
    
    if [ ${#ADDITIONS[@]} -gt 0 ]; then
        COMMIT_MSG="${COMMIT_MSG}**Added:**\n"
        for addition in "${ADDITIONS[@]}"; do
            # Format: module|version
            IFS='|' read -r module version <<< "$addition"
            module_link=$(format_module_link "$module")
            COMMIT_MSG="${COMMIT_MSG}- ${module_link}@\`${version}\`\n"
        done
        COMMIT_MSG="${COMMIT_MSG}\n"
    fi
    
    if [ ${#REMOVALS[@]} -gt 0 ]; then
        COMMIT_MSG="${COMMIT_MSG}**Removed:**\n"
        for removal in "${REMOVALS[@]}"; do
            module_link=$(format_module_link "$removal")
            COMMIT_MSG="${COMMIT_MSG}- ${module_link}\n"
        done
        COMMIT_MSG="${COMMIT_MSG}\n"
    fi
fi

# Clean up temp files
rm -rf "${TMPDIR}"

# Stage only go.mod and go.sum
git add go.mod go.sum

# Check if there are staged changes
if git diff --cached --quiet; then
    echo "No changes to commit"
    exit 0
fi

# Create commit
echo -e "${COMMIT_MSG}" | git commit -F -

echo "✅ Dependencies updated and committed"
echo ""
echo "Commit message:"
echo -e "${COMMIT_MSG}"

