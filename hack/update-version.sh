#!/bin/bash
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

# Script to update .release-version based on the current phase in .arch-plan-docs.md
#
# Usage:
#   ./update-version.sh [phase_number]
#
#   If phase_number is provided, updates version for that specific phase.
#   If not provided, finds the phase that matches the current version in .release-version,
#   or uses Phase 2 as default.
#
# Version mapping:
#   Phase 0: Project Foundation (no version)
#   Phase 1: MVP (v0.1) -> 0.1.0
#   Phase 2: Enhanced Features (v0.2) -> 0.2.0
#   Phase 3: Production Features (v0.3) -> 0.3.0
#   Phase 4: Stable Release (v1.0) -> 1.0.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ARCH_PLAN="${REPO_ROOT}/.arch-plan-docs.md"
VERSION_FILE="${REPO_ROOT}/.release-version"

if [ ! -f "${ARCH_PLAN}" ]; then
    echo "Error: .arch-plan-docs.md not found at ${ARCH_PLAN}" >&2
    exit 1
fi

# Extract phase and version from arch plan
# If phase number is provided as argument, use it
if [ $# -ge 1 ]; then
    PHASE_NUM_ARG="$1"
    PHASE_LINE=$(grep -E "^## Phase ${PHASE_NUM_ARG}:" "${ARCH_PLAN}")
    if [ -z "${PHASE_LINE}" ]; then
        echo "Error: Phase ${PHASE_NUM_ARG} not found in ${ARCH_PLAN}" >&2
        exit 1
    fi
else
    # Try to determine phase from current version in .release-version
    if [ -f "${VERSION_FILE}" ]; then
        CURRENT_VERSION=$(cat "${VERSION_FILE}" | tr -d '[:space:]')
        # Extract major.minor from version (e.g., "0.2.0" -> "0.2")
        VERSION_MAJOR_MINOR=$(echo "${CURRENT_VERSION}" | cut -d. -f1-2)
        
        # Find phase that matches this version
        # Phase 1: v0.1 -> 0.1.x, Phase 2: v0.2 -> 0.2.x, Phase 3: v0.3 -> 0.3.x, Phase 4: v1.0 -> 1.0.x
        if [ "${VERSION_MAJOR_MINOR}" = "1.0" ]; then
            PHASE_LINE=$(grep -E "^## Phase 4:" "${ARCH_PLAN}")
        elif [ "${VERSION_MAJOR_MINOR}" = "0.3" ]; then
            PHASE_LINE=$(grep -E "^## Phase 3:" "${ARCH_PLAN}")
        elif [ "${VERSION_MAJOR_MINOR}" = "0.2" ]; then
            PHASE_LINE=$(grep -E "^## Phase 2:" "${ARCH_PLAN}")
        elif [ "${VERSION_MAJOR_MINOR}" = "0.1" ]; then
            PHASE_LINE=$(grep -E "^## Phase 1:" "${ARCH_PLAN}")
        else
            # Default to Phase 2 if version doesn't match any phase
            PHASE_LINE=$(grep -E "^## Phase 2:" "${ARCH_PLAN}")
        fi
    else
        # If .release-version doesn't exist, default to Phase 2
        PHASE_LINE=$(grep -E "^## Phase 2:" "${ARCH_PLAN}")
    fi
fi
if [ -z "${PHASE_LINE}" ]; then
    echo "Error: Could not find phase information in ${ARCH_PLAN}" >&2
    exit 1
fi

# Extract version from phase line (e.g., "Phase 2: Enhanced Features (v0.2)" -> "0.2", "Phase 4: Stable Release (v1.0)" -> "1.0")
# Match pattern: (vX.Y) or (vX.Y.Z)
# Extract text between (v and )
VERSION_TEMP=$(echo "${PHASE_LINE}" | sed -n 's/.*(v\([^)]*\)).*/\1/p')
# Remove leading/trailing whitespace
VERSION=$(echo "${VERSION_TEMP}" | xargs)

if [ -z "${VERSION}" ]; then
    echo "Error: Could not extract version from phase line: ${PHASE_LINE}" >&2
    exit 1
fi

# Convert version to full format (e.g., "0.2" -> "0.2.0")
# If version already has patch version, keep it; otherwise add .0
if [[ "${VERSION}" =~ ^[0-9]+\.[0-9]+$ ]]; then
    FULL_VERSION="${VERSION}.0"
elif [[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    FULL_VERSION="${VERSION}"
else
    echo "Error: Invalid version format: ${VERSION}" >&2
    exit 1
fi

# Extract phase number and name
# Extract phase number using cut (text between "Phase " and ":")
PHASE_NUM=$(echo "${PHASE_LINE}" | cut -d' ' -f3 | cut -d: -f1)
# Extract phase name (text between ": " and " (v")
# Use cut to extract text after ": " and before " ("
PHASE_NAME=$(echo "${PHASE_LINE}" | cut -d: -f2- | cut -d'(' -f1 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

# Update version file
echo "${FULL_VERSION}" > "${VERSION_FILE}"

echo "Updated .release-version to ${FULL_VERSION} (Phase ${PHASE_NUM}: ${PHASE_NAME})"
echo "Version file: ${VERSION_FILE}"

