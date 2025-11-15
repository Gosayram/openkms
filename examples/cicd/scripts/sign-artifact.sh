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

# Script for signing artifacts using OpenKMS CLI
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function for error output
error() {
    echo -e "${RED}Error:${NC} $1" >&2
    exit 1
}

# Function for info output
info() {
    echo -e "${GREEN}Info:${NC} $1"
}

# Function for warning output
warn() {
    echo -e "${YELLOW}Warning:${NC} $1"
}

# Function for help output
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Signs artifacts using OpenKMS.

OPTIONS:
    -k, --key-id KEY_ID          Key ID for signing (required)
    -f, --file FILE              File to sign (required)
    -u, --url URL                OpenKMS server URL (required)
    -t, --token TOKEN            Authentication token (required)
    -o, --output OUTPUT          Output signature file (default: FILE.sig)
    -c, --cli-path PATH          Path to OpenKMS CLI (default: openkms-cli)
    -h, --help                   Show this help

EXAMPLES:
    # Sign a file
    $0 --key-id signing-key --file artifact.tar.gz --url https://openkms.example.com --token YOUR_TOKEN

    # Sign a file with output file specified
    $0 -k signing-key -f artifact.tar.gz -u https://openkms.example.com -t YOUR_TOKEN -o artifact.sig

    # Use environment variables
    export OPENKMS_URL=https://openkms.example.com
    export OPENKMS_TOKEN=YOUR_TOKEN
    export OPENKMS_KEY_ID=signing-key
    $0 -f artifact.tar.gz

ENVIRONMENT VARIABLES:
    OPENKMS_URL                  OpenKMS server URL
    OPENKMS_TOKEN                Authentication token
    OPENKMS_KEY_ID               Key ID for signing
    OPENKMS_CLI_PATH             Path to OpenKMS CLI

EOF
}

# Parse arguments
KEY_ID=""
FILE=""
URL=""
TOKEN=""
OUTPUT=""
CLI_PATH="openkms-cli"

while [[ $# -gt 0 ]]; do
    case $1 in
        -k|--key-id)
            KEY_ID="$2"
            shift 2
            ;;
        -f|--file)
            FILE="$2"
            shift 2
            ;;
        -u|--url)
            URL="$2"
            shift 2
            ;;
        -t|--token)
            TOKEN="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT="$2"
            shift 2
            ;;
        -c|--cli-path)
            CLI_PATH="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            error "Unknown argument: $1"
            ;;
    esac
done

# Use environment variables if arguments are not provided
KEY_ID="${KEY_ID:-${OPENKMS_KEY_ID:-}}"
URL="${URL:-${OPENKMS_URL:-}}"
TOKEN="${TOKEN:-${OPENKMS_TOKEN:-}}"
CLI_PATH="${CLI_PATH:-${OPENKMS_CLI_PATH:-openkms-cli}}"

# Validate required parameters
if [[ -z "$KEY_ID" ]]; then
    error "KEY_ID not specified. Use -k/--key-id or set OPENKMS_KEY_ID"
fi

if [[ -z "$FILE" ]]; then
    error "FILE not specified. Use -f/--file"
fi

if [[ -z "$URL" ]]; then
    error "URL not specified. Use -u/--url or set OPENKMS_URL"
fi

if [[ -z "$TOKEN" ]]; then
    error "TOKEN not specified. Use -t/--token or set OPENKMS_TOKEN"
fi

# Check if file exists
if [[ ! -f "$FILE" ]]; then
    error "File not found: $FILE"
fi

# Determine output file if not specified
if [[ -z "$OUTPUT" ]]; then
    OUTPUT="${FILE}.sig"
fi

# Check if OpenKMS CLI is available
if ! command -v "$CLI_PATH" &> /dev/null; then
    error "OpenKMS CLI not found: $CLI_PATH. Install it or specify path with -c/--cli-path"
fi

# Sign file
info "Signing file: $FILE"
info "Using key: $KEY_ID"
info "OpenKMS server: $URL"

if "$CLI_PATH" sign \
    --key-id "$KEY_ID" \
    --file "$FILE" \
    --server-url "$URL" \
    --token "$TOKEN" \
    --output "$OUTPUT"; then
    info "File signed successfully: $OUTPUT"
    
    # Show signature information
    if command -v jq &> /dev/null; then
        info "Signature information:"
        jq . "$OUTPUT" 2>/dev/null || cat "$OUTPUT"
    else
        info "Signature saved to: $OUTPUT"
    fi
else
    error "Failed to sign file"
fi

