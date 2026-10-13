#!/bin/bash
#
# Barzakh Threat Intelligence Feed Updater
#
# Fetches and validates IOC feeds for the scanner's intel detectors
# (see docs/INTEL.md). Each feed must be JSON with a "name" string and
# an "iocs" array. Validated feeds land in the intel directory and can
# be passed to the scanner via --ioc-feed.
#
# USAGE:
#   ./intel-update.sh [OPTIONS]
#
# OPTIONS:
#   --dir DIRECTORY    Feed directory (default: ./intel-feeds)
#   --feed URL|FILE    Fetch a specific feed (URL or local file path).
#                      Can be used multiple times. Default: refresh the
#                      bundled local feed note only.
#   --help             Show this help message
#
# FEED FORMAT (JSON):
#   {
#     "name": "barzakh-default",
#     "version": 1,
#     "iocs": [
#       {"sha256": "...", "pattern": "hex:DEADBEEF", "family": "LoJax",
#        "cve": null, "description": "..."}
#     ]
#   }
#
# EXIT STATUS:
#   0 — all feeds valid (offline skip of remote feeds still exits 0)
#   1 — a feed failed to download or failed validation
#
# EXAMPLES:
#   ./intel-update.sh
#   ./intel-update.sh --dir /var/lib/barzakh/intel --feed https://example.com/feed.json
#
# Copyright (c) 2026, Barzakh Research Project
# SPDX-License-Identifier: BSD-2-Clause-Patent

set -euo pipefail

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Default values
FEED_DIR="$PROJECT_ROOT/intel-feeds"
FEEDS=()

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Show usage
show_usage() {
    head -n 35 "$0" | grep "^#" | sed 's/^# \?//'
    exit 0
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dir)
                FEED_DIR="$2"
                shift 2
                ;;
            --feed)
                FEEDS+=("$2")
                shift 2
                ;;
            --help)
                show_usage
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                ;;
        esac
    done
}

# Validate that a file is a well-formed Barzakh IOC feed:
# JSON object with a "name" string and an "iocs" array.
# Uses python3 when available (strict JSON parsing); falls back to
# grep-based structural checks otherwise.
validate_feed() {
    local file="$1"

    if [[ ! -s "$file" ]]; then
        log_error "Feed is empty: $file"
        return 1
    fi

    if command -v python3 &> /dev/null; then
        if ! python3 - "$file" <<'PYEOF'
import json, sys

path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8") as fh:
        feed = json.load(fh)
except Exception as exc:
    print(f"invalid JSON: {exc}", file=sys.stderr)
    sys.exit(1)

if not isinstance(feed, dict):
    print("feed is not a JSON object", file=sys.stderr)
    sys.exit(1)

name = feed.get("name")
if not isinstance(name, str) or not name.strip():
    print('missing "name" string', file=sys.stderr)
    sys.exit(1)

iocs = feed.get("iocs")
if not isinstance(iocs, list):
    print('missing "iocs" array', file=sys.stderr)
    sys.exit(1)

print(f"{len(iocs)}")
PYEOF
        then
            log_error "Feed validation failed: $file"
            return 1
        fi
        return 0
    fi

    # Fallback: structural grep checks (no python3 available)
    if ! grep -q '"name"' "$file"; then
        log_error "Feed has no \"name\" field: $file"
        return 1
    fi
    if ! grep -q '"iocs"' "$file"; then
        log_error "Feed has no \"iocs\" array: $file"
        return 1
    fi
    return 0
}

# Fetch a single feed (URL or local file) into the feed directory.
# Returns 0 on success, 1 on failure.
fetch_feed() {
    local source="$1"
    local dest

    if [[ "$source" == http://* || "$source" == https://* ]]; then
        local filename
        filename="$(basename "${source%%\?*}")"
        # Ensure a .json extension
        if [[ "$filename" != *.json ]]; then
            filename="${filename}.json"
        fi
        dest="$FEED_DIR/$filename"

        log_info "Fetching $source"
        if ! curl --fail --silent --show-error --location \
                --output "$dest.tmp" "$source"; then
            rm -f "$dest.tmp"
            log_error "Download failed: $source"
            return 1
        fi
        mv "$dest.tmp" "$dest"
    else
        # Local file
        if [[ ! -f "$source" ]]; then
            log_error "Feed file not found: $source"
            return 1
        fi
        dest="$FEED_DIR/$(basename "$source")"
        if [[ "$(cd "$(dirname "$source")" && pwd)/$(basename "$source")" != "$(cd "$FEED_DIR" && pwd)/$(basename "$source")" ]]; then
            cp "$source" "$dest"
        fi
    fi

    if ! validate_feed "$dest"; then
        return 1
    fi

    log_success "Feed OK: $dest"
    return 0
}

# Main execution
main() {
    parse_args "$@"

    mkdir -p "$FEED_DIR"

    log_info "=== Barzakh Threat Intel Update ==="
    log_info "Feed directory: $FEED_DIR"
    echo

    local failures=0
    local fetched=0

    if [[ ${#FEEDS[@]} -eq 0 ]]; then
        log_info "No --feed given. Default: using the bundled local feed note."
        cat > "$FEED_DIR/README.txt" <<EOF
Barzakh IOC feeds
=================

This directory holds validated IOC feeds consumed by the scanner:

    barzakh-scanner scan --target fw.bin --ioc-feed <feed.json>

The bundled feed (intel-feeds/barzakh-default.json, when present in the
repository) ships with the project. To pull remote feeds, run:

    ./scripts/intel-update.sh --feed https://example.com/barzakh-feed.json

Each feed must be a JSON object with a "name" string and an "iocs" array.
See docs/INTEL.md for the full feed format and YARA-subset rule support.
EOF
        log_success "Bundled feed note written to $FEED_DIR/README.txt"
        log_info "Pass --feed <url-or-file> to fetch and validate specific feeds."
    else
        for feed in "${FEEDS[@]}"; do
            if fetch_feed "$feed"; then
                fetched=$((fetched + 1))
            else
                failures=$((failures + 1))
            fi
        done
    fi

    # Summary
    echo
    log_info "=== Summary ==="
    log_info "Fetched/validated: $fetched"
    log_info "Failures:          $failures"

    if ls "$FEED_DIR"/*.json &> /dev/null; then
        log_info "Feeds present in $FEED_DIR:"
        for f in "$FEED_DIR"/*.json; do
            echo "  - $f ($(stat -c%s "$f") bytes)"
        done
        log_info "Scan with: barzakh-scanner scan --target fw.bin --ioc-feed $FEED_DIR/<feed>.json"
    fi

    if [[ $failures -gt 0 ]]; then
        exit 1
    fi
}

# Run main function
main "$@"
