#!/bin/bash
#
# Barzakh Cross-Platform Installer
#
# Detects OS/architecture, downloads the matching release tarball from
# GitHub releases, verifies its SHA-256 checksum, and installs the four
# Barzakh binaries (barzakh-scanner, barzakh-adversary, barzakh-server,
# barzakh-agent) into ~/.local/bin or a --prefix directory.
#
# USAGE:
#   ./install.sh [OPTIONS]
#
# OPTIONS:
#   --prefix DIR     Installation prefix (default: ~/.local)
#                    Binaries land in <prefix>/bin
#   --version TAG    Release tag to install (default: latest)
#   --help           Show this help message
#
# SUPPORTED PLATFORMS:
#   linux  x86_64, aarch64
#   macos  x86_64, aarch64
#
# REQUIREMENTS:
#   curl, tar, sha256sum (Linux) or shasum (macOS)
#
# Copyright (c) 2026, Barzakh Research Project
# SPDX-License-Identifier: BSD-2-Clause-Patent

set -euo pipefail

# Configuration
RELEASE_BASE="https://github.com/yasindce1998/Barzakh/releases"
PREFIX="$HOME/.local"
VERSION="latest"

# Binaries shipped in the release tarball
BINARIES=(barzakh-scanner barzakh-adversary barzakh-server barzakh-agent)

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
    head -n 28 "$0" | grep "^#" | sed 's/^# \?//'
    exit 0
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --prefix)
                PREFIX="$2"
                shift 2
                ;;
            --version)
                VERSION="$2"
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

# Detect platform and set OS/ARCH/TARGET
detect_platform() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Linux) OS="linux" ;;
        Darwin) OS="macos" ;;
        *)
            log_error "Unsupported operating system: $OS (supported: linux, macos)"
            exit 1
            ;;
    esac

    case "$ARCH" in
        x86_64|amd64) ARCH="x86_64" ;;
        aarch64|arm64) ARCH="aarch64" ;;
        *)
            log_error "Unsupported architecture: $ARCH (supported: x86_64, aarch64)"
            exit 1
            ;;
    esac

    case "$OS-$ARCH" in
        linux-x86_64)   TARGET="x86_64-unknown-linux-gnu" ;;
        linux-aarch64)  TARGET="aarch64-unknown-linux-gnu" ;;
        macos-x86_64)   TARGET="x86_64-apple-darwin" ;;
        macos-aarch64)  TARGET="aarch64-apple-darwin" ;;
        *)
            log_error "No release asset for platform: $OS-$ARCH"
            exit 1
            ;;
    esac

    log_info "Detected platform: $OS $ARCH ($TARGET)"
}

# Resolve the release download URL for the requested version
resolve_url() {
    if [[ "$VERSION" == "latest" ]]; then
        RELEASE_URL="$RELEASE_BASE/latest/download"
    else
        RELEASE_URL="$RELEASE_BASE/download/$VERSION"
    fi
}

# Compute the sha256 of a file (Linux: sha256sum, macOS: shasum)
sha256_file() {
    local file="$1"
    if command -v sha256sum &> /dev/null; then
        sha256sum "$file" | cut -d' ' -f1
    elif command -v shasum &> /dev/null; then
        shasum -a 256 "$file" | cut -d' ' -f1
    else
        log_error "Neither sha256sum nor shasum found — cannot verify checksums."
        exit 1
    fi
}

# Download, verify, extract, and install
install_barzakh() {
    local tarball="barzakh-${TARGET}.tar.gz"
    local workdir
    workdir="$(mktemp -d /tmp/opencode/barzakh-install.XXXXXX)"

    log_info "Downloading $RELEASE_URL/$tarball"
    if ! curl --fail --silent --show-error --location \
            --output "$workdir/$tarball" "$RELEASE_URL/$tarball"; then
        log_error "Download failed. Check the release exists:"
        log_error "  $RELEASE_URL/$tarball"
        rm -rf "$workdir"
        exit 1
    fi

    log_info "Downloading checksum file"
    if ! curl --fail --silent --show-error --location \
            --output "$workdir/$tarball.sha256" "$RELEASE_URL/$tarball.sha256"; then
        log_error "Checksum download failed — refusing to install unverified artifacts."
        rm -rf "$workdir"
        exit 1
    fi

    # Verify checksum using grep/sed (no jq dependency)
    local expected actual
    expected="$(sed -n 's/^\([0-9a-fA-F]\{64\}\).*$/\1/p' "$workdir/$tarball.sha256" | head -n1)"
    actual="$(sha256_file "$workdir/$tarball")"
    if [[ -z "$expected" ]]; then
        # Some checksum files use the "<hash>  <file>" or bare-hash formats;
        # fall back to the first 64-hex-char token on the line
        expected="$(grep -oE '[0-9a-fA-F]{64}' "$workdir/$tarball.sha256" | head -n1)"
    fi
    if [[ -z "$expected" || "$expected" != "$actual" ]]; then
        log_error "Checksum mismatch!"
        log_error "  expected: $expected"
        log_error "  actual:   $actual"
        rm -rf "$workdir"
        exit 1
    fi
    log_success "Checksum verified: $actual"

    # Extract and locate binaries
    tar -xzf "$workdir/$tarball" -C "$workdir"

    local bindir="$PREFIX/bin"
    mkdir -p "$bindir"

    local bin_name bin_path found
    for bin_name in "${BINARIES[@]}"; do
        bin_path="$(find "$workdir" -type f -name "$bin_name" | head -n1)"
        if [[ -z "$bin_path" ]]; then
            log_warning "Binary not found in tarball: $bin_name (skipping)"
            continue
        fi
        install -m 0755 "$bin_path" "$bindir/$bin_name"
        log_success "Installed $bindir/$bin_name"
    done

    # Print versions of everything installed
    echo
    log_info "Installed versions:"
    for bin_name in "${BINARIES[@]}"; do
        if [[ -x "$bindir/$bin_name" ]]; then
            echo "  $("$bindir/$bin_name" --version 2> /dev/null || echo "$bin_name (version unavailable)")"
        fi
    done

    rm -rf "$workdir"

    echo
    log_info "Ensure '$bindir' is on your PATH:"
    log_info "  export PATH=\"$bindir:\$PATH\""
    case ":$PATH:" in
        *":$bindir:"*) ;;
        *) log_warning "$bindir is NOT currently on your PATH" ;;
    esac
}

# Main execution
main() {
    parse_args "$@"
    log_info "=== Barzakh Installer ==="
    detect_platform
    resolve_url
    log_info "Version: $VERSION"
    log_info "Prefix:  $PREFIX"
    echo
    install_barzakh
    log_success "=== Installation complete ==="
}

# Run main function
main "$@"
