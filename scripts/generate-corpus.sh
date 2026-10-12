#!/bin/bash
#
# Barzakh Synthetic Corpus Generator
#
# Generates malicious_*.bin and clean_*.bin pairs via the Rust adversary
# binary, placing them under tests/corpus/synthetic/ for lab testing
# and corpus validation.
#
# Usage: ./generate-corpus.sh [output-dir] [--validate]
#
# Requirements: Rust toolchain (cargo)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RUST_DIR="$PROJECT_ROOT/src/barzakh-scanner-rs"

CORPUS_DIR="$PROJECT_ROOT/tests/corpus/synthetic"
DO_VALIDATE=0
for arg in "$@"; do
    case "$arg" in
        --validate) DO_VALIDATE=1 ;;
        -*) echo "Unknown option: $arg" >&2; exit 1 ;;
        *) CORPUS_DIR="$arg" ;;
    esac
done

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}=== Barzakh Synthetic Corpus Generator ===${NC}"
echo "Output: $CORPUS_DIR"
echo ""

# Build the adversary binary if needed
ADVERSARY="$RUST_DIR/target/release/barzakh-adversary"
if [[ ! -x "$ADVERSARY" ]]; then
    echo -e "${CYAN}Building barzakh-adversary (release)...${NC}"
    cargo build --release --manifest-path "$RUST_DIR/Cargo.toml" -p barzakh-cli
fi

if [[ ! -x "$ADVERSARY" ]]; then
    echo -e "${RED}ERROR: barzakh-adversary binary not found at $ADVERSARY${NC}"
    exit 1
fi

# Create the directory structure documented in tests/corpus/README.md
mkdir -p "$PROJECT_ROOT/tests/corpus/malicious"
mkdir -p "$PROJECT_ROOT/tests/corpus/benign"
mkdir -p "$CORPUS_DIR"

# Generate corpus (malicious + clean pairs)
echo -e "${CYAN}Generating corpus...${NC}"
"$ADVERSARY" corpus --output "$CORPUS_DIR"

# Count results
MALICIOUS=$(find "$CORPUS_DIR" -name 'malicious_*.bin' | wc -l)
CLEAN=$(find "$CORPUS_DIR" -name 'clean_*.bin' | wc -l)
TOTAL=$(find "$CORPUS_DIR" -name '*.bin' | wc -l)

echo ""
echo -e "${BOLD}=== Corpus Generation Complete ===${NC}"
echo -e "  Malicious: ${RED}$MALICIOUS${NC}"
echo -e "  Clean:     ${GREEN}$CLEAN${NC}"
echo -e "  Total:     $TOTAL"
echo ""

# Run validation if requested
if [[ "$DO_VALIDATE" == "1" ]]; then
    echo -e "${CYAN}Validating corpus...${NC}"
    "$ADVERSARY" validate --corpus "$CORPUS_DIR"
else
    echo "To validate: $ADVERSARY validate --corpus $CORPUS_DIR"
    echo "  or re-run with: VALIDATE=1 $0"
fi
