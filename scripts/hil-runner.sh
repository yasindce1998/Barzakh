#!/bin/bash
#
# Barzakh Hardware-in-the-Loop (HIL) Runner
#
# Automates the real-silicon lab path (see docs/LAB_TESTING.md) across five
# phases: read (backup), inject (adversary payload), flash (write), verify
# (scan + report), recover (restore backup). Every write operation requires
# an explicit --i-understand-the-risks acknowledgment and an appropriately
# configured SIMULATION environment variable.
#
# USAGE:
#   ./hil-runner.sh --phase <phase> [OPTIONS]
#
# PHASES:
#   read     Read a full backup of the SPI flash via flashrom (read twice,
#            checksum-compared per LAB_TESTING.md Step 1)
#   inject   Create a modified image with barzakh-adversary inject-single
#   flash    Write the modified image to the SPI flash via flashrom
#   verify   Scan the flashed/dumped image with barzakh-scanner and write reports
#   recover  Restore the original backup image via flashrom
#
# OPTIONS:
#   --phase PHASE            Phase to run (read|inject|flash|verify|recover) (required)
#   --image FILE             Firmware image (inject input, flash/verify input)
#   --backup FILE            Backup path (read output; flash/recover safety reference)
#   --programmer PROG        flashrom -p argument (default: internal — WARNING)
#   --payload NAME           Payload for inject phase (e.g. acpi_backdoor)
#   --i-understand-the-risks Explicit acknowledgment required for flash/recover
#   --help                   Show this help message
#
# SAFETY:
#   - This script can PERMANENTLY BRICK hardware. Read docs/LAB_TESTING.md first.
#   - Write phases (flash, recover) require --i-understand-the-risks.
#   - Write phases refuse to run unless SIMULATION is set to one of:
#       SIMULATION=0   real-hardware mode (destructive!)
#       SIMULATION=1   simulation mode (flashrom invoked with --layout-limited
#                      safety / dry-run style checks where possible)
#   - Always keep an untouched copy of your backup on separate media.
#
# EXAMPLES:
#   SIMULATION=1 ./hil-runner.sh --phase read --backup fw-backup.bin --programmer ch341a_spi
#   SIMULATION=1 ./hil-runner.sh --phase inject --image fw-backup.bin --payload acpi_backdoor
#   SIMULATION=0 ./hil-runner.sh --phase flash --image fw-injected.bin \
#       --backup fw-backup.bin --programmer ch341a_spi --i-understand-the-risks
#
# Copyright (c) 2026, Barzakh Research Project
# SPDX-License-Identifier: BSD-2-Clause-Patent

set -euo pipefail

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Source environment if available
if [[ -f "$PROJECT_ROOT/.env" ]]; then
    source "$PROJECT_ROOT/.env"
fi

# Configuration
ADVERSARY_BIN="${ADVERSARY_BIN:-$PROJECT_ROOT/src/barzakh-scanner-rs/target/release/barzakh-adversary}"
SCANNER_BIN="${SCANNER_BIN:-$PROJECT_ROOT/src/barzakh-scanner-rs/target/release/barzakh-scanner}"
HIL_OUT_DIR="${HIL_OUT_DIR:-$PROJECT_ROOT/test/hil}"

# Default values
PHASE=""
IMAGE=""
BACKUP=""
PROGRAMMER="internal"
PAYLOAD=""
ACKNOWLEDGE_RISKS=false

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
    head -n 45 "$0" | grep "^#" | sed 's/^# \?//'
    exit 0
}

# Print the prominent safety banner
print_safety_banner() {
    echo -e "${RED}"
    echo "====================================================================="
    echo "  !! HARDWARE-IN-THE-LOOP MODE — REAL SILICON RISK !!"
    echo "====================================================================="
    echo "  Incorrect SPI flash writes can PERMANENTLY BRICK your motherboard."
    echo "  There is no software recovery path once the flash is corrupted."
    echo ""
    echo "  Before ANY write phase:"
    echo "   * Work only on a dedicated, sacrificial test machine"
    echo "   * Keep a verified backup (read twice, checksums compared)"
    echo "   * Confirm Boot Guard / PSB is NOT enabled (see LAB_TESTING.md)"
    echo "   * Never remove the SOIC clip mid-write"
    echo "  See docs/LAB_TESTING.md for the full safety prerequisites."
    echo "====================================================================="
    echo -e "${NC}"
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --phase)
                PHASE="$2"
                shift 2
                ;;
            --image)
                IMAGE="$2"
                shift 2
                ;;
            --backup)
                BACKUP="$2"
                shift 2
                ;;
            --programmer)
                PROGRAMMER="$2"
                shift 2
                ;;
            --payload)
                PAYLOAD="$2"
                shift 2
                ;;
            --i-understand-the-risks)
                ACKNOWLEDGE_RISKS=true
                shift
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

# Validate environment and options
validate_environment() {
    log_info "Validating environment..."

    case "$PHASE" in
        read|inject|flash|verify|recover) ;;
        "")
            log_error "--phase is required (read|inject|flash|verify|recover)"
            exit 1
            ;;
        *)
            log_error "Unknown phase: $PHASE (expected read|inject|flash|verify|recover)"
            exit 1
            ;;
    esac

    # SIMULATION interlock: refuse write operations unless configured
    if [[ "$PHASE" == "flash" || "$PHASE" == "recover" ]]; then
        if [[ -z "${SIMULATION:-}" ]]; then
            log_error "SIMULATION environment variable is not set."
            log_error "Write phases refuse to run without it. Set one of:"
            log_error "  SIMULATION=1  simulation mode (safe rehearsal)"
            log_error "  SIMULATION=0  real-hardware mode (DESTRUCTIVE — bricks possible)"
            exit 1
        fi
        if [[ "$SIMULATION" != "0" && "$SIMULATION" != "1" ]]; then
            log_error "SIMULATION must be 0 (real hardware) or 1 (simulation), got: $SIMULATION"
            exit 1
        fi
        if [[ "$ACKNOWLEDGE_RISKS" != "true" ]]; then
            log_error "Write phase '$PHASE' requires --i-understand-the-risks"
            log_error "This flag acknowledges you may PERMANENTLY BRICK the target."
            exit 1
        fi
    fi

    # flashrom is required for the phases that touch the chip
    if [[ "$PHASE" == "read" || "$PHASE" == "flash" || "$PHASE" == "recover" ]]; then
        if ! command -v flashrom &> /dev/null; then
            log_error "flashrom not found. Install flashrom first."
            exit 1
        fi
    fi

    # Phase-specific inputs
    case "$PHASE" in
        read)
            if [[ -z "$BACKUP" ]]; then
                log_error "--phase read requires --backup <file>"
                exit 1
            fi
            ;;
        inject)
            if [[ -z "$IMAGE" || -z "$PAYLOAD" ]]; then
                log_error "--phase inject requires --image <input> and --payload <name>"
                exit 1
            fi
            if [[ ! -f "$IMAGE" ]]; then
                log_error "Input image not found: $IMAGE"
                exit 1
            fi
            if [[ ! -x "$ADVERSARY_BIN" ]]; then
                log_error "barzakh-adversary not found or not executable: $ADVERSARY_BIN"
                log_error "Build it first: cd src/barzakh-scanner-rs && cargo build --release"
                exit 1
            fi
            ;;
        flash)
            if [[ -z "$IMAGE" ]]; then
                log_error "--phase flash requires --image <file>"
                exit 1
            fi
            if [[ ! -f "$IMAGE" ]]; then
                log_error "Image to flash not found: $IMAGE"
                exit 1
            fi
            if [[ -z "$BACKUP" ]]; then
                log_error "--phase flash requires --backup <file> (recovery reference)"
                exit 1
            fi
            if [[ ! -f "$BACKUP" ]]; then
                log_error "Backup image not found: $BACKUP"
                log_error "Run the 'read' phase first and keep this file safe."
                exit 1
            fi
            ;;
        verify)
            if [[ -z "$IMAGE" ]]; then
                log_error "--phase verify requires --image <file>"
                exit 1
            fi
            if [[ ! -f "$IMAGE" ]]; then
                log_error "Image to verify not found: $IMAGE"
                exit 1
            fi
            if [[ ! -x "$SCANNER_BIN" ]]; then
                log_error "barzakh-scanner not found or not executable: $SCANNER_BIN"
                log_error "Build it first: cd src/barzakh-scanner-rs && cargo build --release"
                exit 1
            fi
            ;;
        recover)
            if [[ -z "$BACKUP" ]]; then
                log_error "--phase recover requires --backup <file>"
                exit 1
            fi
            if [[ ! -f "$BACKUP" ]]; then
                log_error "Backup image not found: $BACKUP"
                log_error "Without a backup there is NO recovery path. See docs/LAB_TESTING.md."
                exit 1
            fi
            ;;
    esac

    # Warn on the default internal programmer
    if [[ "$PROGRAMMER" == "internal" && ( "$PHASE" == "flash" || "$PHASE" == "recover" || "$PHASE" == "read" ) ]]; then
        log_warning "Using flashrom programmer 'internal' (default)."
        log_warning "For lab work an EXTERNAL programmer (ch341a_spi, dediprog) is strongly"
        log_warning "recommended — internal writes are blocked when the flash is locked and"
        log_warning "you have no out-of-band recovery path if the image is bad."
    fi

    mkdir -p "$HIL_OUT_DIR"

    log_success "Environment validation passed"
}

# Phase: read — full backup, read twice with checksum comparison
phase_read() {
    log_info "Phase READ: backing up SPI flash to $BACKUP"

    mkdir -p "$(dirname "$BACKUP")"

    flashrom -p "$PROGRAMMER" -r "$BACKUP"

    # LAB_TESTING.md Step 1: always read twice and compare
    local verify_copy="$HIL_OUT_DIR/read-verify.bin"
    log_info "Reading a second time for verification..."
    flashrom -p "$PROGRAMMER" -r "$verify_copy"

    if ! cmp -s "$BACKUP" "$verify_copy"; then
        log_error "The two reads DIFFER — the backup cannot be trusted!"
        log_error "Likely cause: unreliable SOIC clip connection."
        log_error "Re-seat the clip (check pin 1 alignment) and re-run the read phase."
        exit 1
    fi

    rm -f "$verify_copy"

    log_success "Backup verified (both reads identical)"
    log_info "SHA-256: $(sha256sum "$BACKUP" | cut -d' ' -f1)"
    log_info "Copy $BACKUP to separate media (USB + network share) before proceeding."
}

# Phase: inject — build a modified image with barzakh-adversary
phase_inject() {
    log_info "Phase INJECT: creating modified image with payload '$PAYLOAD'"

    local output="${HIL_IMAGE:-$HIL_OUT_DIR/injected.bin}"

    "$ADVERSARY_BIN" inject-single \
        --input "$IMAGE" \
        --output "$output" \
        --payload "$PAYLOAD"

    if [[ ! -f "$output" ]]; then
        log_error "Adversary did not produce an output image"
        exit 1
    fi

    log_success "Injected image written to $output"
    log_info "Set HIL_IMAGE=$output (or export it) and use it as --image for the flash phase"
}

# Phase: flash — write the modified image (destructive)
phase_flash() {
    print_safety_banner

    if [[ "$SIMULATION" == "1" ]]; then
        log_warning "SIMULATION=1 — performing read-back verification only, NO write."
        log_warning "The chip contents are compared against $IMAGE without programming."
        flashrom -p "$PROGRAMMER" -v "$IMAGE" || {
            log_info "Chip does not match $IMAGE (expected — nothing was written)"
        }
        return 0
    fi

    log_warning "REAL-HARDWARE MODE (SIMULATION=0): erasing and writing the SPI flash."
    log_warning "Do NOT remove the clip or interrupt power during this operation."

    flashrom -p "$PROGRAMMER" -w "$IMAGE"
    flashrom -p "$PROGRAMMER" -v "$IMAGE"

    log_success "Flash + verify completed"
    log_warning "Boot behavior may differ. Recovery: $BACKUP"
    log_warning "  ./hil-runner.sh --phase recover --backup $BACKUP \\"
    log_warning "      --programmer $PROGRAMMER --i-understand-the-risks"
}

# Phase: verify — scan the image and produce reports
phase_verify() {
    log_info "Phase VERIFY: scanning $IMAGE with barzakh-scanner"

    local report_json="$HIL_OUT_DIR/hil-report.json"
    local report_html="$HIL_OUT_DIR/hil-report.html"

    set +e
    "$SCANNER_BIN" scan --target "$IMAGE" --report "$report_json"
    local scan_status=$?
    set -e

    "$SCANNER_BIN" report --target "$IMAGE" --format html --output "$report_html" || true

    log_success "Reports written:"
    log_info "  JSON: $report_json"
    log_info "  HTML: $report_html"
    log_info "Scanner exit code: $scan_status (non-zero indicates findings)"

    if [[ $scan_status -ne 0 ]]; then
        log_warning "Findings detected — record them in the knowledge base:"
        log_warning "  barzakh-scanner kb add --target $IMAGE --vendor <V> --device <D> --notes 'HIL phase'"
    fi
    return 0
}

# Phase: recover — restore the original backup (destructive)
phase_recover() {
    print_safety_banner

    if [[ "$SIMULATION" == "1" ]]; then
        log_warning "SIMULATION=1 — comparing chip against backup only, NO write."
        flashrom -p "$PROGRAMMER" -v "$BACKUP" || {
            log_info "Chip does not match backup (expected — nothing was written)"
        }
        return 0
    fi

    log_warning "REAL-HARDWARE MODE (SIMULATION=0): restoring backup image."
    log_warning "This is the emergency recovery path — do not interrupt it."

    flashrom -p "$PROGRAMMER" -w "$BACKUP"
    flashrom -p "$PROGRAMMER" -v "$BACKUP"

    log_success "Recovery flash verified — remove the clip and attempt boot"
    log_warning "First boot after ME-region recovery may take ~30 minutes (see LAB_TESTING.md)"
}

# Main execution
main() {
    parse_args "$@"
    validate_environment

    print_safety_banner

    log_info "=== Barzakh HIL Runner ==="
    log_info "Phase:      $PHASE"
    log_info "Programmer: $PROGRAMMER"
    log_info "Image:      ${IMAGE:-<none>}"
    log_info "Backup:     ${BACKUP:-<none>}"
    log_info "SIMULATION: ${SIMULATION:-<unset>}"
    echo

    case "$PHASE" in
        read)    phase_read ;;
        inject)  phase_inject ;;
        flash)   phase_flash ;;
        verify)  phase_verify ;;
        recover) phase_recover ;;
    esac

    log_success "Phase '$PHASE' completed"
}

# Run main function
main "$@"
