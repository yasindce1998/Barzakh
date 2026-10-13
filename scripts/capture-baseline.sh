#!/bin/bash
#
# Barzakh Golden Baseline Capture
#
# End-to-end capture of a known-good ("golden") baseline: boots QEMU+OVMF
# with a swtpm-backed vTPM, dumps PCR values and guest memory, then feeds
# everything into `barzakh-scanner baseline create` to produce a baseline
# JSON file for later drift comparison (--baseline baseline.json).
#
# USAGE:
#   ./capture-baseline.sh --target <firmware.bin> [OPTIONS]
#
# OPTIONS:
#   --target FILE      Firmware image to boot and baseline (required)
#   --output FILE      Baseline output path (default: baselines/<target-stem>.baseline.json)
#   --keep             Keep the temporary capture directory (PCRs, memmap, memory dump)
#   --help             Show this help message
#
# NEW SCANNER FLAGS (implemented alongside this script):
#   --pcrs FILE        Parses `tpm2_pcrread`-style output lines:
#                        "  0 : 0x0000... <hex-digest>"
#   --memmap FILE      Parses memory-map lines of either form:
#                        "start end type"   (whitespace separated)
#                        "0xADDR-0xADDR TYPE"
#
# EXAMPLES:
#   ./capture-baseline.sh --target OVMF_CODE.fd
#   ./capture-baseline.sh --target fw.bin --output baselines/fw.json --keep
#
# Copyright (c) 2026, Barzakh Research Project
# SPDX-License-Identifier: BSD-2-Clause-Patent

set -euo pipefail

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Source environment if available
if [[ -f "$PROJECT_ROOT/.env" ]]; then
    source "$PROJECT_ROOT/.env"
fi

# Configuration
WORKSPACE="${WORKSPACE:-$HOME/barzakh-workspace/edk2}"
OVMF_CODE="${OVMF_CODE:-$WORKSPACE/Build/OvmfX64/DEBUG_GCC5/FV/OVMF_CODE.fd}"
OVMF_VARS="${OVMF_VARS:-$WORKSPACE/Build/OvmfX64/DEBUG_GCC5/FV/OVMF_VARS.fd}"
VTPM_STATE_DIR="${VTPM_STATE_DIR:-$HOME/barzakh-workspace/vtpm-state}"
VM_MEMORY="${VM_MEMORY:-4096}"
VM_CPUS="${VM_CPUS:-2}"
VM_UUID="${BARZAKH_ALLOWED_UUID:-00000000-0000-0000-0000-000000000000}"
QEMU_MONITOR_PORT="${QEMU_MONITOR_PORT:-55555}"
SCANNER_BIN="${SCANNER_BIN:-$PROJECT_ROOT/src/barzakh-scanner-rs/target/release/barzakh-scanner}"
BASELINE_DIR="${BASELINE_DIR:-$PROJECT_ROOT/baselines}"

# Options
TARGET=""
OUTPUT=""
KEEP=false

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
    head -n 30 "$0" | grep "^#" | sed 's/^# \?//'
    exit 0
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --target)
                TARGET="$2"
                shift 2
                ;;
            --output)
                OUTPUT="$2"
                shift 2
                ;;
            --keep)
                KEEP=true
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

    if [[ -z "$TARGET" ]]; then
        log_error "--target is required (firmware image to baseline)"
        exit 1
    fi

    if [[ ! -f "$TARGET" ]]; then
        log_error "Target firmware not found: $TARGET"
        exit 1
    fi

    # Resolve the target early so later phases see an absolute path
    TARGET="$(cd "$(dirname "$TARGET")" && pwd)/$(basename "$TARGET")"

    # Default output derives from the target name
    if [[ -z "$OUTPUT" ]]; then
        local stem
        stem="$(basename "$TARGET")"
        stem="${stem%.*}"
        OUTPUT="$BASELINE_DIR/${stem}.baseline.json"
    fi

    if [[ ! -x "$SCANNER_BIN" ]]; then
        log_error "barzakh-scanner not found or not executable: $SCANNER_BIN"
        log_error "Build it first: cd src/barzakh-scanner-rs && cargo build --release"
        exit 1
    fi

    # Reuse the OVMF/QEMU validation from the QEMU harness
    if [[ ! -f "$OVMF_CODE" ]]; then
        log_error "OVMF_CODE not found: $OVMF_CODE"
        log_error "Run 'build -a X64 -t GCC5 -p OvmfPkg/OvmfPkgX64.dsc -D TPM2_ENABLE=TRUE' first"
        exit 1
    fi

    if [[ ! -f "$OVMF_VARS" ]]; then
        log_error "OVMF_VARS not found: $OVMF_VARS"
        exit 1
    fi

    if ! command -v qemu-system-x86_64 &> /dev/null; then
        log_error "qemu-system-x86_64 not found. Install QEMU first."
        exit 1
    fi

    if ! command -v swtpm &> /dev/null; then
        log_error "swtpm not found. Install swtpm (vTPM emulation) first."
        exit 1
    fi

    if ! command -v tpm2_pcrread &> /dev/null; then
        log_error "tpm2_pcrread not found. Install tpm2-tools first."
        exit 1
    fi

    log_success "Environment validation passed"
}

# Start vTPM (same logic as qemu-run.sh, fresh state for a golden boot)
start_vtpm() {
    log_info "Starting vTPM with fresh state..."

    # Golden baseline must be captured from a clean TPM state
    rm -rf "$VTPM_STATE_DIR"/*
    mkdir -p "$VTPM_STATE_DIR"

    local vtpm_sock="$VTPM_STATE_DIR/swtpm-sock"

    swtpm socket \
        --tpmstate dir="$VTPM_STATE_DIR" \
        --ctrl type=unixio,path="$vtpm_sock" \
        --tpm2 \
        --log level=20 \
        --daemon

    local retries=10
    while [[ $retries -gt 0 ]]; do
        if [[ -S "$vtpm_sock" ]]; then
            log_success "vTPM started"
            return 0
        fi
        sleep 0.5
        ((retries--))
    done

    log_error "Failed to start vTPM"
    exit 1
}

# Boot the target firmware in QEMU (headless, snapshot mode, monitor on TCP)
boot_target() {
    log_info "Booting target firmware in QEMU..."

    local vars_copy
    vars_copy="$(mktemp -p "$VTPM_STATE_DIR" OVMF_VARS_baseline.XXXXXX.fd)"
    cp "$OVMF_VARS" "$vars_copy"

    local qemu_cmd=(
        qemu-system-x86_64
        -machine q35,smm=on
        -cpu host
        -m "$VM_MEMORY"
        -smp "$VM_CPUS"
        -uuid "$VM_UUID"
        -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE"
        -drive if=pflash,format=raw,snapshot=on,file="$vars_copy"
        -drive if=pflash,format=raw,snapshot=on,file="$TARGET"
        -chardev socket,id=chrtpm,path="$VTPM_STATE_DIR/swtpm-sock"
        -tpmdev emulator,id=tpm0,chardev=chrtpm
        -device tpm-tis,tpmdev=tpm0
        -net none
        -monitor tcp:127.0.0.1:"$QEMU_MONITOR_PORT",server,nowait
        -serial null
        -nographic
    )

    if [[ -e /dev/kvm ]]; then
        qemu_cmd=(-accel kvm "${qemu_cmd[@]}")
    fi

    # Boot in the background so PCRs and memory can be dumped from the live VM
    "${qemu_cmd[@]}" &> "$CAPTURE_DIR/qemu-console.log" &
    QEMU_PID=$!

    # Give the firmware time to reach DXE and extend PCRs
    log_info "Waiting for boot to settle (${BOOT_SETTLE_SECS}s)..."
    sleep "$BOOT_SETTLE_SECS"

    if ! kill -0 "$QEMU_PID" 2> /dev/null; then
        log_error "QEMU exited prematurely - check $CAPTURE_DIR/qemu-console.log"
        exit 1
    fi

    log_success "Target firmware booted (QEMU PID $QEMU_PID)"
}

# Dump PCR values via the dump-pcrs.sh helper into the capture directory
capture_pcrs() {
    log_info "Dumping PCR values..."
    "$SCRIPT_DIR/dump-pcrs.sh" "$CAPTURE_DIR/pcrs.txt" > /dev/null
    log_success "PCR values dumped to $CAPTURE_DIR/pcrs.txt"
}

# Dump guest memory + build a memory map via the dump-memory.sh helper
capture_memory() {
    log_info "Dumping guest memory..."
    "$SCRIPT_DIR/dump-memory.sh" "$CAPTURE_DIR/memory.bin" > /dev/null

    # Derive a simple memory map from the dump (start end type lines).
    # The scanner's --memmap parser accepts "start end type" or
    # "0xADDR-0xADDR TYPE" lines; we emit the former.
    local size
    size=$(stat -c%s "$CAPTURE_DIR/memory.bin")
    {
        echo "# start end type"
        echo "0 0x$(printf '%x' "$size") ram"
    } > "$CAPTURE_DIR/memmap.txt"

    log_success "Memory dumped to $CAPTURE_DIR/memory.bin (map: $CAPTURE_DIR/memmap.txt)"
}

# Create the baseline with barzakh-scanner
create_baseline() {
    log_info "Creating baseline with barzakh-scanner..."

    mkdir -p "$(dirname "$OUTPUT")"

    "$SCANNER_BIN" baseline create \
        --target "$TARGET" \
        --pcrs "$CAPTURE_DIR/pcrs.txt" \
        --memmap "$CAPTURE_DIR/memmap.txt" \
        --output "$OUTPUT"

    if [[ ! -f "$OUTPUT" ]]; then
        log_error "Baseline creation failed - no output written to $OUTPUT"
        exit 1
    fi

    log_success "Baseline written to $OUTPUT"
}

# Main execution
main() {
    parse_args "$@"
    validate_environment

    # How long to let the firmware boot before capturing
    BOOT_SETTLE_SECS="${BOOT_SETTLE_SECS:-25}"

    # Temporary capture directory
    CAPTURE_DIR="$(mktemp -d /tmp/opencode/barzakh-baseline.XXXXXX)"
    QEMU_PID=""

    log_info "=== Barzakh Golden Baseline Capture ==="
    log_info "Target:  $TARGET"
    log_info "Output:  $OUTPUT"
    log_info "Capture: $CAPTURE_DIR"
    echo

    # Ensure QEMU is stopped on exit (keep dir only if --keep)
    cleanup() {
        if [[ -n "$QEMU_PID" ]] && kill -0 "$QEMU_PID" 2> /dev/null; then
            log_info "Stopping QEMU..."
            kill "$QEMU_PID" 2> /dev/null || true
            wait "$QEMU_PID" 2> /dev/null || true
        fi
        pkill -f "swtpm socket.*$VTPM_STATE_DIR" 2> /dev/null || true
        if [[ "$KEEP" == "true" ]]; then
            log_info "Keeping capture directory: $CAPTURE_DIR"
        else
            rm -rf "$CAPTURE_DIR"
        fi
    }
    trap cleanup EXIT

    start_vtpm
    boot_target
    capture_pcrs
    capture_memory
    create_baseline

    echo
    log_success "=== Baseline capture complete ==="
    log_info "Use it for drift comparison with:"
    log_info "  barzakh-scanner scan --target <new-fw> --baseline $OUTPUT"
}

# Run main function
main "$@"
