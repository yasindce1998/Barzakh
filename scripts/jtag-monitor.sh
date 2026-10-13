#!/bin/bash
#
# Barzakh JTAG/SWD Debug Interface Monitor
#
# Captures physical debug-interface (JTAG/SWD) traces during a test run
# using OpenOCD. Traces feed the `debug_interface` detector as artifacts
# (see docs/LAB_AUTOMATION.md).
#
# USAGE:
#   ./jtag-monitor.sh --config <openocd.cfg> [OPTIONS]
#
# OPTIONS:
#   --config FILE    OpenOCD configuration file for the target board
#                    (required; e.g. board/ti-am335x.cfg or a custom .cfg)
#   --duration SECS  How long to capture (default: 60)
#   --output FILE    Output trace file (default: jtag-trace.log)
#   --help           Show this help message
#
# REQUIREMENTS:
#   - OpenOCD installed and on PATH
#   - A supported debug probe (e.g. Olimex ARM-USB-TINY-H, FTDI FT2232,
#     ST-Link, J-Link) connected to the target's JTAG/SWD port
#   - Target board powered and correctly wired (see docs/LAB_TESTING.md
#     for lab equipment notes)
#
# EXAMPLES:
#   ./jtag-monitor.sh --config board/custom-target.cfg --duration 300 \
#       --output traces/boot-trace.log
#
# Copyright (c) 2026, Barzakh Research Project
# SPDX-License-Identifier: BSD-2-Clause-Patent

set -euo pipefail

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Default values
CONFIG=""
DURATION=60
OUTPUT="jtag-trace.log"

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
    head -n 32 "$0" | grep "^#" | sed 's/^# \?//'
    exit 0
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --config)
                CONFIG="$2"
                shift 2
                ;;
            --duration)
                DURATION="$2"
                shift 2
                ;;
            --output)
                OUTPUT="$2"
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

# Validate environment
validate_environment() {
    log_info "Validating environment..."

    if [[ -z "$CONFIG" ]]; then
        log_error "--config is required (OpenOCD configuration file for the target)"
        exit 1
    fi

    if [[ ! -f "$CONFIG" ]]; then
        log_error "OpenOCD config file not found: $CONFIG"
        exit 1
    fi

    if ! command -v openocd &> /dev/null; then
        log_error "openocd not found. Install it first, e.g.:"
        log_error "  Debian/Ubuntu: sudo apt install openocd"
        log_error "  Fedora:        sudo dnf install openocd"
        log_error "  Arch:          sudo pacman -S openocd"
        exit 1
    fi

    log_success "Environment validation passed"
}

# Capture the debug interface trace
capture_trace() {
    log_info "Starting OpenOCD with config: $CONFIG"
    log_info "Capturing for ${DURATION}s into $OUTPUT"

    # Run OpenOCD with:
    #   -f <config>      target board / probe configuration
    #   -c "init"        initialize the debug session
    #   -c "targets"     list discovered targets (records DAP/AP state)
    #   -c "sleep N"     keep the session alive for the capture duration
    #   -c "shutdown"    terminate cleanly
    #
    # The debug_interface detector consumes the captured transcript:
    #   - target DAP/AP enumeration (debug port access patterns)
    #   - halt/resume events (unexpected halts during boot = probe activity)
    #   - memory/register read accesses logged by OpenOCD debug level 3
    set +e
    openocd \
        -f "$CONFIG" \
        -c "debug_level 3" \
        -c "init" \
        -c "targets" \
        -c "sleep $((DURATION * 1000))" \
        -c "shutdown" \
        &> "$OUTPUT" &
    local openocd_pid=$!

    # Monitor progress
    local waited=0
    while [[ $waited -lt $DURATION ]]; do
        sleep 5
        waited=$((waited + 5))
        if ! kill -0 "$openocd_pid" 2> /dev/null; then
            break
        fi
        log_info "Capturing... ${waited}s / ${DURATION}s"
    done

    # Ensure OpenOCD is terminated
    if kill -0 "$openocd_pid" 2> /dev/null; then
        kill "$openocd_pid" 2> /dev/null || true
        wait "$openocd_pid" 2> /dev/null || true
    else
        wait "$openocd_pid" 2> /dev/null || true
    fi
    set -e

    if [[ ! -s "$OUTPUT" ]]; then
        log_error "Trace file is empty — OpenOCD failed to start or the probe is not connected."
        log_error "Check the config file, probe wiring, and target power."
        exit 1
    fi

    log_success "Trace captured to $OUTPUT ($(wc -l < "$OUTPUT") lines)"

    # Quick sanity summary of what was captured
    local halts targets
    halts=$(grep -c -i "halted" "$OUTPUT" || true)
    targets=$(grep -c -i "target state" "$OUTPUT" || true)
    log_info "Trace summary: ${targets} target-state lines, ${halts} halt events"
}

# Main execution
main() {
    parse_args "$@"
    validate_environment

    log_info "=== Barzakh JTAG/SWD Debug Interface Monitor ==="
    log_info "Config:   $CONFIG"
    log_info "Duration: ${DURATION}s"
    log_info "Output:   $OUTPUT"
    echo

    capture_trace

    echo
    log_success "=== Capture complete ==="
    log_info "Feed the trace to the debug_interface detector artifacts:"
    log_info "  barzakh-scanner scan --target <fw> --debug-trace $OUTPUT"
    log_info "See docs/LAB_AUTOMATION.md for the full HIL workflow."
}

# Run main function
main "$@"
