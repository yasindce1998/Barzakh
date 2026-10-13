#!/bin/bash
#
# Barzakh HPC Profile Collector
#
# Collects hardware performance counter (HPC) profiles for the
# `hpc_monitor` detector using Linux `perf stat`. The detector consumes
# a plain-text profile in the exact format produced by this script:
#
#   # barzakh-hpc-profile v1
#   cpu_cycles=<value>
#   cache_miss_rate=<0..1>
#   branch_mispredict_rate=<0..1>
#   smi_count=<value>
#   dcache_evictions=<value>
#
# USAGE:
#   ./hpc-collect.sh [OPTIONS] [--workload "<command>"]
#
# OPTIONS:
#   --duration SECONDS   How long to sample (default: 10; ignored when
#                        --workload is given — the workload defines duration)
#   --output FILE        Output profile path (default: hpc-profile.txt)
#   --workload CMD       Shell command to run under perf stat
#   --help               Show this help message
#
# REQUIREMENTS:
#   - Linux with perf installed (linux-tools / linux-tools-common)
#   - /proc/sys/kernel/perf_event_paranoid <= 2 (or run as root)
#   - Hardware PMU support on the target CPU
#
# EXAMPLES:
#   ./hpc-collect.sh --duration 30 --output idle-profile.txt
#   ./hpc-collect.sh --workload "./scanner-bench.sh" --output bench-profile.txt
#
# Copyright (c) 2026, Barzakh Research Project
# SPDX-License-Identifier: BSD-2-Clause-Patent

set -euo pipefail

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Default values
DURATION=10
OUTPUT="hpc-profile.txt"
WORKLOAD=""

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
    head -n 34 "$0" | grep "^#" | sed 's/^# \?//'
    exit 0
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --duration)
                DURATION="$2"
                shift 2
                ;;
            --output)
                OUTPUT="$2"
                shift 2
                ;;
            --workload)
                WORKLOAD="$2"
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

# Extract a counter value from perf stat output.
# Matches either "  123,456  event-name" (perf >= 5) or the
# "event-name: 123456" style used with -x.
perf_value() {
    local event="$1"
    local file="$2"
    # Match the value column preceding the event name; strip commas
    awk -v ev="$event" '$NF == ev || $NF ~ ("^" ev "$") {gsub(/,/, "", $1); print $1; exit}' "$file"
}

# Extract a ratio a/b from perf stat output, guarding divide-by-zero
perf_ratio() {
    local numerator_event="$1"
    local denominator_event="$2"
    local file="$3"
    local num den
    num=$(perf_value "$numerator_event" "$file" || echo "")
    den=$(perf_value "$denominator_event" "$file" || echo "")
    if [[ -z "$num" || -z "$den" ]]; then
        echo "0"
        return
    fi
    if [[ "$den" -eq 0 ]]; then
        echo "0"
        return
    fi
    awk -v n="$num" -v d="$den" 'BEGIN {printf "%.6f", n / d}'
}

# Validate environment
validate_environment() {
    log_info "Validating environment..."

    if [[ "$(uname -s)" != "Linux" ]]; then
        log_error "This script requires Linux perf (unsupported platform: $(uname -s))"
        exit 1
    fi

    if ! command -v perf &> /dev/null; then
        log_error "perf not found. Install it first, e.g.:"
        log_error "  Debian/Ubuntu:  sudo apt install linux-tools-common linux-tools-\$(uname -r)"
        log_error "  Fedora:         sudo dnf install perf"
        log_error "  Arch:           sudo pacman -S perf"
        log_error ""
        log_error "The hpc_monitor detector needs hardware performance counter"
        log_error "profiles collected with 'perf stat'."
        exit 1
    fi

    # Check perf_event_paranoid — values > 2 block userspace PMU access
    local paranoid=-1
    if [[ -r /proc/sys/kernel/perf_event_paranoid ]]; then
        paranoid=$(cat /proc/sys/kernel/perf_event_paranoid)
    fi
    if [[ "$paranoid" -gt 2 ]]; then
        log_error "kernel.perf_event_paranoid is $paranoid — perf cannot access hardware counters."
        log_error "Fix it with one of:"
        log_error "  sudo sysctl kernel.perf_event_paranoid=1   (allow user-space measurement)"
        log_error "  sudo sysctl kernel.perf_event_paranoid=0   (allow kernel access too)"
        log_error "or re-run this script as root."
        exit 1
    fi
    if [[ "$paranoid" -eq 2 ]]; then
        log_warning "kernel.perf_event_paranoid=2 — some counters (kernel-side) may be unavailable"
    fi

    if ! perf stat -e cycles true &> /dev/null; then
        log_error "perf is installed but cannot measure hardware counters."
        log_error "Possible causes:"
        log_error "  - Running inside a VM without PMU passthrough (use -cpu host)"
        log_error "  - perf binary does not match the running kernel (linux-tools-$(uname -r))"
        log_error "  - paranoid setting blocks access (see /proc/sys/kernel/perf_event_paranoid)"
        exit 1
    fi

    log_success "Environment validation passed"
}

# Run perf stat and write the profile
collect_profile() {
    local perf_raw
    perf_raw="$(mktemp /tmp/opencode/barzakh-hpc.XXXXXX)"
    trap 'rm -f "$perf_raw"' RETURN

    local perf_events="cycles,cache-misses,cache-references,branch-misses,branches,instructions"

    # SMI counting needs root on most kernels; add it optimistically and
    # fall back to 0 when the event is unavailable.
    local events_with_smi="$perf_events"
    if perf stat -e cycles,msr/smi/ true &> /dev/null 2>&1; then
        events_with_smi="$perf_events,msr/smi/"
    fi

    if [[ -n "$WORKLOAD" ]]; then
        log_info "Running workload under perf stat: $WORKLOAD"
        if ! perf stat -e "$events_with_smi" -o "$perf_raw" bash -c "$WORKLOAD"; then
            log_error "Workload failed to run under perf stat"
            exit 1
        fi
    else
        log_info "Sampling system for ${DURATION}s..."
        # Use a background true(1) pinned for the duration as the measured process
        if ! perf stat -e "$events_with_smi" -o "$perf_raw" -- timeout "$DURATION" bash -c 'sleep infinity' 2> /dev/null; then
            # Older perf without -- timeout support: plain sleep
            perf stat -e "$events_with_smi" -o "$perf_raw" sleep "$DURATION"
        fi
    fi

    log_info "Parsing perf stat output..."

    local cpu_cycles cache_miss_rate branch_mispredict_rate smi_count dcache_evictions

    cpu_cycles=$(perf_value "cycles" "$perf_raw")
    if [[ -z "$cpu_cycles" ]]; then
        cpu_cycles=0
    fi

    cache_miss_rate=$(perf_ratio "cache-misses" "cache-references" "$perf_raw")
    branch_mispredict_rate=$(perf_ratio "branch-misses" "branches" "$perf_raw")

    smi_count=$(perf_value "msr/smi/" "$perf_raw")
    if [[ -z "$smi_count" ]]; then
        smi_count=0
    fi

    # dcache_evictions: no architected event exists; approximate with
    # dTLB-load-misses when available, otherwise cache-misses.
    dcache_evictions=$(perf_value "dTLB-load-misses" "$perf_raw")
    if [[ -z "$dcache_evictions" ]]; then
        dcache_evictions=$(perf_value "cache-misses" "$perf_raw")
    fi
    if [[ -z "$dcache_evictions" ]]; then
        dcache_evictions=0
    fi

    if [[ "$cpu_cycles" -eq 0 ]]; then
        log_warning "cpu_cycles is 0 — counters may not have been collected correctly"
    fi

    log_info "Writing profile to $OUTPUT"
    cat > "$OUTPUT" <<EOF
# barzakh-hpc-profile v1
cpu_cycles=$cpu_cycles
cache_miss_rate=$cache_miss_rate
branch_mispredict_rate=$branch_mispredict_rate
smi_count=$smi_count
dcache_evictions=$dcache_evictions
EOF

    log_success "HPC profile written to $OUTPUT"
    log_info "Feed it to the hpc_monitor detector with:"
    log_info "  barzakh-scanner scan --target <fw> --hpc-profile $OUTPUT"
}

# Main execution
main() {
    parse_args "$@"
    validate_environment
    collect_profile
}

# Run main function
main "$@"
