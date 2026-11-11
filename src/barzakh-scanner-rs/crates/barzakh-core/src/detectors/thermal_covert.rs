use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

// WRMSR opcode
const WRMSR: [u8; 2] = [0x0F, 0x30];

// RAPL MSR addresses (as 2-byte LE sequences used in MOV ECX, imm32 encodings)
// MSR 0x610 = PKG_POWER_LIMIT
const MSR_PKG_POWER_LIMIT: [u8; 2] = [0x10, 0x06];
// MSR 0x619 = DRAM_POWER_LIMIT
const MSR_DRAM_POWER_LIMIT: [u8; 2] = [0x19, 0x06];
// MSR 0x614 = PKG_ENERGY_STATUS
const MSR_PKG_ENERGY_STATUS: [u8; 2] = [0x14, 0x06];

// MSR 0x1A2 = TEMPERATURE_TARGET
const MSR_TEMPERATURE_TARGET: [u8; 2] = [0xA2, 0x01];

// MSR 0x199 = IA32_PERF_CTL
const MSR_IA32_PERF_CTL: [u8; 2] = [0x99, 0x01];

// ACPI thermal zone strings
const ACPI_TMP: &[u8] = b"_TMP";
const ACPI_AC0: &[u8] = b"_AC0";
const ACPI_PSV: &[u8] = b"_PSV";

/// Bytes to look back before WRMSR when searching for MSR address loads
const MSR_LOAD_LOOKBACK: usize = 16;

/// Window for counting RAPL WRMSR density
const RAPL_WINDOW: usize = 256;
/// Threshold: more than 2 RAPL-targeting WRMSRs in 256 bytes = covert channel
const RAPL_WRMSR_THRESHOLD: usize = 2;

/// Window for counting P-state WRMSR density
const PSTATE_WINDOW: usize = 512;
/// Threshold: more than 3 P-state WRMSRs in 512 bytes = suspicious
const PSTATE_WRMSR_THRESHOLD: usize = 3;

pub struct ThermalCovertDetector;

impl Default for ThermalCovertDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ThermalCovertDetector {
    pub fn new() -> Self {
        Self
    }

    /// Check whether any of the given 2-byte MSR address patterns appear within
    /// `lookback` bytes before offset `wrmsr_pos` in `data`.
    fn msr_pattern_precedes(
        data: &[u8],
        wrmsr_pos: usize,
        patterns: &[&[u8; 2]],
        lookback: usize,
    ) -> bool {
        let search_start = wrmsr_pos.saturating_sub(lookback);
        let region = &data[search_start..wrmsr_pos];
        for pat in patterns {
            if region.windows(2).any(|w| w == *pat as &[u8]) {
                return true;
            }
        }
        false
    }

    /// Collect offsets of all WRMSR instructions preceded by one of the given
    /// MSR address patterns within `lookback` bytes.
    fn collect_targeted_wrmsr_offsets(
        data: &[u8],
        patterns: &[&[u8; 2]],
        lookback: usize,
    ) -> Vec<usize> {
        let mut offsets = Vec::new();
        for i in 0..data.len().saturating_sub(2) {
            if data[i..i + 2] == WRMSR && Self::msr_pattern_precedes(data, i, patterns, lookback) {
                offsets.push(i);
            }
        }
        offsets
    }

    /// Detect RAPL MSR manipulation (PKG_POWER_LIMIT, DRAM_POWER_LIMIT, PKG_ENERGY_STATUS).
    fn check_rapl_msr_manipulation(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let rapl_patterns: &[&[u8; 2]] = &[
            &MSR_PKG_POWER_LIMIT,
            &MSR_DRAM_POWER_LIMIT,
            &MSR_PKG_ENERGY_STATUS,
        ];

        let offsets = Self::collect_targeted_wrmsr_offsets(data, rapl_patterns, MSR_LOAD_LOOKBACK);

        if offsets.is_empty() {
            return findings;
        }

        // Slide a 256-byte window and flag dense clusters
        let mut reported_windows: Vec<usize> = Vec::new();
        for &wrmsr_offset in &offsets {
            let window_start = wrmsr_offset.saturating_sub(RAPL_WINDOW);
            let count_in_window = offsets
                .iter()
                .filter(|&&o| o >= window_start && o <= wrmsr_offset)
                .count();

            if count_in_window > RAPL_WRMSR_THRESHOLD {
                if reported_windows
                    .iter()
                    .any(|&prev| wrmsr_offset.saturating_sub(prev) < RAPL_WINDOW)
                {
                    continue;
                }
                reported_windows.push(wrmsr_offset);

                findings.push(
                    Finding::new(
                        "thermal_covert",
                        Severity::High,
                        "Dense RAPL MSR writes — potential thermal power covert channel",
                        &format!(
                            "Found {} RAPL-targeting WRMSR instructions within a {} byte \
                             window ending at offset 0x{:08X}. MSRs targeted include \
                             PKG_POWER_LIMIT (0x610), DRAM_POWER_LIMIT (0x619), and/or \
                             PKG_ENERGY_STATUS (0x614). Repeated RAPL manipulation can \
                             encode data through package power consumption as a covert \
                             side-channel.",
                            count_in_window, RAPL_WINDOW, wrmsr_offset
                        ),
                    )
                    .with_confidence(0.85)
                    .with_details(serde_json::json!({
                        "window_end_offset": format!("0x{:08X}", wrmsr_offset),
                        "rapl_wrmsr_count": count_in_window,
                        "threshold": RAPL_WRMSR_THRESHOLD,
                        "msrs_targeted": ["PKG_POWER_LIMIT (0x610)", "DRAM_POWER_LIMIT (0x619)", "PKG_ENERGY_STATUS (0x614)"],
                    }))
                    .with_recommendation(
                        "Restrict firmware access to RAPL MSRs. Enable RAPL locking \
                         (PKG_POWER_LIMIT lock bit) and audit any firmware path that \
                         writes to power-limit MSRs outside of legitimate DPTF/EC handlers.",
                    ),
                );
            }
        }

        findings
    }

    /// Detect TEMPERATURE_TARGET MSR writes and adjacent ACPI thermal zone strings.
    fn check_thermal_target_manipulation(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let temp_patterns: &[&[u8; 2]] = &[&MSR_TEMPERATURE_TARGET];
        let wrmsr_offsets =
            Self::collect_targeted_wrmsr_offsets(data, temp_patterns, MSR_LOAD_LOOKBACK);

        for &wrmsr_offset in &wrmsr_offsets {
            let region_start = wrmsr_offset.saturating_sub(64);
            let region_end = (wrmsr_offset + 64).min(data.len());
            let region = &data[region_start..region_end];

            findings.push(
                Finding::new(
                    "thermal_covert",
                    Severity::High,
                    "TEMPERATURE_TARGET MSR write detected",
                    &format!(
                        "WRMSR targeting MSR 0x1A2 (IA32_TEMPERATURE_TARGET) found at \
                         offset 0x{:08X}. Manipulating the thermal trip point can be \
                         used to throttle CPU performance in a controlled pattern, \
                         creating a thermal covert signaling channel.",
                        wrmsr_offset
                    ),
                )
                .with_confidence(0.80)
                .with_details(serde_json::json!({
                    "offset": format!("0x{:08X}", wrmsr_offset),
                    "msr": "0x1A2 (IA32_TEMPERATURE_TARGET)",
                }))
                .with_recommendation(
                    "Lock the TEMPERATURE_TARGET MSR in firmware init and prohibit \
                     runtime writes. Verify ACPI thermal zone handlers do not \
                     accept untrusted input for thermal limit adjustment.",
                ),
            );

            // Check for ACPI thermal zone strings nearby
            let acpi_strings = [ACPI_TMP, ACPI_AC0, ACPI_PSV];
            for acpi_str in &acpi_strings {
                if region.windows(acpi_str.len()).any(|w| w == *acpi_str) {
                    findings.push(
                        Finding::new(
                            "thermal_covert",
                            Severity::High,
                            "ACPI thermal zone string adjacent to TEMPERATURE_TARGET write",
                            &format!(
                                "ACPI thermal zone identifier '{}' found within 64 bytes \
                                 of a TEMPERATURE_TARGET WRMSR at offset 0x{:08X}. \
                                 This co-location suggests a thermal zone handler that \
                                 modifies CPU temperature limits, enabling covert \
                                 signaling via observable thermal throttling.",
                                String::from_utf8_lossy(acpi_str),
                                wrmsr_offset
                            ),
                        )
                        .with_confidence(0.78)
                        .with_details(serde_json::json!({
                            "wrmsr_offset": format!("0x{:08X}", wrmsr_offset),
                            "acpi_identifier": String::from_utf8_lossy(acpi_str),
                        }))
                        .with_recommendation(
                            "Audit ACPI thermal zone AML code for control-flow paths \
                             that write to temperature limit MSRs. Restrict thermal \
                             management to trusted EC firmware.",
                        ),
                    );
                }
            }
        }

        findings
    }

    /// Detect dense IA32_PERF_CTL MSR writes suggesting P-state modulation.
    fn check_pstate_modulation(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let pstate_patterns: &[&[u8; 2]] = &[&MSR_IA32_PERF_CTL];
        let offsets =
            Self::collect_targeted_wrmsr_offsets(data, pstate_patterns, MSR_LOAD_LOOKBACK);

        if offsets.is_empty() {
            return findings;
        }

        let mut reported_windows: Vec<usize> = Vec::new();
        for &wrmsr_offset in &offsets {
            let window_start = wrmsr_offset.saturating_sub(PSTATE_WINDOW);
            let count_in_window = offsets
                .iter()
                .filter(|&&o| o >= window_start && o <= wrmsr_offset)
                .count();

            if count_in_window > PSTATE_WRMSR_THRESHOLD {
                if reported_windows
                    .iter()
                    .any(|&prev| wrmsr_offset.saturating_sub(prev) < PSTATE_WINDOW)
                {
                    continue;
                }
                reported_windows.push(wrmsr_offset);

                findings.push(
                    Finding::new(
                        "thermal_covert",
                        Severity::Medium,
                        "Dense IA32_PERF_CTL writes — potential P-state covert channel",
                        &format!(
                            "Found {} IA32_PERF_CTL (MSR 0x199) WRMSR instructions within \
                             a {} byte window ending at offset 0x{:08X}. Rapidly cycling \
                             P-states encodes information in observable CPU frequency \
                             patterns, enabling a covert signaling channel detectable \
                             via power analysis or performance counters.",
                            count_in_window, PSTATE_WINDOW, wrmsr_offset
                        ),
                    )
                    .with_confidence(0.75)
                    .with_details(serde_json::json!({
                        "window_end_offset": format!("0x{:08X}", wrmsr_offset),
                        "perf_ctl_wrmsr_count": count_in_window,
                        "threshold": PSTATE_WRMSR_THRESHOLD,
                        "msr": "0x199 (IA32_PERF_CTL)",
                    }))
                    .with_recommendation(
                        "Audit firmware P-state management routines for unusual frequency \
                         switching patterns. Consider enabling Hardware P-State (HWP) \
                         control to prevent firmware-driven P-state modulation at runtime.",
                    ),
                );
            }
        }

        findings
    }
}

impl Detector for ThermalCovertDetector {
    fn name(&self) -> &str {
        "thermal_covert"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_rapl_msr_manipulation(&data));
        findings.extend(self.check_thermal_target_manipulation(&data));
        findings.extend(self.check_pstate_modulation(&data));

        Ok(findings)
    }
}
