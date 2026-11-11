use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

// MSR 0xC80 — IA32_DEBUG_INTERFACE (DCI enable/lock)
// Little-endian u16 representation of 0x0C80
const MSR_DEBUG_INTERFACE_LO: u8 = 0x80;
const MSR_DEBUG_INTERFACE_HI: u8 = 0x0C;

// MSR 0xDB0 — HDC (Hardware Duty Cycling, also used for debug consent gating)
// Little-endian u16 representation of 0x0DB0
const MSR_HDC_LO: u8 = 0xB0;
const MSR_HDC_HI: u8 = 0x0D;

// x86 WRMSR opcode (documented for reference; bytes are matched inline for position context)
#[allow(dead_code)]
const WRMSR: &[u8] = &[0x0F, 0x30];

// ASCII patterns
const JTAG_MARKER: &[u8] = b"JTAG";
const DCI_EN_MARKER: &[u8] = b"DCI_EN";
const DEBUG_MARKER: &[u8] = b"DEBUG";
const BOOT_GUARD_MARKER: &[u8] = b"BootGuard";
const BT_GUARD_MARKER: &[u8] = b"BtGuard";

// ARM CoreSight DAP address space prefix
const DAP_ADDRESS_PREFIX_0: u8 = 0xED;
const DAP_ADDRESS_PREFIX_1: u8 = 0x00;

// DAP lock access register range: offsets 0xFB0–0xFBC (low byte range for quick scan)
const DAP_LOCK_REG_LO_MIN: u8 = 0xB0;
const DAP_LOCK_REG_LO_MAX: u8 = 0xBC;
// High byte of the 0xFBx offset
const DAP_LOCK_REG_HI: u8 = 0x0F;

pub struct DebugInterfaceDetector;

impl Default for DebugInterfaceDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DebugInterfaceDetector {
    pub fn new() -> Self {
        Self
    }

    /// Detect DCI (Direct Connect Interface) enablement via MSR 0xC80 WRMSR.
    /// DCI enablement in production firmware grants USB-based JTAG access without
    /// physical debug pins and is a critical security violation.
    fn check_dci_enable(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for i in 0..data.len().saturating_sub(1) {
            if data[i] != 0x0F || data[i + 1] != 0x30 {
                continue;
            }

            let scan_start = i.saturating_sub(16);
            let pre_wrmsr = &data[scan_start..i];

            let has_msr_c80 = pre_wrmsr
                .windows(2)
                .any(|w| w[0] == MSR_DEBUG_INTERFACE_LO && w[1] == MSR_DEBUG_INTERFACE_HI);

            if !has_msr_c80 {
                continue;
            }

            // Check whether bit 0 (enable bit) appears set in the surrounding value bytes.
            // A WRMSR with EDX:EAX where EAX bit 0 = 1 enables DCI.
            let enable_bit_set = pre_wrmsr
                .windows(2)
                .any(|w| w[0] & 0x01 != 0 && w[1] == 0x00);

            findings.push(
                Finding::new(
                    "debug_interface",
                    Severity::Critical,
                    "DCI (Direct Connect Interface) enable via MSR 0xC80",
                    &format!(
                        "WRMSR targeting IA32_DEBUG_INTERFACE (MSR 0xC80) at offset \
                         0x{:08X}{}. DCI enablement allows USB-based CPU debug access \
                         without physical JTAG pins, bypassing all physical access controls.",
                        i,
                        if enable_bit_set {
                            " with enable bit (bit 0) set"
                        } else {
                            ""
                        }
                    ),
                )
                .with_confidence(if enable_bit_set { 0.93 } else { 0.80 })
                .with_details(serde_json::json!({
                    "offset": format!("0x{:08X}", i),
                    "msr": "0xC80 (IA32_DEBUG_INTERFACE)",
                    "enable_bit_set": enable_bit_set,
                    "technique": "Intel DCI USB debug enablement",
                }))
                .with_recommendation(
                    "Disable DCI in production firmware (set IA32_DEBUG_INTERFACE lock bit). \
                     Ensure MSR 0xC80 bit 30 (lock) is set before handoff to OS. \
                     Verify via Intel platform debug configuration policy.",
                ),
            );
        }

        findings
    }

    /// Detect JTAG TAP enablement via GPIO pin mux patterns or embedded ASCII markers.
    fn check_jtag_tap_enable(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // ASCII marker scan: "JTAG", "DCI_EN", "DEBUG"
        let markers: &[(&[u8], &str)] = &[
            (JTAG_MARKER, "JTAG string marker"),
            (DCI_EN_MARKER, "DCI_EN string marker"),
            (DEBUG_MARKER, "DEBUG string marker"),
        ];

        for &(marker, label) in markers {
            for pos in (0..data.len().saturating_sub(marker.len()))
                .filter(|&p| data[p..].starts_with(marker))
            {
                findings.push(
                    Finding::new(
                        "debug_interface",
                        Severity::High,
                        "JTAG/debug string marker found in firmware image",
                        &format!(
                            "{} found at offset 0x{:08X}. Debug interface identifiers in \
                             production firmware may indicate active or residual debug \
                             configuration code.",
                            label, pos
                        ),
                    )
                    .with_confidence(0.65)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", pos),
                        "marker": std::str::from_utf8(marker).unwrap_or("<binary>"),
                        "technique": "JTAG/debug interface string residue",
                    }))
                    .with_recommendation(
                        "Audit debug string references for active debug GPIO or TAP \
                         configuration code paths reachable at runtime.",
                    ),
                );
            }
        }

        // GPIO pin mux pattern: byte 0x0C followed by pin function select bytes 0x01-0x04
        // in sequence (TCK=0x01, TMS=0x02, TDI=0x03, TDO=0x04 as common JTAG pin roles).
        for i in 0..data.len().saturating_sub(4) {
            if data[i] != 0x0C {
                continue;
            }
            if data[i + 1] == 0x01
                && data[i + 2] == 0x02
                && data[i + 3] == 0x03
                && data[i + 4] == 0x04
            {
                findings.push(
                    Finding::new(
                        "debug_interface",
                        Severity::Critical,
                        "JTAG GPIO pin mux sequence detected",
                        &format!(
                            "GPIO pin function select sequence (0x0C 0x01 0x02 0x03 0x04) at \
                             offset 0x{:08X}. This matches TCK/TMS/TDI/TDO JTAG pin \
                             multiplexing assignments, indicating JTAG TAP activation.",
                            i
                        ),
                    )
                    .with_confidence(0.82)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", i),
                        "sequence": "0x0C 0x01 0x02 0x03 0x04",
                        "pin_roles": ["TCK", "TMS", "TDI", "TDO"],
                        "technique": "JTAG TAP GPIO pin multiplexing",
                    }))
                    .with_recommendation(
                        "Verify JTAG GPIO pin assignments are locked to non-JTAG functions \
                         in production builds. Audit firmware GPIO configuration tables.",
                    ),
                );
            }
        }

        findings
    }

    /// Detect debug consent bypass patterns: MSR 0xDB0 near WRMSR, or Boot Guard debug
    /// consent disable strings near debug register manipulation.
    fn check_debug_consent_bypass(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // MSR 0xDB0 (HDC) WRMSR occurrences
        let mut hdc_wrmsr_offsets: Vec<usize> = Vec::new();
        for i in 0..data.len().saturating_sub(1) {
            if data[i] != 0x0F || data[i + 1] != 0x30 {
                continue;
            }
            let scan_start = i.saturating_sub(16);
            let pre = &data[scan_start..i];
            if pre
                .windows(2)
                .any(|w| w[0] == MSR_HDC_LO && w[1] == MSR_HDC_HI)
            {
                hdc_wrmsr_offsets.push(i);
                findings.push(
                    Finding::new(
                        "debug_interface",
                        Severity::High,
                        "HDC MSR 0xDB0 write near debug manipulation",
                        &format!(
                            "WRMSR targeting MSR 0xDB0 (HDC) at offset 0x{:08X}. Writing this \
                             MSR can affect debug consent gating on some Intel platforms.",
                            i
                        ),
                    )
                    .with_confidence(0.70)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", i),
                        "msr": "0xDB0 (HDC)",
                        "technique": "HDC debug consent bypass attempt",
                    }))
                    .with_recommendation(
                        "Verify HDC MSR access is locked before OS handoff. Review \
                         debug consent policy enforcement in firmware.",
                    ),
                );
            }
        }

        // Boot Guard string markers near debug register patterns
        let bg_markers: &[(&[u8], &str)] = &[
            (BOOT_GUARD_MARKER, "BootGuard"),
            (BT_GUARD_MARKER, "BtGuard"),
        ];

        for &(marker, label) in bg_markers {
            for bg_pos in (0..data.len().saturating_sub(marker.len()))
                .filter(|&p| data[p..].starts_with(marker))
            {
                // Check whether any HDC WRMSR or debug MSR write is within 256 bytes
                let near_debug = hdc_wrmsr_offsets
                    .iter()
                    .any(|&off| off.abs_diff(bg_pos) <= 256);

                if near_debug {
                    findings.push(
                        Finding::new(
                            "debug_interface",
                            Severity::Critical,
                            "Boot Guard debug consent bypass pattern",
                            &format!(
                                "'{}' string at offset 0x{:08X} is within 256 bytes of an HDC \
                                 (MSR 0xDB0) WRMSR. This proximity suggests firmware code that \
                                 disables Boot Guard debug consent checking.",
                                label, bg_pos
                            ),
                        )
                        .with_confidence(0.87)
                        .with_details(serde_json::json!({
                            "bootguard_offset": format!("0x{:08X}", bg_pos),
                            "marker": label,
                            "technique": "Boot Guard debug consent bypass",
                        }))
                        .with_recommendation(
                            "Inspect firmware code at the flagged offset for debug consent \
                             policy manipulation. Validate Boot Guard policy descriptor \
                             settings match production security requirements.",
                        ),
                    );
                }
            }
        }

        findings
    }

    /// Detect ARM CoreSight DAP unlock patterns: DAP address-space prefix bytes (0xED 0x00)
    /// followed by authentication register offsets in the 0xFB0–0xFBC range.
    fn check_dap_unlock(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for i in 0..data.len().saturating_sub(3) {
            if data[i] != DAP_ADDRESS_PREFIX_0 || data[i + 1] != DAP_ADDRESS_PREFIX_1 {
                continue;
            }

            // The next two bytes encode an offset into the DAP address space.
            // The lock access register (LAR) is at 0xFB0; unlock key = 0xC5ACCE55.
            let offset_lo = data[i + 2];
            let offset_hi = data[i + 3];

            let is_lock_reg = offset_hi == DAP_LOCK_REG_HI
                && (DAP_LOCK_REG_LO_MIN..=DAP_LOCK_REG_LO_MAX).contains(&offset_lo);

            if is_lock_reg {
                findings.push(
                    Finding::new(
                        "debug_interface",
                        Severity::Critical,
                        "ARM CoreSight DAP lock access register (LAR) manipulation",
                        &format!(
                            "CoreSight DAP address prefix (0xED 0x00) at offset 0x{:08X} \
                             followed by register offset 0x0F{:02X}, which falls within the \
                             lock access register range (0xFB0–0xFBC). Writing the CoreSight \
                             unlock key (0xC5ACCE55) to the LAR disables DAP authentication, \
                             granting full debug access to the ARM processor.",
                            i, offset_lo
                        ),
                    )
                    .with_confidence(0.88)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", i),
                        "dap_register_offset": format!("0x0F{:02X}", offset_lo),
                        "register_range": "0xFB0-0xFBC (CoreSight LAR/LSR)",
                        "technique": "ARM CoreSight DAP authentication bypass",
                    }))
                    .with_recommendation(
                        "Ensure CoreSight DAP authentication is enforced in production. \
                         Lock the DAP lock access register before handoff. \
                         Verify TrustZone debug authentication policy does not allow \
                         non-secure world DAP unlock.",
                    ),
                );
            }
        }

        findings
    }
}

impl Detector for DebugInterfaceDetector {
    fn name(&self) -> &str {
        "debug_interface"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }

    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_dci_enable(&data));
        findings.extend(self.check_jtag_tap_enable(&data));
        findings.extend(self.check_debug_consent_bypass(&data));
        findings.extend(self.check_dap_unlock(&data));

        Ok(findings)
    }
}
