use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

pub struct SmmTimingDetector;

impl Default for SmmTimingDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SmmTimingDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_tseg_integrity(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Look for TSEG base address patterns (typically in 0x7F000000-0x80000000 range)
        // TSEG base/mask MSR values appear as 8-byte values in firmware images
        for (i, window) in data.windows(8).enumerate() {
            let value = u64::from_le_bytes(window.try_into().unwrap_or([0; 8]));

            // Check if this looks like a TSEG base address
            let base = value & 0xFFF00000;
            if (0x7F000000..=0x80000000).contains(&base) {
                // Check lock bit (bit 0 of the mask register, typically next 8 bytes)
                if i + 16 <= data.len() {
                    let mask_value =
                        u64::from_le_bytes(data[i + 8..i + 16].try_into().unwrap_or([0; 8]));
                    // Lock bit is bit 0
                    if mask_value != 0 && (mask_value & 0x01) == 0 {
                        findings.push(
                            Finding::new(
                                "smm_timing",
                                Severity::High,
                                "TSEG region lock bit not set",
                                &format!(
                                    "TSEG base address 0x{:08X} found at offset 0x{:08X} \
                                     with lock bit clear in mask register. An unlocked TSEG \
                                     allows modification of SMM memory regions.",
                                    base, i
                                ),
                            )
                            .with_confidence(0.60)
                            .with_details(serde_json::json!({
                                "offset": format!("0x{:08X}", i),
                                "tseg_base": format!("0x{:08X}", base),
                                "mask_value": format!("0x{:016X}", mask_value),
                            }))
                            .with_recommendation(
                                "Ensure TSEG lock bit is set during platform initialization \
                                 to prevent runtime modification of SMRAM boundaries.",
                            ),
                        );
                        // Only report the first occurrence
                        break;
                    }
                }
            }
        }

        findings
    }

    fn check_smm_handler_anomaly(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Look for RSM instruction (0x0F 0xAA) which is the SMI handler return
        let rsm_pattern: &[u8] = &[0x0F, 0xAA];

        for (i, window) in data.windows(2).enumerate() {
            if window == rsm_pattern {
                // Check surrounding bytes for suspicious instructions
                let context_start = i.saturating_sub(32);
                let context_end = std::cmp::min(i + 32, data.len());
                let context = &data[context_start..context_end];

                let mut suspicious = false;
                let mut reason = String::new();

                // Check for INT3 (breakpoint) near SMI handler
                if context.contains(&0xCC) {
                    suspicious = true;
                    reason = "INT3 breakpoint instruction found near SMI handler".to_string();
                }

                // Check for far JMP patterns (0xEA followed by address)
                for byte in context.iter().take(context.len().saturating_sub(5)) {
                    if *byte == 0xEA {
                        suspicious = true;
                        reason = "Far JMP instruction found near SMI handler".to_string();
                        break;
                    }
                }

                if suspicious {
                    findings.push(
                        Finding::new(
                            "smm_timing",
                            Severity::Critical,
                            "Anomalous SMI handler code detected",
                            &format!(
                                "RSM instruction at offset 0x{:08X} has suspicious code nearby: {}. \
                                 This may indicate SMM handler manipulation or persistence mechanism.",
                                i, reason
                            ),
                        )
                        .with_confidence(0.55)
                        .with_details(serde_json::json!({
                            "rsm_offset": format!("0x{:08X}", i),
                            "reason": reason,
                        })),
                    );
                }
            }
        }

        findings
    }

    fn check_smram_dump_artifacts(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // SMM Save State Map has a known layout. Key identifiers:
        // - At SMBASE + 0xFE00: SMM revision identifier
        // - At SMBASE + 0xFEFC: SMBASE field itself
        // Look for the SMM revision ID pattern (typically 0x00030064 for modern Intel)
        let smm_revision_patterns: &[u32] = &[0x00030064, 0x00030100, 0x00020064];

        for pattern in smm_revision_patterns {
            let pattern_bytes = pattern.to_le_bytes();
            for (i, window) in data.windows(4).enumerate() {
                if window == pattern_bytes {
                    // Check if this is likely a save state map by looking for
                    // plausible register values nearby (CR0 with PE bit set, etc.)
                    let check_start = i.saturating_sub(0x100);
                    let check_end = std::cmp::min(i + 0x100, data.len());

                    if check_end - check_start >= 0x100 {
                        // Look for typical CR0 value (bit 0 = PE, bit 31 = PG)
                        let region = &data[check_start..check_end];
                        let has_cr0_pattern = region.windows(4).any(|w| {
                            let val = u32::from_le_bytes(w.try_into().unwrap_or([0; 4]));
                            // CR0 with PE and PG set: 0x80000001 or similar
                            val & 0x80000001 == 0x80000001 && val < 0x90000000
                        });

                        if has_cr0_pattern {
                            findings.push(
                                Finding::new(
                                    "smm_timing",
                                    Severity::Medium,
                                    "SMRAM content detected outside protected region",
                                    &format!(
                                        "SMM Save State Map pattern (revision 0x{:08X}) found at \
                                         offset 0x{:08X}. This may indicate SMRAM content has \
                                         been dumped or leaked into accessible memory.",
                                        pattern, i
                                    ),
                                )
                                .with_confidence(0.45)
                                .with_details(serde_json::json!({
                                    "offset": format!("0x{:08X}", i),
                                    "smm_revision": format!("0x{:08X}", pattern),
                                })),
                            );
                            // Report at most one per pattern
                            break;
                        }
                    }
                }
            }
        }

        findings
    }
}

impl Detector for SmmTimingDetector {
    fn name(&self) -> &str {
        "smm_timing"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let mut findings = Vec::new();

        findings.extend(self.check_tseg_integrity(&data));
        findings.extend(self.check_smm_handler_anomaly(&data));
        findings.extend(self.check_smram_dump_artifacts(&data));

        Ok(findings)
    }
}
