use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

// PPL (Page Protection Layer) markers — APRR register configuration
const APRR_MAGIC: [u8; 4] = [0x41, 0x50, 0x52, 0x52]; // "APRR"
const PPL_LOCKDOWN_MARKER: [u8; 4] = [0x50, 0x50, 0x4C, 0x4B]; // "PPLK"

pub struct IosPplDetector;

impl Default for IosPplDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl IosPplDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_ppl(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut found_aprr = false;
        let mut found_ppl_lock = false;

        for offset in 0..data.len().saturating_sub(16) {
            if data[offset..offset + 4] == APRR_MAGIC {
                found_aprr = true;
                self.validate_aprr_config(data, offset, &mut findings);
            }
            if data[offset..offset + 4] == PPL_LOCKDOWN_MARKER {
                found_ppl_lock = true;
                self.validate_ppl_lockdown(data, offset, &mut findings);
            }
        }

        // If APRR is present but PPL lock is absent, the page protection isn't fully engaged
        if found_aprr && !found_ppl_lock {
            findings.push(
                Finding::new(
                    "ios_ppl",
                    Severity::High,
                    "APRR configuration present but PPL lockdown marker missing",
                    "APRR register configuration found but no PPL lockdown indicator. \
                     Page Protection Layer may not be fully engaged — kernel page table \
                     modifications remain possible.",
                )
                .with_confidence(0.78),
            );
        }

        findings
    }

    fn validate_aprr_config(&self, data: &[u8], offset: usize, findings: &mut Vec<Finding>) {
        if offset + 16 > data.len() {
            return;
        }

        // APRR EL1 register values follow the magic
        // Byte +4: config flags — bit 0 should be 1 (enabled)
        let config_flags =
            u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap_or([0; 4]));

        if config_flags == 0 {
            findings.push(
                Finding::new(
                    "ios_ppl",
                    Severity::Critical,
                    "APRR configuration is zeroed (PPL disabled)",
                    &format!(
                        "APRR magic at 0x{:08X} has config_flags=0. \
                         Page Protection Layer enforcement is disabled — \
                         kernel code can modify page tables freely.",
                        offset
                    ),
                )
                .with_confidence(0.90)
                .with_recommendation(
                    "Restore the APRR configuration to enforce PPL page table isolation.",
                ),
            );
        }

        // Check for suspicious all-permissive page table entries (+8)
        let pte_mask =
            u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap_or([0; 4]));

        // 0x3 in both AP bits = EL0/EL1 full RWX (dangerous)
        if pte_mask == 0xFFFFFFFF {
            findings.push(
                Finding::new(
                    "ios_ppl",
                    Severity::High,
                    "APRR PTE mask is all-permissive",
                    &format!(
                        "APRR at 0x{:08X} has PTE mask 0xFFFFFFFF — all page table \
                         entries would be mapped RWX. This defeats W^X and PPL isolation.",
                        offset
                    ),
                )
                .with_confidence(0.85),
            );
        }
    }

    fn validate_ppl_lockdown(&self, data: &[u8], offset: usize, findings: &mut Vec<Finding>) {
        if offset + 12 > data.len() {
            return;
        }

        // Lock status at +4: 0 = not locked
        let lock_status =
            u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap_or([0; 4]));

        if lock_status == 0 {
            findings.push(
                Finding::new(
                    "ios_ppl",
                    Severity::Critical,
                    "PPL lockdown marker present but lock status is zero",
                    &format!(
                        "PPLK at 0x{:08X} has lock_status=0. The PPL lockdown \
                         has not been engaged — page tables remain writable from EL1.",
                        offset
                    ),
                )
                .with_confidence(0.88),
            );
        }
    }
}

impl Detector for IosPplDetector {
    fn name(&self) -> &str {
        "ios_ppl"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        Ok(self.check_ppl(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn fires_on_disabled_aprr() {
        let mut data = vec![0u8; 0x100];
        data[0..4].copy_from_slice(&APRR_MAGIC);
        // config_flags = 0 (disabled)
        data[4..8].copy_from_slice(&0u32.to_le_bytes());

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = IosPplDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn quiet_on_locked_ppl() {
        let mut data = vec![0u8; 0x100];
        // APRR with non-zero config
        data[0..4].copy_from_slice(&APRR_MAGIC);
        data[4..8].copy_from_slice(&0x01u32.to_le_bytes());
        data[8..12].copy_from_slice(&0x00000003u32.to_le_bytes()); // normal PTE mask
                                                                   // PPL locked
        data[0x20..0x24].copy_from_slice(&PPL_LOCKDOWN_MARKER);
        data[0x24..0x28].copy_from_slice(&0x01u32.to_le_bytes()); // locked

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = IosPplDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(findings.is_empty());
    }
}
