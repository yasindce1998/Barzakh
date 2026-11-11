use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const KEYM_MAGIC: [u8; 8] = [0x5F, 0x5F, 0x4B, 0x45, 0x59, 0x4D, 0x5F, 0x5F]; // "__KEYM__"
const BPM_MAGIC: [u8; 8] = [0x5F, 0x5F, 0x41, 0x43, 0x42, 0x50, 0x5F, 0x5F]; // "__ACBP__"

pub struct BootGuardKmDetector;

impl Default for BootGuardKmDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BootGuardKmDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_key_manifest(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for offset in 0..data.len().saturating_sub(264) {
            if data[offset..offset + 8] == KEYM_MAGIC {
                self.validate_km_structure(data, offset, &mut findings);
            }
        }

        for offset in 0..data.len().saturating_sub(264) {
            if data[offset..offset + 8] == BPM_MAGIC {
                self.validate_bpm_structure(data, offset, &mut findings);
            }
        }

        findings
    }

    fn validate_km_structure(&self, data: &[u8], offset: usize, findings: &mut Vec<Finding>) {
        if offset + 0x114 > data.len() {
            return;
        }

        let version = data[offset + 8];
        let key_hash_offset = offset + 0x14;

        // Check if RSA-2048 key hash is zeroed (256 bytes)
        let key_hash =
            &data[key_hash_offset..key_hash_offset + 256.min(data.len() - key_hash_offset)];
        if key_hash.iter().all(|&b| b == 0x00) {
            findings.push(
                Finding::new(
                    "boot_guard_km",
                    Severity::Critical,
                    "Boot Guard Key Manifest has zeroed key hash",
                    &format!(
                        "Key Manifest at offset 0x{:08X} (version {}) contains an all-zero \
                         RSA-2048 key hash. This effectively disables Boot Guard measured/verified \
                         boot, allowing arbitrary firmware to execute.",
                        offset, version
                    ),
                )
                .with_confidence(0.95)
                .with_details(serde_json::json!({
                    "km_offset": format!("0x{:08X}", offset),
                    "version": version,
                    "key_hash_zeroed": true,
                }))
                .with_recommendation(
                    "Key Manifest must contain valid OEM public key hash. \
                     Reprogram the FPFs or reflash with OEM-signed firmware.",
                ),
            );
        }

        // Check for weak/test key pattern (repeating byte)
        if key_hash.len() >= 256 {
            let first_byte = key_hash[0];
            if first_byte != 0 && key_hash.iter().all(|&b| b == first_byte) {
                findings.push(
                    Finding::new(
                        "boot_guard_km",
                        Severity::High,
                        "Boot Guard Key Manifest contains test/weak key hash",
                        &format!(
                            "Key Manifest at 0x{:08X} has a repeating-byte key hash pattern \
                             (0x{:02X}), likely a test/debug key not suitable for production.",
                            offset, first_byte
                        ),
                    )
                    .with_confidence(0.85),
                );
            }
        }
    }

    fn validate_bpm_structure(&self, data: &[u8], offset: usize, findings: &mut Vec<Finding>) {
        if offset + 0x20 > data.len() {
            return;
        }

        let version = data[offset + 8];
        let flags = u16::from_le_bytes(data[offset + 10..offset + 12].try_into().unwrap_or([0; 2]));

        // If BPM flags indicate disabled enforcement
        if flags & 0x01 == 0 && flags != 0 {
            findings.push(
                Finding::new(
                    "boot_guard_km",
                    Severity::High,
                    "Boot Policy Manifest enforcement disabled",
                    &format!(
                        "Boot Policy Manifest at 0x{:08X} (version {}) has enforcement bit \
                         cleared (flags: 0x{:04X}). Boot Guard measured boot may not halt \
                         on verification failure.",
                        offset, version, flags
                    ),
                )
                .with_confidence(0.80)
                .with_details(serde_json::json!({
                    "bpm_offset": format!("0x{:08X}", offset),
                    "version": version,
                    "flags": format!("0x{:04X}", flags),
                })),
            );
        }
    }
}

impl Detector for BootGuardKmDetector {
    fn name(&self) -> &str {
        "boot_guard_km"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }

    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        Ok(self.check_key_manifest(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn fires_on_zeroed_key_hash() {
        let mut data = vec![0u8; 0x200];
        data[0x00..0x08].copy_from_slice(&KEYM_MAGIC);
        data[0x08] = 0x02; // version
                           // key_hash at 0x14 is all zeros

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = BootGuardKmDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(!findings.is_empty());
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn quiet_on_clean() {
        let data = vec![0u8; 0x200];
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = BootGuardKmDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(findings.is_empty());
    }
}
