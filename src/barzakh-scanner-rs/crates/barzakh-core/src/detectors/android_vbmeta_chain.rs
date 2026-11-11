use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const AVB_MAGIC: [u8; 4] = [0x41, 0x56, 0x42, 0x30]; // "AVB0"
const VBMETA_MAGIC: &[u8] = b"AVBf";

pub struct AndroidVbmetaChainDetector;

impl Default for AndroidVbmetaChainDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AndroidVbmetaChainDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_vbmeta_chain(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for offset in 0..data.len().saturating_sub(256) {
            if data[offset..offset + 4] == AVB_MAGIC || data[offset..offset + 4] == *VBMETA_MAGIC {
                self.validate_vbmeta(data, offset, &mut findings);
            }
        }

        findings
    }

    fn validate_vbmeta(&self, data: &[u8], offset: usize, findings: &mut Vec<Finding>) {
        if offset + 128 > data.len() {
            return;
        }

        // Check algorithm type at +0x04
        let algo_type =
            u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap_or([0; 4]));

        // algo_type == 0 means AVB_ALGORITHM_TYPE_NONE (verification disabled)
        if algo_type == 0 {
            findings.push(
                Finding::new(
                    "android_vbmeta_chain",
                    Severity::Critical,
                    "Android vbmeta has verification disabled (AVB_ALGORITHM_TYPE_NONE)",
                    &format!(
                        "vbmeta image at 0x{:08X} uses algorithm type 0 (NONE). \
                         AVB chain of trust is completely broken — any partition content \
                         will be accepted without signature verification.",
                        offset
                    ),
                )
                .with_confidence(0.95)
                .with_details(serde_json::json!({
                    "vbmeta_offset": format!("0x{:08X}", offset),
                    "algorithm": "AVB_ALGORITHM_TYPE_NONE",
                }))
                .with_recommendation(
                    "Re-sign vbmeta with a valid AVB key and set algorithm to SHA256_RSA2048 or higher.",
                ),
            );
        }

        // Check rollback index at +0x10
        let rollback_index =
            u64::from_le_bytes(data[offset + 16..offset + 24].try_into().unwrap_or([0; 8]));

        if rollback_index == 0 && algo_type != 0 {
            findings.push(
                Finding::new(
                    "android_vbmeta_chain",
                    Severity::High,
                    "Android vbmeta rollback index is zero",
                    &format!(
                        "vbmeta at 0x{:08X} has rollback_index=0, defeating anti-rollback protection.",
                        offset
                    ),
                )
                .with_confidence(0.80),
            );
        }

        // Check for zeroed hash descriptor area (no partition hashes bound)
        let hash_desc_offset = offset + 64;
        if hash_desc_offset + 64 <= data.len() {
            let hash_area = &data[hash_desc_offset..hash_desc_offset + 64];
            if hash_area.iter().all(|&b| b == 0x00) {
                findings.push(
                    Finding::new(
                        "android_vbmeta_chain",
                        Severity::High,
                        "vbmeta hash descriptor area is empty",
                        &format!(
                            "vbmeta at 0x{:08X} has zeroed hash descriptor region. \
                             No partition hashes are bound to this vbmeta — boot, dtbo, \
                             and vendor_boot partitions are unverified.",
                            offset
                        ),
                    )
                    .with_confidence(0.75),
                );
            }
        }
    }
}

impl Detector for AndroidVbmetaChainDetector {
    fn name(&self) -> &str {
        "android_vbmeta_chain"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }

    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        Ok(self.check_vbmeta_chain(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn fires_on_disabled_verification() {
        let mut data = vec![0u8; 0x200];
        data[0..4].copy_from_slice(&AVB_MAGIC);
        // algo_type = 0 (NONE)
        data[4..8].copy_from_slice(&0u32.to_le_bytes());

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = AndroidVbmetaChainDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn quiet_on_clean() {
        let mut data = vec![0u8; 0x200];
        // Valid algo type and non-zero rollback + non-zero hash area
        data[0..4].copy_from_slice(&AVB_MAGIC);
        data[4..8].copy_from_slice(&1u32.to_le_bytes()); // SHA256_RSA2048
        data[16..24].copy_from_slice(&5u64.to_le_bytes()); // rollback=5
        data[64..68].fill(0xAA); // non-zero hash area

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = AndroidVbmetaChainDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(findings.is_empty());
    }
}
