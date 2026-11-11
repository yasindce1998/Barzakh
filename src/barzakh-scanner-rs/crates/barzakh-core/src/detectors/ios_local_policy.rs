use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const LPOL_MAGIC: [u8; 4] = [0x6C, 0x70, 0x6F, 0x6C]; // "lpol"
const IMG4_MANIFEST_MAGIC: [u8; 4] = [0x49, 0x4D, 0x34, 0x4D]; // "IM4M"

pub struct IosLocalPolicyDetector;

impl Default for IosLocalPolicyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl IosLocalPolicyDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_local_policy(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for offset in 0..data.len().saturating_sub(64) {
            if data[offset..offset + 4] == LPOL_MAGIC {
                self.validate_lpol(data, offset, &mut findings);
            }
            if data[offset..offset + 4] == IMG4_MANIFEST_MAGIC {
                self.validate_manifest_policy(data, offset, &mut findings);
            }
        }

        findings
    }

    fn validate_lpol(&self, data: &[u8], offset: usize, findings: &mut Vec<Finding>) {
        if offset + 0x80 > data.len() {
            return;
        }

        // LocalPolicy structure: magic(4) + version(4) + nonce_hash(32) + next_stage_hash(32)
        let nonce_hash = &data[offset + 8..offset + 40];
        let next_stage_hash = &data[offset + 40..offset + 72];

        // Zeroed nonce hash means anti-replay protection is defeated
        if nonce_hash.iter().all(|&b| b == 0x00) {
            findings.push(
                Finding::new(
                    "ios_local_policy",
                    Severity::Critical,
                    "LocalPolicy nonce hash is zeroed (anti-replay defeated)",
                    &format!(
                        "lpol at 0x{:08X} has zeroed nonce_hash. \
                         Anti-replay protection is non-functional — \
                         old boot policies can be replayed to downgrade security.",
                        offset
                    ),
                )
                .with_confidence(0.92)
                .with_recommendation("Regenerate LocalPolicy with valid nonce binding via 1TR."),
            );
        }

        // Zeroed next-stage hash means no chain binding
        if next_stage_hash.iter().all(|&b| b == 0x00) {
            findings.push(
                Finding::new(
                    "ios_local_policy",
                    Severity::Critical,
                    "LocalPolicy next-stage hash is zeroed (chain binding broken)",
                    &format!(
                        "lpol at 0x{:08X} has zeroed next_stage_hash. \
                         The boot policy doesn't bind to the next stage (iBoot/kernel). \
                         Any next-stage image will be accepted.",
                        offset
                    ),
                )
                .with_confidence(0.90),
            );
        }

        // Check version — version 0 may indicate uninitialized policy
        let version = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap_or([0; 4]));
        if version == 0 {
            findings.push(
                Finding::new(
                    "ios_local_policy",
                    Severity::Medium,
                    "LocalPolicy has version 0 (possibly uninitialized)",
                    &format!(
                        "lpol at 0x{:08X} has version=0. This may indicate a \
                         factory-state or uninitialized policy.",
                        offset
                    ),
                )
                .with_confidence(0.60),
            );
        }
    }

    fn validate_manifest_policy(&self, data: &[u8], offset: usize, findings: &mut Vec<Finding>) {
        if offset + 0x40 > data.len() {
            return;
        }

        // IM4M (Image4 Manifest) wrapping a policy should have cert chain
        // Check for "lpol" type tag within the manifest
        let manifest_region = &data[offset..offset.saturating_add(0x100).min(data.len())];
        let has_lpol = manifest_region.windows(4).any(|w| w == LPOL_MAGIC);

        if has_lpol {
            // Verify the manifest has a non-zero signature
            let sig_offset = offset + 0x20;
            if sig_offset + 0x40 <= data.len() {
                let sig = &data[sig_offset..sig_offset + 0x40];
                if sig.iter().all(|&b| b == 0x00) {
                    findings.push(
                        Finding::new(
                            "ios_local_policy",
                            Severity::Critical,
                            "Image4 manifest wrapping LocalPolicy has zeroed signature",
                            &format!(
                                "IM4M at 0x{:08X} contains lpol but has zeroed signature. \
                                 The policy is not authenticated by the Secure Enclave.",
                                offset
                            ),
                        )
                        .with_confidence(0.87),
                    );
                }
            }
        }
    }
}

impl Detector for IosLocalPolicyDetector {
    fn name(&self) -> &str {
        "ios_local_policy"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        Ok(self.check_local_policy(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn fires_on_zeroed_nonce() {
        let mut data = vec![0u8; 0x100];
        data[0..4].copy_from_slice(&LPOL_MAGIC);
        data[4..8].copy_from_slice(&1u32.to_le_bytes()); // version=1
                                                         // nonce_hash at +8 is zeroed (already)

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = IosLocalPolicyDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn quiet_on_valid_policy() {
        let mut data = vec![0u8; 0x100];
        data[0..4].copy_from_slice(&LPOL_MAGIC);
        data[4..8].copy_from_slice(&1u32.to_le_bytes()); // version=1
        data[8..40].fill(0xAA); // nonce_hash non-zero
        data[40..72].fill(0xBB); // next_stage_hash non-zero

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = IosLocalPolicyDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(findings.is_empty());
    }
}
