use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const ANE_MAGIC: [u8; 4] = [0x61, 0x6E, 0x65, 0x30]; // "ane0"
const H11ANE_ID: &[u8] = b"H11ANE";

pub struct IosAneBootDetector;

impl Default for IosAneBootDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl IosAneBootDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_ane(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for offset in 0..data.len().saturating_sub(64) {
            if data[offset..offset + 4] == ANE_MAGIC {
                self.validate_ane_firmware(data, offset, &mut findings);
            }
        }

        // Also check for H11ANE product identifier in IMG4 payload
        self.check_ane_img4(data, &mut findings);

        findings
    }

    fn validate_ane_firmware(&self, data: &[u8], offset: usize, findings: &mut Vec<Finding>) {
        if offset + 0x100 > data.len() {
            return;
        }

        // ANE firmware structure: magic(4) + version(4) + size(4) + flags(4) + sig(256)
        let declared_size =
            u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap_or([0; 4]));

        // Signature at +0x10 (256 bytes)
        let sig_start = offset + 0x10;
        let sig_end = sig_start + 0x100;
        if sig_end <= data.len() {
            let sig = &data[sig_start..sig_end];
            if sig.iter().all(|&b| b == 0x00) {
                findings.push(
                    Finding::new(
                        "ios_ane_boot",
                        Severity::Critical,
                        "Apple Neural Engine firmware has zeroed signature",
                        &format!(
                            "ANE firmware at 0x{:08X} has a completely zeroed signature. \
                             Unsigned ANE firmware allows arbitrary neural network model \
                             execution and potential DMA access to host memory.",
                            offset
                        ),
                    )
                    .with_confidence(0.91)
                    .with_recommendation("Restore genuine ANE firmware signed by Apple."),
                );
            }
        }

        // Check for abnormal size (> 16MB is suspicious for ANE firmware)
        if declared_size > 16 * 1024 * 1024 {
            findings.push(
                Finding::new(
                    "ios_ane_boot",
                    Severity::Medium,
                    "ANE firmware declares abnormally large size",
                    &format!(
                        "ANE at 0x{:08X} declares size {} bytes ({:.1} MB). \
                         Legitimate ANE firmware is typically under 8 MB.",
                        offset,
                        declared_size,
                        declared_size as f64 / (1024.0 * 1024.0)
                    ),
                )
                .with_confidence(0.70),
            );
        }

        // Check flags for debug/development mode
        let flags = u32::from_le_bytes(data[offset + 12..offset + 16].try_into().unwrap_or([0; 4]));
        if flags & 0x02 != 0 {
            findings.push(
                Finding::new(
                    "ios_ane_boot",
                    Severity::High,
                    "ANE firmware has development flag set",
                    &format!(
                        "ANE at 0x{:08X} has development/debug flag (flags=0x{:08X}). \
                         Development ANE firmware may bypass DMA protections.",
                        offset, flags
                    ),
                )
                .with_confidence(0.80),
            );
        }
    }

    fn check_ane_img4(&self, data: &[u8], findings: &mut Vec<Finding>) {
        // Look for H11ANE product identifier
        for offset in 0..data.len().saturating_sub(32) {
            if data[offset..].starts_with(H11ANE_ID) {
                // Found ANE identifier — check surrounding IMG4 integrity
                if offset >= 0x10 {
                    let img4_header_start = offset - 0x10;
                    // Check if there's an IM4P tag preceding it
                    let im4p_magic: [u8; 4] = [0x49, 0x4D, 0x34, 0x50];
                    if img4_header_start + 4 <= data.len()
                        && data[img4_header_start..img4_header_start + 4] == im4p_magic
                    {
                        // Verify the payload has a signature
                        let payload_sig = offset + H11ANE_ID.len() + 0x10;
                        if payload_sig + 0x20 <= data.len() {
                            let sig = &data[payload_sig..payload_sig + 0x20];
                            if sig.iter().all(|&b| b == 0x00) {
                                findings.push(
                                    Finding::new(
                                        "ios_ane_boot",
                                        Severity::High,
                                        "H11ANE IMG4 payload has zeroed signature",
                                        &format!(
                                            "H11ANE identifier at 0x{:08X} within IM4P container \
                                             has zeroed signature. ANE firmware is not authenticated.",
                                            offset
                                        ),
                                    )
                                    .with_confidence(0.82),
                                );
                            }
                        }
                    }
                }
                return;
            }
        }
    }
}

impl Detector for IosAneBootDetector {
    fn name(&self) -> &str {
        "ios_ane_boot"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        Ok(self.check_ane(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn fires_on_unsigned_ane() {
        let mut data = vec![0u8; 0x200];
        data[0..4].copy_from_slice(&ANE_MAGIC);
        data[8..12].copy_from_slice(&0x100000u32.to_le_bytes()); // 1MB size
                                                                 // sig at +0x10 is zeroed

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = IosAneBootDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn quiet_on_signed_ane() {
        let mut data = vec![0u8; 0x200];
        data[0..4].copy_from_slice(&ANE_MAGIC);
        data[8..12].copy_from_slice(&0x100000u32.to_le_bytes()); // 1MB
                                                                 // Non-zero signature
        data[0x10..0x110].fill(0xCC);

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = IosAneBootDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(findings.is_empty());
    }
}
