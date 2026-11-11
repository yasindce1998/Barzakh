use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const SMU_MAGIC: [u8; 4] = [0x01, 0x00, 0x00, 0x00];
const SMU_TAG: [u8; 3] = [0x53, 0x4D, 0x55]; // "SMU"

pub struct SmuFirmwareDetector;

impl Default for SmuFirmwareDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SmuFirmwareDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_smu_firmware(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for offset in 0..data.len().saturating_sub(0x200) {
            if data[offset..offset + 4] == SMU_MAGIC
                && offset + 7 <= data.len()
                && data[offset + 4..offset + 7] == SMU_TAG
            {
                self.validate_smu_image(data, offset, &mut findings);
            }
        }

        findings
    }

    fn validate_smu_image(&self, data: &[u8], offset: usize, findings: &mut Vec<Finding>) {
        if offset + 0x110 > data.len() {
            return;
        }

        let declared_size =
            u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap_or([0; 4]));

        // Check for abnormal size
        if declared_size > 0x100000 || declared_size == 0 {
            findings.push(
                Finding::new(
                    "smu_firmware",
                    Severity::Medium,
                    "SMU firmware declares abnormal size",
                    &format!(
                        "SMU image at 0x{:08X} declares size 0x{:08X} ({}KB). \
                         Normal SMU firmware is 64-512KB.",
                        offset,
                        declared_size,
                        declared_size / 1024
                    ),
                )
                .with_confidence(0.70),
            );
        }

        // Check signature region at offset +0x100 (64 bytes)
        let sig_offset = offset + 0x100;
        if sig_offset + 64 <= data.len() {
            let sig_region = &data[sig_offset..sig_offset + 64];
            if sig_region.iter().all(|&b| b == 0x00) {
                findings.push(
                    Finding::new(
                        "smu_firmware",
                        Severity::Critical,
                        "SMU firmware has zeroed signature",
                        &format!(
                            "SMU firmware at 0x{:08X} has all-zero signature region at \
                             offset +0x100. The SMU controls voltage/frequency/power — \
                             unsigned SMU firmware enables voltage fault injection attacks.",
                            offset
                        ),
                    )
                    .with_confidence(0.92)
                    .with_details(serde_json::json!({
                        "smu_offset": format!("0x{:08X}", offset),
                        "declared_size": declared_size,
                        "signature_zeroed": true,
                    }))
                    .with_recommendation(
                        "SMU firmware must be signed by AMD. Reflash with vendor-provided BIOS update.",
                    ),
                );
            }
        }

        // Check for repeated pattern in code section (possible empty/stubbed firmware)
        let code_start = offset + 0x200;
        if code_start + 256 <= data.len() {
            let code_section = &data[code_start..code_start + 256];
            let first = code_section[0];
            if first != 0x00 && code_section.iter().all(|&b| b == first) {
                findings.push(
                    Finding::new(
                        "smu_firmware",
                        Severity::High,
                        "SMU firmware code section is filled with repeated byte",
                        &format!(
                            "SMU at 0x{:08X} has code section filled with 0x{:02X}. \
                             Likely stub/tampered firmware.",
                            offset, first
                        ),
                    )
                    .with_confidence(0.80),
                );
            }
        }
    }
}

impl Detector for SmuFirmwareDetector {
    fn name(&self) -> &str {
        "smu_firmware"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        Ok(self.check_smu_firmware(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn fires_on_zeroed_signature() {
        let mut data = vec![0u8; 0x300];
        data[0..4].copy_from_slice(&SMU_MAGIC);
        data[4..7].copy_from_slice(&SMU_TAG);
        data[8..12].copy_from_slice(&0x8000u32.to_le_bytes()); // 32KB
                                                               // Signature at +0x100 is already zero

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = SmuFirmwareDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn quiet_on_clean() {
        let data = vec![0u8; 0x300];
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = SmuFirmwareDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(findings.is_empty());
    }
}
