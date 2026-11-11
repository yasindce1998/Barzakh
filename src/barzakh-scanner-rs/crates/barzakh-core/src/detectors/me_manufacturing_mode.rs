use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const FPT_MAGIC: [u8; 4] = [0x24, 0x46, 0x50, 0x54]; // "$FPT"
const FLASH_DESC_SIGNATURE: [u8; 4] = [0x5A, 0xA5, 0xF0, 0x0F];

pub struct MeManufacturingModeDetector;

impl Default for MeManufacturingModeDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MeManufacturingModeDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_manufacturing_mode(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for offset in 0..data.len().saturating_sub(16) {
            if data[offset..offset + 4] == FLASH_DESC_SIGNATURE && offset + 0x44 < data.len() {
                let fitm_byte = data[offset + 0x40];
                if fitm_byte & 0x02 != 0 {
                    findings.push(
                        Finding::new(
                            "me_manufacturing_mode",
                            Severity::Critical,
                            "Intel ME Manufacturing Mode enabled",
                            &format!(
                                "Flash descriptor at offset 0x{:08X} has Manufacturing Mode bit set \
                                 (FITM offset 0x40, bit 1). This unlocks flash write access and ME debug \
                                 interfaces, allowing full firmware modification.",
                                offset
                            ),
                        )
                        .with_confidence(0.95)
                        .with_details(serde_json::json!({
                            "descriptor_offset": format!("0x{:08X}", offset),
                            "fitm_byte": format!("0x{:02X}", fitm_byte),
                            "manufacturing_mode_bit": true,
                        }))
                        .with_recommendation(
                            "Manufacturing Mode should never be enabled in production firmware. \
                             Reflash with production-signed firmware from OEM.",
                        ),
                    );
                }
            }
        }

        self.check_fpt_manufacturing_flags(data, &mut findings);
        findings
    }

    fn check_fpt_manufacturing_flags(&self, data: &[u8], findings: &mut Vec<Finding>) {
        for offset in 0..data.len().saturating_sub(32) {
            if data[offset..offset + 4] == FPT_MAGIC {
                if offset + 24 < data.len() {
                    let flags = u32::from_le_bytes(
                        data[offset + 20..offset + 24].try_into().unwrap_or([0; 4]),
                    );
                    if flags & 0x01 != 0 {
                        findings.push(
                            Finding::new(
                                "me_manufacturing_mode",
                                Severity::High,
                                "FPT header indicates manufacturing/debug state",
                                &format!(
                                    "Flash Partition Table at 0x{:08X} has debug flag set in header \
                                     flags (0x{:08X}). Indicates firmware was not finalized for production.",
                                    offset, flags
                                ),
                            )
                            .with_confidence(0.85)
                            .with_details(serde_json::json!({
                                "fpt_offset": format!("0x{:08X}", offset),
                                "flags": format!("0x{:08X}", flags),
                            })),
                        );
                    }
                }
                break;
            }
        }
    }
}

impl Detector for MeManufacturingModeDetector {
    fn name(&self) -> &str {
        "me_manufacturing_mode"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        Ok(self.check_manufacturing_mode(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn fires_on_manufacturing_mode() {
        let mut data = vec![0u8; 0x200];
        data[0..4].copy_from_slice(&FLASH_DESC_SIGNATURE);
        data[0x40] = 0x02; // Manufacturing mode bit set

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = MeManufacturingModeDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(!findings.is_empty());
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn quiet_on_clean() {
        let data = vec![0u8; 0x200];
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = MeManufacturingModeDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(findings.is_empty());
    }
}
