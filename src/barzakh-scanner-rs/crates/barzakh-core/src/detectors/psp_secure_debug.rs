use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const DEBUG_UNLOCK_MAGIC: [u8; 4] = [0x44, 0x42, 0x55, 0x4B]; // "DBUK"
const PSP_DEBUG_ENTRY_TYPE: u8 = 0x09;
const PSP_DIR_MAGIC: [u8; 4] = [0x24, 0x50, 0x53, 0x50]; // "$PSP"

pub struct PspSecureDebugDetector;

impl Default for PspSecureDebugDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PspSecureDebugDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_debug_unlock(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Scan for debug unlock token magic
        for offset in 0..data.len().saturating_sub(64) {
            if data[offset..offset + 4] == DEBUG_UNLOCK_MAGIC {
                findings.push(
                    Finding::new(
                        "psp_secure_debug",
                        Severity::Critical,
                        "PSP Secure Debug Unlock token detected",
                        &format!(
                            "Debug unlock token (DBUK) found at offset 0x{:08X}. \
                             This token enables full PSP debug access including JTAG, \
                             memory dump, and firmware extraction capabilities.",
                            offset
                        ),
                    )
                    .with_confidence(0.95)
                    .with_details(serde_json::json!({
                        "token_offset": format!("0x{:08X}", offset),
                        "magic": "DBUK",
                    }))
                    .with_recommendation(
                        "Debug unlock tokens must not be present in production firmware. \
                         Remove the token and reflash.",
                    ),
                );
            }
        }

        // Check PSP directory for debug entry types
        self.check_debug_entries(data, &mut findings);

        findings
    }

    fn check_debug_entries(&self, data: &[u8], findings: &mut Vec<Finding>) {
        for offset in 0..data.len().saturating_sub(32) {
            if data[offset..offset + 4] == PSP_DIR_MAGIC {
                if offset + 16 > data.len() {
                    continue;
                }

                let num_entries =
                    u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap_or([0; 4]));

                if num_entries > 256 || num_entries == 0 {
                    continue;
                }

                let entries_start = offset + 16;
                for i in 0..num_entries.min(128) as usize {
                    let entry_offset = entries_start + i * 16;
                    if entry_offset + 16 > data.len() {
                        break;
                    }

                    if data[entry_offset] == PSP_DEBUG_ENTRY_TYPE {
                        let entry_size = u32::from_le_bytes(
                            data[entry_offset + 8..entry_offset + 12]
                                .try_into()
                                .unwrap_or([0; 4]),
                        );

                        if entry_size > 0 {
                            findings.push(
                                Finding::new(
                                    "psp_secure_debug",
                                    Severity::High,
                                    "PSP directory contains debug policy entry",
                                    &format!(
                                        "PSP directory at 0x{:08X}, entry {} (type 0x09) declares \
                                         debug policy of {} bytes. Debug policy entries control \
                                         JTAG and secure debug interface access.",
                                        offset, i, entry_size
                                    ),
                                )
                                .with_confidence(0.85)
                                .with_details(serde_json::json!({
                                    "dir_offset": format!("0x{:08X}", offset),
                                    "entry_index": i,
                                    "entry_size": entry_size,
                                })),
                            );
                        }
                    }
                }
            }
        }
    }
}

impl Detector for PspSecureDebugDetector {
    fn name(&self) -> &str {
        "psp_secure_debug"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        Ok(self.check_debug_unlock(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn fires_on_debug_token() {
        let mut data = vec![0u8; 0x200];
        data[0x50..0x54].copy_from_slice(&DEBUG_UNLOCK_MAGIC);

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = PspSecureDebugDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(!findings.is_empty());
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn quiet_on_clean() {
        let data = vec![0u8; 0x200];
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = PspSecureDebugDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(findings.is_empty());
    }
}
