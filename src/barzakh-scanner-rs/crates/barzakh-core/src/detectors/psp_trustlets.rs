use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const PSP_DIR_MAGIC: [u8; 4] = [0x24, 0x50, 0x53, 0x50]; // "$PSP"

const KNOWN_ENTRY_TYPES: &[u8] = &[
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x10, 0x12, 0x13, 0x20,
    0x21, 0x22, 0x24, 0x28, 0x30, 0x31, 0x32, 0x38, 0x39, 0x40, 0x47, 0x48, 0x49,
];

pub struct PspTrustletsDetector;

impl Default for PspTrustletsDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PspTrustletsDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_trustlets(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for offset in 0..data.len().saturating_sub(32) {
            if data[offset..offset + 4] == PSP_DIR_MAGIC {
                self.scan_directory_entries(data, offset, &mut findings);
            }
        }

        findings
    }

    fn scan_directory_entries(&self, data: &[u8], dir_offset: usize, findings: &mut Vec<Finding>) {
        if dir_offset + 16 > data.len() {
            return;
        }

        let num_entries = u32::from_le_bytes(
            data[dir_offset + 8..dir_offset + 12]
                .try_into()
                .unwrap_or([0; 4]),
        );

        if num_entries > 256 || num_entries == 0 {
            return;
        }

        let entries_start = dir_offset + 16;
        let entry_size = 16;
        let mut rogue_entries: Vec<(usize, u8)> = Vec::new();

        for i in 0..num_entries as usize {
            let entry_offset = entries_start + i * entry_size;
            if entry_offset + entry_size > data.len() {
                break;
            }

            let entry_type = data[entry_offset];
            if !KNOWN_ENTRY_TYPES.contains(&entry_type) && entry_type != 0xFF {
                rogue_entries.push((entry_offset, entry_type));
            }

            // Check for zeroed-signature entries (trustlet with no auth)
            let entry_size_val = u32::from_le_bytes(
                data[entry_offset + 8..entry_offset + 12]
                    .try_into()
                    .unwrap_or([0; 4]),
            );
            let entry_loc = u32::from_le_bytes(
                data[entry_offset + 4..entry_offset + 8]
                    .try_into()
                    .unwrap_or([0; 4]),
            );

            if entry_size_val > 0 && entry_loc > 0 {
                let loc = entry_loc as usize;
                if loc + 0x100 < data.len() {
                    let sig_region =
                        &data[loc + 0x100..loc + 0x100 + 64.min(data.len() - loc - 0x100)];
                    if sig_region.iter().all(|&b| b == 0x00) && entry_size_val > 0x200 {
                        findings.push(
                            Finding::new(
                                "psp_trustlets",
                                Severity::High,
                                "PSP trustlet with zeroed signature",
                                &format!(
                                    "PSP directory entry at 0x{:08X} (type 0x{:02X}) points to \
                                     a trustlet at 0x{:08X} with zeroed signature region. \
                                     Unsigned trustlet injection suspected.",
                                    entry_offset, entry_type, loc
                                ),
                            )
                            .with_confidence(0.85)
                            .with_details(serde_json::json!({
                                "entry_offset": format!("0x{:08X}", entry_offset),
                                "entry_type": format!("0x{:02X}", entry_type),
                                "trustlet_location": format!("0x{:08X}", loc),
                                "trustlet_size": entry_size_val,
                            })),
                        );
                    }
                }
            }
        }

        if !rogue_entries.is_empty() {
            findings.push(
                Finding::new(
                    "psp_trustlets",
                    Severity::Critical,
                    "Unknown PSP directory entry types detected",
                    &format!(
                        "PSP directory at 0x{:08X} contains {} entries with unknown types: {}. \
                         These may be injected rogue trustlets.",
                        dir_offset,
                        rogue_entries.len(),
                        rogue_entries
                            .iter()
                            .map(|(_, t)| format!("0x{:02X}", t))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                )
                .with_confidence(0.80)
                .with_details(serde_json::json!({
                    "dir_offset": format!("0x{:08X}", dir_offset),
                    "rogue_entries": rogue_entries.iter()
                        .map(|(o, t)| serde_json::json!({"offset": format!("0x{:08X}", o), "type": format!("0x{:02X}", t)}))
                        .collect::<Vec<_>>(),
                }))
                .with_recommendation(
                    "Compare PSP directory entries against AMD's published entry type table. \
                     Unknown entries should be investigated for trustlet injection.",
                ),
            );
        }
    }
}

impl Detector for PspTrustletsDetector {
    fn name(&self) -> &str {
        "psp_trustlets"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        Ok(self.check_trustlets(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn fires_on_rogue_entry() {
        let mut data = vec![0u8; 0x200];
        data[0x00..0x04].copy_from_slice(&PSP_DIR_MAGIC);
        data[0x08..0x0C].copy_from_slice(&2u32.to_le_bytes()); // 2 entries
                                                               // Entry 0: known type 0x01
        data[0x10] = 0x01;
        // Entry 1: unknown type 0xFE
        data[0x20] = 0xFE;

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = PspTrustletsDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(!findings.is_empty());
    }

    #[test]
    fn quiet_on_clean() {
        let data = vec![0u8; 0x200];
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = PspTrustletsDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(findings.is_empty());
    }
}
