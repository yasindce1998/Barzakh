use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const CSME_UPDATE_MAGIC: [u8; 4] = [0x24, 0x43, 0x50, 0x44]; // "$CPD"

pub struct CsmeUpdateDetector;

impl Default for CsmeUpdateDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CsmeUpdateDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_csme_update(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for offset in 0..data.len().saturating_sub(32) {
            if data[offset..offset + 4] == CSME_UPDATE_MAGIC {
                self.validate_cpd_header(data, offset, &mut findings);
            }
        }

        findings
    }

    fn validate_cpd_header(&self, data: &[u8], offset: usize, findings: &mut Vec<Finding>) {
        if offset + 16 > data.len() {
            return;
        }

        let num_entries =
            u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap_or([0; 4]));
        let header_version = data[offset + 8];

        if num_entries > 512 {
            findings.push(
                Finding::new(
                    "csme_update",
                    Severity::High,
                    "CSME update capsule has excessive entry count",
                    &format!(
                        "Code Partition Directory at 0x{:08X} declares {} entries \
                         (max expected ~128). Possible capsule corruption or injection.",
                        offset, num_entries
                    ),
                )
                .with_confidence(0.82)
                .with_details(serde_json::json!({
                    "cpd_offset": format!("0x{:08X}", offset),
                    "num_entries": num_entries,
                    "header_version": header_version,
                })),
            );
            return;
        }

        let entry_size = 0x18;
        let entries_start = offset + 16;

        for i in 0..num_entries.min(64) as usize {
            let entry_offset = entries_start + i * entry_size;
            if entry_offset + entry_size > data.len() {
                break;
            }

            let entry_offset_val = u32::from_le_bytes(
                data[entry_offset + 12..entry_offset + 16]
                    .try_into()
                    .unwrap_or([0; 4]),
            );
            let entry_length = u32::from_le_bytes(
                data[entry_offset + 16..entry_offset + 20]
                    .try_into()
                    .unwrap_or([0; 4]),
            );

            if entry_length > 0 && entry_offset_val == 0 {
                findings.push(
                    Finding::new(
                        "csme_update",
                        Severity::Medium,
                        "CSME capsule entry has zero offset with non-zero length",
                        &format!(
                            "CPD entry {} at 0x{:08X} declares length {} but offset 0. \
                             May indicate partial update or tampered capsule.",
                            i, entry_offset, entry_length
                        ),
                    )
                    .with_confidence(0.70),
                );
            }
        }

        // Check for version skipping (adjacent CPD partitions with large version gap)
        self.check_version_skip(data, offset, header_version, &mut *findings);
    }

    fn check_version_skip(
        &self,
        data: &[u8],
        offset: usize,
        _version: u8,
        findings: &mut Vec<Finding>,
    ) {
        // Look for a second CPD after this one
        let search_start = offset + 32;
        for next_offset in search_start..data.len().saturating_sub(16) {
            if data[next_offset..next_offset + 4] == CSME_UPDATE_MAGIC {
                let next_version = data[next_offset + 8];
                let this_version = data[offset + 8];
                if next_version > 0 && this_version > 0 && next_version.abs_diff(this_version) > 3 {
                    findings.push(
                        Finding::new(
                            "csme_update",
                            Severity::High,
                            "CSME update version skip detected",
                            &format!(
                                "CPD at 0x{:08X} (v{}) and CPD at 0x{:08X} (v{}) show a \
                                 version gap of {}. May indicate forced downgrade via capsule splicing.",
                                offset, this_version, next_offset, next_version,
                                next_version.abs_diff(this_version)
                            ),
                        )
                        .with_confidence(0.75),
                    );
                }
                break;
            }
        }
    }
}

impl Detector for CsmeUpdateDetector {
    fn name(&self) -> &str {
        "csme_update"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }

    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        Ok(self.check_csme_update(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn fires_on_excessive_entries() {
        let mut data = vec![0u8; 0x100];
        data[0..4].copy_from_slice(&CSME_UPDATE_MAGIC);
        data[4..8].copy_from_slice(&1000u32.to_le_bytes()); // excessive
        data[8] = 2; // version

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = CsmeUpdateDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(!findings.is_empty());
    }

    #[test]
    fn quiet_on_clean() {
        let data = vec![0u8; 0x100];
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = CsmeUpdateDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(findings.is_empty());
    }
}
