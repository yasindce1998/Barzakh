use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const PSP_L2_MAGIC: [u8; 4] = [0x24, 0x50, 0x4C, 0x32]; // "$PL2"
const PSP_BL2_MAGIC: [u8; 4] = [0x24, 0x42, 0x4C, 0x32]; // "$BL2"

pub struct PspVersionChainDetector;

impl Default for PspVersionChainDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PspVersionChainDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_psp_versions(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut directory_svns: Vec<(usize, u32, &str)> = Vec::new();

        for offset in 0..data.len().saturating_sub(20) {
            if data[offset..offset + 4] == PSP_L2_MAGIC || data[offset..offset + 4] == PSP_BL2_MAGIC
            {
                let magic_str = if data[offset..offset + 4] == PSP_L2_MAGIC {
                    "$PL2"
                } else {
                    "$BL2"
                };

                if offset + 16 < data.len() {
                    let svn = u32::from_le_bytes(
                        data[offset + 12..offset + 16].try_into().unwrap_or([0; 4]),
                    );
                    directory_svns.push((offset, svn, magic_str));
                }
            }
        }

        // Check for rollback
        if directory_svns.len() >= 2 {
            for i in 1..directory_svns.len() {
                let (prev_off, prev_svn, _) = directory_svns[i - 1];
                let (curr_off, curr_svn, curr_magic) = directory_svns[i];

                if curr_svn < prev_svn && prev_svn < 0xFFFF {
                    findings.push(
                        Finding::new(
                            "psp_version_chain",
                            Severity::Critical,
                            "AMD PSP firmware version rollback detected",
                            &format!(
                                "PSP directory ({}) at 0x{:08X} has SVN {} which is lower than \
                                 directory at 0x{:08X} with SVN {}. Firmware downgrade attack \
                                 may reintroduce patched PSP vulnerabilities.",
                                curr_magic, curr_off, curr_svn, prev_off, prev_svn
                            ),
                        )
                        .with_confidence(0.90)
                        .with_details(serde_json::json!({
                            "directories": directory_svns.iter()
                                .map(|(o, s, m)| serde_json::json!({
                                    "offset": format!("0x{:08X}", o),
                                    "svn": s,
                                    "magic": m,
                                }))
                                .collect::<Vec<_>>(),
                        }))
                        .with_recommendation(
                            "Verify PSP firmware against AMD-published minimum SVN for this platform.",
                        ),
                    );
                }
            }
        }

        // Check for zero SVN
        for (offset, svn, magic) in &directory_svns {
            if *svn == 0 {
                findings.push(
                    Finding::new(
                        "psp_version_chain",
                        Severity::High,
                        "PSP directory with zero SVN",
                        &format!(
                            "PSP directory ({}) at 0x{:08X} has SVN=0, defeating anti-rollback.",
                            magic, offset
                        ),
                    )
                    .with_confidence(0.85),
                );
            }
        }

        findings
    }
}

impl Detector for PspVersionChainDetector {
    fn name(&self) -> &str {
        "psp_version_chain"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        Ok(self.check_psp_versions(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn fires_on_rollback() {
        let mut data = vec![0u8; 0x200];
        // First directory with SVN=5
        data[0x00..0x04].copy_from_slice(&PSP_L2_MAGIC);
        data[0x0C..0x10].copy_from_slice(&5u32.to_le_bytes());
        // Second directory with SVN=2
        data[0x100..0x104].copy_from_slice(&PSP_L2_MAGIC);
        data[0x10C..0x110].copy_from_slice(&2u32.to_le_bytes());

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = PspVersionChainDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn quiet_on_clean() {
        let data = vec![0u8; 0x200];
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = PspVersionChainDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(findings.is_empty());
    }
}
