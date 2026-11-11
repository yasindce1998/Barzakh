use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const MN2_MAGIC: [u8; 4] = [0x24, 0x4D, 0x4E, 0x32]; // "$MN2"

pub struct MeVersionChainDetector;

impl Default for MeVersionChainDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MeVersionChainDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_version_chain(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut manifest_versions: Vec<(usize, u32)> = Vec::new();

        for offset in 0..data.len().saturating_sub(40) {
            if data[offset..offset + 4] == MN2_MAGIC && offset + 0x28 < data.len() {
                let svn = u32::from_le_bytes(
                    data[offset + 0x24..offset + 0x28]
                        .try_into()
                        .unwrap_or([0; 4]),
                );
                manifest_versions.push((offset, svn));
            }
        }

        if manifest_versions.len() >= 2 {
            for i in 1..manifest_versions.len() {
                let (prev_offset, prev_svn) = manifest_versions[i - 1];
                let (curr_offset, curr_svn) = manifest_versions[i];

                if curr_svn < prev_svn {
                    findings.push(
                        Finding::new(
                            "me_version_chain",
                            Severity::Critical,
                            "Intel ME firmware version rollback detected",
                            &format!(
                                "Manifest at 0x{:08X} has SVN {} which is lower than previous \
                                 manifest at 0x{:08X} with SVN {}. This indicates a firmware \
                                 downgrade attack that may reintroduce patched vulnerabilities.",
                                curr_offset, curr_svn, prev_offset, prev_svn
                            ),
                        )
                        .with_confidence(0.92)
                        .with_details(serde_json::json!({
                            "manifests": manifest_versions.iter()
                                .map(|(o, s)| serde_json::json!({"offset": format!("0x{:08X}", o), "svn": s}))
                                .collect::<Vec<_>>(),
                            "rollback_from": prev_svn,
                            "rollback_to": curr_svn,
                        }))
                        .with_recommendation(
                            "Verify firmware version against OEM-published minimum SVN. \
                             Reflash with latest firmware update.",
                        ),
                    );
                }
            }
        }

        self.check_zero_svn(data, &manifest_versions, &mut findings);
        findings
    }

    fn check_zero_svn(
        &self,
        _data: &[u8],
        manifests: &[(usize, u32)],
        findings: &mut Vec<Finding>,
    ) {
        for (offset, svn) in manifests {
            if *svn == 0 {
                findings.push(
                    Finding::new(
                        "me_version_chain",
                        Severity::High,
                        "ME manifest with SVN of zero",
                        &format!(
                            "Manifest at 0x{:08X} has Security Version Number of 0. \
                             This defeats anti-rollback protection and allows loading \
                             any firmware version.",
                            offset
                        ),
                    )
                    .with_confidence(0.88)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", offset),
                        "svn": 0,
                    })),
                );
            }
        }
    }
}

impl Detector for MeVersionChainDetector {
    fn name(&self) -> &str {
        "me_version_chain"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        Ok(self.check_version_chain(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn fires_on_version_rollback() {
        let mut data = vec![0u8; 0x400];
        // First manifest with SVN=5
        data[0x00..0x04].copy_from_slice(&MN2_MAGIC);
        data[0x24..0x28].copy_from_slice(&5u32.to_le_bytes());
        // Second manifest with SVN=2 (rollback)
        data[0x100..0x104].copy_from_slice(&MN2_MAGIC);
        data[0x124..0x128].copy_from_slice(&2u32.to_le_bytes());

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = MeVersionChainDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn quiet_on_clean() {
        let data = vec![0u8; 0x400];
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = MeVersionChainDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(findings.is_empty());
    }
}
