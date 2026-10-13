use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const PLATFORM_MARKERS: &[&[u8]] = &[b"NVIDIA", b"Tegra", b"Jetson"];

const FORGERY_MARKERS: &[&[u8]] = &[
    b"nsp_cmd_forge",
    b"sec_mailbox_redirect",
    b"keyslot_dump",
    b"se_crypto_override",
];

pub struct NspCommandDetector;

impl Default for NspCommandDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl NspCommandDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn matched_markers(data: &[u8]) -> Vec<String> {
        FORGERY_MARKERS
            .iter()
            .filter(|m| Self::contains(data, m))
            .map(|m| String::from_utf8_lossy(m).into_owned())
            .collect()
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let has_nsp = Self::contains(data, b"NSP");
        let has_vendor = PLATFORM_MARKERS.iter().any(|m| Self::contains(data, m));
        if !has_nsp || !has_vendor {
            return findings;
        }

        let hits = Self::matched_markers(data);
        if !hits.is_empty() {
            findings.push(
                Finding::new(
                    "nsp_command",
                    Severity::High,
                    "NSP command forgery",
                    &format!(
                        "Firmware contains {} NVIDIA Security Processor mailbox command \
                         forgery indicator(s): {}. Forged NSP commands can redirect the \
                         secure mailbox, dump keyslot material, and override crypto \
                         operations enforced by the Tegra Security Engine.",
                        hits.len(),
                        hits.join(", "),
                    ),
                )
                .with_confidence(0.86)
                .with_details(serde_json::json!({
                    "indicators": hits,
                }))
                .with_recommendation(
                    "Re-flash the NSP/SE firmware from a NVIDIA-signed image; revoke and \
                     re-provision keys held in compromised keyslots; audit mailbox \
                     command logs for unauthorized traffic.",
                ),
            );
        }

        findings
    }
}

impl Detector for NspCommandDetector {
    fn name(&self) -> &str {
        "nsp_command"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        Ok(self.scan(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fires_on_command_forgery() {
        let mut v = b"NVIDIA Tegra NSP mailbox driver\n".to_vec();
        v.extend_from_slice(b"nsp_cmd_forge=1\nkeyslot_dump=all\n");
        let findings = NspCommandDetector::new().scan(&v);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::High && f.title == "NSP command forgery"));
    }

    #[test]
    fn quiet_on_clean_nsp() {
        let v = b"NVIDIA Tegra NSP secure mailbox production driver".to_vec();
        assert!(NspCommandDetector::new().scan(&v).is_empty());
    }

    #[test]
    fn quiet_without_nsp_marker() {
        let v = b"Tegra firmware with nsp_cmd_forge marker but no platform tag".to_vec();
        assert!(NspCommandDetector::new().scan(&v).is_empty());
    }
}
