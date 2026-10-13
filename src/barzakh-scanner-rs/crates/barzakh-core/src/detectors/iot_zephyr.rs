use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const PLATFORM_MARKERS: &[&[u8]] = &[b"Zephyr", b"zephyr", b"mcuboot", b"MCUboot"];

const BOOT_TAMPER_MARKERS: &[&[u8]] = &[
    b"mcuboot_sig_bypass",
    b"swap_move_persist",
    b"version_rollback",
];

pub struct IotZephyrDetector;

impl Default for IotZephyrDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl IotZephyrDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn matched_markers(data: &[u8]) -> Vec<String> {
        BOOT_TAMPER_MARKERS
            .iter()
            .filter(|m| Self::contains(data, m))
            .map(|m| String::from_utf8_lossy(m).into_owned())
            .collect()
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !PLATFORM_MARKERS.iter().any(|m| Self::contains(data, m)) {
            return findings;
        }

        let hits = Self::matched_markers(data);
        if !hits.is_empty() {
            findings.push(
                Finding::new(
                    "iot_zephyr",
                    Severity::High,
                    "Zephyr/MCUboot signature bypass",
                    &format!(
                        "Zephyr/MCUboot boot chain firmware contains {} tampering \
                         indicator(s): {}. These markers bypass image signature \
                         verification, persist implants across swap-move upgrades, or \
                         allow rollback to vulnerable image versions.",
                        hits.len(),
                        hits.join(", "),
                    ),
                )
                .with_confidence(0.83)
                .with_details(serde_json::json!({
                    "indicators": hits,
                }))
                .with_recommendation(
                    "Restore MCUboot from a clean signed build with anti-rollback \
                     (version counters) enforced; re-verify the full image chain from \
                     ROM loader to application; rotate device identity keys if the boot \
                     chain was compromised.",
                ),
            );
        }

        findings
    }
}

impl Detector for IotZephyrDetector {
    fn name(&self) -> &str {
        "iot_zephyr"
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
    fn fires_on_mcuboot_bypass() {
        let mut v = b"Zephyr MCUboot bootloader\n".to_vec();
        v.extend_from_slice(b"mcuboot_sig_bypass=1\nversion_rollback=true\n");
        let findings = IotZephyrDetector::new().scan(&v);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::High && f.title == "Zephyr/MCUboot signature bypass"));
    }

    #[test]
    fn quiet_on_clean_zephyr() {
        let v = b"Zephyr MCUboot production bootloader v2.1 signed images".to_vec();
        assert!(IotZephyrDetector::new().scan(&v).is_empty());
    }

    #[test]
    fn quiet_without_platform_marker() {
        let v = b"generic firmware with version_rollback marker only".to_vec();
        assert!(IotZephyrDetector::new().scan(&v).is_empty());
    }
}
