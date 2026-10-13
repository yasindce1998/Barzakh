use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const PLATFORM_MARKERS: &[&[u8]] = &[b"AUTOSAR", b"ECU", b"UDS"];

const ECU_BACKDOOR_MARKERS: &[&[u8]] = &[
    b"uds_backdoor",
    b"security_access_bypass",
    b"ecu_persistence",
];

pub struct AutomotiveEcuDetector;

impl Default for AutomotiveEcuDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AutomotiveEcuDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn matched_markers(data: &[u8]) -> Vec<String> {
        ECU_BACKDOOR_MARKERS
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
                    "automotive_ecu",
                    Severity::Critical,
                    "Automotive ECU backdoor",
                    &format!(
                        "Automotive ECU firmware contains {} backdoor indicator(s): {}. \
                         UDS backdoors and security access bypasses allow unauthenticated \
                         flashing and diagnostic control, while persistence markers keep \
                         the implant resident across apparent re-flashes — enabling \
                         remote manipulation of safety-critical vehicle systems.",
                        hits.len(),
                        hits.join(", "),
                    ),
                )
                .with_confidence(0.9)
                .with_details(serde_json::json!({
                    "indicators": hits,
                }))
                .with_recommendation(
                    "Perform a full chip erase (not in-place re-flash) and restore \
                     OEM-signed firmware; verify UDS security access seed-key behavior; \
                     audit vehicle CAN traffic for unauthorized diagnostic sessions.",
                ),
            );
        }

        findings
    }
}

impl Detector for AutomotiveEcuDetector {
    fn name(&self) -> &str {
        "automotive_ecu"
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
    fn fires_on_ecu_backdoor() {
        let mut v = b"AUTOSAR ECU UDS diagnostic stack\n".to_vec();
        v.extend_from_slice(b"uds_backdoor=0x2711\nsecurity_access_bypass=1\n");
        let findings = AutomotiveEcuDetector::new().scan(&v);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Critical && f.title == "Automotive ECU backdoor"));
    }

    #[test]
    fn quiet_on_clean_ecu() {
        let v = b"AUTOSAR ECU UDS diagnostic production firmware v3.1".to_vec();
        assert!(AutomotiveEcuDetector::new().scan(&v).is_empty());
    }

    #[test]
    fn quiet_without_platform_marker() {
        let v = b"generic firmware with uds_backdoor marker only".to_vec();
        assert!(AutomotiveEcuDetector::new().scan(&v).is_empty());
    }
}
