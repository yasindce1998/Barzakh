use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const PLATFORM_MARKERS: &[&[u8]] = &[b"CANBUS", b"CAN", b"arbitration"];

const INJECTION_MARKERS: &[&[u8]] = &[
    b"can_inject_frame",
    b"arbitration_spoof",
    b"busoff_suppress",
];

pub struct CanInjectionDetector;

impl Default for CanInjectionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CanInjectionDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn matched_markers(data: &[u8]) -> Vec<String> {
        INJECTION_MARKERS
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
                    "can_injection",
                    Severity::High,
                    "CAN bus injection backdoor",
                    &format!(
                        "Firmware contains {} CAN bus injection indicator(s): {}. These \
                         markers allow forging frames with arbitrary arbitration IDs \
                         (spoofing higher-priority nodes), and suppressing bus-off \
                         recovery so malicious traffic cannot be isolated by the network.",
                        hits.len(),
                        hits.join(", "),
                    ),
                )
                .with_confidence(0.87)
                .with_details(serde_json::json!({
                    "indicators": hits,
                }))
                .with_recommendation(
                    "Re-flash the affected node with OEM-signed firmware; deploy CAN \
                     intrusion detection to flag injected arbitration IDs; review bus \
                     topology to confirm which node originates the forged frames.",
                ),
            );
        }

        findings
    }
}

impl Detector for CanInjectionDetector {
    fn name(&self) -> &str {
        "can_injection"
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
    fn fires_on_can_injection() {
        let mut v = b"CANBUS arbitration controller\n".to_vec();
        v.extend_from_slice(b"can_inject_frame=0x123\narbitration_spoof=high\n");
        let findings = CanInjectionDetector::new().scan(&v);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::High && f.title == "CAN bus injection backdoor"));
    }

    #[test]
    fn quiet_on_clean_can_stack() {
        let v = b"CANBUS arbitration scheduler production firmware v2.4".to_vec();
        assert!(CanInjectionDetector::new().scan(&v).is_empty());
    }

    #[test]
    fn quiet_without_platform_marker() {
        let v = b"generic firmware with can_inject_frame marker only".to_vec();
        assert!(CanInjectionDetector::new().scan(&v).is_empty());
    }
}
