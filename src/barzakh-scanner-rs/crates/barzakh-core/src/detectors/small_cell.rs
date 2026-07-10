use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const FEMTOCELL_MARKERS: &[&[u8]] = &[b"HeNB", b"femtocell", b"smallcell", b"CSG-ID", b"HNB-GW"];

const PICOCELL_MARKERS: &[&[u8]] = &[b"picocell", b"metrocell", b"enterprise_ran"];

// Known small-cell platform identifiers
const PLATFORM_MARKERS: &[&[u8]] = &[
    b"Qualcomm FSM",
    b"ip.access",
    b"Airspan",
    b"Baicells",
    b"CommScope",
];

pub struct SmallCellDetector;

impl Default for SmallCellDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SmallCellDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn has_smallcell_marker(data: &[u8]) -> bool {
        FEMTOCELL_MARKERS.iter().any(|m| Self::contains(data, m))
            || PICOCELL_MARKERS.iter().any(|m| Self::contains(data, m))
            || PLATFORM_MARKERS.iter().any(|m| Self::contains(data, m))
    }

    fn detect_imsi_catcher(data: &[u8]) -> Vec<usize> {
        let indicators = [
            b"IDENTITY REQUEST" as &[u8],
            b"imsi_collect",
            b"catch_imsi",
            b"silent_sms",
            b"paging_flood",
        ];
        let mut hits = Vec::new();
        for pat in &indicators {
            if let Some(pos) = data.windows(pat.len()).position(|w| w == *pat) {
                hits.push(pos);
            }
        }
        hits
    }

    fn detect_downgrade_attack(data: &[u8]) -> bool {
        // Forcing UEs to connect on 2G (no encryption) is a classic rogue-cell tactic
        let downgrade_markers = [
            b"force_2g" as &[u8],
            b"disable_lte",
            b"reject_5g",
            b"cipher_none",
            b"A5/0",
        ];
        downgrade_markers
            .iter()
            .filter(|m| Self::contains(data, m))
            .count()
            >= 2
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !Self::has_smallcell_marker(data) {
            return findings;
        }

        let imsi_hits = Self::detect_imsi_catcher(data);
        if imsi_hits.len() >= 2 {
            let first = imsi_hits[0];
            findings.push(
                Finding::new(
                    "small_cell",
                    Severity::Critical,
                    "IMSI catcher capability in small cell firmware",
                    &format!(
                        "Small cell/femtocell firmware contains {} indicators of IMSI \
                         catching functionality (identity harvesting, silent SMS, paging \
                         flood). First at offset 0x{first:08X}. This firmware is configured \
                         to operate as a rogue base station for subscriber surveillance.",
                        imsi_hits.len(),
                    ),
                )
                .with_confidence(0.87)
                .with_details(serde_json::json!({
                    "indicator_count": imsi_hits.len(),
                    "first_offset": format!("0x{first:08X}"),
                }))
                .with_recommendation(
                    "Isolate and power down the small cell immediately; forensic image \
                     the firmware; audit HeNB-GW logs for unauthorized cell registrations; \
                     verify CSG-ID against operator allocation.",
                ),
            );
        }

        if Self::detect_downgrade_attack(data) {
            findings.push(
                Finding::new(
                    "small_cell",
                    Severity::Critical,
                    "RAT downgrade attack configuration in small cell firmware",
                    "Small cell firmware contains multiple indicators of forcing UEs \
                     to downgrade to 2G/GSM with null ciphering (A5/0). This is a \
                     classic rogue base station technique to intercept voice and \
                     data without encryption.",
                )
                .with_confidence(0.90)
                .with_details(serde_json::json!({
                    "technique": "forced_rat_downgrade",
                    "target_rat": "GSM/2G",
                    "cipher": "A5/0 (none)",
                }))
                .with_recommendation(
                    "Power down the cell; investigate physical access logs; notify \
                     operator security team; check for unauthorized SeGW tunnel \
                     configurations.",
                ),
            );
        }

        findings
    }
}

impl Detector for SmallCellDetector {
    fn name(&self) -> &str {
        "small_cell"
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
    fn fires_on_imsi_catcher() {
        let mut v = b"HeNB femtocell firmware v1.2\n".to_vec();
        v.extend_from_slice(b"imsi_collect=true\nsilent_sms=enable\n");
        let findings = SmallCellDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn fires_on_downgrade() {
        let mut v = b"HeNB CSG-ID=0x01\n".to_vec();
        v.extend_from_slice(b"force_2g=1\ncipher_none=true\nA5/0\n");
        let findings = SmallCellDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn quiet_on_clean_smallcell() {
        let v = b"HeNB femtocell firmware v1.2 clean operator build".to_vec();
        assert!(SmallCellDetector::new().scan(&v).is_empty());
    }
}
