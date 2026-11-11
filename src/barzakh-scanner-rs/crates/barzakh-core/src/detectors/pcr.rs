use std::path::Path;

use crate::baseline::Baseline;
use crate::detector::{Detector, DetectorError, Finding, Severity};

pub struct PcrDetector {
    baseline: Option<Baseline>,
}

impl PcrDetector {
    pub fn new(baseline: Option<Baseline>) -> Self {
        Self { baseline }
    }
}

impl Detector for PcrDetector {
    fn name(&self) -> &str {
        "pcr"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        if let Some(ref baseline) = self.baseline {
            let pcr_values = match baseline.pcr_values.as_ref() {
                Some(v) => v,
                None => return Ok(findings),
            };
            for (pcr_index, expected_value) in pcr_values {
                let index: u8 = pcr_index.parse().unwrap_or(0);
                if index >= 24 {
                    continue;
                }
                // PCR[7] is most critical for Secure Boot policy
                if index == 7 && !expected_value.is_empty() {
                    // Look for PCR measurement structures in the binary
                    let pcr7_marker = [0x07u8, 0x00, 0x00, 0x00];
                    if let Some(offset) = data.windows(4).position(|w| w == pcr7_marker) {
                        if offset + 36 <= data.len() {
                            let measured = &data[offset + 4..offset + 36];
                            let measured_hex: String =
                                measured.iter().map(|b| format!("{:02x}", b)).collect();
                            if measured_hex != *expected_value {
                                findings.push(
                                    Finding::new(
                                        "pcr",
                                        Severity::Critical,
                                        "PCR[7] mismatch detected",
                                        &format!(
                                            "PCR[7] value {} does not match baseline {}. \
                                             This may indicate Secure Boot policy tampering.",
                                            measured_hex, expected_value
                                        ),
                                    )
                                    .with_confidence(0.9)
                                    .with_details(serde_json::json!({
                                        "pcr_index": 7,
                                        "measured": measured_hex,
                                        "expected": expected_value,
                                        "offset": offset,
                                    }))
                                    .with_recommendation(
                                        "Verify Secure Boot configuration and re-measure firmware.",
                                    ),
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }
}
