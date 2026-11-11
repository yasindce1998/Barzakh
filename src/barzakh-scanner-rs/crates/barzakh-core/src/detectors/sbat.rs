use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const SBAT_HEADER: &[u8] = b"sbat,";
const SBAT_LEVEL_VAR: &[u8] = b"S\x00b\x00a\x00t\x00L\x00e\x00v\x00e\x00l\x00";

pub struct SbatDetector;

impl Default for SbatDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SbatDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_sbat_rollback(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(var_pos) = data
            .windows(SBAT_LEVEL_VAR.len())
            .position(|w| w == SBAT_LEVEL_VAR)
        {
            let attrs_offset = var_pos + SBAT_LEVEL_VAR.len() + 2;
            if attrs_offset + 4 < data.len() {
                let attrs = u32::from_le_bytes(
                    data[attrs_offset..attrs_offset + 4]
                        .try_into()
                        .unwrap_or([0; 4]),
                );

                let bs_rt_at = 0x27;
                if attrs & bs_rt_at == bs_rt_at {
                    let value_start = attrs_offset + 8;
                    if value_start < data.len() {
                        let value_end = (value_start + 256).min(data.len());
                        let value_region = &data[value_start..value_end];

                        if let Some(sbat_pos) = value_region
                            .windows(SBAT_HEADER.len())
                            .position(|w| w == SBAT_HEADER)
                        {
                            let gen_start = sbat_pos + SBAT_HEADER.len();
                            if gen_start < value_region.len() {
                                let gen_byte = value_region[gen_start];
                                if gen_byte == b'1' || gen_byte == b'0' {
                                    findings.push(
                                        Finding::new(
                                            "sbat",
                                            Severity::High,
                                            "SBAT revocation counter rolled back to minimum",
                                            &format!(
                                                "SbatLevel variable at offset 0x{:08X} contains \
                                                 generation '{}' which is below expected minimum. \
                                                 An attacker may have rolled back SBAT to allow \
                                                 execution of revoked bootloaders.",
                                                var_pos, gen_byte as char
                                            ),
                                        )
                                        .with_confidence(0.85)
                                        .with_details(serde_json::json!({
                                            "offset": format!("0x{:08X}", var_pos),
                                            "generation": gen_byte as char,
                                            "attributes": format!("0x{:08X}", attrs),
                                            "technique": "SBAT rollback via SetVariable",
                                        }))
                                        .with_recommendation(
                                            "Reset SbatLevel to current revocation generation via firmware update",
                                        ),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        findings
    }

    fn check_sbat_metadata_tampering(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut sbat_sections = Vec::new();

        let mut pos = 0;
        while pos < data.len().saturating_sub(SBAT_HEADER.len()) {
            if data[pos..].starts_with(SBAT_HEADER) {
                sbat_sections.push(pos);
            }
            pos += 1;
        }

        if sbat_sections.len() > 3 {
            findings.push(
                Finding::new(
                    "sbat",
                    Severity::Medium,
                    "Multiple SBAT metadata sections detected",
                    &format!(
                        "Found {} SBAT header sections. Multiple copies may indicate \
                         SBAT confusion attack where conflicting revocation data is injected.",
                        sbat_sections.len()
                    ),
                )
                .with_confidence(0.65)
                .with_details(serde_json::json!({
                    "section_count": sbat_sections.len(),
                    "offsets": sbat_sections.iter().take(5).map(|o| format!("0x{:08X}", o)).collect::<Vec<_>>(),
                })),
            );
        }

        findings
    }
}

impl Detector for SbatDetector {
    fn name(&self) -> &str {
        "sbat"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_sbat_rollback(&data));
        findings.extend(self.check_sbat_metadata_tampering(&data));

        Ok(findings)
    }
}
