use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const COSE_SIGN1_TAG: [u8; 2] = [0xD2, 0x84];
const CBOR_MAP_TAG: u8 = 0xA5;
const DICE_CDI_MARKER: &[u8] = b"CDI_Attest";
const DICE_UDS_MARKER: &[u8] = b"UDS";
const DICE_CERT_CHAIN_MARKER: &[u8] = b"DiceCertChain";

pub struct AndroidDiceDetector;

impl Default for AndroidDiceDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AndroidDiceDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_forged_dice_chain(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(COSE_SIGN1_TAG.len())
            .position(|w| w == COSE_SIGN1_TAG)
        {
            let region_end = (pos + 512).min(data.len());
            let region = &data[pos..region_end];

            let has_cert_chain = region
                .windows(DICE_CERT_CHAIN_MARKER.len())
                .any(|w| w == DICE_CERT_CHAIN_MARKER);

            let has_predictable_bytes = region
                .windows(16)
                .any(|w| w.iter().all(|&b| b == w[0]) || w == [0x00; 16] || w == [0xFF; 16]);

            if has_cert_chain && has_predictable_bytes {
                findings.push(
                    Finding::new(
                        "android_dice",
                        Severity::Critical,
                        "DICE certificate chain with predictable/forged key material",
                        &format!(
                            "Found COSE_Sign1 structure at offset 0x{:08X} containing a \
                             DiceCertChain with predictable key material (repeated bytes or zeros). \
                             Legitimate DICE chains derive keys from hardware UDS with full entropy. \
                             Predictable values indicate a forged attestation chain.",
                            pos
                        ),
                    )
                    .with_confidence(0.92)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", pos),
                        "has_cert_chain_marker": true,
                        "predictable_key_material": true,
                        "technique": "DICE certificate chain forgery with predictable CDI",
                    }))
                    .with_recommendation(
                        "Device attestation is compromised; re-provision DICE chain from hardware root of trust",
                    ),
                );
            }
        }

        findings
    }

    fn check_uds_tampering(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(DICE_UDS_MARKER.len())
            .position(|w| w == DICE_UDS_MARKER)
        {
            let value_start = (pos + DICE_UDS_MARKER.len() + 4).min(data.len());
            let value_end = (value_start + 32).min(data.len());

            if value_end - value_start >= 32 {
                let uds_region = &data[value_start..value_end];
                let zero_count = uds_region.iter().filter(|&&b| b == 0x00).count();
                let entropy = uds_region
                    .iter()
                    .collect::<std::collections::HashSet<_>>()
                    .len();

                if zero_count > 24 || entropy < 4 {
                    findings.push(
                        Finding::new(
                            "android_dice",
                            Severity::Critical,
                            "DICE Unique Device Secret (UDS) with anomalously low entropy",
                            &format!(
                                "Found UDS marker at offset 0x{:08X} followed by 32 bytes with \
                                 only {} unique values (expected ~200+ for true hardware RNG). \
                                 A low-entropy UDS indicates the hardware root of trust has been \
                                 compromised or the UDS was injected with a known value.",
                                pos, entropy
                            ),
                        )
                        .with_confidence(0.94)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", pos),
                            "unique_byte_values": entropy,
                            "zero_byte_count": zero_count,
                            "technique": "UDS entropy analysis for DICE root compromise detection",
                        }))
                        .with_recommendation(
                            "Hardware root of trust may be compromised; device requires factory re-provisioning",
                        ),
                    );
                }
            }
        }

        findings
    }

    fn check_cdi_attest_forgery(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(DICE_CDI_MARKER.len())
            .position(|w| w == DICE_CDI_MARKER)
        {
            let region_end = (pos + 128).min(data.len());
            let region = &data[pos..region_end];

            let has_cbor_map = region.contains(&CBOR_MAP_TAG);
            let has_zero_hash = region.windows(32).any(|w| w.iter().all(|&b| b == 0x00));

            if has_cbor_map && has_zero_hash {
                findings.push(
                    Finding::new(
                        "android_dice",
                        Severity::High,
                        "CDI_Attest value with zeroed code hash in DICE layer",
                        &format!(
                            "Found CDI_Attest marker at offset 0x{:08X} with a CBOR map containing \
                             a zeroed 32-byte hash field. The CDI derivation should include a \
                             non-zero hash of the next boot layer's code. A zeroed hash means \
                             any code will be accepted in attestation.",
                            pos
                        ),
                    )
                    .with_confidence(0.88)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", pos),
                        "cbor_map_present": true,
                        "zeroed_code_hash": true,
                        "technique": "CDI attestation bypass via zeroed code measurement",
                    }))
                    .with_recommendation(
                        "Verify CDI derivation includes non-zero code hash for each boot layer",
                    ),
                );
            }
        }

        findings
    }
}

impl Detector for AndroidDiceDetector {
    fn name(&self) -> &str {
        "android_dice"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }

    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_forged_dice_chain(&data));
        findings.extend(self.check_uds_tampering(&data));
        findings.extend(self.check_cdi_attest_forgery(&data));

        Ok(findings)
    }
}
