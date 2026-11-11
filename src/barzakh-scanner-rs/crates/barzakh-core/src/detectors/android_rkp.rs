use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const CBOR_ARRAY_TAG: u8 = 0x83;
const COSE_KEY_TYPE: [u8; 3] = [0xA5, 0x01, 0x02];
const RKP_GEEK_MARKER: &[u8] = b"google/keymint";
const EEK_CURVE_MARKER: [u8; 3] = [0x20, 0x01, 0x21];

pub struct AndroidRkpDetector;

impl Default for AndroidRkpDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AndroidRkpDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_spoofed_eek_chain(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(COSE_KEY_TYPE.len())
            .position(|w| w == COSE_KEY_TYPE)
        {
            let region_end = (pos + 512).min(data.len());
            let region = &data[pos..region_end];

            let has_eek_curve = region
                .windows(EEK_CURVE_MARKER.len())
                .any(|w| w == EEK_CURVE_MARKER);

            let has_non_google_root = !region
                .windows(RKP_GEEK_MARKER.len())
                .any(|w| w == RKP_GEEK_MARKER);

            let has_predictable_key = region.windows(32).any(|w| w.iter().all(|&b| b == w[0]));

            if has_eek_curve && has_non_google_root && has_predictable_key {
                findings.push(
                    Finding::new(
                        "android_rkp",
                        Severity::Critical,
                        "RKP Endpoint Encryption Key with non-Google root and predictable key material",
                        &format!(
                            "Found COSE_Key structure at offset 0x{:08X} with EEK curve parameters \
                             but missing Google GEEK root identifier, and containing predictable \
                             key bytes. This indicates a spoofed RKP provisioning response designed \
                             to intercept Remote Key Provisioning for KeyMint attestation keys.",
                            pos
                        ),
                    )
                    .with_confidence(0.91)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", pos),
                        "has_eek_curve": true,
                        "missing_google_root": true,
                        "predictable_key_material": true,
                        "technique": "RKP EEK chain spoofing for attestation key interception",
                    }))
                    .with_recommendation(
                        "Reject RKP responses not signed by Google GEEK; re-provision attestation keys",
                    ),
                );
            }
        }

        findings
    }

    fn check_csr_manipulation(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let has_cbor_array = data.contains(&CBOR_ARRAY_TAG);
        let has_keymint_ref = data
            .windows(RKP_GEEK_MARKER.len())
            .any(|w| w == RKP_GEEK_MARKER);

        if has_cbor_array && has_keymint_ref {
            let has_debug_level = data.windows(8).any(|w| {
                w[0] == 0x19 && w[1] == 0x01 && w[2] == 0x00 && w[3] == 0x41 && w[4] == 0x00
            });

            if has_debug_level {
                findings.push(
                    Finding::new(
                        "android_rkp",
                        Severity::High,
                        "RKP certificate signing request with debug security level",
                        "Found RKP CSR payload with KeyMint reference containing \
                         securityLevel=0 (Software/Debug). Production devices must use \
                         securityLevel >= TrustedEnvironment. A debug CSR can be used to \
                         obtain attestation certificates that misrepresent device security.",
                    )
                    .with_confidence(0.85)
                    .with_details(serde_json::json!({
                        "has_keymint_reference": true,
                        "security_level": "debug/software (0)",
                        "technique": "RKP CSR security level downgrade",
                    }))
                    .with_recommendation(
                        "Reject attestation from devices reporting debug security level in production",
                    ),
                );
            }
        }

        findings
    }

    fn check_provisioning_bypass(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let has_factory_key_marker = data.windows(11).any(|w| w == b"FactoryKeys");
        let has_test_cert = data.windows(8).any(|w| w == b"testcert");

        if has_factory_key_marker && has_test_cert {
            findings.push(
                Finding::new(
                    "android_rkp",
                    Severity::High,
                    "RKP provisioning blob containing factory/test certificates",
                    "Found provisioning data with both FactoryKeys marker and test certificate \
                     references. This may indicate an attempt to use factory provisioning \
                     artifacts to bypass production RKP flow and obtain valid attestation \
                     without proper device identity verification.",
                )
                .with_confidence(0.82)
                .with_details(serde_json::json!({
                    "factory_keys_present": true,
                    "test_certs_present": true,
                    "technique": "RKP provisioning bypass via factory test certificates",
                }))
                .with_recommendation(
                    "Revoke factory test certificates; ensure production provisioning rejects test artifacts",
                ),
            );
        }

        findings
    }
}

impl Detector for AndroidRkpDetector {
    fn name(&self) -> &str {
        "android_rkp"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }

    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_spoofed_eek_chain(&data));
        findings.extend(self.check_csr_manipulation(&data));
        findings.extend(self.check_provisioning_bypass(&data));

        Ok(findings)
    }
}
