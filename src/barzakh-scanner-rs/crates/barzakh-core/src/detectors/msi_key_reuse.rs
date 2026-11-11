use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const BOOT_GUARD_KM_MAGIC: &[u8] = b"__KEYM__";
const BOOT_GUARD_BPM_MAGIC: &[u8] = b"__ACBP__";
const MSI_OEM_KEY_MARKER: &[u8] = b"MSI-OEM-KEY-2023";
const LEAKED_KEY_MODULUS_PREFIX: [u8; 32] = [
    0xD4, 0x07, 0xE5, 0x13, 0x9B, 0x7A, 0x2C, 0x61, 0xA8, 0x33, 0x02, 0xF9, 0x44, 0xBE, 0x55, 0xD7,
    0x8E, 0x6F, 0x21, 0xC3, 0x77, 0xAA, 0x09, 0xE8, 0x50, 0x1B, 0x4D, 0x96, 0xCB, 0x63, 0xF2, 0x38,
];

pub struct MsiKeyReuseDetector;

impl Default for MsiKeyReuseDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MsiKeyReuseDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_leaked_key_modulus(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(LEAKED_KEY_MODULUS_PREFIX.len())
            .position(|w| w == LEAKED_KEY_MODULUS_PREFIX)
        {
            findings.push(
                Finding::new(
                    "msi_key_reuse",
                    Severity::Critical,
                    "MSI leaked Boot Guard OEM key modulus detected",
                    &format!(
                        "Found the RSA key modulus prefix from MSI's 2023 leaked OEM signing key \
                         at offset 0x{:08X}. Firmware signed with this key cannot be trusted as \
                         the private key is publicly available.",
                        pos
                    ),
                )
                .with_confidence(0.97)
                .with_details(serde_json::json!({
                    "offset": format!("0x{:08X}", pos),
                    "key_source": "MSI 2023 breach (Money Message ransomware)",
                    "technique": "Firmware signing with leaked OEM Boot Guard key",
                }))
                .with_recommendation(
                    "Reject firmware signed with compromised key; MSI must provision new keys via Intel ACM update",
                ),
            );
        }

        findings
    }

    fn check_oem_key_marker(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(MSI_OEM_KEY_MARKER.len())
            .position(|w| w == MSI_OEM_KEY_MARKER)
        {
            findings.push(
                Finding::new(
                    "msi_key_reuse",
                    Severity::Critical,
                    "Explicit MSI leaked OEM key identifier present",
                    &format!(
                        "Found MSI OEM key marker string at offset 0x{:08X}. This firmware \
                         image explicitly references the compromised MSI signing key from the \
                         2023 data breach.",
                        pos
                    ),
                )
                .with_confidence(0.95)
                .with_details(serde_json::json!({
                    "offset": format!("0x{:08X}", pos),
                    "marker": "MSI-OEM-KEY-2023",
                    "technique": "Compromised OEM key reuse",
                }))
                .with_recommendation(
                    "Do not trust this firmware image; verify with MSI for key rotation status",
                ),
            );
        }

        findings
    }

    fn check_boot_guard_with_weak_signature(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let has_km = data
            .windows(BOOT_GUARD_KM_MAGIC.len())
            .any(|w| w == BOOT_GUARD_KM_MAGIC);

        let has_bpm = data
            .windows(BOOT_GUARD_BPM_MAGIC.len())
            .any(|w| w == BOOT_GUARD_BPM_MAGIC);

        if has_km && has_bpm {
            // Check for PKCS#1 v1.5 signature with known pattern
            let has_pkcs1_sig = data
                .windows(3)
                .any(|w| w[0] == 0x00 && w[1] == 0x01 && w[2] == 0xFF);

            let has_msi_board = data.windows(3).any(|w| w == b"MS-");

            if has_pkcs1_sig && has_msi_board {
                findings.push(
                    Finding::new(
                        "msi_key_reuse",
                        Severity::High,
                        "Boot Guard manifests with MSI board ID and PKCS#1 signature",
                        "Found Intel Boot Guard Key Manifest and Boot Policy Manifest with MSI \
                         board identifier and PKCS#1 v1.5 signature. Cross-reference with known \
                         leaked key database recommended.",
                    )
                    .with_confidence(0.70)
                    .with_details(serde_json::json!({
                        "has_key_manifest": true,
                        "has_boot_policy_manifest": true,
                        "has_msi_board_id": true,
                        "signature_type": "PKCS#1 v1.5",
                        "technique": "Boot Guard signed with potentially compromised MSI key",
                    }))
                    .with_recommendation(
                        "Verify Boot Guard key hash against Intel's provisioned FPF values",
                    ),
                );
            }
        }

        findings
    }
}

impl Detector for MsiKeyReuseDetector {
    fn name(&self) -> &str {
        "msi_key_reuse"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_leaked_key_modulus(&data));
        findings.extend(self.check_oem_key_marker(&data));
        findings.extend(self.check_boot_guard_with_weak_signature(&data));

        Ok(findings)
    }
}
