use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};
use crate::detectors::varstore;

/// `gEfiGlobalVariableGuid` — the vendor GUID of SecureBoot/SetupMode.
const EFI_GLOBAL_VARIABLE_GUID: [u8; 16] = [
    0x61, 0xDF, 0xE4, 0x8B, 0xCA, 0x93, 0xD2, 0x11, 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C,
];

const SECURE_BOOT_ENABLED: u8 = 1;

pub struct SecureBootDetector;

impl Default for SecureBootDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureBootDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_secure_boot_state(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // SecureBoot/SetupMode are UEFI variables: they only carry meaning
        // inside a real variable store. Every UEFI binary embeds the
        // variable *names* as strings, so name-matching outside a store is
        // pure noise.
        for entry in varstore::parse_entries(data) {
            if entry.guid != EFI_GLOBAL_VARIABLE_GUID || entry.data.is_empty() {
                continue;
            }
            match entry.name.as_str() {
                "SecureBoot" if entry.data[0] != SECURE_BOOT_ENABLED => {
                    findings.push(
                        Finding::new(
                            "secureboot",
                            Severity::High,
                            "Secure Boot is disabled",
                            "The SecureBoot variable in the firmware variable store is set \
                             to 0. Unsigned code execution is permitted during boot.",
                        )
                        .with_confidence(0.90)
                        .with_details(serde_json::json!({
                            "variable": "SecureBoot",
                            "value": entry.data[0],
                            "offset": format!("0x{:08X}", entry.offset),
                        }))
                        .with_recommendation("Enable Secure Boot in firmware settings."),
                    );
                }
                "SetupMode" if entry.data[0] == 1 => {
                    findings.push(
                        Finding::new(
                            "secureboot",
                            Severity::Critical,
                            "Platform in Setup Mode",
                            "SetupMode is enabled, meaning the Platform Key (PK) can be \
                             enrolled by anyone. An attacker can install their own keys.",
                        )
                        .with_confidence(0.95)
                        .with_details(serde_json::json!({
                            "variable": "SetupMode",
                            "value": 1,
                            "offset": format!("0x{:08X}", entry.offset),
                        }))
                        .with_recommendation(
                            "Enroll a Platform Key to exit Setup Mode immediately.",
                        ),
                    );
                }
                _ => {}
            }
        }

        findings
    }
}

impl Detector for SecureBootDetector {
    fn name(&self) -> &str {
        "secureboot"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let findings = self.check_secure_boot_state(&data);
        Ok(findings)
    }
}
