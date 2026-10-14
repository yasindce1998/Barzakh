use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};
use crate::detectors::varstore;

const EFI_IMAGE_SECURITY_DATABASE_GUID: [u8; 16] = [
    0xCB, 0xB2, 0x19, 0xD7, 0x3A, 0x3D, 0x96, 0x45, 0xA3, 0xBC, 0xDA, 0xD0, 0x0E, 0x67, 0x65, 0x6F,
];

const EFI_VARIABLE_TIME_BASED_AUTH: u32 = 0x00000020;
const EFI_VARIABLE_APPEND_WRITE: u32 = 0x00000040;

pub struct AuthVariableDetector;

impl Default for AuthVariableDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthVariableDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_authenticated_variables(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Variables only carry meaning inside a real EFI variable store:
        // every UEFI binary embeds variable GUIDs as data, and bytes
        // preceding such a GUID are code, not a variable header.
        for entry in varstore::parse_entries(data) {
            let is_security_db = entry.guid == EFI_IMAGE_SECURITY_DATABASE_GUID;

            // Check for time-based authenticated variable without proper auth data
            if entry.attributes & EFI_VARIABLE_TIME_BASED_AUTH != 0
                && entry.timestamp.iter().all(|&b| b == 0)
            {
                findings.push(
                    Finding::new(
                        "auth_variable",
                        Severity::High,
                        "Authenticated variable with zeroed timestamp (replay possible)",
                        &format!(
                            "Authenticated variable '{}' at offset 0x{:08X} has an all-zero \
                             timestamp. This defeats time-based replay protection and may \
                             allow variable content rollback.",
                            entry.name, entry.offset
                        ),
                    )
                    .with_confidence(0.78)
                    .with_details(serde_json::json!({
                        "variable_offset": format!("0x{:08X}", entry.offset),
                        "variable_name": entry.name,
                        "attributes": format!("0x{:08X}", entry.attributes),
                        "is_security_db": is_security_db,
                    }))
                    .with_recommendation(
                        "Re-provision variable with proper time-based authentication",
                    ),
                );
            }

            // Check for security database variable without authentication attribute
            if is_security_db && entry.attributes & EFI_VARIABLE_TIME_BASED_AUTH == 0 {
                findings.push(
                    Finding::new(
                        "auth_variable",
                        Severity::Critical,
                        "Security database variable without authentication",
                        &format!(
                            "Variable '{}' at offset 0x{:08X} uses the image security database \
                             GUID but lacks TIME_BASED_AUTHENTICATED_WRITE_ACCESS attribute. The \
                             db/dbx can be modified without cryptographic proof.",
                            entry.name, entry.offset
                        ),
                    )
                    .with_confidence(0.85)
                    .with_details(serde_json::json!({
                        "variable_offset": format!("0x{:08X}", entry.offset),
                        "variable_name": entry.name,
                        "attributes": format!("0x{:08X}", entry.attributes),
                    }))
                    .with_recommendation(
                        "Ensure PK, KEK, db, and dbx all require authenticated writes",
                    ),
                );
            }

            // Check for append-write without authentication (allows unauthorized additions)
            if entry.attributes & EFI_VARIABLE_APPEND_WRITE != 0
                && entry.attributes & EFI_VARIABLE_TIME_BASED_AUTH == 0
            {
                findings.push(
                    Finding::new(
                        "auth_variable",
                        Severity::Medium,
                        "Variable with APPEND_WRITE but no authentication requirement",
                        &format!(
                            "Variable '{}' at offset 0x{:08X} allows append writes without \
                             authentication. An attacker at runtime could append malicious \
                             data to this variable.",
                            entry.name, entry.offset
                        ),
                    )
                    .with_confidence(0.70)
                    .with_details(serde_json::json!({
                        "variable_offset": format!("0x{:08X}", entry.offset),
                        "variable_name": entry.name,
                        "attributes": format!("0x{:08X}", entry.attributes),
                    }))
                    .with_recommendation(
                        "Require authenticated writes for append-capable variables",
                    ),
                );
            }
        }

        findings
    }
}

impl Detector for AuthVariableDetector {
    fn name(&self) -> &str {
        "auth_variable"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        Ok(self.check_authenticated_variables(&data))
    }
}
