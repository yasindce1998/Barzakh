use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

// EFI_IMAGE_SECURITY_DATABASE_GUID — the vendor GUID of the `dbx` forbidden
// signature database, in EFI_GUID wire layout (Data1/2/3 little-endian).
const DBX_GUID: [u8; 16] = [
    0xCB, 0xB2, 0x19, 0xD7, 0x3A, 0x3D, 0x96, 0x45, 0xA3, 0xBC, 0xDA, 0xD0, 0x0E, 0x67, 0x65, 0x6F,
];

// UTF-16LE encoding of the variable name "dbx".
const DBX_NAME_UTF16: [u8; 6] = [0x64, 0x00, 0x62, 0x00, 0x78, 0x00];

// EFI_SIGNATURE_LIST header = SignatureType(16) + 3 * u32 = 28 bytes. A list
// whose declared SignatureListSize is <= the header carries zero signatures.
const SIGNATURE_LIST_HEADER_LEN: u32 = 0x1C;

// Authenticated-variable timestamps older than this almost certainly indicate a
// rollback to a pre-BlackLotus revocation set (the 2023 dbx updates are the ones
// that matter); anything before 2016 is implausible for a current platform.
const MIN_PLAUSIBLE_DBX_YEAR: u16 = 2016;

pub struct SecurebootDbxDetector;

impl Default for SecurebootDbxDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurebootDbxDetector {
    pub fn new() -> Self {
        Self
    }

    fn name_precedes(&self, data: &[u8], guid_off: usize) -> bool {
        let start = guid_off.saturating_sub(64);
        data[start..guid_off]
            .windows(DBX_NAME_UTF16.len())
            .any(|w| w == DBX_NAME_UTF16)
    }

    fn check_record(&self, data: &[u8], off: usize) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Layout we key on: [dbx VendorGuid(16)][EFI_SIGNATURE_LIST: SignatureType(16),
        // SignatureListSize u32, SignatureHeaderSize u32, SignatureSize u32]...
        let size_off = off + 16 + 16;
        if size_off + 4 > data.len() {
            return findings;
        }

        // Require a non-zero SignatureType GUID so we are really looking at a
        // signature list and not an incidental GUID match.
        let sig_type = &data[off + 16..off + 32];
        if sig_type.iter().all(|&b| b == 0) {
            return findings;
        }

        let list_size =
            u32::from_le_bytes(data[size_off..size_off + 4].try_into().unwrap_or([0; 4]));

        if list_size <= SIGNATURE_LIST_HEADER_LEN {
            findings.push(
                Finding::new(
                    "secureboot_dbx",
                    Severity::Critical,
                    "Secure Boot dbx revocation list is empty (rollback)",
                    &format!(
                        "The dbx forbidden-signature database at offset 0x{off:08X} declares \
                         SignatureListSize={list_size} (<= the {SIGNATURE_LIST_HEADER_LEN}-byte \
                         header), so it contains no revocation entries. An emptied or rolled-back \
                         dbx re-enables every previously revoked bootloader — the exact gap abused \
                         by BlackLotus to defeat Secure Boot.",
                    ),
                )
                .with_confidence(0.88)
                .with_details(serde_json::json!({
                    "offset": format!("0x{off:08X}"),
                    "signature_list_size": list_size,
                    "header_size": SIGNATURE_LIST_HEADER_LEN,
                    "variable": "dbx",
                }))
                .with_recommendation(
                    "Re-apply the current UEFI revocation list (KEK-signed dbx update) from the \
                     OS / firmware vendor; verify dbx contains the 2023 BlackLotus revocations.",
                ),
            );
        }

        // Optional authenticated-variable timestamp immediately after the list
        // header (EFI_TIME: Year u16, then Month/Day/...). A stale year is a
        // strong secondary rollback signal.
        let time_off = size_off + 12;
        if time_off + 2 <= data.len() {
            let year =
                u16::from_le_bytes(data[time_off..time_off + 2].try_into().unwrap_or([0; 2]));
            if year != 0 && year < MIN_PLAUSIBLE_DBX_YEAR {
                findings.push(
                    Finding::new(
                        "secureboot_dbx",
                        Severity::High,
                        "Secure Boot dbx authenticated timestamp rolled back",
                        &format!(
                            "The dbx authenticated variable at offset 0x{off:08X} carries an \
                             EFI_TIME year of {year}, predating the modern revocation set. \
                             Replaying an old signed dbx lets an attacker downgrade the platform \
                             to a revocation list that still trusts known-malicious loaders.",
                        ),
                    )
                    .with_confidence(0.70)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{off:08X}"),
                        "timestamp_year": year,
                        "min_plausible_year": MIN_PLAUSIBLE_DBX_YEAR,
                    })),
                );
            }
        }

        findings
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (i, window) in data.windows(DBX_GUID.len()).enumerate() {
            if window == DBX_GUID && self.name_precedes(data, i) {
                findings.extend(self.check_record(data, i));
            }
        }
        findings
    }
}

impl Detector for SecurebootDbxDetector {
    fn name(&self) -> &str {
        "secureboot_dbx"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        Ok(self.scan(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA256_TYPE: [u8; 16] = [
        0x26, 0x16, 0xC4, 0xC1, 0x4C, 0x50, 0x92, 0x40, 0xAC, 0xA9, 0x41, 0xF9, 0x36, 0x93, 0x43,
        0x28,
    ];

    fn empty_dbx_record() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&DBX_NAME_UTF16); // name "dbx"
        v.extend_from_slice(&[0, 0]); // name terminator
        v.extend_from_slice(&DBX_GUID); // VendorGuid
        v.extend_from_slice(&SHA256_TYPE); // SignatureType
        v.extend_from_slice(&SIGNATURE_LIST_HEADER_LEN.to_le_bytes()); // empty list
        v.extend_from_slice(&0u32.to_le_bytes()); // SignatureHeaderSize
        v.extend_from_slice(&0x30u32.to_le_bytes()); // SignatureSize
        v
    }

    #[test]
    fn fires_on_empty_dbx() {
        let findings = SecurebootDbxDetector::new().scan(&empty_dbx_record());
        assert!(
            findings.iter().any(|f| f.severity == Severity::Critical),
            "empty dbx should raise a critical finding"
        );
    }

    #[test]
    fn quiet_on_clean_buffer() {
        let data = vec![0u8; 0x4000];
        assert!(SecurebootDbxDetector::new().scan(&data).is_empty());
    }

    #[test]
    fn quiet_without_name_marker() {
        // GUID present but no preceding "dbx" name → not our variable.
        let mut v = vec![0u8; 64];
        v.extend_from_slice(&DBX_GUID);
        v.extend_from_slice(&SHA256_TYPE);
        v.extend_from_slice(&SIGNATURE_LIST_HEADER_LEN.to_le_bytes());
        assert!(SecurebootDbxDetector::new().scan(&v).is_empty());
    }
}
