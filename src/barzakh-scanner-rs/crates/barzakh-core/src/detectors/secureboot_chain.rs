use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

// X509 SignatureType GUID: {a5c059a1-94e4-4aa7-87b5-ab155c2bf072}
const X509_SIGNATURE_GUID: [u8; 16] = [
    0xA1, 0x59, 0xC0, 0xA5, 0xE4, 0x94, 0xA7, 0x4A, 0x87, 0xB5, 0xAB, 0x15, 0x5C, 0x2B, 0xF0, 0x72,
];

// SecureBoot variable GUID: {8be4df61-93ca-11d2-aa0d-00e098032b8c}
const SECUREBOOT_GUID: [u8; 16] = [
    0x61, 0xDF, 0xE4, 0x8B, 0xCA, 0x93, 0xD2, 0x11, 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C,
];

pub struct SecurebootChainDetector;

impl Default for SecurebootChainDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurebootChainDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_pk_kek_chain(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Look for EFI_SIGNATURE_LIST structures with X509 SignatureType
        // EFI_SIGNATURE_LIST: SignatureType(16) + SignatureListSize(4) +
        //                     SignatureHeaderSize(4) + SignatureSize(4)
        let mut cert_count = 0;
        let mut list_count = 0;

        for (i, window) in data.windows(28).enumerate() {
            if window[..16] == X509_SIGNATURE_GUID {
                list_count += 1;
                let sig_list_size = u32::from_le_bytes(window[16..20].try_into().unwrap_or([0; 4]));
                let sig_header_size =
                    u32::from_le_bytes(window[20..24].try_into().unwrap_or([0; 4]));
                let sig_size = u32::from_le_bytes(window[24..28].try_into().unwrap_or([0; 4]));

                // Calculate number of certificates in this list
                if sig_size > 0 && sig_list_size > 28 + sig_header_size {
                    let data_size = sig_list_size - 28 - sig_header_size;
                    let certs_in_list = data_size / sig_size;
                    cert_count += certs_in_list;

                    // PK should have exactly 1 certificate. If this is the first
                    // signature list (likely PK) and has != 1 cert, flag it
                    if list_count == 1 && (certs_in_list == 0 || certs_in_list > 1) {
                        findings.push(
                            Finding::new(
                                "secureboot_chain",
                                Severity::Critical,
                                "Platform Key (PK) anomaly in Secure Boot chain",
                                &format!(
                                    "EFI Signature List at offset 0x{:08X} (likely PK) \
                                     contains {} certificates. The Platform Key should \
                                     contain exactly 1 certificate. This indicates Secure \
                                     Boot chain manipulation.",
                                    i, certs_in_list
                                ),
                            )
                            .with_confidence(0.70)
                            .with_details(serde_json::json!({
                                "offset": format!("0x{:08X}", i),
                                "cert_count": certs_in_list,
                                "list_size": sig_list_size,
                                "sig_size": sig_size,
                            }))
                            .with_recommendation(
                                "Verify Platform Key contains exactly one trusted certificate. \
                                 Re-enroll PK if compromised.",
                            ),
                        );
                    }
                }

                // Skip past this signature list to avoid double-counting
                let _ = (i, cert_count);
            }
        }

        findings
    }

    fn check_unauthorized_db_entry(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Look for ASN.1 validity fields in certificates
        // ASN.1 UTCTime tag: 0x17, GeneralizedTime tag: 0x18
        // Short validity certificates are suspicious (test certs)

        for (i, window) in data.windows(15).enumerate() {
            // UTCTime is tag 0x17, length 0x0D (13 bytes for YYMMDDHHMMSSZ)
            if window[0] == 0x17 && window[1] == 0x0D {
                // Parse the year from UTCTime (first 2 bytes are year)
                let year_hi = window[2];
                let year_lo = window[3];

                // Check if this is followed by another UTCTime (validity period)
                if i + 17 + 15 < data.len() {
                    let next_offset = i + 2 + 13; // After first UTCTime
                    if data[next_offset] == 0x17 && data[next_offset + 1] == 0x0D {
                        let end_year_hi = data[next_offset + 2];
                        let end_year_lo = data[next_offset + 3];

                        // Parse years (ASCII digits)
                        if year_hi.is_ascii_digit()
                            && year_lo.is_ascii_digit()
                            && end_year_hi.is_ascii_digit()
                            && end_year_lo.is_ascii_digit()
                        {
                            let start_year = (year_hi - b'0') as u32 * 10 + (year_lo - b'0') as u32;
                            let end_year =
                                (end_year_hi - b'0') as u32 * 10 + (end_year_lo - b'0') as u32;

                            // Normalize 2-digit year (00-49 = 2000-2049, 50-99 = 1950-1999)
                            let start_full = if start_year < 50 {
                                2000 + start_year
                            } else {
                                1900 + start_year
                            };
                            let end_full = if end_year < 50 {
                                2000 + end_year
                            } else {
                                1900 + end_year
                            };

                            // Certificate with < 1 year validity is suspicious
                            if end_full > start_full && (end_full - start_full) < 1 {
                                findings.push(
                                    Finding::new(
                                        "secureboot_chain",
                                        Severity::High,
                                        "Potentially unauthorized certificate in Secure Boot db",
                                        &format!(
                                            "Certificate at offset 0x{:08X} has very short \
                                             validity period ({}-{}). Short-lived certificates \
                                             are typical of test or debug certificates that \
                                             should not be in production Secure Boot databases.",
                                            i, start_full, end_full
                                        ),
                                    )
                                    .with_confidence(0.55)
                                    .with_details(serde_json::json!({
                                        "offset": format!("0x{:08X}", i),
                                        "validity_start_year": start_full,
                                        "validity_end_year": end_full,
                                    }))
                                    .with_recommendation(
                                        "Review Secure Boot signature database for unauthorized \
                                         or test certificates. Remove any non-production entries.",
                                    ),
                                );
                            }
                        }
                    }
                }
            }
        }

        findings
    }

    fn check_secureboot_state(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Look for SecureBoot EFI variable GUID followed by variable content
        for (i, window) in data.windows(16).enumerate() {
            if window == SECUREBOOT_GUID {
                // The variable name "SecureBoot" in UCS-2 follows the GUID in NVRAM
                // Variable value is typically at a known offset after header
                // Look for the variable value byte (0x00 = disabled, 0x01 = enabled)

                // Search nearby for the actual value (within reasonable header distance)
                let search_end = std::cmp::min(i + 256, data.len());
                let search_region = &data[i + 16..search_end];

                // Look for "SecureBoot" in UCS-2 encoding
                let secureboot_ucs2: &[u8] = &[
                    0x53, 0x00, 0x65, 0x00, 0x63, 0x00, 0x75, 0x00, 0x72, 0x00, 0x65, 0x00, 0x42,
                    0x00, 0x6F, 0x00, 0x6F, 0x00, 0x74, 0x00, 0x00, 0x00, // null terminator
                ];

                if let Some(name_offset) = search_region
                    .windows(secureboot_ucs2.len())
                    .position(|w| w == secureboot_ucs2)
                {
                    // Value follows after the name
                    let value_offset = i + 16 + name_offset + secureboot_ucs2.len();
                    if value_offset < data.len() && data[value_offset] == 0x00 {
                        findings.push(
                            Finding::new(
                                "secureboot_chain",
                                Severity::High,
                                "Secure Boot disabled in firmware image",
                                &format!(
                                    "SecureBoot variable at offset 0x{:08X} has value 0x00 \
                                     (disabled). Secure Boot should be enabled in production \
                                     firmware images to maintain the boot chain of trust.",
                                    i
                                ),
                            )
                            .with_confidence(0.75)
                            .with_details(serde_json::json!({
                                "guid_offset": format!("0x{:08X}", i),
                                "value_offset": format!("0x{:08X}", value_offset),
                                "value": "0x00 (disabled)",
                            }))
                            .with_recommendation(
                                "Enable Secure Boot in the firmware configuration. \
                                 Investigate why it was disabled.",
                            ),
                        );
                    }
                }
            }
        }

        findings
    }
}

impl Detector for SecurebootChainDetector {
    fn name(&self) -> &str {
        "secureboot_chain"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let mut findings = Vec::new();

        findings.extend(self.check_pk_kek_chain(&data));
        findings.extend(self.check_unauthorized_db_entry(&data));
        findings.extend(self.check_secureboot_state(&data));

        Ok(findings)
    }
}
