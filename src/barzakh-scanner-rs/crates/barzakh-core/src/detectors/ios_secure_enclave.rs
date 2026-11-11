use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const SEPI_MAGIC: [u8; 4] = [0x73, 0x65, 0x70, 0x69]; // "sepi"
const SEPOS_MAGIC: [u8; 5] = [0x53, 0x45, 0x50, 0x4F, 0x53]; // "SEPOS"

pub struct IosSecureEnclaveDetector;

impl Default for IosSecureEnclaveDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl IosSecureEnclaveDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_sep(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for offset in 0..data.len().saturating_sub(64) {
            if data[offset..offset + 4] == SEPI_MAGIC {
                self.validate_sepi(data, offset, &mut findings);
            }
            if offset + 5 <= data.len() && data[offset..offset + 5] == SEPOS_MAGIC {
                self.validate_sepos(data, offset, &mut findings);
            }
        }

        findings
    }

    fn validate_sepi(&self, data: &[u8], offset: usize, findings: &mut Vec<Finding>) {
        if offset + 0x100 > data.len() {
            return;
        }

        // SEP image structure: magic + version(4) + size(4) + flags(4) + sig(256)
        let flags = u32::from_le_bytes(data[offset + 12..offset + 16].try_into().unwrap_or([0; 4]));

        // Check signature region at +0x10 (256 bytes for RSA-2048)
        let sig_start = offset + 0x10;
        let sig_end = sig_start + 0x100;
        if sig_end <= data.len() {
            let sig = &data[sig_start..sig_end];
            if sig.iter().all(|&b| b == 0x00) {
                findings.push(
                    Finding::new(
                        "ios_secure_enclave",
                        Severity::Critical,
                        "SEP firmware image has zeroed signature",
                        &format!(
                            "SEPI image at 0x{:08X} has a completely zeroed RSA signature. \
                             Secure Enclave Processor firmware integrity cannot be verified — \
                             key material and biometric data are at risk.",
                            offset
                        ),
                    )
                    .with_confidence(0.94)
                    .with_recommendation("Restore genuine SEP firmware signed by Apple."),
                );
            }
        }

        // Check for debug flag (bit 0 of flags)
        if flags & 0x01 != 0 {
            findings.push(
                Finding::new(
                    "ios_secure_enclave",
                    Severity::High,
                    "SEP firmware has debug flag enabled",
                    &format!(
                        "SEPI at 0x{:08X} has debug flag set (flags=0x{:08X}). \
                         Debug-enabled SEP firmware allows key extraction and \
                         attestation bypass.",
                        offset, flags
                    ),
                )
                .with_confidence(0.85),
            );
        }
    }

    fn validate_sepos(&self, data: &[u8], offset: usize, findings: &mut Vec<Finding>) {
        if offset + 0x80 > data.len() {
            return;
        }

        // SEPOS header: magic(5) + padding(3) + version(4) + key_attestation_blob(64)
        let key_att_offset = offset + 0x10;
        if key_att_offset + 64 <= data.len() {
            let key_att = &data[key_att_offset..key_att_offset + 64];

            if key_att.iter().all(|&b| b == 0x00) {
                findings.push(
                    Finding::new(
                        "ios_secure_enclave",
                        Severity::Critical,
                        "SEPOS key attestation blob is zeroed",
                        &format!(
                            "SEPOS at 0x{:08X} has an empty key attestation blob. \
                             Hardware-backed key attestation is non-functional — \
                             device identity claims cannot be trusted.",
                            offset
                        ),
                    )
                    .with_confidence(0.88),
                );
            }

            // Check for repeated-byte attestation (likely forge attempt)
            if key_att.len() >= 4 && key_att.iter().all(|&b| b == key_att[0]) && key_att[0] != 0 {
                findings.push(
                    Finding::new(
                        "ios_secure_enclave",
                        Severity::High,
                        "SEPOS key attestation blob appears forged (repeated bytes)",
                        &format!(
                            "SEPOS at 0x{:08X} key attestation is filled with byte 0x{:02X}. \
                             Likely an attempted forgery of device attestation.",
                            offset, key_att[0]
                        ),
                    )
                    .with_confidence(0.82),
                );
            }
        }
    }
}

impl Detector for IosSecureEnclaveDetector {
    fn name(&self) -> &str {
        "ios_secure_enclave"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        Ok(self.check_sep(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn fires_on_unsigned_sep() {
        let mut data = vec![0u8; 0x200];
        data[0..4].copy_from_slice(&SEPI_MAGIC);
        // sig at +0x10 is all zeros (already)

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = IosSecureEnclaveDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn fires_on_zeroed_attestation() {
        let mut data = vec![0u8; 0x200];
        data[0..5].copy_from_slice(&SEPOS_MAGIC);
        // key attestation at +0x10 is zeroed (already)

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = IosSecureEnclaveDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn quiet_on_signed_sep() {
        let mut data = vec![0u8; 0x200];
        data[0..4].copy_from_slice(&SEPI_MAGIC);
        // Non-zero sig
        data[0x10..0x110].fill(0xAA);
        // flags = 0 (no debug)
        data[12..16].copy_from_slice(&0u32.to_le_bytes());

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = IosSecureEnclaveDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(findings.is_empty());
    }
}
