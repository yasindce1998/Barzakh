use std::path::Path;

use crate::detector::{Detector, DetectorError, Evidence, EvidenceKind, Finding, Severity};
use crate::detectors::varstore::parse_bounded_authenticated_entries;
use crate::ScanContext;

/// Correlates authenticated policy variables with a separately acquired TCG log.
/// A standalone image cannot establish whether writes were measured. Variable
/// timestamps across different names are not a rollback counter.
pub struct NvramVerifierDetector;

impl Default for NvramVerifierDetector {
    fn default() -> Self {
        Self::new()
    }
}
impl NvramVerifierDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Detector for NvramVerifierDetector {
    fn name(&self) -> &str {
        "nvram_verifier"
    }

    fn detect(&self, path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&ScanContext::load(path)?)
    }

    fn detect_context(&self, context: &ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let vars = parse_bounded_authenticated_entries(context.data());
        let vars: Vec<_> = vars
            .into_iter()
            .filter(|v| {
                let expected: [u8; 16] = if matches!(v.name.as_str(), "db" | "dbx") {
                    [
                        0xCB, 0xB2, 0x19, 0xD7, 0x3A, 0x3D, 0x96, 0x45, 0xA3, 0xBC, 0xDA, 0xD0,
                        0x0E, 0x67, 0x65, 0x6F,
                    ]
                } else if matches!(v.name.as_str(), "PK" | "KEK") {
                    [
                        0x61, 0xDF, 0xE4, 0x8B, 0xCA, 0x93, 0xD2, 0x11, 0xAA, 0x0D, 0x00, 0xE0,
                        0x98, 0x03, 0x2B, 0x8C,
                    ]
                } else {
                    return false;
                };
                v.guid == expected
            })
            .collect();
        if vars.is_empty() {
            // Legacy synthetic $VSS layouts are not proof of an authenticated
            // EDK2 store. Never promote them to a tampering verdict.
            if context.data().windows(4).any(|w| w == b"$VSS") {
                return Err(DetectorError::InsufficientEvidence("legacy variable-store layout requires a format-specific parser and same-boot TCG log".into()));
            }
            return Err(DetectorError::NotApplicable(
                "no authenticated Secure Boot variables".into(),
            ));
        }
        let measurements = context.variable_measurements().ok_or_else(||
            DetectorError::InsufficientEvidence("no separately captured same-boot TCG event log; absence from an image is not an unmeasured write".into()))?;
        let mut findings = Vec::new();
        for var in vars {
            let measurement = measurements
                .iter()
                .rev()
                .find(|m| m.name == var.name && m.guid == var.guid);
            let Some(measurement) = measurement else {
                findings.push(Finding::new("nvram_verifier", Severity::Info,
                    "Secure Boot variable has no matching policy measurement",
                    "The supplied log may be incomplete or use a different measurement policy; this does not prove an unmeasured write.")
                    .with_evidence(EvidenceKind::Insufficient, Evidence {
                        offset: Some(var.offset as u64), structure_path: format!("nvram/{}", var.name),
                        observed: "no matching GUID/name in supplied log".into(), expected: "same-boot policy measurement".into(),
                        provenance: "image and caller-supplied TCG log; not quote-verified".into(),
                    }));
                continue;
            };
            if var.data != measurement.data {
                findings.push(Finding::new("nvram_verifier", Severity::High,
                    "Secure Boot variable differs from supplied boot measurement",
                    "Current policy bytes differ from the last matching GUID/name measurement. Investigate acquisition timing and authorized updates before concluding tampering.")
                    .with_confidence(0.65)
                    .with_evidence(EvidenceKind::Structural, Evidence {
                        offset: Some(var.offset as u64), structure_path: format!("nvram/{}", var.name),
                        observed: format!("image SHA-256 {:x}", <sha2::Sha256 as sha2::Digest>::digest(var.data)),
                        expected: format!("event SHA-256 {:x}", <sha2::Sha256 as sha2::Digest>::digest(&measurement.data)),
                        provenance: format!("caller-supplied TCG log event at {}; not quote-verified", measurement.offset),
                    }));
            }
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(value: u8) -> (Vec<u8>, Vec<u8>) {
        let guid = [
            0xCB, 0xB2, 0x19, 0xD7, 0x3A, 0x3D, 0x96, 0x45, 0xA3, 0xBC, 0xDA, 0xD0, 0x0E, 0x67,
            0x65, 0x6F,
        ];
        let mut image = vec![0u8; 256];
        image[..16].copy_from_slice(&crate::detectors::varstore::AUTH_VARSTORE_GUID);
        image[16..20].copy_from_slice(&256u32.to_le_bytes());
        image[20..22].copy_from_slice(&[0x5A, 0xFE]);
        let entry = 28;
        image[entry..entry + 3].copy_from_slice(&[0x55, 0xAA, 0x3F]);
        image[entry + 36..entry + 40].copy_from_slice(&6u32.to_le_bytes());
        image[entry + 40..entry + 44].copy_from_slice(&1u32.to_le_bytes());
        image[entry + 44..entry + 60].copy_from_slice(&guid);
        image[entry + 60..entry + 66].copy_from_slice(b"d\0b\0\0\0");
        image[entry + 66] = value;
        let mut event = guid.to_vec();
        event.extend_from_slice(&2u64.to_le_bytes());
        event.extend_from_slice(&1u64.to_le_bytes());
        event.extend_from_slice(b"d\0b\0");
        event.push(42);
        let mut log = 7u32.to_le_bytes().to_vec();
        log.extend_from_slice(&0x8000_0001u32.to_le_bytes());
        log.extend_from_slice(&[0; 20]);
        log.extend_from_slice(&(event.len() as u32).to_le_bytes());
        log.extend(event);
        (image, log)
    }
    #[test]
    fn correlates_guid_name_and_value_without_claiming_attestation() {
        for (value, expected) in [(42, 0), (43, 1)] {
            let (image, log) = fixture(value);
            let context = ScanContext::from_bytes("vars".into(), image)
                .with_event_log(&log)
                .unwrap();
            let findings = NvramVerifierDetector.detect_context(&context).unwrap();
            assert_eq!(findings.len(), expected);
            if expected > 0 {
                assert_eq!(findings[0].evidence_kind, EvidenceKind::Structural);
                assert!(findings[0]
                    .evidence
                    .as_ref()
                    .unwrap()
                    .provenance
                    .contains("not quote-verified"));
            }
        }
    }
    #[test]
    fn real_store_without_log_is_inconclusive() {
        let (image, _) = fixture(42);
        let context = ScanContext::from_bytes("vars".into(), image);
        assert!(matches!(
            NvramVerifierDetector.detect_context(&context),
            Err(DetectorError::InsufficientEvidence(_))
        ));
    }
    #[test]
    fn variable_outside_declared_store_is_not_evidence() {
        let (mut image, log) = fixture(43);
        image[16..20].copy_from_slice(&28u32.to_le_bytes());
        let context = ScanContext::from_bytes("vars".into(), image)
            .with_event_log(&log)
            .unwrap();
        assert!(matches!(
            NvramVerifierDetector.detect_context(&context),
            Err(DetectorError::NotApplicable(_))
        ));
    }
    #[test]
    fn legacy_store_without_log_is_insufficient_not_critical() {
        let context = ScanContext::from_bytes("nvram".into(), b"$VSS\0\0\0\0".to_vec());
        assert!(matches!(
            NvramVerifierDetector.detect_context(&context),
            Err(DetectorError::InsufficientEvidence(_))
        ));
    }
    #[test]
    fn unrelated_image_is_not_applicable() {
        let context = ScanContext::from_bytes("fw".into(), vec![0; 4096]);
        assert!(matches!(
            NvramVerifierDetector.detect_context(&context),
            Err(DetectorError::NotApplicable(_))
        ));
    }
}
