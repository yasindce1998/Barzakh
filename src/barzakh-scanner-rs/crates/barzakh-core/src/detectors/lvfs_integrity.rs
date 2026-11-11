use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const LVFS_XML_HEADER: &[u8] = b"<?xml version=\"1.0\"";
const FIRMWARE_COMPONENT: &[u8] = b"<component type=\"firmware\">";
const PROVIDES_FIRMWARE: &[u8] = b"<provides><firmware type=\"flashed\">";
const CABINET_MAGIC: [u8; 4] = [0x4D, 0x53, 0x43, 0x46]; // "MSCF"
const JCAT_MAGIC: &[u8] = b"JCAT";
const FMP_CAPSULE_GUID: [u8; 16] = [
    0xB1, 0x22, 0xA2, 0x6D, 0x4D, 0x1A, 0x1C, 0x41, 0xAF, 0xC2, 0xC5, 0x86, 0x17, 0xF1, 0xC4, 0x24,
];
const DEADBEEF_HASH: &[u8] = b"deadbeefdeadbeef";

pub struct LvfsIntegrityDetector;

impl Default for LvfsIntegrityDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl LvfsIntegrityDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_spoofed_metadata(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let has_xml = data
            .windows(LVFS_XML_HEADER.len())
            .any(|w| w == LVFS_XML_HEADER);
        let has_component = data
            .windows(FIRMWARE_COMPONENT.len())
            .any(|w| w == FIRMWARE_COMPONENT);
        let has_provides = data
            .windows(PROVIDES_FIRMWARE.len())
            .any(|w| w == PROVIDES_FIRMWARE);

        if has_xml && has_component && has_provides {
            let has_suspicious_version = data.windows(14).any(|w| w == b"version=\"99.9");

            if has_suspicious_version {
                findings.push(
                    Finding::new(
                        "lvfs_integrity",
                        Severity::High,
                        "LVFS firmware metadata with suspiciously high version number",
                        "Found LVFS/fwupd firmware metadata XML with component version 99.x. \
                         This is characteristic of spoofed metadata designed to force a firmware \
                         downgrade-to-upgrade attack by appearing newer than any legitimate release.",
                    )
                    .with_confidence(0.88)
                    .with_details(serde_json::json!({
                        "has_xml_header": true,
                        "has_firmware_component": true,
                        "suspicious_version": "99.x",
                        "technique": "LVFS metadata version spoofing for forced update",
                    }))
                    .with_recommendation(
                        "Verify firmware metadata signature against LVFS GPG key and validate version plausibility",
                    ),
                );
            }
        }

        findings
    }

    fn check_checksum_mismatch(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let has_checksum_tag = data.windows(15).any(|w| w == b"checksum type=\"");

        if has_checksum_tag {
            let has_dummy_hash = data
                .windows(DEADBEEF_HASH.len())
                .any(|w| w == DEADBEEF_HASH);

            if has_dummy_hash {
                findings.push(
                    Finding::new(
                        "lvfs_integrity",
                        Severity::Critical,
                        "LVFS metadata contains dummy/placeholder checksum value",
                        "Found firmware metadata with a placeholder checksum \
                         (deadbeef pattern). This indicates either a test artifact or \
                         intentionally crafted spoofed metadata with invalid integrity checks.",
                    )
                    .with_confidence(0.95)
                    .with_details(serde_json::json!({
                        "checksum_pattern": "deadbeef repeated",
                        "technique": "Metadata integrity bypass via dummy checksum",
                    }))
                    .with_recommendation(
                        "Reject firmware with invalid checksums; re-download metadata from official LVFS remote",
                    ),
                );
            }
        }

        findings
    }

    fn check_cabinet_with_fmp(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let has_cabinet = data
            .windows(CABINET_MAGIC.len())
            .any(|w| w == CABINET_MAGIC);
        let has_fmp = data
            .windows(FMP_CAPSULE_GUID.len())
            .any(|w| w == FMP_CAPSULE_GUID);
        let has_metadata = data
            .windows(FIRMWARE_COMPONENT.len())
            .any(|w| w == FIRMWARE_COMPONENT);

        if has_cabinet && has_fmp && has_metadata {
            findings.push(
                Finding::new(
                    "lvfs_integrity",
                    Severity::High,
                    "Combined LVFS cabinet archive with embedded FMP capsule and metadata",
                    "Found Microsoft Cabinet archive containing both LVFS firmware metadata \
                     and an EFI Firmware Management Protocol capsule. This is the standard \
                     LVFS delivery format; verify the cabinet signature matches the LVFS GPG key.",
                )
                .with_confidence(0.70)
                .with_details(serde_json::json!({
                    "has_cabinet_archive": true,
                    "has_fmp_capsule": true,
                    "has_metadata_xml": true,
                    "technique": "LVFS cabinet capsule delivery analysis",
                }))
                .with_recommendation(
                    "Validate Jcat/GPG signature and ensure metadata GUID matches target hardware",
                ),
            );
        }

        findings
    }

    fn check_jcat_signature_spoofing(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data.windows(JCAT_MAGIC.len()).position(|w| w == JCAT_MAGIC) {
            let region_end = (pos + 256).min(data.len());
            let region = &data[pos..region_end];

            // Check for known-bad GPG key IDs (not the real LVFS signing key)
            let has_fake_keyid = region.windows(4).any(|w| w == [0xDE, 0xAD, 0xBE, 0xEF]);

            if has_fake_keyid {
                findings.push(
                    Finding::new(
                        "lvfs_integrity",
                        Severity::Critical,
                        "Jcat signature file with forged GPG key identifier",
                        &format!(
                            "Found Jcat signature container at offset 0x{:08X} with a GPG key \
                             ID that does not match any known LVFS signing key. This indicates \
                             a spoofed signature designed to bypass fwupd verification.",
                            pos
                        ),
                    )
                    .with_confidence(0.91)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", pos),
                        "fake_key_detected": true,
                        "technique": "Jcat/GPG signature spoofing for LVFS metadata",
                    }))
                    .with_recommendation(
                        "Reject firmware with unrecognized signing keys; only trust the official LVFS GPG key",
                    ),
                );
            }
        }

        findings
    }
}

impl Detector for LvfsIntegrityDetector {
    fn name(&self) -> &str {
        "lvfs_integrity"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_spoofed_metadata(&data));
        findings.extend(self.check_checksum_mismatch(&data));
        findings.extend(self.check_cabinet_with_fmp(&data));
        findings.extend(self.check_jcat_signature_spoofing(&data));

        Ok(findings)
    }
}
