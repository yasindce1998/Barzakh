use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const SHIM_GUID: [u8; 16] = [
    0xC1, 0xC4, 0x1B, 0x60, 0x77, 0xF8, 0x04, 0x45, 0x9E, 0x5E, 0xCD, 0x99, 0x30, 0x1E, 0x4D, 0x97,
];

const KNOWN_REVOKED_HASHES: [[u8; 4]; 3] = [
    [0x80, 0xB4, 0xD9, 0x6B], // BlackLotus shimx64 prefix
    [0xA5, 0x31, 0xF2, 0xD0], // CVE-2022-21894 baton drop shim
    [0xFE, 0xDB, 0xAC, 0x19], // Known compromised MOK signer
];

pub struct BlacklotusDetector;

impl Default for BlacklotusDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BlacklotusDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_mok_variables(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Search for MokList variable markers
        let moklist_name = b"M\x00o\x00k\x00L\x00i\x00s\x00t\x00";
        for i in 0..data.len().saturating_sub(moklist_name.len() + 32) {
            if data[i..].starts_with(moklist_name) {
                // Check if there's a shim GUID nearby
                for j in i.saturating_sub(64)..i.saturating_add(128).min(data.len() - 16) {
                    if data[j..j + 16] == SHIM_GUID {
                        // Check for revoked hash prefixes in the MOK entry
                        for k in j..j.saturating_add(512).min(data.len() - 4) {
                            for revoked in &KNOWN_REVOKED_HASHES {
                                if data[k..k + 4] == *revoked {
                                    findings.push(
                                        Finding::new(
                                            "blacklotus",
                                            Severity::Critical,
                                            "BlackLotus: Revoked MOK key enrolled in firmware",
                                            &format!(
                                                "MokList at offset 0x{:08X} contains a hash matching \
                                                 known-revoked BlackLotus bootkit signer. This allows \
                                                 loading arbitrary code bypassing Secure Boot.",
                                                i
                                            ),
                                        )
                                        .with_confidence(0.92)
                                        .with_details(serde_json::json!({
                                            "moklist_offset": format!("0x{:08X}", i),
                                            "hash_prefix": format!("{:02X}{:02X}{:02X}{:02X}",
                                                revoked[0], revoked[1], revoked[2], revoked[3]),
                                            "cve": "CVE-2022-21894",
                                        }))
                                        .with_recommendation(
                                            "Clear MOK database and apply latest UEFI dbx revocations"
                                        ),
                                    );
                                    return findings;
                                }
                            }
                        }
                    }
                }
            }
        }

        findings
    }

    fn check_baton_drop(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // CVE-2022-21894 "Baton Drop": Windows Boot Manager allows loading
        // a policy that disables Secure Boot enforcement
        let bcd_policy_marker = b"BcdStore";
        for i in 0..data.len().saturating_sub(bcd_policy_marker.len() + 128) {
            if data[i..].starts_with(bcd_policy_marker) {
                // Look for truncated serialization pattern that triggers the baton drop
                let search_end = (i + 512).min(data.len());
                for j in i..search_end.saturating_sub(8) {
                    // Pattern: 0x10000007 (integrity disable flag)
                    let val = u32::from_le_bytes(data[j..j + 4].try_into().unwrap_or([0; 4]));
                    if val == 0x10000007 {
                        findings.push(
                            Finding::new(
                                "blacklotus",
                                Severity::Critical,
                                "BlackLotus: Baton Drop policy with integrity checks disabled",
                                &format!(
                                    "BCD policy at offset 0x{:08X} contains integrity disable flag \
                                     (0x10000007). This is the CVE-2022-21894 'Baton Drop' exploit \
                                     used by BlackLotus to bypass Secure Boot.",
                                    j
                                ),
                            )
                            .with_confidence(0.88)
                            .with_details(serde_json::json!({
                                "bcd_offset": format!("0x{:08X}", i),
                                "flag_offset": format!("0x{:08X}", j),
                                "cve": "CVE-2022-21894",
                            }))
                            .with_recommendation(
                                "Apply KB5025885 Windows update and rotate Secure Boot keys",
                            ),
                        );
                        break;
                    }
                }
            }
        }

        findings
    }

    fn check_bootloader_anomalies(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // BlackLotus drops shimx64.efi to non-standard ESP path
        let shimx64 = b"shimx64.efi";
        let grubx64 = b"grubx64.efi";

        let shim_count = data
            .windows(shimx64.len())
            .filter(|w| w.eq_ignore_ascii_case(shimx64))
            .count();

        let grub_count = data
            .windows(grubx64.len())
            .filter(|w| w.eq_ignore_ascii_case(grubx64))
            .count();

        if shim_count > 3 {
            findings.push(
                Finding::new(
                    "blacklotus",
                    Severity::High,
                    "BlackLotus: Multiple shimx64.efi references (persistence indicator)",
                    &format!(
                        "Found {} references to shimx64.efi in firmware image. BlackLotus installs \
                         multiple copies of shim in non-standard paths for persistence.",
                        shim_count
                    ),
                )
                .with_confidence(0.70)
                .with_details(serde_json::json!({
                    "shim_references": shim_count,
                    "grub_references": grub_count,
                })),
            );
        }

        findings
    }
}

impl Detector for BlacklotusDetector {
    fn name(&self) -> &str {
        "blacklotus"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }

    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_mok_variables(&data));
        findings.extend(self.check_baton_drop(&data));
        findings.extend(self.check_bootloader_anomalies(&data));

        Ok(findings)
    }
}
