use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const ACM_MODULE_TYPE: u16 = 0x0002;
const ACM_HEADER_SIZE: usize = 0xA0;
const KM_SIGNATURE: [u8; 8] = [0x5F, 0x5F, 0x4B, 0x45, 0x59, 0x4D, 0x5F, 0x5F]; // "__KEYM__"
const BPM_SIGNATURE: [u8; 8] = [0x5F, 0x5F, 0x42, 0x50, 0x4D, 0x5F, 0x5F, 0x00]; // "__BPM__\0"

pub struct BootGuardDetector;

impl Default for BootGuardDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BootGuardDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_acm_header(&self, data: &[u8], offset: usize) -> Vec<Finding> {
        let mut findings = Vec::new();

        if offset + ACM_HEADER_SIZE > data.len() {
            return findings;
        }

        let module_type = u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap_or([0; 2]));

        if module_type != ACM_MODULE_TYPE {
            return findings;
        }

        let module_sub_type =
            u16::from_le_bytes(data[offset + 2..offset + 4].try_into().unwrap_or([0; 2]));
        let header_len =
            u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap_or([0; 4])) as usize
                * 4;
        let module_size =
            u32::from_le_bytes(data[offset + 12..offset + 16].try_into().unwrap_or([0; 4]))
                as usize
                * 4;

        // Check for invalid ACM size
        if module_size == 0 || offset + module_size > data.len() {
            findings.push(
                Finding::new(
                    "boot_guard",
                    Severity::Critical,
                    "Intel Boot Guard: ACM module with invalid size",
                    &format!(
                        "Authenticated Code Module at offset 0x{:08X} declares size 0x{:X} which \
                         exceeds available data. ACM may have been tampered with or corrupted.",
                        offset, module_size
                    ),
                )
                .with_confidence(0.88)
                .with_details(serde_json::json!({
                    "offset": format!("0x{:08X}", offset),
                    "module_type": format!("0x{:04X}", module_type),
                    "module_sub_type": format!("0x{:04X}", module_sub_type),
                    "declared_size": module_size,
                }))
                .with_recommendation("Re-flash firmware with vendor-signed Boot Guard ACM"),
            );
            return findings;
        }

        // Check header length sanity
        if header_len < 0x60 || header_len > module_size {
            findings.push(
                Finding::new(
                    "boot_guard",
                    Severity::High,
                    "Intel Boot Guard: ACM header length mismatch",
                    &format!(
                        "ACM at offset 0x{:08X} has header_len=0x{:X} which is outside valid range \
                         [0x60, module_size]. Indicates ACM structure corruption.",
                        offset, header_len
                    ),
                )
                .with_confidence(0.82),
            );
        }

        findings
    }

    fn check_key_manifest(&self, data: &[u8], offset: usize) -> Vec<Finding> {
        let mut findings = Vec::new();

        if offset + 32 > data.len() {
            return findings;
        }

        // Key Manifest structure version
        let km_version = u8::from_le_bytes([data[offset + 8]]);
        let km_svn = u8::from_le_bytes([data[offset + 9]]);
        let km_id = u16::from_le_bytes(data[offset + 10..offset + 12].try_into().unwrap_or([0; 2]));

        // SVN of 0 is suspicious — could indicate a rollback attack
        if km_svn == 0 && km_version > 0 {
            findings.push(
                Finding::new(
                    "boot_guard",
                    Severity::High,
                    "Intel Boot Guard: Key Manifest SVN is zero (possible rollback)",
                    &format!(
                        "Key Manifest at offset 0x{:08X} has SVN=0 with version={}. A zero SVN \
                         may indicate a rollback attack to use a revoked key manifest.",
                        offset, km_version
                    ),
                )
                .with_confidence(0.75)
                .with_details(serde_json::json!({
                    "offset": format!("0x{:08X}", offset),
                    "km_version": km_version,
                    "km_svn": km_svn,
                    "km_id": km_id,
                })),
            );
        }

        findings
    }

    fn check_boot_policy_manifest(&self, data: &[u8], offset: usize) -> Vec<Finding> {
        let mut findings = Vec::new();

        if offset + 32 > data.len() {
            return findings;
        }

        let bpm_version = u8::from_le_bytes([data[offset + 8]]);
        let bpm_svn = u8::from_le_bytes([data[offset + 9]]);

        // Check for IBB (Initial Boot Block) entries
        let search_end = (offset + 1024).min(data.len());
        let mut ibb_found = false;
        for i in offset + 16..search_end.saturating_sub(8) {
            // IBB element structure marker
            if data[i] == 0x00 && data[i + 1] == 0x00 && data[i + 2] == 0x0B {
                ibb_found = true;
                // Check IBB hash size
                if i + 36 < data.len() {
                    let hash_size =
                        u16::from_le_bytes(data[i + 34..i + 36].try_into().unwrap_or([0; 2]));
                    if hash_size == 0 {
                        findings.push(
                            Finding::new(
                                "boot_guard",
                                Severity::Critical,
                                "Intel Boot Guard: IBB entry with empty hash (boot verification disabled)",
                                &format!(
                                    "Boot Policy Manifest at offset 0x{:08X} contains IBB element \
                                     with hash_size=0. Boot Guard verification is effectively disabled.",
                                    offset
                                ),
                            )
                            .with_confidence(0.90)
                            .with_details(serde_json::json!({
                                "bpm_offset": format!("0x{:08X}", offset),
                                "ibb_offset": format!("0x{:08X}", i),
                                "bpm_version": bpm_version,
                                "bpm_svn": bpm_svn,
                            }))
                            .with_recommendation(
                                "Re-provision Boot Guard with proper IBB measurements"
                            ),
                        );
                    }
                }
                break;
            }
        }

        if !ibb_found && bpm_version > 0 {
            findings.push(
                Finding::new(
                    "boot_guard",
                    Severity::High,
                    "Intel Boot Guard: Boot Policy Manifest missing IBB entries",
                    &format!(
                        "BPM at offset 0x{:08X} (version={}) contains no IBB elements. \
                         Without IBB hashes, Boot Guard cannot verify the initial boot block.",
                        offset, bpm_version
                    ),
                )
                .with_confidence(0.78),
            );
        }

        findings
    }
}

impl Detector for BootGuardDetector {
    fn name(&self) -> &str {
        "boot_guard"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }

    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        // Scan for ACM modules
        for i in 0..data.len().saturating_sub(ACM_HEADER_SIZE) {
            let module_type = u16::from_le_bytes(data[i..i + 2].try_into().unwrap_or([0; 2]));
            if module_type == ACM_MODULE_TYPE {
                let vendor_id =
                    u32::from_le_bytes(data[i + 16..i + 20].try_into().unwrap_or([0; 4]));
                // Intel vendor ID for ACM
                if vendor_id == 0x8086 {
                    findings.extend(self.check_acm_header(&data, i));
                }
            }
        }

        // Scan for Key Manifest
        for i in 0..data.len().saturating_sub(32) {
            if data[i..i + 8] == KM_SIGNATURE {
                findings.extend(self.check_key_manifest(&data, i));
            }
        }

        // Scan for Boot Policy Manifest
        for i in 0..data.len().saturating_sub(32) {
            if data[i..i + 8] == BPM_SIGNATURE {
                findings.extend(self.check_boot_policy_manifest(&data, i));
            }
        }

        Ok(findings)
    }
}
