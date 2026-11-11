use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const PE_MAGIC: &[u8] = b"MZ";
const PE_SIGNATURE: &[u8] = b"PE\x00\x00";
const RELOADER_PATH: &[u8] = b"reloader.efi";
const CLOAK_DAT: &[u8] = b"cloak.dat";
const MS_UEFI_CA_MARKER: &[u8] = b"Microsoft Corporation UEFI CA";

pub struct ReloaderDetector;

impl Default for ReloaderDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ReloaderDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_pe_in_pe(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut pe_offsets = Vec::new();

        for i in 0..data.len().saturating_sub(64) {
            if data[i..].starts_with(PE_MAGIC) && i + 60 < data.len() {
                let pe_header_offset =
                    u32::from_le_bytes(data[i + 60..i + 64].try_into().unwrap_or([0; 4])) as usize;
                if i + pe_header_offset + 4 <= data.len()
                    && data[i + pe_header_offset..].starts_with(PE_SIGNATURE)
                {
                    pe_offsets.push(i);
                }
            }
        }

        if pe_offsets.len() >= 2 {
            let has_ca_marker = data
                .windows(MS_UEFI_CA_MARKER.len())
                .any(|w| w == MS_UEFI_CA_MARKER);

            if has_ca_marker {
                findings.push(
                    Finding::new(
                        "reloader",
                        Severity::Critical,
                        "CVE-2024-7344: Signed UEFI application with embedded unsigned PE",
                        &format!(
                            "Found {} PE images with Microsoft UEFI CA signature present. \
                             Matches the CVE-2024-7344 reloader pattern where a legitimately \
                             signed UEFI app loads an embedded unsigned payload.",
                            pe_offsets.len()
                        ),
                    )
                    .with_confidence(0.90)
                    .with_details(serde_json::json!({
                        "pe_count": pe_offsets.len(),
                        "pe_offsets": pe_offsets.iter().map(|o| format!("0x{:08X}", o)).collect::<Vec<_>>(),
                        "has_ms_ca": true,
                        "cve": "CVE-2024-7344",
                    }))
                    .with_recommendation(
                        "Revoke the affected signed binary and update to patched firmware",
                    ),
                );
            }
        }

        findings
    }

    fn check_reloader_paths(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let has_reloader = data
            .windows(RELOADER_PATH.len())
            .any(|w| w == RELOADER_PATH);
        let has_cloak = data.windows(CLOAK_DAT.len()).any(|w| w == CLOAK_DAT);

        if has_reloader && has_cloak {
            findings.push(
                Finding::new(
                    "reloader",
                    Severity::Critical,
                    "CVE-2024-7344: reloader.efi + cloak.dat payload delivery pattern",
                    "Found both 'reloader.efi' and 'cloak.dat' references. This matches the \
                     exact file naming convention used by CVE-2024-7344 exploits to deliver \
                     unsigned UEFI code through a signed application.",
                )
                .with_confidence(0.95)
                .with_details(serde_json::json!({
                    "reloader_present": true,
                    "cloak_dat_present": true,
                    "cve": "CVE-2024-7344",
                }))
                .with_recommendation(
                    "Remove reloader.efi and cloak.dat from ESP, apply January 2025 UEFI revocations",
                ),
            );
        } else if has_reloader {
            findings.push(
                Finding::new(
                    "reloader",
                    Severity::High,
                    "Suspicious reloader.efi path reference",
                    "Found 'reloader.efi' path string which is associated with CVE-2024-7344 \
                     exploit chain. May indicate an attempt to use the signed reloader vulnerability.",
                )
                .with_confidence(0.70)
                .with_details(serde_json::json!({
                    "reloader_present": true,
                    "cve": "CVE-2024-7344",
                })),
            );
        }

        findings
    }
}

impl Detector for ReloaderDetector {
    fn name(&self) -> &str {
        "reloader"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_pe_in_pe(&data));
        findings.extend(self.check_reloader_paths(&data));

        Ok(findings)
    }
}
