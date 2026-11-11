use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const PSP_DIRECTORY_MAGIC: [u8; 4] = [0x24, 0x50, 0x53, 0x50]; // "$PSP"
const PSP_COMBO_MAGIC: [u8; 4] = [0x32, 0x50, 0x53, 0x50]; // "2PSP"

pub struct AmdPspDetector;

impl Default for AmdPspDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AmdPspDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_psp_directory(&self, data: &[u8], offset: usize) -> Vec<Finding> {
        let mut findings = Vec::new();

        if offset + 16 > data.len() {
            return findings;
        }

        // PSP Directory Header structure:
        // [0:4]   = Magic "$PSP"
        // [4:8]   = Checksum (Fletcher32)
        // [8:12]  = Total entries
        // [12:16] = Additional info
        let declared_checksum =
            u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap_or([0; 4]));
        let total_entries =
            u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap_or([0; 4]));

        if total_entries > 256 {
            findings.push(
                Finding::new(
                    "amd_psp",
                    Severity::High,
                    "AMD PSP: Directory entry count exceeds reasonable maximum",
                    &format!(
                        "PSP directory at offset 0x{:08X} declares {} entries (max expected ~64). \
                         May indicate directory corruption or tampering.",
                        offset, total_entries
                    ),
                )
                .with_confidence(0.80)
                .with_details(serde_json::json!({
                    "offset": format!("0x{:08X}", offset),
                    "total_entries": total_entries,
                }))
                .with_recommendation("Compare PSP directory against known-good firmware from AMD"),
            );
            return findings;
        }

        // Validate entries (each entry is 16 bytes after the 16-byte header)
        let entry_base = offset + 16;
        let entries = total_entries.min(64) as usize;

        for i in 0..entries {
            let entry_offset = entry_base + i * 16;
            if entry_offset + 16 > data.len() {
                break;
            }

            let entry_type = u8::from_le_bytes([data[entry_offset]]);
            let entry_size = u32::from_le_bytes(
                data[entry_offset + 8..entry_offset + 12]
                    .try_into()
                    .unwrap_or([0; 4]),
            );
            let entry_location = u64::from_le_bytes(
                data[entry_offset + 8..entry_offset + 16]
                    .try_into()
                    .unwrap_or([0; 8]),
            );

            // PSP OS entry (type 0x0C) with suspicious properties
            if entry_type == 0x0C && entry_size > 0x100000 {
                findings.push(
                    Finding::new(
                        "amd_psp",
                        Severity::High,
                        "AMD PSP: Oversized PSP OS firmware entry",
                        &format!(
                            "PSP directory entry {} (type 0x0C/PSP-OS) at offset 0x{:08X} has size \
                             0x{:X} which is abnormally large. Could contain injected code.",
                            i, entry_offset, entry_size
                        ),
                    )
                    .with_confidence(0.70)
                    .with_details(serde_json::json!({
                        "entry_index": i,
                        "entry_type": format!("0x{:02X}", entry_type),
                        "entry_size": format!("0x{:X}", entry_size),
                        "entry_location": format!("0x{:X}", entry_location),
                    })),
                );
            }

            // SMU firmware (type 0x08) — check for zero-size (indicates wiped entry)
            if entry_type == 0x08 && entry_size == 0 {
                findings.push(
                    Finding::new(
                        "amd_psp",
                        Severity::Medium,
                        "AMD PSP: SMU firmware entry with zero size",
                        &format!(
                            "PSP directory entry {} (type 0x08/SMU) at offset 0x{:08X} has size 0. \
                             SMU firmware may have been wiped, affecting power management security.",
                            i, entry_offset
                        ),
                    )
                    .with_confidence(0.65),
                );
            }
        }

        // Verify directory checksum
        if declared_checksum == 0 && total_entries > 0 {
            findings.push(
                Finding::new(
                    "amd_psp",
                    Severity::High,
                    "AMD PSP: Directory checksum is zero (validation bypassed)",
                    &format!(
                        "PSP directory at offset 0x{:08X} has checksum=0 with {} entries. \
                         A zeroed checksum may indicate the directory was modified without \
                         proper re-signing.",
                        offset, total_entries
                    ),
                )
                .with_confidence(0.82)
                .with_details(serde_json::json!({
                    "offset": format!("0x{:08X}", offset),
                    "checksum": "0x00000000",
                    "entries": total_entries,
                }))
                .with_recommendation("Verify PSP firmware integrity using AMD signing tools"),
            );
        }

        findings
    }
}

impl Detector for AmdPspDetector {
    fn name(&self) -> &str {
        "amd_psp"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }

    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        // Scan for PSP directory headers
        for i in 0..data.len().saturating_sub(16) {
            if data[i..i + 4] == PSP_DIRECTORY_MAGIC || data[i..i + 4] == PSP_COMBO_MAGIC {
                findings.extend(self.check_psp_directory(&data, i));
            }
        }

        Ok(findings)
    }
}
