use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const FIP_TOC_MAGIC: &[u8] = &[0xAA, 0x64, 0x0A, 0x4E];
const BL2_UUID: &[u8] = &[0x5F, 0xF9, 0xEC, 0x0B, 0x4D, 0x22, 0x3E, 0x4D];
const BL31_UUID: &[u8] = &[0x63, 0xB4, 0xC3, 0xE6, 0x26, 0x0E, 0x11, 0xE3];
const NV_COUNTER_MARKER: &[u8] = b"NV_CTR";

pub struct ArmTbbrDetector;

impl Default for ArmTbbrDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ArmTbbrDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_fip_zeroed_hash(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(fip_pos) = data
            .windows(FIP_TOC_MAGIC.len())
            .position(|w| w == FIP_TOC_MAGIC)
        {
            let toc_start = fip_pos + FIP_TOC_MAGIC.len();
            let toc_end = (toc_start + 1024).min(data.len());
            let toc_region = &data[toc_start..toc_end];

            let check_uuids: &[&[u8]] = &[BL2_UUID, BL31_UUID];

            for uuid in check_uuids {
                if let Some(entry_pos) = toc_region.windows(uuid.len()).position(|w| w == *uuid) {
                    let hash_offset = entry_pos + uuid.len() + 16;
                    if hash_offset + 32 <= toc_region.len() {
                        let hash_region = &toc_region[hash_offset..hash_offset + 32];
                        if hash_region.iter().all(|&b| b == 0) {
                            let abs_offset = toc_start + entry_pos;
                            findings.push(
                                Finding::new(
                                    "arm_tbbr",
                                    Severity::Critical,
                                    "ARM TBBR: FIP entry with zeroed hash field",
                                    &format!(
                                        "FIP TOC entry at offset 0x{:08X} contains a zeroed \
                                         SHA-256 hash where a valid boot stage measurement should \
                                         be. This bypasses the ARM Trusted Board Boot chain of \
                                         trust, allowing unsigned code to be loaded as BL2/BL31.",
                                        abs_offset
                                    ),
                                )
                                .with_confidence(0.93)
                                .with_details(serde_json::json!({
                                    "fip_offset": format!("0x{:08X}", fip_pos),
                                    "entry_offset": format!("0x{:08X}", abs_offset),
                                    "hash": "0000...0000 (32 zero bytes)",
                                    "technique": "ARM TBBR chain of trust bypass",
                                }))
                                .with_recommendation(
                                    "Re-sign FIP image with proper certificate chain and non-zero measurements",
                                ),
                            );
                        }
                    }
                }
            }
        }

        findings
    }

    fn check_nv_counter_bypass(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(nv_pos) = data
            .windows(NV_COUNTER_MARKER.len())
            .position(|w| w == NV_COUNTER_MARKER)
        {
            let counter_offset = nv_pos + NV_COUNTER_MARKER.len();
            if counter_offset + 8 < data.len() {
                let counter_value = u32::from_le_bytes(
                    data[counter_offset..counter_offset + 4]
                        .try_into()
                        .unwrap_or([0; 4]),
                );

                if counter_value == 0 {
                    findings.push(
                        Finding::new(
                            "arm_tbbr",
                            Severity::High,
                            "ARM TBBR: NV counter zeroed (anti-rollback bypass)",
                            &format!(
                                "NV_CTR at offset 0x{:08X} is set to 0. A zeroed non-volatile \
                                 counter disables anti-rollback protection, allowing old/vulnerable \
                                 firmware versions to be loaded despite TBBR requirements.",
                                nv_pos
                            ),
                        )
                        .with_confidence(0.85)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", nv_pos),
                            "counter_value": 0,
                            "technique": "TBBR NV counter rollback",
                        }))
                        .with_recommendation(
                            "Restore NV counter to monotonically increasing value matching latest firmware version",
                        ),
                    );
                }
            }
        }

        findings
    }

    fn check_fip_header_integrity(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(fip_pos) = data
            .windows(FIP_TOC_MAGIC.len())
            .position(|w| w == FIP_TOC_MAGIC)
        {
            if fip_pos + 16 < data.len() {
                let flags = u32::from_le_bytes(
                    data[fip_pos + 8..fip_pos + 12].try_into().unwrap_or([0; 4]),
                );

                if flags == 0xFFFFFFFF {
                    findings.push(
                        Finding::new(
                            "arm_tbbr",
                            Severity::Medium,
                            "FIP header with all flags set (possible corruption or tampering)",
                            &format!(
                                "FIP TOC at offset 0x{:08X} has flags field set to 0xFFFFFFFF. \
                                 While not necessarily malicious, this is an unusual value that \
                                 may indicate header corruption or intentional manipulation.",
                                fip_pos
                            ),
                        )
                        .with_confidence(0.60)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", fip_pos),
                            "flags": "0xFFFFFFFF",
                        })),
                    );
                }
            }
        }

        findings
    }
}

impl Detector for ArmTbbrDetector {
    fn name(&self) -> &str {
        "arm_tbbr"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }

    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_fip_zeroed_hash(&data));
        findings.extend(self.check_nv_counter_bypass(&data));
        findings.extend(self.check_fip_header_integrity(&data));

        Ok(findings)
    }
}
