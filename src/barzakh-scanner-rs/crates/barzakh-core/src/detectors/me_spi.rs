use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const FLASH_DESCRIPTOR_SIGNATURE: [u8; 4] = [0x5A, 0xA5, 0xF0, 0x0F]; // 0x0FF0A55A little-endian

pub struct MeSpiDetector;

impl Default for MeSpiDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MeSpiDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_flash_descriptor_signature(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Look for Intel flash descriptor signature 0x0FF0A55A at expected offsets
        let expected_offsets: &[usize] = &[0x10, 0x14, 0x20];
        let mut descriptor_found = false;

        for &offset in expected_offsets {
            if offset + 4 <= data.len() && data[offset..offset + 4] == FLASH_DESCRIPTOR_SIGNATURE {
                descriptor_found = true;

                // Validate FLMAP0/FLMAP1 pointers
                let flmap0_offset = offset + 0x14;
                let flmap1_offset = offset + 0x18;

                if flmap0_offset + 4 <= data.len() && flmap1_offset + 4 <= data.len() {
                    let flmap0 = u32::from_le_bytes(
                        data[flmap0_offset..flmap0_offset + 4]
                            .try_into()
                            .unwrap_or([0; 4]),
                    );
                    let flmap1 = u32::from_le_bytes(
                        data[flmap1_offset..flmap1_offset + 4]
                            .try_into()
                            .unwrap_or([0; 4]),
                    );

                    // Check for corrupted FLMAP values
                    if flmap0 == 0 || flmap0 == 0xFFFFFFFF || flmap1 == 0xFFFFFFFF {
                        findings.push(
                            Finding::new(
                                "me_spi",
                                Severity::High,
                                "Flash descriptor signature anomaly",
                                &format!(
                                    "Flash descriptor found at offset 0x{:04X} but \
                                     FLMAP0/FLMAP1 pointers appear corrupted \
                                     (FLMAP0=0x{:08X}, FLMAP1=0x{:08X}).",
                                    offset, flmap0, flmap1
                                ),
                            )
                            .with_confidence(0.70)
                            .with_details(serde_json::json!({
                                "descriptor_offset": format!("0x{:04X}", offset),
                                "flmap0": format!("0x{:08X}", flmap0),
                                "flmap1": format!("0x{:08X}", flmap1),
                            })),
                        );
                    }
                }
                break;
            }
        }

        if !descriptor_found && data.len() > 0x20 {
            // Also scan first 4KB for the signature at any offset
            let scan_len = data.len().min(4096);
            let found_anywhere = data[..scan_len]
                .windows(4)
                .any(|w| w == FLASH_DESCRIPTOR_SIGNATURE);

            if !found_anywhere && data.len() >= 4096 {
                findings.push(
                    Finding::new(
                        "me_spi",
                        Severity::High,
                        "Flash descriptor signature anomaly",
                        "Intel flash descriptor signature (0x0FF0A55A) not found at \
                         expected offsets or within first 4KB. Descriptor may be missing \
                         or corrupted.",
                    )
                    .with_confidence(0.60)
                    .with_details(serde_json::json!({
                        "expected_offsets": ["0x10", "0x14", "0x20"],
                        "scanned_range": "0x0000-0x1000",
                    }))
                    .with_recommendation(
                        "Verify flash image integrity and check for descriptor corruption.",
                    ),
                );
            }
        }

        findings
    }

    fn check_me_region_bounds(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Find flash descriptor first
        let descriptor_base = self.find_descriptor_base(data);
        let Some(base) = descriptor_base else {
            return findings;
        };

        // FLREG0 (BIOS region) at descriptor offset 0x54
        // FLREG1 (ME region) at descriptor offset 0x58
        let flreg0_offset = base + 0x54;
        let flreg1_offset = base + 0x58;

        if flreg1_offset + 4 > data.len() || flreg0_offset + 4 > data.len() {
            return findings;
        }

        let flreg0 = u32::from_le_bytes(
            data[flreg0_offset..flreg0_offset + 4]
                .try_into()
                .unwrap_or([0; 4]),
        );
        let flreg1 = u32::from_le_bytes(
            data[flreg1_offset..flreg1_offset + 4]
                .try_into()
                .unwrap_or([0; 4]),
        );

        // Extract base and limit (bits 15:0 = base, bits 31:16 = limit, in 4KB units)
        let bios_base = (flreg0 & 0xFFFF) as u64 * 0x1000;
        let bios_limit = ((flreg0 >> 16) & 0xFFFF) as u64 * 0x1000 + 0xFFF;
        let me_base = (flreg1 & 0xFFFF) as u64 * 0x1000;
        let me_limit = ((flreg1 >> 16) & 0xFFFF) as u64 * 0x1000 + 0xFFF;

        // Check for ME region overlapping BIOS region
        if me_base <= bios_limit && me_limit >= bios_base && me_base != 0 && bios_base != 0 {
            findings.push(
                Finding::new(
                    "me_spi",
                    Severity::Critical,
                    "ME region boundary violation - overlaps BIOS",
                    &format!(
                        "ME region (0x{:08X}-0x{:08X}) overlaps with BIOS region \
                         (0x{:08X}-0x{:08X}). This indicates flash descriptor \
                         manipulation allowing ME access to BIOS code.",
                        me_base, me_limit, bios_base, bios_limit
                    ),
                )
                .with_confidence(0.80)
                .with_details(serde_json::json!({
                    "me_base": format!("0x{:08X}", me_base),
                    "me_limit": format!("0x{:08X}", me_limit),
                    "bios_base": format!("0x{:08X}", bios_base),
                    "bios_limit": format!("0x{:08X}", bios_limit),
                    "flreg0_raw": format!("0x{:08X}", flreg0),
                    "flreg1_raw": format!("0x{:08X}", flreg1),
                }))
                .with_recommendation(
                    "Flash descriptor has been tampered with. Re-flash with known-good descriptor.",
                ),
            );
        }

        findings
    }

    fn check_flockdn_status(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Find flash descriptor
        let descriptor_base = self.find_descriptor_base(data);
        let Some(base) = descriptor_base else {
            return findings;
        };

        // HSFS register at descriptor + 0x04
        let hsfs_offset = base + 0x04;
        if hsfs_offset + 2 > data.len() {
            return findings;
        }

        let hsfs = u16::from_le_bytes(
            data[hsfs_offset..hsfs_offset + 2]
                .try_into()
                .unwrap_or([0; 2]),
        );

        // FLOCKDN is bit 15 of HSFS
        if hsfs & (1 << 15) == 0 {
            findings.push(
                Finding::new(
                    "me_spi",
                    Severity::High,
                    "SPI flash lock-down not engaged",
                    &format!(
                        "HSFS register at offset 0x{:04X} has FLOCKDN bit (bit 15) clear \
                         (HSFS=0x{:04X}). SPI flash configuration is not locked, allowing \
                         runtime modification of flash regions.",
                        hsfs_offset, hsfs
                    ),
                )
                .with_confidence(0.65)
                .with_details(serde_json::json!({
                    "hsfs_offset": format!("0x{:04X}", hsfs_offset),
                    "hsfs_value": format!("0x{:04X}", hsfs),
                    "flockdn_bit": "clear",
                }))
                .with_recommendation(
                    "Ensure FLOCKDN is set during boot to prevent runtime flash descriptor modification.",
                ),
            );
        }

        findings
    }

    fn find_descriptor_base(&self, data: &[u8]) -> Option<usize> {
        let expected_offsets: &[usize] = &[0x10, 0x14, 0x20];
        for &offset in expected_offsets {
            if offset + 4 <= data.len() && data[offset..offset + 4] == FLASH_DESCRIPTOR_SIGNATURE {
                return Some(offset);
            }
        }
        // Scan first 4KB
        let scan_len = data.len().min(4096);
        data[..scan_len]
            .windows(4)
            .position(|w| w == FLASH_DESCRIPTOR_SIGNATURE)
    }
}

impl Detector for MeSpiDetector {
    fn name(&self) -> &str {
        "me_spi"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let mut findings = Vec::new();

        findings.extend(self.check_flash_descriptor_signature(&data));
        findings.extend(self.check_me_region_bounds(&data));
        findings.extend(self.check_flockdn_status(&data));

        Ok(findings)
    }
}
