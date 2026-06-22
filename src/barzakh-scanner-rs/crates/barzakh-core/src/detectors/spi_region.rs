use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const FLASH_DESCRIPTOR_SIG: u32 = 0x0FF0A55A;
const FLREG_BASE_OFFSET: usize = 0x54;
const FLMSTR1_OFFSET: usize = 0x80;

pub struct SpiRegionDetector;

impl Default for SpiRegionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SpiRegionDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_region_descriptor(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Look for Intel flash descriptor signature
        if data.len() < 0x68 {
            return findings;
        }

        let sig_pos = data.windows(4).position(|w| {
            u32::from_le_bytes(w.try_into().unwrap_or([0; 4])) == FLASH_DESCRIPTOR_SIG
        });

        let base_offset = match sig_pos {
            Some(pos) => pos,
            None => return findings,
        };

        // Parse FLREG0-FLREG4 (BIOS, ME, GbE, Platform, EC)
        let flreg_offset = base_offset + FLREG_BASE_OFFSET;
        if flreg_offset + 0x14 > data.len() {
            return findings;
        }

        let region_names = ["BIOS", "ME", "GbE", "Platform", "EC"];
        for (i, name) in region_names.iter().enumerate() {
            let reg_offset = flreg_offset + (i * 4);
            if reg_offset + 4 > data.len() {
                break;
            }
            let reg_val = u32::from_le_bytes(
                data[reg_offset..reg_offset + 4]
                    .try_into()
                    .unwrap_or([0; 4]),
            );

            let region_base = (reg_val & 0x7FFF) << 12;
            let region_limit = ((reg_val >> 16) & 0x7FFF) << 12;

            // If base > limit and region is not unused (all zeros), it's invalid
            if region_base > region_limit && reg_val != 0 && region_limit != 0 {
                findings.push(
                    Finding::new(
                        "spi_region",
                        Severity::High,
                        "SPI flash region descriptor corruption",
                        &format!(
                            "Flash region {} ({}) has base 0x{:08X} > limit 0x{:08X}, \
                             indicating descriptor corruption or manipulation.",
                            i, name, region_base, region_limit
                        ),
                    )
                    .with_confidence(0.75)
                    .with_details(serde_json::json!({
                        "region_index": i,
                        "region_name": name,
                        "base": format!("0x{:08X}", region_base),
                        "limit": format!("0x{:08X}", region_limit),
                        "raw_register": format!("0x{:08X}", reg_val),
                    })),
                );
            }
        }

        findings
    }

    fn check_master_access_bits(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Find flash descriptor first
        let sig_pos = data.windows(4).position(|w| {
            u32::from_le_bytes(w.try_into().unwrap_or([0; 4])) == FLASH_DESCRIPTOR_SIG
        });

        let base_offset = match sig_pos {
            Some(pos) => pos,
            None => return findings,
        };

        // Check FLMSTR1 (BIOS master) at offset 0x80 from descriptor base
        let flmstr1_offset = base_offset + FLMSTR1_OFFSET;
        if flmstr1_offset + 4 > data.len() {
            return findings;
        }

        let flmstr1 = u32::from_le_bytes(
            data[flmstr1_offset..flmstr1_offset + 4]
                .try_into()
                .unwrap_or([0; 4]),
        );

        // Bits 20-23 control write access to regions (ME region is bit 21)
        // If BIOS master has write access to ME region, flag it
        let bios_write_me = (flmstr1 >> 21) & 0x01;
        if bios_write_me != 0 {
            findings.push(
                Finding::new(
                    "spi_region",
                    Severity::Critical,
                    "Unauthorized SPI master access configuration",
                    "BIOS flash master has write access to the ME region. \
                     This configuration should not exist in production firmware \
                     and may indicate SPI flash access control manipulation.",
                )
                .with_confidence(0.80)
                .with_details(serde_json::json!({
                    "register": "FLMSTR1",
                    "offset": format!("0x{:08X}", flmstr1_offset),
                    "value": format!("0x{:08X}", flmstr1),
                    "bios_write_me_access": true,
                }))
                .with_recommendation(
                    "Verify SPI flash master access permissions and ensure ME region \
                     is not writable by the BIOS master.",
                ),
            );
        }

        findings
    }

    fn check_region_overlap(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Find flash descriptor
        let sig_pos = data.windows(4).position(|w| {
            u32::from_le_bytes(w.try_into().unwrap_or([0; 4])) == FLASH_DESCRIPTOR_SIG
        });

        let base_offset = match sig_pos {
            Some(pos) => pos,
            None => return findings,
        };

        let flreg_offset = base_offset + FLREG_BASE_OFFSET;
        if flreg_offset + 0x14 > data.len() {
            return findings;
        }

        // Parse all regions
        let region_names = ["BIOS", "ME", "GbE", "Platform", "EC"];
        let mut regions: Vec<(usize, u32, u32)> = Vec::new();

        for i in 0..5 {
            let reg_offset = flreg_offset + (i * 4);
            if reg_offset + 4 > data.len() {
                break;
            }
            let reg_val = u32::from_le_bytes(
                data[reg_offset..reg_offset + 4]
                    .try_into()
                    .unwrap_or([0; 4]),
            );

            let region_base = (reg_val & 0x7FFF) << 12;
            let region_limit = ((reg_val >> 16) & 0x7FFF) << 12;

            if reg_val != 0 && region_limit >= region_base {
                regions.push((i, region_base, region_limit));
            }
        }

        // Check BIOS region (index 0) for overlap with any other region
        if let Some(&(_, bios_base, bios_limit)) = regions.iter().find(|(idx, _, _)| *idx == 0) {
            for &(idx, other_base, other_limit) in &regions {
                if idx == 0 {
                    continue;
                }
                // Check for overlap: ranges overlap if base1 <= limit2 AND base2 <= limit1
                if bios_base <= other_limit && other_base <= bios_limit {
                    findings.push(
                        Finding::new(
                            "spi_region",
                            Severity::High,
                            "SPI region overlap detected",
                            &format!(
                                "BIOS region (0x{:08X}-0x{:08X}) overlaps with {} region \
                                 (0x{:08X}-0x{:08X}). This indicates potential SPI flash \
                                 region manipulation.",
                                bios_base, bios_limit, region_names[idx], other_base, other_limit
                            ),
                        )
                        .with_confidence(0.85)
                        .with_details(serde_json::json!({
                            "bios_base": format!("0x{:08X}", bios_base),
                            "bios_limit": format!("0x{:08X}", bios_limit),
                            "overlapping_region": region_names[idx],
                            "overlap_base": format!("0x{:08X}", other_base),
                            "overlap_limit": format!("0x{:08X}", other_limit),
                        })),
                    );
                }
            }
        }

        findings
    }
}

impl Detector for SpiRegionDetector {
    fn name(&self) -> &str {
        "spi_region"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let mut findings = Vec::new();

        findings.extend(self.check_region_descriptor(&data));
        findings.extend(self.check_master_access_bits(&data));
        findings.extend(self.check_region_overlap(&data));

        Ok(findings)
    }
}
