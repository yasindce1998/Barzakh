use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const EFI_FV_SIGNATURE: &[u8] = b"_FVH";
const EFI_FV_FILETYPE_PEI_CORE: u8 = 0x04;
const EFI_FV_FILETYPE_PEIM: u8 = 0x06;
const PE_SIGNATURE: [u8; 4] = [0x50, 0x45, 0x00, 0x00]; // "PE\0\0"

pub struct PeiImplantDetector;

impl Default for PeiImplantDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PeiImplantDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_pei_core_entry(&self, data: &[u8], fv_start: usize, fv_length: usize) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Scan for PEI Core file within this firmware volume
        let fv_end = (fv_start + fv_length).min(data.len());
        let mut pos = fv_start + 0x48; // Skip FV header (typical size)

        while pos + 24 < fv_end {
            let file_type = data.get(pos + 18).copied().unwrap_or(0);
            let file_size =
                u32::from_le_bytes([data[pos + 20], data[pos + 21], data[pos + 22], 0]) as usize;

            if !(24..=0x1000000).contains(&file_size) || pos + file_size > fv_end {
                break;
            }

            if file_type == EFI_FV_FILETYPE_PEI_CORE {
                // Found PEI Core — check its PE entry point
                self.validate_pei_core_pe(data, pos, file_size, fv_start, fv_length, &mut findings);
            } else if file_type == EFI_FV_FILETYPE_PEIM {
                // Check PEIM for suspicious characteristics
                self.check_peim_anomalies(data, pos, file_size, fv_start, &mut findings);
            }

            pos += (file_size + 7) & !7; // 8-byte alignment
        }

        findings
    }

    fn validate_pei_core_pe(
        &self,
        data: &[u8],
        file_offset: usize,
        file_size: usize,
        fv_start: usize,
        _fv_length: usize,
        findings: &mut Vec<Finding>,
    ) {
        let file_end = (file_offset + file_size).min(data.len());

        // Search for PE signature within PEI Core file
        for i in file_offset + 24..file_end.saturating_sub(64) {
            if data[i..i + 4] == PE_SIGNATURE {
                // COFF header follows PE signature
                let optional_header_offset = i + 24;
                if optional_header_offset + 28 > data.len() {
                    break;
                }

                let entry_point = u32::from_le_bytes(
                    data[optional_header_offset + 16..optional_header_offset + 20]
                        .try_into()
                        .unwrap_or([0; 4]),
                ) as usize;

                let image_base = u32::from_le_bytes(
                    data[optional_header_offset + 28..optional_header_offset + 32]
                        .try_into()
                        .unwrap_or([0; 4]),
                ) as usize;

                // Entry point should be within the firmware volume
                let absolute_entry = image_base.wrapping_add(entry_point);
                if entry_point > file_size {
                    findings.push(
                        Finding::new(
                            "pei_implant",
                            Severity::Critical,
                            "PEI Core entry point outside file boundaries",
                            &format!(
                                "PEI Core at offset 0x{:08X} has entry point RVA 0x{:08X} which \
                                 exceeds file size 0x{:X}. Entry may have been redirected to an \
                                 implant outside the core module.",
                                file_offset, entry_point, file_size
                            ),
                        )
                        .with_confidence(0.90)
                        .with_details(serde_json::json!({
                            "file_offset": format!("0x{:08X}", file_offset),
                            "entry_point_rva": format!("0x{:08X}", entry_point),
                            "image_base": format!("0x{:08X}", image_base),
                            "absolute_entry": format!("0x{:08X}", absolute_entry),
                            "file_size": format!("0x{:X}", file_size),
                            "fv_start": format!("0x{:08X}", fv_start),
                        }))
                        .with_recommendation(
                            "Compare PEI Core binary against vendor reference and re-flash",
                        ),
                    );
                }

                break;
            }
        }
    }

    fn check_peim_anomalies(
        &self,
        data: &[u8],
        file_offset: usize,
        file_size: usize,
        fv_start: usize,
        findings: &mut Vec<Finding>,
    ) {
        let file_end = (file_offset + file_size).min(data.len());

        // Check for PEIMs with unusual section types
        let mut section_pos = file_offset + 24; // Skip FFS header
        while section_pos + 4 < file_end {
            let section_size = u32::from_le_bytes([
                data[section_pos],
                data[section_pos + 1],
                data[section_pos + 2],
                0,
            ]) as usize;
            let section_type = data.get(section_pos + 3).copied().unwrap_or(0);

            if section_size < 4 || section_pos + section_size > file_end {
                break;
            }

            // Section type 0x01 = COMPRESSION, 0x02 = GUID_DEFINED
            // RAW section (0x19) in a PEIM is unusual and suspicious
            if section_type == 0x19 && section_size > 512 {
                // Check for high entropy in RAW section (possible encrypted implant)
                let section_data =
                    &data[section_pos + 4..(section_pos + section_size).min(file_end)];
                let entropy = self.estimate_entropy(section_data);
                if entropy > 7.5 {
                    findings.push(
                        Finding::new(
                            "pei_implant",
                            Severity::High,
                            "PEI module contains high-entropy RAW section (possible implant)",
                            &format!(
                                "PEIM at offset 0x{:08X} has RAW section (type 0x19) with size {} \
                                 and entropy {:.2}. High-entropy RAW data in PEI phase is unusual \
                                 and may contain an encrypted/compressed implant payload.",
                                file_offset, section_size, entropy
                            ),
                        )
                        .with_confidence(0.72)
                        .with_details(serde_json::json!({
                            "peim_offset": format!("0x{:08X}", file_offset),
                            "section_offset": format!("0x{:08X}", section_pos),
                            "section_size": section_size,
                            "entropy": format!("{:.2}", entropy),
                            "fv_offset": format!("0x{:08X}", fv_start),
                        })),
                    );
                }
            }

            section_pos += (section_size + 3) & !3; // 4-byte alignment
        }
    }

    fn estimate_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut counts = [0u64; 256];
        for &b in data {
            counts[b as usize] += 1;
        }
        let len = data.len() as f64;
        let mut entropy = 0.0;
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }
}

impl Detector for PeiImplantDetector {
    fn name(&self) -> &str {
        "pei_implant"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let mut findings = Vec::new();

        // Find firmware volumes and check PEI components
        let mut pos = 0;
        while pos + 56 < data.len() {
            if let Some(offset) = data[pos..].windows(4).position(|w| w == EFI_FV_SIGNATURE) {
                let fv_header_start = (pos + offset).saturating_sub(40);
                if fv_header_start + 40 < data.len() {
                    let fv_length = u64::from_le_bytes(
                        data[fv_header_start + 32..fv_header_start + 40]
                            .try_into()
                            .unwrap_or([0; 8]),
                    ) as usize;

                    if fv_length > 0 && fv_length <= data.len() {
                        findings.extend(self.check_pei_core_entry(
                            &data,
                            fv_header_start,
                            fv_length,
                        ));
                    }
                }
                pos = pos + offset + 4;
            } else {
                break;
            }
        }

        Ok(findings)
    }
}
