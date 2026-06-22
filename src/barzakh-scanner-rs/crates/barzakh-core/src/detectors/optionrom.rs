use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const OPTION_ROM_SIGNATURE: [u8; 2] = [0x55, 0xAA];
const PCIR_SIGNATURE: &[u8; 4] = b"PCIR";

pub struct OptionromDetector;

impl Default for OptionromDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl OptionromDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_rom_header(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Scan for PCI Option ROM signature (0x55AA)
        for (i, window) in data.windows(2).enumerate() {
            if window == OPTION_ROM_SIGNATURE {
                // Validate basic ROM structure
                if i + 0x1A > data.len() {
                    continue;
                }

                // Size byte at offset 0x02 (in 512-byte units)
                let rom_size_units = data[i + 2] as usize;
                if rom_size_units == 0 {
                    continue; // Not a valid ROM header
                }

                // PCI data structure pointer at offset 0x18 (2 bytes, LE)
                let pci_data_ptr =
                    u16::from_le_bytes(data[i + 0x18..i + 0x1A].try_into().unwrap_or([0; 2]))
                        as usize;

                // Validate PCI data structure pointer
                if pci_data_ptr == 0 || i + pci_data_ptr + 4 > data.len() {
                    findings.push(
                        Finding::new(
                            "optionrom",
                            Severity::High,
                            "Malformed PCI Option ROM header",
                            &format!(
                                "PCI Option ROM at offset 0x{:08X} has invalid PCI data \
                                 structure pointer (0x{:04X}). The pointer is either zero \
                                 or points outside available data.",
                                i, pci_data_ptr
                            ),
                        )
                        .with_confidence(0.65)
                        .with_details(serde_json::json!({
                            "rom_offset": format!("0x{:08X}", i),
                            "pci_data_ptr": format!("0x{:04X}", pci_data_ptr),
                            "rom_size_units": rom_size_units,
                        })),
                    );
                    continue;
                }

                // Check for PCIR signature at the pointed location
                let pcir_offset = i + pci_data_ptr;
                if &data[pcir_offset..pcir_offset + 4] != PCIR_SIGNATURE {
                    findings.push(
                        Finding::new(
                            "optionrom",
                            Severity::High,
                            "Malformed PCI Option ROM header",
                            &format!(
                                "PCI Option ROM at offset 0x{:08X} has PCI data pointer \
                                 (0x{:04X}) that does not point to a valid PCIR signature. \
                                 Found bytes: {:02X} {:02X} {:02X} {:02X}.",
                                i,
                                pci_data_ptr,
                                data[pcir_offset],
                                data[pcir_offset + 1],
                                data[pcir_offset + 2],
                                data[pcir_offset + 3],
                            ),
                        )
                        .with_confidence(0.70)
                        .with_details(serde_json::json!({
                            "rom_offset": format!("0x{:08X}", i),
                            "pci_data_ptr": format!("0x{:04X}", pci_data_ptr),
                            "expected": "PCIR",
                            "found": format!("{:02X}{:02X}{:02X}{:02X}",
                                data[pcir_offset], data[pcir_offset+1],
                                data[pcir_offset+2], data[pcir_offset+3]),
                        })),
                    );
                }
            }
        }

        findings
    }

    fn check_rom_code_injection(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Find valid ROM headers and check initialization vectors
        for (i, window) in data.windows(2).enumerate() {
            if window != OPTION_ROM_SIGNATURE {
                continue;
            }

            if i + 5 > data.len() {
                continue;
            }

            let rom_size_units = data[i + 2] as usize;
            if rom_size_units == 0 {
                continue;
            }
            let rom_size_bytes = rom_size_units * 512;

            // Init entry point is at offset 0x03-0x04 (relative offset from ROM start)
            let init_entry =
                u16::from_le_bytes(data[i + 3..i + 5].try_into().unwrap_or([0; 2])) as usize;

            // If init entry point is beyond the declared ROM size, flag it
            if init_entry > 0 && init_entry > rom_size_bytes {
                findings.push(
                    Finding::new(
                        "optionrom",
                        Severity::Critical,
                        "Option ROM initialization vector points outside ROM boundaries",
                        &format!(
                            "PCI Option ROM at offset 0x{:08X} has initialization entry \
                             point 0x{:04X} which exceeds declared ROM size ({} bytes / \
                             {} units). This may indicate code injection beyond ROM bounds.",
                            i, init_entry, rom_size_bytes, rom_size_units
                        ),
                    )
                    .with_confidence(0.75)
                    .with_details(serde_json::json!({
                        "rom_offset": format!("0x{:08X}", i),
                        "init_entry_point": format!("0x{:04X}", init_entry),
                        "declared_rom_size": rom_size_bytes,
                        "rom_size_units": rom_size_units,
                    }))
                    .with_recommendation(
                        "Investigate the Option ROM for unauthorized code injection. \
                         Compare against known-good ROM images for the device.",
                    ),
                );
            }
        }

        findings
    }

    fn check_rom_size_mismatch(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (i, window) in data.windows(2).enumerate() {
            if window != OPTION_ROM_SIGNATURE {
                continue;
            }

            if i + 3 > data.len() {
                continue;
            }

            let rom_size_units = data[i + 2] as usize;
            if rom_size_units == 0 {
                continue;
            }
            let rom_size_bytes = rom_size_units * 512;

            // Check for high-entropy data beyond the declared ROM size
            let beyond_start = i + rom_size_bytes;
            let beyond_end = std::cmp::min(beyond_start + 256, data.len());

            if beyond_start >= data.len() || beyond_end <= beyond_start {
                continue;
            }

            let beyond_data = &data[beyond_start..beyond_end];

            // Calculate entropy of data beyond declared boundary
            let mut freq = [0u32; 256];
            for &byte in beyond_data {
                freq[byte as usize] += 1;
            }

            let len = beyond_data.len() as f64;
            let mut entropy = 0.0;
            for &count in &freq {
                if count > 0 {
                    let p = count as f64 / len;
                    entropy -= p * p.log2();
                }
            }

            // High entropy beyond boundary suggests hidden data
            if entropy > 6.0 {
                findings.push(
                    Finding::new(
                        "optionrom",
                        Severity::Medium,
                        "Option ROM size mismatch - data beyond declared boundary",
                        &format!(
                            "PCI Option ROM at offset 0x{:08X} declares size {} bytes, \
                             but high-entropy data (entropy={:.2}) exists beyond the \
                             declared boundary. This may indicate hidden payload.",
                            i, rom_size_bytes, entropy
                        ),
                    )
                    .with_confidence(0.50)
                    .with_details(serde_json::json!({
                        "rom_offset": format!("0x{:08X}", i),
                        "declared_size": rom_size_bytes,
                        "beyond_offset": format!("0x{:08X}", beyond_start),
                        "beyond_entropy": format!("{:.4}", entropy),
                    })),
                );
            }
        }

        findings
    }
}

impl Detector for OptionromDetector {
    fn name(&self) -> &str {
        "optionrom"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let mut findings = Vec::new();

        findings.extend(self.check_rom_header(&data));
        findings.extend(self.check_rom_code_injection(&data));
        findings.extend(self.check_rom_size_mismatch(&data));

        Ok(findings)
    }
}
