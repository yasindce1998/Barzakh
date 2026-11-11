use std::path::Path;

use sha2::{Digest, Sha256};

use crate::baseline::Baseline;
use crate::detector::{Detector, DetectorError, Finding, Severity};

#[allow(dead_code)]
const SPI_REGION_NAMES: &[&str] = &["Descriptor", "BIOS", "ME/CSME", "GbE", "Platform Data"];

pub struct SpiIntegrityDetector {
    baseline: Option<Baseline>,
}

impl SpiIntegrityDetector {
    pub fn new(baseline: Option<Baseline>) -> Self {
        Self { baseline }
    }

    fn compute_region_hash(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn check_flash_descriptor(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Intel Flash Descriptor signature at offset 0x10
        if data.len() >= 0x18 {
            let descriptor_sig = u32::from_le_bytes(data[0x10..0x14].try_into().unwrap_or([0; 4]));
            // Only judge the signature when the image carries flash
            // descriptor *structure*: FLMAP0 at 0x14 with plausible
            // component counts. Code-only firmware images (OVMF_CODE,
            // capsules, EFI binaries) legitimately have no descriptor at
            // all — a missing descriptor is not corruption.
            let flmap0 = u32::from_le_bytes(data[0x14..0x18].try_into().unwrap_or([0; 4]));
            let nc = (flmap0 >> 8) & 0xFF; // number of flash components
            let nr = (flmap0 >> 24) & 0x07; // number of regions
            let fcba = flmap0 & 0xFF; // component base (dword units)
            let frba = (flmap0 >> 16) & 0xFF; // region base (dword units)
            let has_descriptor_structure = flmap0 != 0
                && flmap0 != 0xFFFF_FFFF
                && nc <= 2
                && nr <= 3
                && fcba <= 0x3F
                && frba <= 0x3F;

            if has_descriptor_structure && descriptor_sig != 0x0FF0A55A {
                findings.push(
                    Finding::new(
                        "spi_integrity",
                        Severity::High,
                        "Invalid SPI flash descriptor signature",
                        &format!(
                            "Expected descriptor signature 0x0FF0A55A, found 0x{:08X}. \
                             SPI flash descriptor may be corrupted or modified.",
                            descriptor_sig
                        ),
                    )
                    .with_confidence(0.90)
                    .with_details(serde_json::json!({
                        "expected": "0x0FF0A55A",
                        "found": format!("0x{:08X}", descriptor_sig),
                    })),
                );
            }
        }

        // Check write-protect bits in descriptor
        if data.len() >= 0x70 {
            let flmstr1 = u32::from_le_bytes(data[0x64..0x68].try_into().unwrap_or([0; 4]));
            // Bits 20-23: BIOS write access
            let bios_write = (flmstr1 >> 20) & 0xF;
            if bios_write == 0xF {
                findings.push(
                    Finding::new(
                        "spi_integrity",
                        Severity::Medium,
                        "BIOS region write access is fully open",
                        "Flash Master 1 (host CPU) has full write access to BIOS region. \
                         Write protection should be enabled to prevent runtime modification.",
                    )
                    .with_confidence(0.75)
                    .with_details(serde_json::json!({
                        "flmstr1": format!("0x{:08X}", flmstr1),
                        "bios_write_bits": bios_write,
                    })),
                );
            }
        }

        findings
    }
}

impl Detector for SpiIntegrityDetector {
    fn name(&self) -> &str {
        "spi_integrity"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_flash_descriptor(&data));

        // Baseline comparison: hash the full image and compare
        if let Some(ref baseline) = self.baseline {
            let hash = Self::compute_region_hash(&data);
            if let Some(ref bst) = baseline.boot_services_table {
                if let Some(expected) = bst.get("spi_hash").and_then(|v| v.as_str()) {
                    if hash != expected {
                        findings.push(
                            Finding::new(
                                "spi_integrity",
                                Severity::Critical,
                                "SPI flash content differs from baseline",
                                &format!(
                                    "SHA-256 of SPI flash image does not match baseline. \
                                     Expected: {}, Got: {}",
                                    expected, hash
                                ),
                            )
                            .with_confidence(0.95)
                            .with_recommendation(
                                "SPI flash has been modified since baseline. Investigate immediately.",
                            ),
                        );
                    }
                }
            }
        }

        Ok(findings)
    }
}
