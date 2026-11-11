use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

// ACPI table signatures that describe the platform IOMMU.
const DMAR_SIG: &[u8; 4] = b"DMAR"; // Intel VT-d (DMA Remapping)
const IVRS_SIG: &[u8; 4] = b"IVRS"; // AMD-Vi (I/O Virtualization Reporting Structure)

// Standard ACPI table header is 36 bytes. Both DMAR and IVRS carry a further
// 12 bytes of fixed fields (DMAR: HostAddressWidth + Flags + 10 reserved;
// IVRS: IVinfo + 8 reserved) before their first remapping/IVHD structure.
// A table whose total length is <= this prologue therefore defines NO hardware
// remapping units at all — i.e. the OS is told "there is no IOMMU to program",
// leaving the platform open to pre-boot/early DMA (Thunderspy / PCILeech class).
const ACPI_HEADER_LEN: usize = 36;
const IOMMU_PROLOGUE_LEN: usize = 48;

// DMAR Flags byte (offset 37). Bit 0 = INTR_REMAP (interrupt remapping enabled).
const DMAR_FLAGS_OFFSET: usize = 37;
const DMAR_FLAG_INTR_REMAP: u8 = 0x01;

pub struct IommuDmarDetector;

impl Default for IommuDmarDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl IommuDmarDetector {
    pub fn new() -> Self {
        Self
    }

    fn read_table_len(&self, data: &[u8], off: usize) -> Option<usize> {
        if off + 8 > data.len() {
            return None;
        }
        let len = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap_or([0; 4])) as usize;
        // Sanity-bound the declared length against the file.
        if !(ACPI_HEADER_LEN..=0x0010_0000).contains(&len) || off + len > data.len() {
            return None;
        }
        Some(len)
    }

    fn check_table(&self, data: &[u8], off: usize, sig: &str, unit: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let Some(len) = self.read_table_len(data, off) else {
            return findings;
        };

        if len <= IOMMU_PROLOGUE_LEN {
            findings.push(
                Finding::new(
                    "iommu_dmar",
                    Severity::Critical,
                    &format!("{sig} table defines no {unit} units — IOMMU not enforced"),
                    &format!(
                        "ACPI {sig} table at offset 0x{off:08X} has total length {len} bytes, \
                         which is only the fixed prologue and contains zero {unit} remapping \
                         structures. The OS will conclude there is no IOMMU to program, leaving \
                         the platform exposed to pre-boot and early-boot DMA attacks \
                         (Thunderspy / PCILeech class). A populated {sig} table is expected to be \
                         far larger than {IOMMU_PROLOGUE_LEN} bytes.",
                    ),
                )
                .with_confidence(0.90)
                .with_details(serde_json::json!({
                    "offset": format!("0x{off:08X}"),
                    "signature": sig,
                    "table_length": len,
                    "prologue_length": IOMMU_PROLOGUE_LEN,
                    "remapping_units": 0,
                }))
                .with_recommendation(
                    "Restore the vendor firmware so the IOMMU description table enumerates its \
                     hardware units, and enable VT-d / AMD-Vi and kernel DMA protection.",
                ),
            );
        }

        // VT-d only: a present-but-empty interrupt-remapping flag is a weaker
        // tampering signal that complements the structural check above.
        if sig == "DMAR" && off + DMAR_FLAGS_OFFSET < data.len() {
            let flags = data[off + DMAR_FLAGS_OFFSET];
            if flags & DMAR_FLAG_INTR_REMAP == 0 && len > IOMMU_PROLOGUE_LEN {
                findings.push(
                    Finding::new(
                        "iommu_dmar",
                        Severity::Medium,
                        "VT-d DMAR has interrupt remapping disabled",
                        &format!(
                            "DMAR table at offset 0x{off:08X} clears the INTR_REMAP flag \
                             (flags=0x{flags:02X}). Without interrupt remapping, MSI-based \
                             interrupt-injection DMA attacks are not mitigated.",
                        ),
                    )
                    .with_confidence(0.55)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{off:08X}"),
                        "flags": format!("0x{flags:02X}"),
                    })),
                );
            }
        }

        findings
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (i, window) in data.windows(4).enumerate() {
            if window == DMAR_SIG.as_slice() {
                findings.extend(self.check_table(data, i, "DMAR", "DRHD"));
            } else if window == IVRS_SIG.as_slice() {
                findings.extend(self.check_table(data, i, "IVRS", "IVHD"));
            }
        }
        findings
    }
}

impl Detector for IommuDmarDetector {
    fn name(&self) -> &str {
        "iommu_dmar"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        Ok(self.scan(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal ACPI table header with the given signature and length.
    fn acpi_table(sig: &[u8; 4], len: usize) -> Vec<u8> {
        let mut t = vec![0u8; len.max(ACPI_HEADER_LEN)];
        t[0..4].copy_from_slice(sig);
        t[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        t
    }

    #[test]
    fn fires_on_dmar_without_drhd() {
        // DMAR table of exactly the prologue length → zero DRHD units.
        let data = acpi_table(DMAR_SIG, IOMMU_PROLOGUE_LEN);
        let findings = IommuDmarDetector::new().scan(&data);
        assert!(
            findings.iter().any(|f| f.severity == Severity::Critical),
            "empty DMAR should raise a critical finding"
        );
    }

    #[test]
    fn fires_on_ivrs_without_ivhd() {
        let data = acpi_table(IVRS_SIG, IOMMU_PROLOGUE_LEN);
        let findings = IommuDmarDetector::new().scan(&data);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn quiet_on_clean_buffer() {
        let data = vec![0u8; 0x4000];
        assert!(IommuDmarDetector::new().scan(&data).is_empty());
    }
}
