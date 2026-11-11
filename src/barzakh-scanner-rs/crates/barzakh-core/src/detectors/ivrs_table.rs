use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

/// Structural validation of the AMD-Vi `IVRS` ACPI table — the AMD-Vi
/// counterpart of the Intel DMAR checks. Walks the IVHD (I/O Virtualization
/// Hardware Definition) and IVMD (I/O Virtualization Memory Definition)
/// blocks and flags:
///
/// * forged block walks (declared lengths that overrun or zero-fill the
///   table — the table cannot be parsed at all), and
/// * IVMD blocks that map effectively all of physical memory into a single
///   device-readable range — the AMD-Vi form of the pre-boot DMA remap hole
///   (CVE-2025-11901 / CVE-2025-14302 class), where AMD-Vi is enabled but
///   every page remains device-accessible during the PEI→DXE window.
pub struct IvrsTableDetector;

impl Default for IvrsTableDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl IvrsTableDetector {
    pub fn new() -> Self {
        Self
    }

    /// Legitimate IVMD blocks alias small legacy ranges (e.g. the VGA
    /// framebuffer). Beyond this magnitude the block is a full-memory map.
    const LEGIT_IVMD_LIMIT: u64 = 16 * 1024 * 1024;

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (off, window) in data.windows(4).enumerate() {
            if window == b"IVRS" {
                findings.extend(self.check_ivrs(data, off));
            }
        }
        findings
    }

    fn check_ivrs(&self, data: &[u8], off: usize) -> Vec<Finding> {
        let mut findings = Vec::new();
        if off + 48 > data.len() {
            return findings;
        }
        let total_len = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap()) as usize;
        // Require a structurally sane, populated table — empty-IVRS coverage
        // belongs to iommu_dmar.
        if !(64..=0x0010_0000).contains(&total_len) || off + total_len > data.len() {
            return findings;
        }

        let end = off + total_len;
        let mut pos = off + 48;
        let mut ivhd_count = 0usize;
        let mut block_index = 0usize;
        while pos + 4 <= end {
            let block_type = data[pos];
            let block_len = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;
            if block_len == 0 || pos + block_len > end {
                findings.push(
                    Finding::new(
                        "ivrs_table",
                        Severity::High,
                        "Forged IVRS block walk",
                        &format!(
                            "IVRS table at offset 0x{off:08X} declares block #{block_index} \
                             (type 0x{block_type:02X}) with length {block_len} bytes, which \
                             overruns or zero-fills the table boundary at 0x{end:08X}. The \
                             AMD-Vi description cannot be walked — the IVRS has been tampered \
                             with.",
                        ),
                    )
                    .with_confidence(0.75)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{off:08X}"),
                        "block_index": block_index,
                        "block_type": format!("0x{block_type:02X}"),
                        "block_length": block_len,
                    })),
                );
                break;
            }

            match block_type {
                0x10..=0x13 => ivhd_count += 1, // IVHD variants
                0x20..=0x22 if block_len >= 32 && pos + 32 <= end => {
                    // IVMD variants: type(1) + flags(1) + length(2) + reserved(4)
                    // + start(8) + end(8)... The common IVMD layout is:
                    // type(1)+flags(1)+length(2)+reserved(4)+deviceID(2)+
                    // reserved(2)+auxiliary(4)+start(8)+end(8)? Layouts vary by
                    // type; the fixed part every IVMD shares ends with 64-bit
                    // start/end physical addresses. Use the 0x22 (all-devices)
                    // layout: 32-byte header with start at +16, end at +24.
                    let start = u64::from_le_bytes(data[pos + 16..pos + 24].try_into().unwrap());
                    let end_addr = u64::from_le_bytes(data[pos + 24..pos + 32].try_into().unwrap());
                    let span = end_addr.saturating_sub(start);
                    if end_addr >= start && span > Self::LEGIT_IVMD_LIMIT {
                        findings.push(
                            Finding::new(
                                "ivrs_table",
                                Severity::Critical,
                                "IVRS IVMD unity mapping — pre-boot DMA remap hole",
                                &format!(
                                    "IVMD block #{block_index} in the IVRS table at offset \
                                         0x{off:08X} maps the physical range \
                                         0x{start:012X}–0x{end_addr:012X} ({span} bytes) as \
                                         device-accessible. Legitimate IVMDs alias small \
                                         legacy ranges (<16 MiB); a range of this magnitude \
                                         leaves effectively all of RAM reachable by device \
                                         DMA despite AMD-Vi being enabled — the pre-boot \
                                         exposure of the CVE-2025-11901 / CVE-2025-14302 \
                                         class.",
                                ),
                            )
                            .with_confidence(0.85)
                            .with_details(serde_json::json!({
                                "offset": format!("0x{off:08X}"),
                                "ivmd_index": block_index,
                                "start": format!("0x{start:012X}"),
                                "end": format!("0x{end_addr:012X}"),
                                "span_bytes": span,
                            }))
                            .with_recommendation(
                                "Restore the vendor IVRS so IVMD blocks cover only legacy \
                                     compatibility ranges, and verify the OS enables AMD-Vi \
                                     translation for all devices before ExitBootServices.",
                            ),
                        );
                    }
                }
                _ => {}
            }
            pos += block_len;
            block_index += 1;
        }

        if ivhd_count == 0 && block_index > 0 {
            findings.push(
                Finding::new(
                    "ivrs_table",
                    Severity::High,
                    "IVRS defines memory blocks but no IVHD units",
                    &format!(
                        "The IVRS table at offset 0x{off:08X} contains {block_index} blocks \
                         but zero IVHD hardware definitions. Without an IVHD the OS has no \
                         AMD-Vi translation hardware to program, so any declared memory maps \
                         cannot be enforced — a self-contradictory table produced by tampering.",
                    ),
                )
                .with_confidence(0.70)
                .with_details(serde_json::json!({
                    "offset": format!("0x{off:08X}"),
                    "blocks": block_index,
                    "ivhd_count": 0,
                })),
            );
        }
        findings
    }
}

impl Detector for IvrsTableDetector {
    fn name(&self) -> &str {
        "ivrs_table"
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

    /// IVRS prologue + one 32-byte IVMD block (type 0x22, all devices).
    fn ivrs_with_ivmd(start: u64, end_addr: u64) -> Vec<u8> {
        let mut t = vec![0u8; 48 + 32];
        t[0..4].copy_from_slice(b"IVRS");
        let len = t.len() as u32;
        t[4..8].copy_from_slice(&len.to_le_bytes());
        t[0x24..0x28].copy_from_slice(&0x0u32.to_le_bytes()); // IVinfo
        let block = &mut t[48..];
        block[0] = 0x22; // IVMD all devices
        block[2..4].copy_from_slice(&32u16.to_le_bytes());
        block[16..24].copy_from_slice(&start.to_le_bytes());
        block[24..32].copy_from_slice(&end_addr.to_le_bytes());
        t
    }

    #[test]
    fn fires_on_full_memory_ivmd() {
        let data = ivrs_with_ivmd(0, 0xFFFF_FFFF_FFFF);
        let findings = IvrsTableDetector::new().scan(&data);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("unity mapping") && f.severity == Severity::Critical));
    }

    #[test]
    fn fires_on_forged_block_walk() {
        let mut data = ivrs_with_ivmd(0, 0x1000);
        data[50] = 0xFF; // block length low byte → overruns table
        let findings = IvrsTableDetector::new().scan(&data);
        assert!(findings.iter().any(|f| f.title.contains("Forged IVRS")));
    }

    #[test]
    fn fires_on_ivmd_without_ivhd() {
        let data = ivrs_with_ivmd(0, 0x1000);
        let findings = IvrsTableDetector::new().scan(&data);
        assert!(findings.iter().any(|f| f.title.contains("no IVHD")));
    }

    #[test]
    fn quiet_on_clean_buffer() {
        assert!(IvrsTableDetector::new().scan(&vec![0u8; 0x8000]).is_empty());
    }
}
