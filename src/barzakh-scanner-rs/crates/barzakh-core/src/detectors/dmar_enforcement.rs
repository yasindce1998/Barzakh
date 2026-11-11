use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

/// Detects DMAR tables whose RMRR (Reserved Memory Region Reporting)
/// structures declare a *full-memory unity mapping* — the "remap hole"
/// exploited in the CVE-2025-11901 / CVE-2025-14302 class of pre-boot DMA
/// attacks, where the IOMMU is enabled but every physical page is aliased
/// into a single device-readable region during the PEI→DXE window.
///
/// Distinct from `iommu_dmar`, which fires on *empty* tables (no DRHD units
/// at all). This detector walks the remapping structures of a *populated*
/// DMAR and flags implausible protection ranges and forged entry walks.
pub struct DmarEnforcementDetector;

impl Default for DmarEnforcementDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DmarEnforcementDetector {
    pub fn new() -> Self {
        Self
    }

    /// RMRR entries legitimately cover small legacy buffers (USB/EGA/VGA
    /// compatibility), typically well under 16 MiB. Anything above this
    /// magnitude is a unity-mapping remap hole, not a compatibility carveout.
    const LEGIT_RMRR_LIMIT: u64 = 16 * 1024 * 1024;

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (off, window) in data.windows(4).enumerate() {
            if window != b"DMAR" {
                continue;
            }
            findings.extend(self.check_dmar(data, off));
        }
        findings
    }

    fn check_dmar(&self, data: &[u8], off: usize) -> Vec<Finding> {
        let mut findings = Vec::new();
        if off + 48 > data.len() {
            return findings;
        }
        let total_len = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap()) as usize;
        // Require a structurally sane, populated table — the empty-table case
        // belongs to iommu_dmar.
        if !(64..=0x0010_0000).contains(&total_len) || off + total_len > data.len() {
            return findings;
        }

        // Walk the remapping structures that follow the 48-byte prologue.
        let mut pos = off + 48;
        let end = off + total_len;
        let mut drhd_count = 0usize;
        let mut rmrr_count = 0usize;
        let mut entry_index = 0usize;
        while pos + 4 <= end {
            let entry_type = u16::from_le_bytes([data[pos], data[pos + 1]]);
            let entry_len = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;
            if entry_len == 0 || pos + entry_len > end {
                findings.push(
                    Finding::new(
                        "dmar_enforcement",
                        Severity::High,
                        "Forged DMAR remapping entry walk",
                        &format!(
                            "DMAR table at offset 0x{off:08X} declares entry #{entry_index} \
                             (type 0x{entry_type:04X}) with length {entry_len} bytes, which \
                             overruns or zero-fills the table boundary at 0x{end:08X}. A valid \
                             table walk is impossible — the DMAR has been tampered with.",
                        ),
                    )
                    .with_confidence(0.75)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{off:08X}"),
                        "entry_index": entry_index,
                        "entry_type": format!("0x{entry_type:04X}"),
                        "entry_length": entry_len,
                    })),
                );
                break;
            }

            match entry_type {
                0 => drhd_count += 1, // DRHD
                1 => {
                    // RMRR: type(2) + length(2) + reserved(2) + segment(2) +
                    // base(8) + limit(8) = 24 bytes.
                    rmrr_count += 1;
                    if entry_len >= 24 && pos + 24 <= end {
                        let base = u64::from_le_bytes(data[pos + 8..pos + 16].try_into().unwrap());
                        let limit =
                            u64::from_le_bytes(data[pos + 16..pos + 24].try_into().unwrap());
                        let span = limit.saturating_sub(base);
                        if limit >= base && span > Self::LEGIT_RMRR_LIMIT {
                            findings.push(
                                Finding::new(
                                    "dmar_enforcement",
                                    Severity::Critical,
                                    "DMAR RMRR unity mapping — pre-boot DMA remap hole",
                                    &format!(
                                        "RMRR structure #{rmrr_count} in the DMAR table at \
                                         offset 0x{off:08X} reserves the physical range \
                                         0x{base:012X}–0x{limit:012X} ({span} bytes, \
                                         {} MiB) for device DMA. Legitimate RMRRs cover \
                                         small legacy compatibility buffers (<16 MiB); a \
                                         range of this magnitude aliases effectively all of \
                                         RAM into device-addressable memory, the pre-boot DMA \
                                         exposure of the CVE-2025-11901 / CVE-2025-14302 \
                                         class. Devices in the RMRR scope bypass VT-d \
                                         translation before ExitBootServices.",
                                        span / (1024 * 1024),
                                    ),
                                )
                                .with_confidence(0.85)
                                .with_details(serde_json::json!({
                                    "offset": format!("0x{off:08X}"),
                                    "rmrr_index": rmrr_count,
                                    "base": format!("0x{base:012X}"),
                                    "limit": format!("0x{limit:012X}"),
                                    "span_bytes": span,
                                }))
                                .with_recommendation(
                                    "Restore the vendor DMAR so RMRRs cover only the legacy \
                                     compatibility ranges, and verify the OS enables kernel \
                                     DMA protection (DMAR_DEFAULT_ON / amd_iommu=on).",
                                ),
                            );
                        }
                    }
                }
                _ => {}
            }
            pos += entry_len;
            entry_index += 1;
        }

        // A populated table whose walk never yields a single DRHD is also a
        // forged-table signal distinct from the truncated/empty variants.
        if drhd_count == 0 && rmrr_count > 0 {
            findings.push(
                Finding::new(
                    "dmar_enforcement",
                    Severity::High,
                    "DMAR defines RMRRs but no DRHD units",
                    &format!(
                        "The DMAR table at offset 0x{off:08X} walks to {rmrr_count} RMRR \
                         structures but zero DRHD remapping units. Without a DRHD the OS has \
                         no translation hardware to program, so the reserved regions cannot \
                         actually be enforced — a self-contradictory table produced by \
                         tampering.",
                    ),
                )
                .with_confidence(0.70)
                .with_details(serde_json::json!({
                    "offset": format!("0x{off:08X}"),
                    "rmrr_count": rmrr_count,
                    "drhd_count": 0,
                })),
            );
        }
        findings
    }
}

impl Detector for DmarEnforcementDetector {
    fn name(&self) -> &str {
        "dmar_enforcement"
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

    /// DMAR prologue followed by one full-memory RMRR entry.
    fn dmar_with_rmrr(base: u64, limit: u64) -> Vec<u8> {
        let mut t = vec![0u8; 48 + 24];
        t[0..4].copy_from_slice(b"DMAR");
        let len = t.len() as u32;
        t[4..8].copy_from_slice(&len.to_le_bytes());
        t[0x24] = 0x27; // Host Address Width
        let entry = &mut t[48..];
        entry[0..2].copy_from_slice(&1u16.to_le_bytes()); // type = RMRR
        entry[2..4].copy_from_slice(&24u16.to_le_bytes()); // length
        entry[8..16].copy_from_slice(&base.to_le_bytes());
        entry[16..24].copy_from_slice(&limit.to_le_bytes());
        t
    }

    #[test]
    fn fires_on_full_memory_rmrr() {
        let data = dmar_with_rmrr(0, 0xFFFF_FFFF_FFFF);
        let findings = DmarEnforcementDetector::new().scan(&data);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("unity mapping") && f.severity == Severity::Critical));
    }

    #[test]
    fn fires_on_forged_entry_walk() {
        let mut data = dmar_with_rmrr(0, 0x1000);
        data[50] = 0xFF; // entry length low byte → huge, overruns table
        let findings = DmarEnforcementDetector::new().scan(&data);
        assert!(findings.iter().any(|f| f.title.contains("Forged DMAR")));
    }

    #[test]
    fn fires_on_rmrr_without_drhd() {
        let data = dmar_with_rmrr(0, 0x1000); // legit small range, but no DRHD
        let findings = DmarEnforcementDetector::new().scan(&data);
        assert!(findings.iter().any(|f| f.title.contains("no DRHD")));
    }

    #[test]
    fn quiet_on_clean_buffer() {
        assert!(DmarEnforcementDetector::new()
            .scan(&vec![0u8; 0x8000])
            .is_empty());
    }
}
