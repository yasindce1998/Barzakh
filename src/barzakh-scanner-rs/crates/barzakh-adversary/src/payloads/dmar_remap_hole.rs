use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

/// Emits firmware carrying a VT-d `DMAR` table with a *populated* remapping
/// structure walk whose single RMRR reserves effectively all of physical
/// memory for device DMA — the "remap hole" of the CVE-2025-11901 /
/// CVE-2025-14302 class: the IOMMU is enabled, the table is well-formed, and
/// yet every page remains device-addressable during the PEI→DXE window.
pub struct DmarRemapHolePayload;

impl Payload for DmarRemapHolePayload {
    fn name(&self) -> &str {
        "dmar_remap_hole"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x1000);
        let mut data = vec![0u8; size];

        // DMAR table: 48-byte prologue + one 24-byte RMRR entry.
        const DMAR_LEN: u32 = 48 + 24;
        data[0x00..0x04].copy_from_slice(b"DMAR");
        data[0x04..0x08].copy_from_slice(&DMAR_LEN.to_le_bytes());
        data[0x08] = 0x01; // Revision
        data[0x0A..0x10].copy_from_slice(b"BRZKH0");
        data[0x10..0x18].copy_from_slice(b"REMAPHOL");
        data[0x18..0x1C].copy_from_slice(&1u32.to_le_bytes());
        data[0x1C..0x20].copy_from_slice(b"BRZK");
        data[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
        data[0x24] = 0x27; // Host Address Width (39-bit)
        data[0x25] = 0x01; // Flags: INTR_REMAP set — IOMMU looks healthy

        // RMRR entry: type(2) + length(2) + reserved(2) + segment(2) +
        // base(8) + limit(8).
        let entry = &mut data[48..72];
        entry[0..2].copy_from_slice(&1u16.to_le_bytes()); // type = RMRR
        entry[2..4].copy_from_slice(&24u16.to_le_bytes()); // length
        entry[4..6].copy_from_slice(&0u16.to_le_bytes()); // reserved
        entry[6..8].copy_from_slice(&0u16.to_le_bytes()); // segment
        entry[8..16].copy_from_slice(&0u64.to_le_bytes()); // base: 0
        entry[16..24].copy_from_slice(&0xFFFF_FFFF_FFFFu64.to_le_bytes()); // limit: all RAM

        // Valid ACPI checksum.
        let sum: u8 = data[0..DMAR_LEN as usize]
            .iter()
            .fold(0u8, |acc, &b| acc.wrapping_add(b));
        data[0x09] = (0u8).wrapping_sub(sum);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "dmar_enforcement".to_string(),
            min_severity: Severity::High,
        }]
    }
}
