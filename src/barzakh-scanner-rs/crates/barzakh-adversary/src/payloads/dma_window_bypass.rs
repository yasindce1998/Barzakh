use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

/// Emits a firmware image modeling the *exploitation* side of the pre-boot
/// DMA window (CVE-2025-11901 / CVE-2025-14302 class): a VT-d `DMAR` whose
/// RMRR unity-maps all of RAM, combined with a forged PCI option-ROM header
/// whose Base Address Register points at the DXE driver region — i.e. a
/// PCILeech-style device writing host memory before `ExitBootServices`, when
/// DMA protection is not yet enforced.
pub struct DmaWindowBypassPayload;

impl Payload for DmaWindowBypassPayload {
    fn name(&self) -> &str {
        "dma_window_bypass"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0u8; size];

        // ── DMAR with full-memory RMRR (the open window) ──────────────────
        const DMAR_OFF: usize = 0x100;
        const DMAR_LEN: u32 = 48 + 24;
        data[DMAR_OFF..DMAR_OFF + 4].copy_from_slice(b"DMAR");
        data[DMAR_OFF + 4..DMAR_OFF + 8].copy_from_slice(&DMAR_LEN.to_le_bytes());
        data[DMAR_OFF + 8] = 0x01;
        data[DMAR_OFF + 0x0A..DMAR_OFF + 0x10].copy_from_slice(b"BRZKH0");
        data[DMAR_OFF + 0x10..DMAR_OFF + 0x18].copy_from_slice(b"DMAWINBR");
        data[DMAR_OFF + 0x24] = 0x27; // Host Address Width
        data[DMAR_OFF + 0x25] = 0x01; // INTR_REMAP — IOMMU "enabled"
        let entry = &mut data[DMAR_OFF + 48..DMAR_OFF + 72];
        entry[0..2].copy_from_slice(&1u16.to_le_bytes()); // RMRR
        entry[2..4].copy_from_slice(&24u16.to_le_bytes());
        entry[8..16].copy_from_slice(&0u64.to_le_bytes());
        entry[16..24].copy_from_slice(&0xFFFF_FFFF_FFFFu64.to_le_bytes());
        let sum: u8 = data[DMAR_OFF..DMAR_OFF + DMAR_LEN as usize]
            .iter()
            .fold(0u8, |acc, &b| acc.wrapping_add(b));
        data[DMAR_OFF + 9] = (0u8).wrapping_sub(sum);

        // ── DXE driver region the attack overwrites ────────────────────────
        const DXE_OFF: usize = 0x2000;
        const DXE_LEN: usize = 0x800;
        let dxe = &mut data[DXE_OFF..DXE_OFF + DXE_LEN];
        dxe[0x00..0x04].copy_from_slice(&0x0000_0017u32.to_le_bytes()); // FV signature offset trick
        dxe[0x10..0x14].copy_from_slice(b"DXE!");
        dxe[0x20..0x28].copy_from_slice(b"PCILEECH");

        // ── Forged PCI option ROM header targeting the DXE region ─────────
        // PCI Expansion ROM header: signature 0xAA55, structure pointer, and
        // a device BAR that points straight into the DXE region — the
        // pre-handoff DMA write path.
        const ROM_OFF: usize = 0x1000;
        let rom = &mut data[ROM_OFF..ROM_OFF + 0x100];
        rom[0x00..0x02].copy_from_slice(&0xAA55u16.to_le_bytes()); // ROM signature
        rom[0x02] = 0x20; // structure offset (PCI data structure)
        let pds = &mut rom[0x20..0x40];
        pds[0x00..0x04].copy_from_slice(b"PCIR"); // PCI data structure sig
        pds[0x08..0x0A].copy_from_slice(&0x0300u16.to_le_bytes()); // type: with image
                                                                   // Image base (BAR) targeting the DXE region — the DMA write lands
                                                                   // before ExitBootServices, when translation is not yet enforced.
        pds[0x10..0x18].copy_from_slice(&(DXE_OFF as u64).to_le_bytes());
        rom[0x40..0x48].copy_from_slice(b"DMAWRITE");

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "dmar_enforcement".to_string(),
            min_severity: Severity::High,
        }]
    }
}
