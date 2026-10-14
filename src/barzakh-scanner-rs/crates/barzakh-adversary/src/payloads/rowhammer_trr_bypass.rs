use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct RowhammerTrrBypassPayload;

impl Payload for RowhammerTrrBypassPayload {
    fn name(&self) -> &str {
        "rowhammer_trr_bypass"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0x00u8; size];

        // Trigger check_cache_flush_hammer: 2+ CLFLUSH within 16 bytes + backward jump.
        // CLFLUSH: 0F AE /7 (modrm & 0x38 == 0x38), e.g., 0F AE 38 (CLFLUSH [eax])
        let base = 0x200;

        // First CLFLUSH [eax]
        data[base] = 0x0F;
        data[base + 1] = 0xAE;
        data[base + 2] = 0x38; // modrm: mod=00, reg=111, rm=000

        // Second CLFLUSH [ecx] — within 16 bytes of first
        data[base + 4] = 0x0F;
        data[base + 5] = 0xAE;
        data[base + 6] = 0x39; // modrm: mod=00, reg=111, rm=001

        // Third CLFLUSH [edx]
        data[base + 8] = 0x0F;
        data[base + 9] = 0xAE;
        data[base + 10] = 0x3A; // modrm: mod=00, reg=111, rm=010

        // Backward short jump (0xEB with negative displacement = bit 7 set)
        data[base + 12] = 0xEB;
        data[base + 13] = 0xF0; // -16, jumps back (bit 7 set)

        // Second hammer cluster at a different offset
        let base2 = base + 32;
        data[base2] = 0x0F;
        data[base2 + 1] = 0xAE;
        data[base2 + 2] = 0x38;
        data[base2 + 4] = 0x0F;
        data[base2 + 5] = 0xAE;
        data[base2 + 6] = 0x3B; // [ebx]
                                // Near conditional jump backward (0F 8x with negative displacement)
        data[base2 + 10] = 0x0F;
        data[base2 + 11] = 0x82; // JB near (conditional)
        data[base2 + 12] = 0xE0; // negative displacement
        data[base2 + 13] = 0xFF;
        data[base2 + 14] = 0xFF;
        data[base2 + 15] = 0xFF;

        // Trigger check_refresh_suppression: "tREFI" string + an extended
        // tREFI value written through the PCI config data port (0xCFC).
        // The detector requires the memory-controller write to carry real
        // PCI config port context: MOV DX, 0xCFC + OUT DX, EAX around the
        // 0x3E timing-offset value.
        let refi_offset = 0x800;
        data[refi_offset..refi_offset + 5].copy_from_slice(b"tREFI");
        let pci_offset = refi_offset + 32;
        let pci_write: [u8; 13] = [
            0x66, 0xBA, 0xFC, 0xC7, // MOV DX, 0xCFC (PCI config data port)
            0xB8, 0x00, 0x30, 0x00, 0x00, // MOV EAX, 0x3000 (extended tREFI)
            0xEF, // OUT DX, EAX
            0x3E, 0x00, 0x30, // DDR timing offset 0x3E, value 0x3000 LE
        ];
        data[pci_offset..pci_offset + pci_write.len()].copy_from_slice(&pci_write);

        // Also place "REFRESH" string
        let refresh_offset = refi_offset + 64;
        data[refresh_offset..refresh_offset + 7].copy_from_slice(b"REFRESH");

        // Trigger check_trr_bypass_pattern: 4+ MOV (0x8B/0x89 with modrm & 0xC0 == 0x80)
        // with displacements forming arithmetic progression of 0x2000 in 128-byte window.
        let trr_base = 0x1000;
        let displacements: [u32; 5] = [0x4000, 0x6000, 0x8000, 0xA000, 0xC000]; // step=0x2000

        for (idx, &disp) in displacements.iter().enumerate() {
            let off = trr_base + idx * 8;
            if off + 6 < size {
                // MOV reg, [reg+disp32]: 8B mod=10 ...
                data[off] = 0x8B;
                data[off + 1] = 0x80; // modrm: mod=10, reg=000, rm=000 (EAX)
                                      // disp32 LE
                data[off + 2] = (disp & 0xFF) as u8;
                data[off + 3] = ((disp >> 8) & 0xFF) as u8;
                data[off + 4] = ((disp >> 16) & 0xFF) as u8;
                data[off + 5] = ((disp >> 24) & 0xFF) as u8;
            }
        }

        // Trigger check_physical_address_calc: 4+ SHR/SHL + AND triplets in 64-byte window.
        // SHR reg, imm8: C1 E8 xx; SHL reg, imm8: C1 E0 xx; AND: 21 or 23
        let pa_base = 0x1800;
        for i in 0..5 {
            let off = pa_base + i * 10;
            if off + 6 < size {
                // SHR EAX, imm8
                data[off] = 0xC1;
                data[off + 1] = 0xE8;
                data[off + 2] = (6 + i) as u8; // shift amount

                // AND EAX, reg: 21 C0+reg
                data[off + 3] = 0x21;
                data[off + 4] = 0xC1; // AND ecx, eax

                // SHL EAX, imm8
                data[off + 5] = 0xC1;
                data[off + 6] = 0xE0;
                data[off + 7] = (3 + i) as u8;
            }
        }

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "rowhammer".to_string(),
            min_severity: Severity::High,
        }]
    }
}
