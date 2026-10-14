use anyhow::Result;
use byteorder::{LittleEndian, WriteBytesExt};

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct RiscvUefiBootPayload;

impl Payload for RiscvUefiBootPayload {
    fn name(&self) -> &str {
        "riscv_uefi_boot"
    }

    fn arch(&self) -> Arch {
        Arch::RiscV64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0u8; size];

        // RISC-V UEFI boot flow attack: a malicious shim that intercepts
        // the PEI-less boot path (RISC-V has no PEI phase, goes directly
        // from OpenSBI to DXE via the hand-off block)

        // PE/COFF header for RISC-V UEFI application
        let offset = 0x0;
        data[offset] = b'M';
        data[offset + 1] = b'Z';

        // e_lfanew
        let pe_ptr: u32 = 0x80;
        let mut cursor = std::io::Cursor::new(&mut data[0x3C..0x40]);
        cursor.write_u32::<LittleEndian>(pe_ptr)?;

        // PE signature
        let pe_off = pe_ptr as usize;
        data[pe_off] = b'P';
        data[pe_off + 1] = b'E';
        data[pe_off + 2] = 0x00;
        data[pe_off + 3] = 0x00;

        // COFF Machine: RISC-V 64 (0x5064)
        data[pe_off + 4] = 0x64;
        data[pe_off + 5] = 0x50;
        // Subsystem: EFI Boot Service Driver (0x000B)
        data[pe_off + 24] = 0x0B;
        data[pe_off + 25] = 0x00;

        // Malicious supervisor-mode trampoline in .text section
        // This code escalates from S-mode to M-mode by exploiting
        // the OpenSBI ecall interface
        let code_offset = 0x200;

        // ECALL — trigger SBI call
        let mut cursor = std::io::Cursor::new(&mut data[code_offset..code_offset + 4]);
        cursor.write_u32::<LittleEndian>(0x0000_0073)?; // ecall

        // After ecall returns, attempt to write mstatus CSR (M-mode privilege escalation)
        // csrw mstatus, a0 = 0x300_51073
        let mut cursor = std::io::Cursor::new(&mut data[code_offset + 4..code_offset + 8]);
        cursor.write_u32::<LittleEndian>(0x3005_1073)?;

        // Write to medeleg (machine exception delegation) to intercept all traps
        // csrw medeleg, a0 = 0x302_51073
        let mut cursor = std::io::Cursor::new(&mut data[code_offset + 8..code_offset + 12]);
        cursor.write_u32::<LittleEndian>(0x3025_1073)?;

        // AUIPC/LD/JALR trampoline to jump to injected code
        let tramp_offset = 0x300;
        let mut cursor = std::io::Cursor::new(&mut data[tramp_offset..tramp_offset + 20]);
        cursor.write_u32::<LittleEndian>(0x0000_0317)?; // AUIPC t1, 0
        cursor.write_u32::<LittleEndian>(0x0083_3303)?; // LD t1, 8(t1)
        cursor.write_u32::<LittleEndian>(0x0003_0067)?; // JALR x0, t1, 0
        cursor.write_u64::<LittleEndian>(0x8000_0000_DEAD_0000)?; // target in M-mode memory

        // Embedded stage-2 image at page 0x1000: the bootkit maps a
        // second unsigned executable into memory after the S-mode
        // trampoline fires.
        let stage2 = 0x1000;
        data[stage2..stage2 + 2].copy_from_slice(b"MZ");
        data[stage2 + 0x3C..stage2 + 0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let s2_pe = stage2 + 0x80;
        data[s2_pe..s2_pe + 4].copy_from_slice(b"PE\0\0");

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![
            ExpectedFinding {
                detector: "opensbi".to_string(),
                min_severity: Severity::High,
            },
            ExpectedFinding {
                detector: "memory".to_string(),
                min_severity: Severity::High,
            },
        ]
    }
}
