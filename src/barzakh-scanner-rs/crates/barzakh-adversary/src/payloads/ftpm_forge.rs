use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct FtpmForgePayload;

impl Payload for FtpmForgePayload {
    fn name(&self) -> &str {
        "ftpm_forge"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // TPM2 command header at offset 0x100 (big-endian)
        // tag = 0x8001 (TPM2_ST_NO_SESSIONS)
        data[0x100] = 0x80;
        data[0x101] = 0x01;
        // commandSize = 0x00000017 (23 bytes)
        data[0x102] = 0x00;
        data[0x103] = 0x00;
        data[0x104] = 0x00;
        data[0x105] = 0x17;
        // commandCode = 0x00000182 (PCR_Extend)
        data[0x106] = 0x00;
        data[0x107] = 0x00;
        data[0x108] = 0x01;
        data[0x109] = 0x82;

        // TPM2 response header with FORGED response at offset 0x200 (big-endian)
        // tag = 0x8001
        data[0x200] = 0x80;
        data[0x201] = 0x01;
        // responseSize = 0x00000005 (TOO SMALL - less than minimum 10)
        data[0x202] = 0x00;
        data[0x203] = 0x00;
        data[0x204] = 0x00;
        data[0x205] = 0x05;
        // responseCode = 0x00000000 (SUCCESS)
        data[0x206] = 0x00;
        data[0x207] = 0x00;
        data[0x208] = 0x00;
        data[0x209] = 0x00;

        // PSP MMIO base pattern at offset 0x300 (little-endian)
        // Base address 0xFED80000
        data[0x300] = 0x00;
        data[0x301] = 0x00;
        data[0x302] = 0xD8;
        data[0x303] = 0xFE;
        // C2P offset 0x10570 (LE u32)
        data[0x304] = 0x70;
        data[0x305] = 0x05;
        data[0x306] = 0x01;
        data[0x307] = 0x00;
        // P2C offset 0x10670 (LE u32)
        data[0x308] = 0x70;
        data[0x309] = 0x06;
        data[0x30A] = 0x01;
        data[0x30B] = 0x00;

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "ftpm".to_string(),
            min_severity: Severity::High,
        }]
    }
}
