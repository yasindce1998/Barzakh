use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct AmtSolPayload;

impl Payload for AmtSolPayload {
    fn name(&self) -> &str {
        "amt_sol"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // PCI config pattern for AMT SOL device (B0:D22:F3) at offset 0x100
        // Vendor ID 0x8086 (Intel) LE
        data[0x100] = 0x86;
        data[0x101] = 0x80;
        // Device ID 0xA13D LE
        data[0x102] = 0x3D;
        data[0x103] = 0xA1;

        // AMT provisioning state = 0x03 (fully provisioned) at offset 0x140
        data[0x140] = 0x03;

        // SOL control register patterns at offset 0x200
        // RECV_CTRL at +0x00 with enable bit set
        data[0x200] = 0x01;
        data[0x201] = 0x00;
        data[0x202] = 0x00;
        data[0x203] = 0x00;
        // SEND_CTRL at +0x04 with enable bit set
        data[0x204] = 0x01;
        data[0x205] = 0x00;
        data[0x206] = 0x00;
        data[0x207] = 0x00;

        // "SOL\x00" string at offset 0x300
        data[0x300] = b'S';
        data[0x301] = b'O';
        data[0x302] = b'L';
        data[0x303] = 0x00;

        // Command structure bytes at +64 bytes (0x340): Platinum APT IOCs
        // 0x01 (beacon), 0x02 (exec), 0x03 (exfil)
        data[0x340] = 0x01; // beacon
        data[0x341] = 0x02; // exec
        data[0x342] = 0x03; // exfil

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "amt".to_string(),
            min_severity: Severity::High,
        }]
    }
}
