use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct HeciTrafficPayload;

impl Payload for HeciTrafficPayload {
    fn name(&self) -> &str {
        "heci_traffic"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // PCI config space pattern for HECI device at offset 0x100
        // Vendor ID 0x8086 (Intel) LE
        data[0x100] = 0x86;
        data[0x101] = 0x80;
        // Device ID 0xA13A LE
        data[0x102] = 0x3A;
        data[0x103] = 0xA1;
        // Class code 0x078000 (communication controller)
        data[0x109] = 0x80;
        data[0x10A] = 0x07;

        // H_CSR register pattern at offset 0x200 + 4 (host ready bit = 0x00000004)
        data[0x204] = 0x04;
        data[0x205] = 0x00;
        data[0x206] = 0x00;
        data[0x207] = 0x00;

        // ME_CSR register pattern at offset 0x200 + 0xC (ME ready = 0x0000000C)
        data[0x20C] = 0x0C;
        data[0x20D] = 0x00;
        data[0x20E] = 0x00;
        data[0x20F] = 0x00;

        // 4 HECI message headers at offset 0x300, each 8 bytes
        // Format: [GroupId, Command, HostAddr, MeAddr, Length(u16 LE), Reserved(u16)]
        // All use GroupId 0xFF (MKHI) within 64 bytes to trigger anomaly detection
        for i in 0..4 {
            let base = 0x300 + i * 8;
            data[base] = 0xFF; // GroupId (MKHI)
            data[base + 1] = i as u8 + 1; // Command (varying)
            data[base + 2] = 0x01; // HostAddr
            data[base + 3] = 0x07; // MeAddr
                                   // Length (u16 LE)
            data[base + 4] = 0x10;
            data[base + 5] = 0x00;
            // Reserved (u16)
            data[base + 6] = 0x00;
            data[base + 7] = 0x00;
        }

        // H_CSR manipulation pattern at offset 0x400
        // Bytes 0x04 0x00 0x00 0x00 followed by OR mask 0x01 (enable interrupt)
        // Repeated 3 times to indicate interception
        for i in 0..3 {
            let base = 0x400 + i * 5;
            data[base] = 0x04;
            data[base + 1] = 0x00;
            data[base + 2] = 0x00;
            data[base + 3] = 0x00;
            data[base + 4] = 0x01; // OR mask: enable interrupt
        }

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "heci".to_string(),
            min_severity: Severity::High,
        }]
    }
}
