use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct SatelliteModemImplantPayload;

impl Payload for SatelliteModemImplantPayload {
    fn name(&self) -> &str {
        "satellite_modem_implant"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x1000);
        let mut data = vec![0u8; size];

        // VSAT modem marker
        data[0..20].copy_from_slice(b"iDirect VSAT DVB-S2\x00");

        // MIPS NOP sled (0x00000000 = sll $zero,$zero,0)
        let sled_start = 0x100;
        let sled_len = 128;
        // Already zeros — MIPS NOP is all-zeros

        // Place code after sled
        let code_start = sled_start + sled_len;
        for i in code_start..code_start + 64 {
            if i < size {
                data[i] = ((i * 19 + 3) & 0xFF) as u8;
            }
        }

        // Traffic mirroring marker
        let mirror_off = 0x300;
        let mirror_str = b"traffic_mirror=all_pids\ndvb_capture=ts_full\n";
        let end = (mirror_off + mirror_str.len()).min(size);
        data[mirror_off..end].copy_from_slice(&mirror_str[..end - mirror_off]);

        let _ = sled_len; // suppress unused warning

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "satellite_modem".to_string(),
            min_severity: Severity::High,
        }]
    }
}
