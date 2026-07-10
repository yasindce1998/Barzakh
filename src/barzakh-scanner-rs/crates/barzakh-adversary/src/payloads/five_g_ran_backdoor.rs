use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct FiveGRanBackdoorPayload;

impl Payload for FiveGRanBackdoorPayload {
    fn name(&self) -> &str {
        "5g_ran_backdoor"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x1000);
        let mut data = vec![0u8; size];

        // 5G gNB marker
        data[0..12].copy_from_slice(b"gNB_DU_FW_v5");

        // ARM PC-relative load hook pattern (LDR PC, [PC, #offset])
        // E59FF000 = LDR PC, [PC, #0]
        let hook_off = 0x80;
        data[hook_off..hook_off + 4].copy_from_slice(&[0x00, 0xF0, 0x9F, 0xE5]);

        // Unsigned code section appended after main firmware boundary
        let boundary = size / 2;
        data[boundary..boundary + 8].copy_from_slice(b"__EXTRA_");
        // Fill with non-zero code-like bytes
        for (j, byte) in data[boundary + 8..(boundary + 256).min(size)]
            .iter_mut()
            .enumerate()
        {
            *byte = (((boundary + 8 + j) * 7 + 3) & 0xFF) as u8;
        }

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "five_g_ran_firmware".to_string(),
            min_severity: Severity::High,
        }]
    }
}
