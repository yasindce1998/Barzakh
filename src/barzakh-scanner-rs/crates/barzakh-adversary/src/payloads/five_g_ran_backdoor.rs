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
        // Needs room for a >=4096-byte 0xFF erased-flash gap followed by
        // non-zero code (the detector's unsigned-section signature).
        let size = config.size.max(0x4000);
        let mut data = vec![0u8; size];

        // 5G gNB marker ("gNB-DU" — in the detector's GNB_MARKERS)
        data[0..6].copy_from_slice(b"gNB-DU");

        // ARM PC-relative load hook pattern (LDR PC, [PC, #0]).
        // The detector scans for the big-endian instruction word
        // E5 9F F0 00 at 4-byte alignment.
        let hook_off = 0x80;
        data[hook_off..hook_off + 4].copy_from_slice(&[0xE5, 0x9F, 0xF0, 0x00]);

        // Unsigned code section appended after an erased-flash gap:
        // >=4096 bytes of 0xFF, then non-zero code bytes.
        let boundary = size / 2;
        let gap_len = 0x1000;
        for b in &mut data[boundary..boundary + gap_len] {
            *b = 0xFF;
        }
        let code_off = boundary + gap_len;
        data[code_off..code_off + 8].copy_from_slice(b"__EXTRA_");
        // Fill with non-zero code-like bytes
        for (j, byte) in data[code_off + 8..(code_off + 256).min(size)]
            .iter_mut()
            .enumerate()
        {
            *byte = (((code_off + 8 + j) * 7 + 3) & 0xFF) as u8;
        }

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "5g_ran_firmware".to_string(),
            min_severity: Severity::High,
        }]
    }
}
