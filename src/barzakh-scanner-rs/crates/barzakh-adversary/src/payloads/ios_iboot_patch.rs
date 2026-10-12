use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct IosIbootPatchPayload;

impl Payload for IosIbootPatchPayload {
    fn name(&self) -> &str {
        "ios_iboot_patch"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x200);
        let mut data = vec![0u8; size];

        // iBoot magic
        data[0..5].copy_from_slice(b"iBoot");

        // No version string (stripped) — triggers version-missing finding

        // Signature region at +0x40 (0x100 bytes, through +0x140):
        // all zeros — the zeroed RSA signature is the Critical finding.
        // Keep this whole range zeroed.

        // NOP sled patch just past the signature region (ARM64 NOP =
        // 0xD503201F, LE bytes [1F, 20, 03, D5]) — the patched code entry
        let nop: [u8; 4] = [0x1F, 0x20, 0x03, 0xD5];
        for i in 0..4 {
            let off = 0x140 + i * 4;
            data[off..off + 4].copy_from_slice(&nop);
        }

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "ios_iboot".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
