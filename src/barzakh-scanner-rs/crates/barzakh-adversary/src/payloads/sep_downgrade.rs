use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

/// Emits a Secure Enclave (SEPOS) personalization blob whose SEPNonce is zeroed.
/// A null/fixed SEP nonce makes the APTicket replayable, enabling a downgrade of
/// the Secure Enclave firmware to an older, signed-but-vulnerable sepos
/// (checkm8 / blackbird-class SEP attack).
pub struct SepDowngradePayload;

impl Payload for SepDowngradePayload {
    fn name(&self) -> &str {
        "sep_downgrade"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x800);
        let mut data = vec![0u8; size];

        // MBR boot signature: this implant models a boot-sector-resident
        // bootkit, so the sector is bootable.
        data[510] = 0x55;
        data[511] = 0xAA;

        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(b"AppleSEPOS sepos firmware (downgrade)\n");
        blob.extend_from_slice(b"SEPNonce");
        blob.extend_from_slice(&[0u8; 16]); // replayable (zeroed) nonce

        let at = 0x40;
        let end = (at + blob.len()).min(size);
        data[at..end].copy_from_slice(&blob[..end - at]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "ios_sep_downgrade".to_string(),
            min_severity: Severity::High,
        }]
    }
}
