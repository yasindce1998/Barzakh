use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct PlutonInterceptPayload;

impl Payload for PlutonInterceptPayload {
    fn name(&self) -> &str {
        "pluton_intercept"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0u8; size];

        // Pluton mailbox command structure
        let mailbox_offset = 0x100;
        // Mailbox magic / identifier ("PLTN" — matches the detector's
        // PLUTON_MAILBOX_MAGIC)
        let pluton_marker = b"PLTN";
        data[mailbox_offset..mailbox_offset + pluton_marker.len()].copy_from_slice(pluton_marker);

        // Mailbox status at mailbox+4: 0xDEADBEEF (tampered/invalid).
        // The detector reads the status u32 at magic+4.
        let tampered_status: u32 = 0xDEADBEEF;
        data[mailbox_offset + 4..mailbox_offset + 8]
            .copy_from_slice(&tampered_status.to_le_bytes());

        // PlutonTPM redirect marker (Pluton shimming dTPM commands)
        let pluton_tpm = b"PlutonTPM";
        let redirect_offset = 0x400;
        data[redirect_offset..redirect_offset + pluton_tpm.len()].copy_from_slice(pluton_tpm);

        // TPM command being redirected (TPM2_CC_GetRandom = 0x0000017B)
        let tpm_cmd: u32 = 0x0000017B;
        data[redirect_offset + pluton_tpm.len() + 4..redirect_offset + pluton_tpm.len() + 8]
            .copy_from_slice(&tpm_cmd.to_be_bytes());

        // DICE attestation layer with zeroed measurement ("DICE_L" —
        // matches the detector's DICE_LAYER_MARKER)
        let dice_offset = 0x800;
        let dice_marker = b"DICE_L";
        data[dice_offset..dice_offset + dice_marker.len()].copy_from_slice(dice_marker);
        // CDI hash: all zeros (indicates tampered attestation chain)
        // Leave 32 bytes after DICE marker as zeros (already zero from init)

        // Also place an 0xFF-filled hash variant (alternative tamper indicator)
        let ff_hash_offset = dice_offset + 64;
        for i in 0..32 {
            data[ff_hash_offset + i] = 0xFF;
        }

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "pluton".to_string(),
            min_severity: Severity::High,
        }]
    }
}
