use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct TpmRefOverflowPayload;

impl Payload for TpmRefOverflowPayload {
    fn name(&self) -> &str {
        "tpm_ref_overflow"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // TPM2 command header
        let cmd_offset = 0x00;
        // Tag: TPM_ST_SESSIONS (0x8002)
        data[cmd_offset..cmd_offset + 2].copy_from_slice(&0x8002u16.to_be_bytes());

        // Declared commandSize: far exceeds the actual buffer (the corpus
        // runner generates 0x10000-byte files) so the detector's
        // command_size > remaining + 64 check fires
        let declared_size: u32 = 0x20000;
        data[cmd_offset + 2..cmd_offset + 6].copy_from_slice(&declared_size.to_be_bytes());

        // Command code: TPM2_CC_CertifyCreation (0x0000_014A)
        let cmd_code: u32 = 0x0000_014A;
        data[cmd_offset + 6..cmd_offset + 10].copy_from_slice(&cmd_code.to_be_bytes());

        // Authorization area starts at offset 10
        let auth_offset = cmd_offset + 10;

        // Auth area size: deliberately oversized (exceeds remaining buffer)
        let auth_size: u32 = 0x1F00;
        data[auth_offset..auth_offset + 4].copy_from_slice(&auth_size.to_be_bytes());

        // Session handle
        data[auth_offset + 4..auth_offset + 8].copy_from_slice(&0x02000000u32.to_be_bytes());

        // Nonce size: oversized to trigger out-of-bounds
        let nonce_size: u16 = 0x0F00;
        data[auth_offset + 8..auth_offset + 10].copy_from_slice(&nonce_size.to_be_bytes());

        // Fill nonce area with recognizable pattern
        let nonce_start = auth_offset + 10;
        let nonce_end = (nonce_start + nonce_size as usize).min(size);
        for byte in data.iter_mut().take(nonce_end).skip(nonce_start) {
            *byte = 0x41;
        }

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "tpm_command".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
