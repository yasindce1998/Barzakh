use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct NspCommandForgePayload;

impl Payload for NspCommandForgePayload {
    fn name(&self) -> &str {
        "nsp_command_forge"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x800);
        let mut data = vec![0u8; size];

        // NVIDIA NSP security processor marker
        let platform = b"NVIDIA NSP Tegra security processor";
        let end = platform.len().min(size);
        data[0..end].copy_from_slice(&platform[..end]);

        // Forged NSP command and secure mailbox redirection
        let forge_off = 0x80;
        let forge_str = b"nsp_cmd_forge=0x5A\nsec_mailbox_redirect=true\n";
        let end = (forge_off + forge_str.len()).min(size);
        data[forge_off..end].copy_from_slice(&forge_str[..end - forge_off]);

        // Keyslot dump and crypto override
        let key_off = 0x120;
        let key_str = b"keyslot_dump=0x00-0x0F\nse_crypto_override=AES-ECB\n";
        let end = (key_off + key_str.len()).min(size);
        data[key_off..end].copy_from_slice(&key_str[..end - key_off]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "nsp_command".to_string(),
            min_severity: Severity::High,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn nsp_command_forge_markers_present() {
        let payload = NspCommandForgePayload;
        let data = payload.generate(&PayloadConfig::default()).unwrap();
        assert!(contains(&data, b"NVIDIA NSP Tegra security processor"));
        assert!(contains(&data, b"nsp_cmd_forge=0x5A\n"));
        assert!(contains(&data, b"sec_mailbox_redirect=true\n"));
        assert!(contains(&data, b"keyslot_dump=0x00-0x0F\n"));
        assert!(contains(&data, b"se_crypto_override=AES-ECB\n"));
    }
}
