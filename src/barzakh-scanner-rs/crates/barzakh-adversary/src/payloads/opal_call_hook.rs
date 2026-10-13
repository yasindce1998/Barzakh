use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct OpalCallHookPayload;

impl Payload for OpalCallHookPayload {
    fn name(&self) -> &str {
        "opal_call_hook"
    }

    fn arch(&self) -> Arch {
        Arch::Power64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x800);
        let mut data = vec![0u8; size];

        // skiboot OPAL platform marker
        let platform = b"skiboot OPAL PowerPC PNOR firmware";
        let end = platform.len().min(size);
        data[0..end].copy_from_slice(&platform[..end]);

        // OPAL call hook and NVRAM backdoor
        let hook_off = 0x80;
        let hook_str = b"opal_call_hook=OPAL_FLASH_WRITE\nopal_nvram_backdoor=0xF0000\n";
        let end = (hook_off + hook_str.len()).min(size);
        data[hook_off..end].copy_from_slice(&hook_str[..end - hook_off]);

        // Secure boot toggle and flash persistence
        let boot_off = 0x120;
        let boot_str = b"secureboot_toggle=off\nopal_flash_persist=/sys/firmware\n";
        let end = (boot_off + boot_str.len()).min(size);
        data[boot_off..end].copy_from_slice(&boot_str[..end - boot_off]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "ibm_opal".to_string(),
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
    fn opal_call_hook_markers_present() {
        let payload = OpalCallHookPayload;
        let data = payload.generate(&PayloadConfig::default()).unwrap();
        assert!(contains(&data, b"skiboot OPAL PowerPC PNOR firmware"));
        assert!(contains(&data, b"opal_call_hook=OPAL_FLASH_WRITE\n"));
        assert!(contains(&data, b"opal_nvram_backdoor=0xF0000\n"));
        assert!(contains(&data, b"secureboot_toggle=off\n"));
        assert!(contains(&data, b"opal_flash_persist=/sys/firmware\n"));
    }
}
