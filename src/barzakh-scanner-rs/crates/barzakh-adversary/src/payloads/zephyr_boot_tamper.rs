use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct ZephyrBootTamperPayload;

impl Payload for ZephyrBootTamperPayload {
    fn name(&self) -> &str {
        "zephyr_boot_tamper"
    }

    fn arch(&self) -> Arch {
        Arch::Armv7
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x800);
        let mut data = vec![0u8; size];

        // Zephyr RTOS platform marker
        let platform = b"Zephyr RTOS mcuboot bootloader";
        let end = platform.len().min(size);
        data[0..end].copy_from_slice(&platform[..end]);

        // MCUboot signature bypass and persistent swap
        let sig_off = 0x80;
        let sig_str = b"mcuboot_sig_bypass=1\nswap_move_persist=scratch\n";
        let end = (sig_off + sig_str.len()).min(size);
        data[sig_off..end].copy_from_slice(&sig_str[..end - sig_off]);

        // Version rollback
        let rollback_off = 0x100;
        let rollback_str = b"version_rollback=v1.0.0\n";
        let end = (rollback_off + rollback_str.len()).min(size);
        data[rollback_off..end].copy_from_slice(&rollback_str[..end - rollback_off]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "iot_zephyr".to_string(),
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
    fn zephyr_boot_tamper_markers_present() {
        let payload = ZephyrBootTamperPayload;
        let data = payload.generate(&PayloadConfig::default()).unwrap();
        assert!(contains(&data, b"Zephyr RTOS mcuboot bootloader"));
        assert!(contains(&data, b"mcuboot_sig_bypass=1\n"));
        assert!(contains(&data, b"swap_move_persist=scratch\n"));
        assert!(contains(&data, b"version_rollback=v1.0.0\n"));
    }
}
