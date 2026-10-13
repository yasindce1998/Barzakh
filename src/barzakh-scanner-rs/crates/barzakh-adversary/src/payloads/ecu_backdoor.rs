use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct EcuBackdoorPayload;

impl Payload for EcuBackdoorPayload {
    fn name(&self) -> &str {
        "ecu_backdoor"
    }

    fn arch(&self) -> Arch {
        Arch::Armv7
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x800);
        let mut data = vec![0u8; size];

        // AUTOSAR ECU platform marker
        let platform = b"AUTOSAR ECU UDS diagnostic firmware";
        let end = platform.len().min(size);
        data[0..end].copy_from_slice(&platform[..end]);

        // UDS backdoor and security access bypass
        let uds_off = 0x80;
        let uds_str = b"uds_backdoor=0x22F190\nsecurity_access_bypass=level0\n";
        let end = (uds_off + uds_str.len()).min(size);
        data[uds_off..end].copy_from_slice(&uds_str[..end - uds_off]);

        // Flash overlay persistence
        let persist_off = 0x100;
        let persist_str = b"ecu_persistence=flash_overlay\n";
        let end = (persist_off + persist_str.len()).min(size);
        data[persist_off..end].copy_from_slice(&persist_str[..end - persist_off]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "automotive_ecu".to_string(),
            min_severity: Severity::Critical,
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
    fn ecu_backdoor_markers_present() {
        let payload = EcuBackdoorPayload;
        let data = payload.generate(&PayloadConfig::default()).unwrap();
        assert!(contains(&data, b"AUTOSAR ECU UDS diagnostic firmware"));
        assert!(contains(&data, b"uds_backdoor=0x22F190\n"));
        assert!(contains(&data, b"security_access_bypass=level0\n"));
        assert!(contains(&data, b"ecu_persistence=flash_overlay\n"));
    }
}
