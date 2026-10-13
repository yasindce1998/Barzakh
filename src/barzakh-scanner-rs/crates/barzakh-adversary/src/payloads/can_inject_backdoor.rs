use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct CanInjectBackdoorPayload;

impl Payload for CanInjectBackdoorPayload {
    fn name(&self) -> &str {
        "can_inject_backdoor"
    }

    fn arch(&self) -> Arch {
        Arch::Armv7
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x800);
        let mut data = vec![0u8; size];

        // CAN bus gateway platform marker
        let platform = b"CANBUS gateway ECU arbitration firmware";
        let end = platform.len().min(size);
        data[0..end].copy_from_slice(&platform[..end]);

        // Frame injection and arbitration spoofing
        let inject_off = 0x80;
        let inject_str = b"can_inject_frame=0x7FF\narbitration_spoof=high_priority\n";
        let end = (inject_off + inject_str.len()).min(size);
        data[inject_off..end].copy_from_slice(&inject_str[..end - inject_off]);

        // Bus-off suppression
        let busoff_off = 0x100;
        let busoff_str = b"busoff_suppress=enabled\n";
        let end = (busoff_off + busoff_str.len()).min(size);
        data[busoff_off..end].copy_from_slice(&busoff_str[..end - busoff_off]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "can_injection".to_string(),
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
    fn can_inject_backdoor_markers_present() {
        let payload = CanInjectBackdoorPayload;
        let data = payload.generate(&PayloadConfig::default()).unwrap();
        assert!(contains(&data, b"CANBUS gateway ECU arbitration firmware"));
        assert!(contains(&data, b"can_inject_frame=0x7FF\n"));
        assert!(contains(&data, b"arbitration_spoof=high_priority\n"));
        assert!(contains(&data, b"busoff_suppress=enabled\n"));
    }
}
