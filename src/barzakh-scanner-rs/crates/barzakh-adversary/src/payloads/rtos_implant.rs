use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct RtosImplantPayload;

impl Payload for RtosImplantPayload {
    fn name(&self) -> &str {
        "rtos_implant"
    }

    fn arch(&self) -> Arch {
        Arch::Armv7
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x800);
        let mut data = vec![0u8; size];

        // RTOS platform marker
        let platform = b"FreeRTOS ThreadX Mbed RTOS firmware";
        let end = platform.len().min(size);
        data[0..end].copy_from_slice(&platform[..end]);

        // SVC hook table redirect and watchdog disable
        let svc_off = 0x80;
        let svc_str = b"svc_hook_table=redirect\nwdt_disable_persist=1\n";
        let end = (svc_off + svc_str.len()).min(size);
        data[svc_off..end].copy_from_slice(&svc_str[..end - svc_off]);

        // Malicious task injection
        let task_off = 0xE0;
        let task_str = b"task_inject=spy_task\n";
        let end = (task_off + task_str.len()).min(size);
        data[task_off..end].copy_from_slice(&task_str[..end - task_off]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "iot_rtos".to_string(),
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
    fn rtos_implant_markers_present() {
        let payload = RtosImplantPayload;
        let data = payload.generate(&PayloadConfig::default()).unwrap();
        assert!(contains(&data, b"FreeRTOS ThreadX Mbed RTOS firmware"));
        assert!(contains(&data, b"svc_hook_table=redirect\n"));
        assert!(contains(&data, b"wdt_disable_persist=1\n"));
        assert!(contains(&data, b"task_inject=spy_task\n"));
    }
}
