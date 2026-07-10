use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct BasebandImplantPayload;

impl Payload for BasebandImplantPayload {
    fn name(&self) -> &str {
        "baseband_implant"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x1000);
        let mut data = vec![0u8; size];

        // Qualcomm baseband marker
        data[0..16].copy_from_slice(b"QCOM_MDM_BB_FW\x00\x00");

        // ARM Thumb NOP sled (0xBF00 repeated) — injection landing zone
        let sled_start = 0x100;
        let sled_len = 128;
        for i in (sled_start..sled_start + sled_len).step_by(2) {
            if i + 1 < size {
                data[i] = 0xBF;
                data[i + 1] = 0x00;
            }
        }

        // Suspicious strings indicating implant behavior
        let implant_str = b"at+csms=intercept\x00baseband_hook\x00";
        let str_off = 0x200;
        let end = (str_off + implant_str.len()).min(size);
        data[str_off..end].copy_from_slice(&implant_str[..end - str_off]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "baseband_firmware".to_string(),
            min_severity: Severity::High,
        }]
    }
}
