use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct ImsFirmwareTamperPayload;

impl Payload for ImsFirmwareTamperPayload {
    fn name(&self) -> &str {
        "ims_firmware_tamper"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x1000);
        let mut data = vec![0u8; size];

        // IMS firmware marker
        data[0..12].copy_from_slice(b"IMS_VoLTE_FW");

        // AArch64 NOP sled (0xD503201F repeated) — implant landing zone
        let sled_start = 0x100;
        let sled_len = 80; // 20 NOPs
        for i in (sled_start..sled_start + sled_len).step_by(4) {
            if i + 3 < size {
                data[i] = 0x1F;
                data[i + 1] = 0x20;
                data[i + 2] = 0x03;
                data[i + 3] = 0xD5;
            }
        }

        // SIP interception marker
        let sip_off = 0x200;
        let sip_str = b"sip_intercept=INVITE,BYE,REGISTER\x00";
        let end = (sip_off + sip_str.len()).min(size);
        data[sip_off..end].copy_from_slice(&sip_str[..end - sip_off]);

        // RTP mirror marker
        let rtp_off = 0x280;
        let rtp_str = b"rtp_mirror_port=9999\x00";
        let end = (rtp_off + rtp_str.len()).min(size);
        data[rtp_off..end].copy_from_slice(&rtp_str[..end - rtp_off]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "ims_firmware".to_string(),
            min_severity: Severity::High,
        }]
    }
}
