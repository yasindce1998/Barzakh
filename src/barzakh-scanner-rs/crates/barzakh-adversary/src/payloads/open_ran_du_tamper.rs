use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct OpenRanDuTamperPayload;

impl Payload for OpenRanDuTamperPayload {
    fn name(&self) -> &str {
        "open_ran_du_tamper"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x800);
        let mut data = vec![0u8; size];

        // O-RAN DU marker
        data[0..12].copy_from_slice(b"O-RAN_DU_FW\x00");

        // Unauthorized xApp descriptor
        let xapp_off = 0x80;
        let xapp_str = b"xapp_id=com.unknown.exfil\nxapp_type=unauthorized\n";
        let end = (xapp_off + xapp_str.len()).min(size);
        data[xapp_off..end].copy_from_slice(&xapp_str[..end - xapp_off]);

        // Non-standard eCPRI message type (types > 15 are reserved/non-standard)
        let ecpri_off = 0x100;
        // eCPRI header: version=1, msg_type=0xFE (non-standard), payload_size
        data[ecpri_off] = 0x10; // version 1, reserved=0
        data[ecpri_off + 1] = 0xFE; // non-standard message type
        data[ecpri_off + 2] = 0x00;
        data[ecpri_off + 3] = 0x40; // payload size = 64

        // Fill eCPRI payload with suspicious data
        for i in ecpri_off + 4..ecpri_off + 68 {
            if i < size {
                data[i] = ((i * 11 + 5) & 0xFF) as u8;
            }
        }

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "open_ran".to_string(),
            min_severity: Severity::High,
        }]
    }
}
