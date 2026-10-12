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

        // O-RAN DU marker ("O-RAN.WG" — in the detector's marker list)
        data[0..8].copy_from_slice(b"O-RAN.WG");

        // Unauthorized xApp descriptor (strings from the detector's list)
        let xapp_off = 0x80;
        let xapp_str = b"unauthorized_xapp xApp_exfil mirror_e2\n";
        let end = (xapp_off + xapp_str.len()).min(size);
        data[xapp_off..end].copy_from_slice(&xapp_str[..end - xapp_off]);

        // Non-standard eCPRI message type — the detector looks for the
        // reserved type 0xFF after the version byte
        let ecpri_off = 0x100;
        // eCPRI header: version=1, msg_type=0xFF (reserved/non-standard), payload_size
        data[ecpri_off] = 0x10; // version 1, reserved=0
        data[ecpri_off + 1] = 0xFF; // reserved message type
        data[ecpri_off + 2] = 0x00;
        data[ecpri_off + 3] = 0x40; // payload size = 64

        // Fill eCPRI payload with suspicious data
        for (j, byte) in data[ecpri_off + 4..(ecpri_off + 68).min(size)]
            .iter_mut()
            .enumerate()
        {
            *byte = (((ecpri_off + 4 + j) * 11 + 5) & 0xFF) as u8;
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
