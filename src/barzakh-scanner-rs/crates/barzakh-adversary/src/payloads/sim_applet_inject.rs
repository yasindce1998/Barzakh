use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct SimAppletInjectPayload;

impl Payload for SimAppletInjectPayload {
    fn name(&self) -> &str {
        "sim_applet_inject"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x400);
        let mut data = vec![0u8; size];

        // SIM toolkit applet header
        data[0..8].copy_from_slice(b"UICC_STK");

        // STK SEND SMS proactive command (exfiltration via SMS)
        // D0 = proactive command tag, followed by length + SEND SMS command
        let stk_off = 0x40;
        data[stk_off] = 0xD0; // proactive command tag
        data[stk_off + 1] = 0x20; // length
        data[stk_off + 2] = 0x81; // command details tag
        data[stk_off + 3] = 0x03;
        data[stk_off + 4] = 0x01; // command number
        data[stk_off + 5] = 0x13; // SEND SHORT MESSAGE type
        data[stk_off + 6] = 0x00; // qualifier

        // STK OPEN CHANNEL command (data exfiltration via bearer)
        let open_ch_off = 0x80;
        data[open_ch_off] = 0xD0;
        data[open_ch_off + 1] = 0x18;
        data[open_ch_off + 2] = 0x81;
        data[open_ch_off + 3] = 0x03;
        data[open_ch_off + 4] = 0x02;
        data[open_ch_off + 5] = 0x40; // OPEN CHANNEL type
        data[open_ch_off + 6] = 0x01;

        // Unauthorized AID
        let aid_off = 0xC0;
        let aid = b"A0000000871002FF49FF0589";
        data[aid_off..aid_off + aid.len()].copy_from_slice(aid);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "sim_applet".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
