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

        // STK SEND SMS proactive command (exfiltration via SMS).
        // The detector pairs the proactive-command tag 0xD0 with the
        // command type byte — its SUSPICIOUS_STK patterns are
        // [D0 13] / [D0 35] / [D0 37].
        let stk_off = 0x40;
        data[stk_off] = 0xD0; // proactive command tag
        data[stk_off + 1] = 0x13; // SEND SHORT MESSAGE type
        data[stk_off + 2] = 0x81; // command details tag
        data[stk_off + 3] = 0x03;
        data[stk_off + 4] = 0x01; // command number
        data[stk_off + 5] = 0x13; // SEND SHORT MESSAGE type (repeated)
        data[stk_off + 6] = 0x00; // qualifier

        // STK OPEN CHANNEL command (data exfiltration via bearer)
        let open_ch_off = 0x80;
        data[open_ch_off] = 0xD0;
        data[open_ch_off + 1] = 0x35; // OPEN CHANNEL type
        data[open_ch_off + 2] = 0x81;
        data[open_ch_off + 3] = 0x03;
        data[open_ch_off + 4] = 0x02;
        data[open_ch_off + 5] = 0x35; // OPEN CHANNEL type (repeated)
        data[open_ch_off + 6] = 0x01;

        // STK SEND DATA command (BIP exfiltration)
        let send_data_off = 0xA0;
        data[send_data_off] = 0xD0;
        data[send_data_off + 1] = 0x37; // SEND DATA type

        // Unauthorized AID — raw binary (the detector matches binary
        // AID prefixes like A0 00 00 00 87)
        let aid_off = 0xC0;
        let aid: [u8; 12] = [
            0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0xFF, 0x49, 0xFF, 0x05, 0x89,
        ];
        data[aid_off..aid_off + aid.len()].copy_from_slice(&aid);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "sim_applet".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
