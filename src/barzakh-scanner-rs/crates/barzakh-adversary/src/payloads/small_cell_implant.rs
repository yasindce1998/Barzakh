use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct SmallCellImplantPayload;

impl Payload for SmallCellImplantPayload {
    fn name(&self) -> &str {
        "small_cell_implant"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x800);
        let mut data = vec![0u8; size];

        // Femtocell marker ("femtocell" — in the detector's marker list)
        data[0..9].copy_from_slice(b"femtocell");

        // IMSI catcher configuration (strings from the detector's list)
        let imsi_off = 0x80;
        let imsi_str = b"catch_imsi silent_sms target_plmn=00101\n";
        let end = (imsi_off + imsi_str.len()).min(size);
        data[imsi_off..end].copy_from_slice(&imsi_str[..end - imsi_off]);

        // RAT downgrade configuration (force 5G/4G -> 2G) — strings from
        // the detector's downgrade list
        let rat_off = 0x100;
        let rat_str = b"force_2g disable_lte reject_5g cipher_none\n";
        let end = (rat_off + rat_str.len()).min(size);
        data[rat_off..end].copy_from_slice(&rat_str[..end - rat_off]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "small_cell".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
