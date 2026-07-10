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

        // Femtocell marker
        data[0..16].copy_from_slice(b"FEMTO_eNB_FW_v3\x00");

        // IMSI catcher configuration
        let imsi_off = 0x80;
        let imsi_str = b"imsi_collect=all\ncatch_mode=active\ntarget_plmn=00101\n";
        let end = (imsi_off + imsi_str.len()).min(size);
        data[imsi_off..end].copy_from_slice(&imsi_str[..end - imsi_off]);

        // RAT downgrade configuration (force 5G/4G -> 2G)
        let rat_off = 0x100;
        let rat_str = b"force_rat=GSM\ndisable_4g=1\nreject_5g=1\n";
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
