use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct GroundStationBackdoorPayload;

impl Payload for GroundStationBackdoorPayload {
    fn name(&self) -> &str {
        "ground_station_backdoor"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x800);
        let mut data = vec![0u8; size];

        // Ground station markers
        data[0..24].copy_from_slice(b"CCSDS ground_station TT&C");

        // Telecommand injection capability
        let tc_off = 0x80;
        let tc_str = b"inject_tc=enabled\noverride_cmd_auth=bypass\nreplay_tc_frame=armed\n";
        let end = (tc_off + tc_str.len()).min(size);
        data[tc_off..end].copy_from_slice(&tc_str[..end - tc_off]);

        // Antenna tracking override
        let track_off = 0x140;
        let track_str = b"force_track_offset=3.5\naz_override=manual\n";
        let end = (track_off + track_str.len()).min(size);
        data[track_off..end].copy_from_slice(&track_str[..end - track_off]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "satellite_ground_station".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
