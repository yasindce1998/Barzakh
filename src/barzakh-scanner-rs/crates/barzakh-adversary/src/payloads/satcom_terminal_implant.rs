use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct SatcomTerminalImplantPayload;

impl Payload for SatcomTerminalImplantPayload {
    fn name(&self) -> &str {
        "satcom_terminal_implant"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x800);
        let mut data = vec![0u8; size];

        // Inmarsat/maritime satcom marker
        data[0..28].copy_from_slice(b"Inmarsat FleetBroadband Sailor");

        // Position spoofing configuration
        let spoof_off = 0x80;
        let spoof_str = b"override_gps_pos=0.0,0.0\nfake_mmsi=201234567\nspoof_ais=enabled\n";
        let end = (spoof_off + spoof_str.len()).min(size);
        data[spoof_off..end].copy_from_slice(&spoof_str[..end - spoof_off]);

        // Communications interception
        let intercept_off = 0x140;
        let intercept_str = b"mirror_voice=all_channels\ncapture_sms=outbound\n";
        let end = (intercept_off + intercept_str.len()).min(size);
        data[intercept_off..end].copy_from_slice(&intercept_str[..end - intercept_off]);

        // Distress signal suppression
        let distress_off = 0x200;
        let distress_str = b"suppress_distress=true\n";
        let end = (distress_off + distress_str.len()).min(size);
        data[distress_off..end].copy_from_slice(&distress_str[..end - distress_off]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "inmarsat_terminal".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
