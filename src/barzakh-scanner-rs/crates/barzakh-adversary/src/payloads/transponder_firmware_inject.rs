use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct TransponderFirmwareInjectPayload;

impl Payload for TransponderFirmwareInjectPayload {
    fn name(&self) -> &str {
        "transponder_firmware_inject"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x800);
        let mut data = vec![0u8; size];

        // Transponder/payload controller marker
        data[0..30].copy_from_slice(b"payload_controller transponder");

        // Unauthorized reconfiguration commands
        let reconfig_off = 0x80;
        let reconfig_str =
            b"force_beam_repoint=region_c\nmodify_freq_plan=alt_plan_2\noverride_eirp=+6dB\n";
        let end = (reconfig_off + reconfig_str.len()).min(size);
        data[reconfig_off..end].copy_from_slice(&reconfig_str[..end - reconfig_off]);

        // Signal injection capability
        let inject_off = 0x180;
        let inject_str = b"inject_carrier=12.450GHz\ninterference_gen=sweep\n";
        let end = (inject_off + inject_str.len()).min(size);
        data[inject_off..end].copy_from_slice(&inject_str[..end - inject_off]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "satellite_transponder".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
