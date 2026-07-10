use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct SatelliteBusTamperPayload;

impl Payload for SatelliteBusTamperPayload {
    fn name(&self) -> &str {
        "satellite_bus_tamper"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x800);
        let mut data = vec![0u8; size];

        // Satellite bus/flight computer marker
        data[0..20].copy_from_slice(b"AOCS flight_computer");
        data[20..28].copy_from_slice(b" RTEMS\x00\x00");

        // AOCS manipulation commands
        let aocs_off = 0x80;
        let aocs_str = b"override_attitude=tumble\ndisable_safemode=1\nforce_deorbit=low_thrust\n";
        let end = (aocs_off + aocs_str.len()).min(size);
        data[aocs_off..end].copy_from_slice(&aocs_str[..end - aocs_off]);

        // Power subsystem attack
        let power_off = 0x140;
        let power_str = b"drain_battery=max_rate\ndisable_solar_array=all\n";
        let end = (power_off + power_str.len()).min(size);
        data[power_off..end].copy_from_slice(&power_str[..end - power_off]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "satellite_bus".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
