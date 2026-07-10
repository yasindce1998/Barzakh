use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct GnssFirmwareSpoofPayload;

impl Payload for GnssFirmwareSpoofPayload {
    fn name(&self) -> &str {
        "gnss_firmware_spoof"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x1000);
        let mut data = vec![0u8; size];

        // GNSS receiver marker
        data[0..20].copy_from_slice(b"u-blox GNSS UBX-CFG\x00");

        // Spoofing configuration
        let spoof_off = 0x80;
        let spoof_str =
            b"spoof_location=37.7749,-122.4194\ninject_ephemeris=gps,glonass\nfake_sv=12\n";
        let end = (spoof_off + spoof_str.len()).min(size);
        data[spoof_off..end].copy_from_slice(&spoof_str[..end - spoof_off]);

        // PNT override
        let pnt_off = 0x150;
        let pnt_str = b"override_pnt=custom_solution\n";
        let end = (pnt_off + pnt_str.len()).min(size);
        data[pnt_off..end].copy_from_slice(&pnt_str[..end - pnt_off]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "gnss_receiver".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
