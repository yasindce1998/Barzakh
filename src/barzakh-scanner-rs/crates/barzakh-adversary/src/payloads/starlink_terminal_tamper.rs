use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct StarlinkTerminalTamperPayload;

impl Payload for StarlinkTerminalTamperPayload {
    fn name(&self) -> &str {
        "starlink_terminal_tamper"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x1000);
        let mut data = vec![0u8; size];

        // Starlink terminal marker
        data[0..28].copy_from_slice(b"SpaceX Starlink user_terminal");

        // Bootloader signature verification bypass
        let boot_off = 0x80;
        let boot_str = b"skip_sig_verify=1\ndisable_antirollback=true\n";
        let end = (boot_off + boot_str.len()).min(size);
        data[boot_off..end].copy_from_slice(&boot_str[..end - boot_off]);

        // Traffic interception configuration
        let intercept_off = 0x140;
        let intercept_str = b"mirror_downlink=all\nsniff_grpc=management\n";
        let end = (intercept_off + intercept_str.len()).min(size);
        data[intercept_off..end].copy_from_slice(&intercept_str[..end - intercept_off]);

        // Phased array beam manipulation
        let beam_off = 0x200;
        let beam_str = b"beam_redirect=192.168.1.0/24\n";
        let end = (beam_off + beam_str.len()).min(size);
        data[beam_off..end].copy_from_slice(&beam_str[..end - beam_off]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "starlink_terminal".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
