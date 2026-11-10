use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

/// Emits a WLAN controller firmware blob (Broadcom FullMAC style) with an
/// injected code stub appended past the signed image — represented as a NOP
/// sled followed by a jump. Models a radio-side persistent implant smuggled
/// into the firmware-load path.
pub struct WifiFirmwareImplantPayload;

impl Payload for WifiFirmwareImplantPayload {
    fn name(&self) -> &str {
        "wifi_firmware_implant"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x1000);
        let mut data = vec![0u8; size];

        // MBR boot signature: this implant models a boot-sector-resident
        // bootkit, so the sector is bootable.
        data[510] = 0x55;
        data[511] = 0xAA;

        let header = b"brcmfmac firmware\nFWID: 01-deadbeefcafe\nwl0: version 7.45\n";
        let at = 0x40;
        let mut p = at;
        let hend = (p + header.len()).min(size);
        data[p..hend].copy_from_slice(&header[..hend - p]);
        p = hend;

        // Injected stub: 64-byte NOP sled + a short relative jump (0xEB 0xFE).
        let sled_end = (p + 64).min(size);
        for b in data.iter_mut().take(sled_end).skip(p) {
            *b = 0x90;
        }
        p = sled_end;
        if p + 2 <= size {
            data[p] = 0xEB;
            data[p + 1] = 0xFE;
        }

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "wifi_firmware".to_string(),
            min_severity: Severity::High,
        }]
    }
}
