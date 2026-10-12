use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct WifiDxeInjectPayload;

impl Payload for WifiDxeInjectPayload {
    fn name(&self) -> &str {
        "wifi_dxe_inject"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0u8; size];

        // PCI config space header for Intel CNVi WiFi
        let pci_offset = 0x00;
        // Vendor ID: Intel (0x8086)
        data[pci_offset..pci_offset + 2].copy_from_slice(&0x8086u16.to_le_bytes());
        // Device ID: Intel CNVi WiFi 6E (0xA0F0)
        data[pci_offset + 2..pci_offset + 4].copy_from_slice(&0xA0F0u16.to_le_bytes());

        // WiFi protocol GUID (matches the detector's WIFI_PROTOCOL_GUID)
        let wifi_guid: [u8; 16] = [
            0xDA, 0x23, 0xF0, 0x98, 0x62, 0x33, 0x4C, 0x47, 0xAC, 0xCD, 0x9F, 0x13, 0x5B, 0x65,
            0x40, 0x66,
        ];
        let guid_offset = 0x100;
        data[guid_offset..guid_offset + 16].copy_from_slice(&wifi_guid);

        // Multiple DEPEX (dependency expression) sections
        let depex_magic = &[0x06, 0x08]; // PUSH opcode + END opcode (minimal DEPEX)
        let depex_offsets = [0x200, 0x400, 0x600];
        for &off in &depex_offsets {
            data[off..off + depex_magic.len()].copy_from_slice(depex_magic);
            // GUID reference in DEPEX
            data[off + 2..off + 18].copy_from_slice(&wifi_guid);
        }

        // First PE image (legitimate WiFi DXE driver)
        let pe1_offset = 0x800;
        data[pe1_offset] = b'M';
        data[pe1_offset + 1] = b'Z';
        data[pe1_offset + 60..pe1_offset + 64].copy_from_slice(&0x80u32.to_le_bytes());
        data[pe1_offset + 0x80..pe1_offset + 0x84].copy_from_slice(b"PE\x00\x00");

        // Second PE image (injected payload alongside WiFi driver)
        let pe2_offset = 0x2000;
        data[pe2_offset] = b'M';
        data[pe2_offset + 1] = b'Z';
        data[pe2_offset + 60..pe2_offset + 64].copy_from_slice(&0x80u32.to_le_bytes());
        data[pe2_offset + 0x80..pe2_offset + 0x84].copy_from_slice(b"PE\x00\x00");

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "wifi_dxe".to_string(),
            min_severity: Severity::High,
        }]
    }
}
