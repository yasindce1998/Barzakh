use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

// Markers for a Broadcom/Cypress Bluetooth controller firmware patch (.hcd / patchram).
const BT_MARKERS: &[&[u8]] = &[b"patchram", b"BCM", b".hcd"];

// HCI vendor command opcodes (little-endian on the wire).
const WRITE_RAM: [u8; 2] = [0x4C, 0xFC]; // 0xFC4C — write a blob into controller RAM
const LAUNCH_RAM: [u8; 2] = [0x4E, 0xFC]; // 0xFC4E — jump into written RAM

// A Write_RAM carrying a 4-byte address plus a sizeable code blob is an implant,
// not a routine register poke.
const MIN_IMPLANT_PARAM_LEN: u8 = 36;

pub struct BluetoothFirmwareDetector;

impl Default for BluetoothFirmwareDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BluetoothFirmwareDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !BT_MARKERS.iter().any(|m| Self::contains(data, m)) {
            return findings;
        }

        let launches = Self::contains(data, &LAUNCH_RAM);

        for i in 0..data.len().saturating_sub(7) {
            if data[i..i + 2] != WRITE_RAM {
                continue;
            }
            let param_len = data[i + 2];
            if param_len < MIN_IMPLANT_PARAM_LEN {
                continue;
            }
            let addr = u32::from_le_bytes(data[i + 3..i + 7].try_into().unwrap_or([0; 4]));
            let severity = if launches {
                Severity::Critical
            } else {
                Severity::High
            };
            findings.push(
                Finding::new(
                    "bluetooth_firmware",
                    severity,
                    "Bluetooth controller firmware writes an implant to RAM",
                    &format!(
                        "A Broadcom Write_RAM (0xFC4C) HCI command at offset 0x{i:08X} writes {} \
                         bytes to controller RAM address 0x{addr:08X}{}. patchram blobs that push a \
                         large code payload into the BT controller (optionally followed by \
                         Launch_RAM) are the mechanism for a persistent radio-side implant.",
                        param_len,
                        if launches { ", followed by Launch_RAM (execution)" } else { "" },
                    ),
                )
                .with_confidence(if launches { 0.85 } else { 0.70 })
                .with_details(serde_json::json!({
                    "offset": format!("0x{i:08X}"),
                    "ram_address": format!("0x{addr:08X}"),
                    "payload_len": param_len,
                    "launch_ram": launches,
                }))
                .with_recommendation(
                    "Load only vendor-signed BT controller firmware; verify the .hcd patch against \
                     a known-good baseline before HCI download.",
                ),
            );
        }

        findings
    }
}

impl Detector for BluetoothFirmwareDetector {
    fn name(&self) -> &str {
        "bluetooth_firmware"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }

    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        Ok(self.scan(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn implant() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"BCM patchram\n");
        v.extend_from_slice(&WRITE_RAM); // opcode
        v.push(0x44); // param_len = 68
        v.extend_from_slice(&0x0020_0000u32.to_le_bytes()); // address
        v.extend_from_slice(&[0xCCu8; 64]); // code blob
        v.extend_from_slice(&LAUNCH_RAM);
        v.push(0x04);
        v.extend_from_slice(&0x0020_0000u32.to_le_bytes());
        v
    }

    #[test]
    fn fires_on_ram_implant() {
        let findings = BluetoothFirmwareDetector::new().scan(&implant());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn quiet_without_marker() {
        // Write_RAM bytes but no BT firmware marker → ignored.
        let mut v = Vec::new();
        v.extend_from_slice(&WRITE_RAM);
        v.push(0x44);
        v.extend_from_slice(&[0u8; 68]);
        assert!(BluetoothFirmwareDetector::new().scan(&v).is_empty());
    }

    #[test]
    fn quiet_on_clean_buffer() {
        assert!(BluetoothFirmwareDetector::new()
            .scan(&vec![0u8; 0x2000])
            .is_empty());
    }
}
