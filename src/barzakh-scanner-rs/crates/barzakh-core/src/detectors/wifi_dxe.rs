use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const CNVI_DEVICE_ID_RANGE: &[u16] = &[0xA0F0, 0xA0F1, 0xA0F2, 0xA0F3, 0x51F0, 0x54F0];
const WIFI_PROTOCOL_GUID: &[u8] =
    b"\xDA\x23\xF0\x98\x62\x33\x4c\x47\xAC\xCD\x9F\x13\x5B\x65\x40\x66";
const DXE_DEPEX_SECTION: u8 = 0x13;
const PE_MAGIC: &[u8] = b"MZ";

pub struct WifiDxeDetector;

impl Default for WifiDxeDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl WifiDxeDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_cnvi_dxe_injection(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let mut has_cnvi_id = false;
        for i in 0..data.len().saturating_sub(2) {
            let val = u16::from_le_bytes(data[i..i + 2].try_into().unwrap_or([0; 2]));
            if CNVI_DEVICE_ID_RANGE.contains(&val) {
                has_cnvi_id = true;
                break;
            }
        }

        if !has_cnvi_id {
            return findings;
        }

        let has_wifi_guid = data
            .windows(WIFI_PROTOCOL_GUID.len())
            .any(|w| w == WIFI_PROTOCOL_GUID);

        if has_wifi_guid {
            let depex_count = data.iter().filter(|&&b| b == DXE_DEPEX_SECTION).count();

            if depex_count >= 2 {
                findings.push(
                    Finding::new(
                        "wifi_dxe",
                        Severity::High,
                        "Intel CNVi WiFi DXE driver with multiple dependency expressions",
                        &format!(
                            "Found Intel CNVi device ID with WiFi protocol GUID and {} DXE \
                             dependency sections. Multiple DEPEX sections in a WiFi DXE may \
                             indicate firmware blob injection after legitimate WiFi init code.",
                            depex_count
                        ),
                    )
                    .with_confidence(0.80)
                    .with_details(serde_json::json!({
                        "cnvi_device_present": true,
                        "wifi_guid_present": true,
                        "depex_count": depex_count,
                        "technique": "Intel CNVi wireless firmware DXE injection",
                    }))
                    .with_recommendation(
                        "Verify WiFi DXE driver against known-good Intel firmware hash",
                    ),
                );
            }
        }

        findings
    }

    fn check_wifi_pe_injection(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let has_wifi_guid = data
            .windows(WIFI_PROTOCOL_GUID.len())
            .any(|w| w == WIFI_PROTOCOL_GUID);

        if !has_wifi_guid {
            return findings;
        }

        let mut pe_count = 0;
        let mut pe_positions = Vec::new();
        for i in 0..data.len().saturating_sub(64) {
            if data[i..].starts_with(PE_MAGIC) && i + 64 < data.len() {
                let pe_offset =
                    u32::from_le_bytes(data[i + 60..i + 64].try_into().unwrap_or([0; 4])) as usize;
                if pe_offset < 0x200
                    && i + pe_offset + 4 <= data.len()
                    && &data[i + pe_offset..i + pe_offset + 4] == b"PE\x00\x00"
                {
                    pe_count += 1;
                    pe_positions.push(i);
                }
            }
        }

        if pe_count >= 2 {
            findings.push(
                Finding::new(
                    "wifi_dxe",
                    Severity::High,
                    "WiFi firmware with multiple PE images (possible DXE injection)",
                    &format!(
                        "Found {} PE/COFF images alongside WiFi protocol GUID. A legitimate \
                         WiFi DXE should contain a single PE image. Multiple PE images suggest \
                         an injected DXE payload piggybacking on the WiFi driver.",
                        pe_count
                    ),
                )
                .with_confidence(0.75)
                .with_details(serde_json::json!({
                    "pe_count": pe_count,
                    "pe_offsets": pe_positions.iter().take(5).map(|o| format!("0x{:08X}", o)).collect::<Vec<_>>(),
                    "technique": "WiFi DXE PE injection",
                })),
            );
        }

        findings
    }
}

impl Detector for WifiDxeDetector {
    fn name(&self) -> &str {
        "wifi_dxe"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_cnvi_dxe_injection(&data));
        findings.extend(self.check_wifi_pe_injection(&data));

        Ok(findings)
    }
}
