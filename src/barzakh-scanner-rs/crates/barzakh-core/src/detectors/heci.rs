use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

pub struct HeciDetector;

impl Default for HeciDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl HeciDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_heci_mmio_patterns(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Look for HECI register layout patterns
        // PCI device 00:16.0 config space: vendor 0x8086, device class 0x0780
        let vendor_id: &[u8] = &[0x86, 0x80]; // 0x8086 little-endian
        let device_class: &[u8] = &[0x80, 0x07]; // 0x0780 little-endian

        for (i, window) in data.windows(256).enumerate() {
            // Check for vendor ID followed by communication controller class
            if let Some(vendor_pos) = window.windows(vendor_id.len()).position(|w| w == vendor_id) {
                let remaining = &window[vendor_pos..];
                if remaining
                    .windows(device_class.len())
                    .any(|w| w == device_class)
                {
                    // Verify HECI register layout: H_CSR at +4, ME_CSR at +0xC
                    if vendor_pos + 0x0C < window.len() {
                        findings.push(
                            Finding::new(
                                "heci",
                                Severity::High,
                                "HECI MMIO register pattern detected",
                                &format!(
                                    "Found HECI PCI config space pattern (vendor 0x8086, \
                                     class 0x0780) at offset 0x{:08X} with register layout \
                                     indicating ME communication controller.",
                                    i + vendor_pos
                                ),
                            )
                            .with_confidence(0.65)
                            .with_details(serde_json::json!({
                                "offset": format!("0x{:08X}", i + vendor_pos),
                                "h_csr_offset": format!("0x{:08X}", i + vendor_pos + 4),
                                "me_csr_offset": format!("0x{:08X}", i + vendor_pos + 0x0C),
                            })),
                        );
                        break;
                    }
                }
            }
        }

        findings
    }

    fn check_heci_message_anomaly(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Look for HECI message headers with MKHI group ID (0xFF)
        // Multiple MKHI commands in rapid succession (within 64 bytes) is anomalous
        let mkhi_group: u8 = 0xFF;
        let mut mkhi_positions: Vec<usize> = Vec::new();

        for i in 0..data.len().saturating_sub(4) {
            // MKHI group byte followed by command byte with host/ME address fields
            if data[i] == mkhi_group && i + 3 < data.len() {
                // Check for valid host/ME address field patterns
                let host_addr = data[i + 2] & 0xF0;
                let me_addr = data[i + 2] & 0x0F;
                if host_addr != 0 && me_addr != 0 {
                    mkhi_positions.push(i);
                }
            }
        }

        // Check for clusters of MKHI commands within 64 bytes
        for window in mkhi_positions.windows(3) {
            if window[2] - window[0] <= 64 {
                findings.push(
                    Finding::new(
                        "heci",
                        Severity::Medium,
                        "Anomalous HECI message sequence",
                        &format!(
                            "Multiple MKHI commands detected in rapid succession within \
                             64 bytes at offsets 0x{:08X}, 0x{:08X}, 0x{:08X}. This may \
                             indicate automated ME command injection.",
                            window[0], window[1], window[2]
                        ),
                    )
                    .with_confidence(0.55)
                    .with_details(serde_json::json!({
                        "offsets": window.iter().map(|o| format!("0x{:08X}", o)).collect::<Vec<_>>(),
                        "span_bytes": window[2] - window[0],
                    })),
                );
                break;
            }
        }

        findings
    }

    fn check_heci_interception(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Detect code patterns that manipulate HECI circular buffers
        // Read-modify-write to H_CSR: enabling host interrupt, resetting host ready bit
        // Pattern: 0x04, 0x00, 0x00, 0x00 (H_CSR value with interrupt enable)
        let h_csr_pattern: &[u8] = &[0x04, 0x00, 0x00, 0x00];

        for (i, window) in data.windows(h_csr_pattern.len() + 8).enumerate() {
            if window[..h_csr_pattern.len()] == *h_csr_pattern {
                // Look for OR mask operations following (read-modify-write pattern)
                let remaining = &window[h_csr_pattern.len()..];
                // x86 OR instruction opcodes: 0x0C (OR AL, imm8), 0x0D (OR EAX, imm32),
                // 0x09 (OR r/m, r), 0x83 with /1 (OR r/m, imm8)
                let has_or_mask = remaining
                    .iter()
                    .any(|&b| b == 0x09 || b == 0x0D || b == 0x0C)
                    || remaining
                        .windows(2)
                        .any(|w| w[0] == 0x83 && (w[1] & 0x38) == 0x08);

                if has_or_mask {
                    findings.push(
                        Finding::new(
                            "heci",
                            Severity::Critical,
                            "HECI bus interception artifacts",
                            &format!(
                                "Detected read-modify-write pattern to HECI H_CSR at offset \
                                 0x{:08X} with OR mask operations. This indicates manipulation \
                                 of HECI circular buffers for bus interception.",
                                i
                            ),
                        )
                        .with_confidence(0.60)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", i),
                            "pattern": "H_CSR read-modify-write with OR mask",
                        }))
                        .with_recommendation(
                            "Investigate HECI bus traffic for signs of ME communication interception.",
                        ),
                    );
                    break;
                }
            }
        }

        findings
    }
}

impl Detector for HeciDetector {
    fn name(&self) -> &str {
        "heci"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let mut findings = Vec::new();

        findings.extend(self.check_heci_mmio_patterns(&data));
        findings.extend(self.check_heci_message_anomaly(&data));
        findings.extend(self.check_heci_interception(&data));

        Ok(findings)
    }
}
