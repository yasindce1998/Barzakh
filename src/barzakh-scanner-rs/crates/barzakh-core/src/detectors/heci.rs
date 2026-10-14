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

        // Single pass over vendor-ID positions (instead of a 256-byte
        // window scan per offset, which is O(n*256) on large images).
        // A finding requires the class code within 256 bytes after the
        // vendor ID — identical to the historical window semantics.
        let mut i = 0;
        while i + 2 <= data.len() {
            if data[i] == vendor_id[0] && data[i + 1] == vendor_id[1] {
                let end = (i + 256).min(data.len());
                if data[i + 1..end].windows(2).any(|w| w == device_class) {
                    findings.push(
                        Finding::new(
                            "heci",
                            Severity::High,
                            "HECI MMIO register pattern detected",
                            &format!(
                                "Found HECI PCI config space pattern (vendor 0x8086, \
                                 class 0x0780) at offset 0x{:08X} with register layout \
                                 indicating ME communication controller.",
                                i
                            ),
                        )
                        .with_confidence(0.65)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", i),
                            "h_csr_offset": format!("0x{:08X}", i + 4),
                            "me_csr_offset": format!("0x{:08X}", i + 0x0C),
                        })),
                    );
                    break;
                }
            }
            i += 1;
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

        // Collect candidate RMW sites first. A lone `u32 == 4` followed by
        // an `OR r/m32, imm8` (0x83 /1) occurs by chance in compressed
        // firmware volumes; an interception routine performs the
        // read-modify-write repeatedly, so a finding requires a cluster of
        // at least two sites within a small window.
        let mut sites: Vec<usize> = Vec::new();
        for i in 0..data.len().saturating_sub(h_csr_pattern.len() + 8) {
            if data[i..i + h_csr_pattern.len()] != *h_csr_pattern {
                continue;
            }
            let remaining = &data[i + h_csr_pattern.len()..i + h_csr_pattern.len() + 8];
            // The canonical read-modify-write on H_CSR is
            // `OR r/m32, imm8` (0x83 /1). Single-byte OR opcodes
            // (0x09/0x0C/0x0D) occur too often in ordinary code and
            // data to be trusted as an RMW signature.
            let has_or_mask = remaining
                .windows(2)
                .any(|w| w[0] == 0x83 && (w[1] & 0x38) == 0x08);
            if has_or_mask {
                sites.push(i);
            }
        }

        // An interception routine performs the read-modify-write
        // repeatedly: a finding requires at least three sites within a
        // 64-byte window. Pairs of coincidental sites occur in ordinary
        // code; triples essentially never do.
        let clustered = sites
            .windows(3)
            .find(|w| w[2] - w[0] <= 64)
            .map(|w| (w[0], w[1], w[2]));
        if let Some((i, second, third)) = clustered {
            findings.push(
                Finding::new(
                    "heci",
                    Severity::Critical,
                    "HECI bus interception artifacts",
                    &format!(
                        "Detected repeated read-modify-write pattern to HECI H_CSR at offsets \
                         0x{:08X}, 0x{:08X} and 0x{:08X} with OR mask operations. This indicates \
                         manipulation of HECI circular buffers for bus interception.",
                        i, second, third
                    ),
                )
                .with_confidence(0.60)
                .with_details(serde_json::json!({
                    "offset": format!("0x{:08X}", i),
                    "second_offset": format!("0x{:08X}", second),
                    "third_offset": format!("0x{:08X}", third),
                    "pattern": "H_CSR read-modify-write with OR mask",
                }))
                .with_recommendation(
                    "Investigate HECI bus traffic for signs of ME communication interception.",
                ),
            );
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
