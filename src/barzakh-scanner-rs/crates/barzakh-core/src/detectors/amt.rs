use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

pub struct AmtDetector;

impl Default for AmtDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AmtDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_amt_provisioning(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Scan for AMT provisioning state artifacts
        // AMT state machine value 0x03 = fully provisioned
        // Near PCI config space for device 00:16.3 (vendor 0x8086)
        let vendor_id: &[u8] = &[0x86, 0x80]; // 0x8086 little-endian
        let provisioned_state: u8 = 0x03;

        // Single pass over vendor-ID positions (instead of a 64-byte window
        // scan per offset, which is O(n*64) on large images). The
        // provisioning state and the 00:16.3 device marker must appear
        // within 64 bytes after the vendor ID.
        let mut i = 0;
        while i + 2 <= data.len() {
            if data[i] == vendor_id[0] && data[i + 1] == vendor_id[1] {
                let end = (i + 64).min(data.len());
                for j in i..end {
                    if data[j] == provisioned_state {
                        // Verify context: look for additional AMT indicators
                        // (device 16, function 3) after the state byte.
                        let has_amt_context = data[j..end].windows(2).any(|w| w == [0x16, 0x03]);

                        if has_amt_context {
                            findings.push(
                                Finding::new(
                                    "amt",
                                    Severity::Medium,
                                    "AMT provisioning state artifacts detected",
                                    &format!(
                                        "Found AMT provisioning state (0x03 = fully provisioned) \
                                         near PCI device 00:16.3 config space at offset 0x{:08X}. \
                                         AMT is active and provisioned on this platform.",
                                        j
                                    ),
                                )
                                .with_confidence(0.55)
                                .with_details(serde_json::json!({
                                    "offset": format!("0x{:08X}", j),
                                    "provisioning_state": "0x03 (fully provisioned)",
                                    "pci_device": "00:16.3",
                                }))
                                .with_recommendation(
                                    "Verify AMT provisioning is intentional and properly secured.",
                                ),
                            );
                            return findings;
                        }
                    }
                }
            }
            i += 1;
        }

        findings
    }

    fn check_sol_channel_signatures(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Detect SOL (Serial-over-LAN) channel setup patterns
        // SOL RECV/SEND control register manipulation (writes to offsets 0x00 and 0x04 from SOL BAR)
        // Look for pairs of register writes to adjacent offsets

        for i in 0..data.len().saturating_sub(16) {
            // Look for patterns indicating SOL BAR register access
            // Typical pattern: write to BAR+0x00 (RECV), then BAR+0x04 (SEND)
            let has_recv_pattern = i + 8 <= data.len()
                && data[i] != 0x00
                && data[i + 1] == 0x00
                && data[i + 2] == 0x00
                && data[i + 3] == 0x00;

            if has_recv_pattern {
                let has_send_pattern = i + 8 <= data.len()
                    && data[i + 4] != 0x00
                    && data[i + 5] == 0x00
                    && data[i + 6] == 0x00
                    && data[i + 7] == 0x00;

                if has_send_pattern {
                    // Check for SOL-related context: port 16994/16995 or "SOL" string nearby
                    let context_start = i.saturating_sub(64);
                    let context_end = (i + 128).min(data.len());
                    let context = &data[context_start..context_end];

                    let has_sol_port = context.windows(2).any(|w| {
                        // Port 16994 = 0x4266, Port 16995 = 0x4267
                        w == [0x66, 0x42] || w == [0x67, 0x42]
                    });

                    let has_sol_string = context.windows(3).any(|w| w == b"SOL");

                    if has_sol_port || has_sol_string {
                        findings.push(
                            Finding::new(
                                "amt",
                                Severity::High,
                                "AMT SOL channel activation detected",
                                &format!(
                                    "SOL control register manipulation pattern detected at \
                                     offset 0x{:08X}. RECV and SEND registers are being \
                                     configured, indicating Serial-over-LAN channel activation.",
                                    i
                                ),
                            )
                            .with_confidence(0.60)
                            .with_details(serde_json::json!({
                                "offset": format!("0x{:08X}", i),
                                "sol_port_reference": has_sol_port,
                                "sol_string_reference": has_sol_string,
                            }))
                            .with_recommendation(
                                "Investigate SOL channel usage. Unauthorized SOL activation \
                                 may indicate covert out-of-band communication.",
                            ),
                        );
                        return findings;
                    }
                }
            }
        }

        findings
    }

    fn check_platinum_apt_iocs(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Search for known Platinum APT group IOCs related to AMT abuse
        // Pattern: "SOL\x00" followed within 256 bytes by command-structure bytes
        let sol_marker: &[u8] = b"SOL\x00";

        for (i, window) in data.windows(sol_marker.len()).enumerate() {
            if window == sol_marker {
                // Look within next 256 bytes for command structure bytes
                let search_end = (i + sol_marker.len() + 256).min(data.len());
                let search_region = &data[i + sol_marker.len()..search_end];

                // Command IDs: 0x01 = beacon, 0x02 = exec, 0x03 = exfil
                let has_beacon = search_region.contains(&0x01);
                let has_exec = search_region.contains(&0x02);
                let has_exfil = search_region.contains(&0x03);

                // Need at least two of the three command types for a match
                let command_count = has_beacon as u8 + has_exec as u8 + has_exfil as u8;

                if command_count >= 2 {
                    findings.push(
                        Finding::new(
                            "amt",
                            Severity::Critical,
                            "Platinum APT AMT/SOL indicators detected",
                            &format!(
                                "SOL marker at offset 0x{:08X} followed by Platinum APT \
                                 command structure bytes (beacon={}, exec={}, exfil={}) \
                                 within 256 bytes. Matches known Platinum APT IOCs for \
                                 AMT/SOL-based covert channel.",
                                i, has_beacon, has_exec, has_exfil
                            ),
                        )
                        .with_confidence(0.70)
                        .with_details(serde_json::json!({
                            "sol_marker_offset": format!("0x{:08X}", i),
                            "command_beacon": has_beacon,
                            "command_exec": has_exec,
                            "command_exfil": has_exfil,
                            "apt_group": "Platinum",
                        }))
                        .with_recommendation(
                            "CRITICAL: Platinum APT indicators detected. Isolate system \
                             immediately and perform full forensic analysis. Disable AMT \
                             at firmware level.",
                        ),
                    );
                    return findings;
                }
            }
        }

        findings
    }
}

impl Detector for AmtDetector {
    fn name(&self) -> &str {
        "amt"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let mut findings = Vec::new();

        findings.extend(self.check_amt_provisioning(&data));
        findings.extend(self.check_sol_channel_signatures(&data));
        findings.extend(self.check_platinum_apt_iocs(&data));

        Ok(findings)
    }
}
