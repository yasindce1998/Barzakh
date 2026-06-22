use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const ENTROPY_THRESHOLD: f64 = 7.5;
const ENTROPY_WINDOW_SIZE: usize = 256;
const NVRAM_VAR_SIGNATURE: u16 = 0xAAF8;
const LARGE_VARIABLE_THRESHOLD: u32 = 32 * 1024; // 32KB

pub struct NvramEntropyDetector;

impl Default for NvramEntropyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl NvramEntropyDetector {
    pub fn new() -> Self {
        Self
    }

    fn calculate_shannon_entropy(window: &[u8]) -> f64 {
        let mut freq = [0u32; 256];
        for &byte in window {
            freq[byte as usize] += 1;
        }

        let len = window.len() as f64;
        let mut entropy = 0.0;
        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    fn check_variable_entropy(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if data.len() < ENTROPY_WINDOW_SIZE {
            return findings;
        }

        let mut high_entropy_regions = 0;
        let mut first_offset = 0;
        let mut max_entropy: f64 = 0.0;

        // Scan with non-overlapping windows for efficiency
        let mut offset = 0;
        while offset + ENTROPY_WINDOW_SIZE <= data.len() {
            let window = &data[offset..offset + ENTROPY_WINDOW_SIZE];
            let entropy = Self::calculate_shannon_entropy(window);

            if entropy > ENTROPY_THRESHOLD {
                if high_entropy_regions == 0 {
                    first_offset = offset;
                }
                high_entropy_regions += 1;
                if entropy > max_entropy {
                    max_entropy = entropy;
                }
            }
            offset += ENTROPY_WINDOW_SIZE;
        }

        if high_entropy_regions > 0 {
            findings.push(
                Finding::new(
                    "nvram_entropy",
                    Severity::High,
                    "High-entropy NVRAM variable detected (possible encrypted payload)",
                    &format!(
                        "Found {} high-entropy regions (>{:.1} bits/byte). First occurrence at \
                         offset 0x{:08X} with maximum entropy {:.2}. High entropy suggests \
                         encrypted or compressed data hidden in NVRAM.",
                        high_entropy_regions, ENTROPY_THRESHOLD, first_offset, max_entropy
                    ),
                )
                .with_confidence(0.65)
                .with_details(serde_json::json!({
                    "high_entropy_regions": high_entropy_regions,
                    "first_offset": format!("0x{:08X}", first_offset),
                    "max_entropy": format!("{:.4}", max_entropy),
                    "threshold": ENTROPY_THRESHOLD,
                }))
                .with_recommendation(
                    "Investigate high-entropy NVRAM regions for hidden payloads. \
                     Legitimate NVRAM variables typically have lower entropy.",
                ),
            );
        }

        findings
    }

    fn check_capsule_header_forgery(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // EFI Capsule Header structure:
        // - CapsuleGuid (16 bytes)
        // - HeaderSize (4 bytes)
        // - Flags (4 bytes)
        // - CapsuleImageSize (4 bytes)
        // Look for capsule GUID patterns followed by suspicious flags

        // EFI_FIRMWARE_MANAGEMENT_CAPSULE_ID_GUID
        let capsule_guid: [u8; 16] = [
            0xB9, 0x82, 0x05, 0x6B, 0xE2, 0x3E, 0xCE, 0x46, 0x99, 0x03, 0xD9, 0xA7, 0xB1, 0xB7,
            0x86, 0x00,
        ];

        for (i, window) in data.windows(28).enumerate() {
            if window[..16] == capsule_guid {
                let header_size = u32::from_le_bytes(window[16..20].try_into().unwrap_or([0; 4]));
                let flags = u32::from_le_bytes(window[20..24].try_into().unwrap_or([0; 4]));
                let image_size = u32::from_le_bytes(window[24..28].try_into().unwrap_or([0; 4]));

                // Suspicious: flags indicate no processing but large image size
                if flags == 0x00 && image_size > 0x10000 {
                    findings.push(
                        Finding::new(
                            "nvram_entropy",
                            Severity::Critical,
                            "Suspicious capsule update header detected",
                            &format!(
                                "EFI capsule header at offset 0x{:08X} has flags=0x{:08X} \
                                 (no processing) but declares ImageSize=0x{:08X} ({} KB). \
                                 This may indicate a forged capsule used to deliver a payload.",
                                i,
                                flags,
                                image_size,
                                image_size / 1024
                            ),
                        )
                        .with_confidence(0.70)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", i),
                            "header_size": format!("0x{:08X}", header_size),
                            "flags": format!("0x{:08X}", flags),
                            "image_size": format!("0x{:08X}", image_size),
                        }))
                        .with_recommendation(
                            "Validate capsule header integrity and verify the capsule \
                             payload against known-good firmware updates.",
                        ),
                    );
                }
            }
        }

        findings
    }

    fn check_variable_size_anomaly(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Look for NVRAM variable headers identified by 0xAAF8 signature
        // (authenticated variable header signature)
        let sig_bytes = NVRAM_VAR_SIGNATURE.to_le_bytes();

        for (i, window) in data.windows(2).enumerate() {
            if window == sig_bytes {
                // After signature, variable header contains:
                // State (1 byte), Reserved (1 byte), Attributes (4 bytes),
                // MonotonicCount (8 bytes), TimeStamp (16 bytes),
                // PubKeyIndex (4 bytes), NameSize (4 bytes), DataSize (4 bytes)
                let data_size_offset = i + 2 + 1 + 1 + 4 + 8 + 16 + 4 + 4;
                if data_size_offset + 4 > data.len() {
                    continue;
                }

                let data_size = u32::from_le_bytes(
                    data[data_size_offset..data_size_offset + 4]
                        .try_into()
                        .unwrap_or([0; 4]),
                );

                if data_size > LARGE_VARIABLE_THRESHOLD && data_size < 0x1000000 {
                    findings.push(
                        Finding::new(
                            "nvram_entropy",
                            Severity::Medium,
                            "Oversized NVRAM variable detected",
                            &format!(
                                "NVRAM variable at offset 0x{:08X} declares DataSize={} bytes \
                                 ({} KB). Normal boot variables are typically under 32KB. \
                                 Oversized variables may contain hidden payloads.",
                                i,
                                data_size,
                                data_size / 1024
                            ),
                        )
                        .with_confidence(0.55)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", i),
                            "data_size": data_size,
                            "threshold": LARGE_VARIABLE_THRESHOLD,
                        })),
                    );
                }
            }
        }

        findings
    }
}

impl Detector for NvramEntropyDetector {
    fn name(&self) -> &str {
        "nvram_entropy"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let mut findings = Vec::new();

        findings.extend(self.check_variable_entropy(&data));
        findings.extend(self.check_capsule_header_forgery(&data));
        findings.extend(self.check_variable_size_anomaly(&data));

        Ok(findings)
    }
}
