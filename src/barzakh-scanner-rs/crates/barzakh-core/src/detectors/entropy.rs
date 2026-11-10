use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const HIGH_ENTROPY_THRESHOLD: f64 = 7.5;
const LOW_ENTROPY_THRESHOLD: f64 = 1.0;
const DEFAULT_WINDOW_SIZE: usize = 256;
const DEFAULT_BLOCK_SIZE: usize = 4096;

pub struct EntropyAnalyzer {
    window_size: usize,
    block_size: usize,
}

impl Default for EntropyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl EntropyAnalyzer {
    pub fn new() -> Self {
        Self {
            window_size: DEFAULT_WINDOW_SIZE,
            block_size: DEFAULT_BLOCK_SIZE,
        }
    }

    pub fn with_params(window_size: usize, block_size: usize) -> Self {
        Self {
            window_size,
            block_size,
        }
    }

    fn shannon_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut freq = [0u64; 256];
        for &byte in data {
            freq[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    fn analyze_blocks(&self, data: &[u8]) -> Vec<(usize, f64)> {
        let mut results = Vec::new();

        for (i, chunk) in data.chunks(self.block_size).enumerate() {
            let entropy = Self::shannon_entropy(chunk);
            results.push((i * self.block_size, entropy));
        }

        results
    }

    fn sliding_window_analysis(&self, data: &[u8]) -> Vec<(usize, f64)> {
        let mut anomalies = Vec::new();

        if data.len() < self.window_size {
            return anomalies;
        }

        let mut prev_entropy = Self::shannon_entropy(&data[..self.window_size]);

        let step = self.window_size / 2;
        let mut offset = step;

        while offset + self.window_size <= data.len() {
            let entropy = Self::shannon_entropy(&data[offset..offset + self.window_size]);

            // Detect sudden entropy transitions (encryption/packing boundaries)
            let delta = (entropy - prev_entropy).abs();
            if delta > 3.0 {
                anomalies.push((offset, entropy));
            }

            prev_entropy = entropy;
            offset += step;
        }

        anomalies
    }
}

impl Detector for EntropyAnalyzer {
    fn name(&self) -> &str {
        "entropy"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let mut findings = Vec::new();

        let block_results = self.analyze_blocks(&data);

        // Detect high-entropy regions (likely encrypted/compressed/packed)
        let high_entropy_blocks: Vec<_> = block_results
            .iter()
            .filter(|(_, e)| *e >= HIGH_ENTROPY_THRESHOLD)
            .collect();

        if !high_entropy_blocks.is_empty() {
            let ratio = high_entropy_blocks.len() as f64 / block_results.len() as f64;

            if ratio > 0.5 {
                findings.push(
                    Finding::new(
                        "entropy",
                        Severity::Medium,
                        "Majority of firmware is encrypted/packed",
                        &format!(
                            "{:.1}% of blocks have entropy >= {:.1} bits/byte. \
                             The image is largely compressed or encrypted. Legitimate \
                             firmware commonly ships compressed firmware volumes \
                             (e.g. FVMAIN_COMPACT), so this alone is not an indicator \
                             of compromise; use it to locate regions that other \
                             detectors cannot parse.",
                            ratio * 100.0,
                            HIGH_ENTROPY_THRESHOLD
                        ),
                    )
                    .with_confidence(0.80)
                    .with_details(serde_json::json!({
                        "high_entropy_ratio": ratio,
                        "high_entropy_blocks": high_entropy_blocks.len(),
                        "total_blocks": block_results.len(),
                        "threshold": HIGH_ENTROPY_THRESHOLD,
                    })),
                );
            } else if high_entropy_blocks.len() >= 3 {
                findings.push(
                    Finding::new(
                        "entropy",
                        Severity::Medium,
                        "Encrypted/packed regions detected in firmware",
                        &format!(
                            "{} blocks with high entropy (>= {:.1}) detected. \
                             These regions may contain encrypted payloads.",
                            high_entropy_blocks.len(),
                            HIGH_ENTROPY_THRESHOLD
                        ),
                    )
                    .with_confidence(0.65)
                    .with_details(serde_json::json!({
                        "count": high_entropy_blocks.len(),
                        "offsets": high_entropy_blocks.iter()
                            .take(10)
                            .map(|(off, ent)| serde_json::json!({"offset": format!("0x{:08X}", off), "entropy": ent}))
                            .collect::<Vec<_>>(),
                    })),
                );
            }
        }

        // Detect anomalous entropy transitions (packing boundaries)
        let transitions = self.sliding_window_analysis(&data);
        if transitions.len() >= 2 {
            findings.push(
                Finding::new(
                    "entropy",
                    Severity::Medium,
                    "Sharp entropy transitions detected",
                    &format!(
                        "{} sudden entropy transitions found, indicating possible \
                         encryption/compression boundaries within the firmware.",
                        transitions.len()
                    ),
                )
                .with_confidence(0.60)
                .with_details(serde_json::json!({
                    "transition_count": transitions.len(),
                    "transitions": transitions.iter()
                        .take(5)
                        .map(|(off, ent)| serde_json::json!({"offset": format!("0x{:08X}", off), "entropy": ent}))
                        .collect::<Vec<_>>(),
                })),
            );
        }

        // Detect suspiciously uniform low-entropy regions (potential NOP sleds)
        let low_entropy_blocks: Vec<_> = block_results
            .iter()
            .filter(|(_, e)| *e <= LOW_ENTROPY_THRESHOLD && *e > 0.0)
            .collect();

        if low_entropy_blocks.len() >= 4 {
            findings.push(
                Finding::new(
                    "entropy",
                    Severity::Low,
                    "Large low-entropy regions detected",
                    &format!(
                        "{} blocks with very low entropy (<= {:.1}) found. \
                         May indicate NOP sleds or padding used for code injection.",
                        low_entropy_blocks.len(),
                        LOW_ENTROPY_THRESHOLD
                    ),
                )
                .with_confidence(0.40)
                .with_details(serde_json::json!({
                    "count": low_entropy_blocks.len(),
                    "offsets": low_entropy_blocks.iter()
                        .take(10)
                        .map(|(off, ent)| serde_json::json!({"offset": format!("0x{:08X}", off), "entropy": ent}))
                        .collect::<Vec<_>>(),
                })),
            );
        }

        Ok(findings)
    }
}
