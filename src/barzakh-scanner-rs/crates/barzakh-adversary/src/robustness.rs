//! Detector robustness benchmark: mutate payloads byte-by-byte and measure
//! how detection rates decay as the adversary perturbs the artifact.

use anyhow::Result;
use serde::Serialize;

use barzakh_core::BarzakhScanner;

use crate::harness::{mutate_payload, MutationStrategy};
use crate::{create_all_payloads, Payload, PayloadConfig};

/// Robustness result for one payload.
#[derive(Debug, Clone, Serialize)]
pub struct RobustnessEntry {
    pub payload: String,
    pub mutations: usize,
    pub detected: usize,
    /// Detection rate over mutated variants.
    pub detection_rate: f64,
}

/// Aggregate benchmark report.
#[derive(Debug, Clone, Serialize)]
pub struct RobustnessReport {
    pub entries: Vec<RobustnessEntry>,
    pub mutations_per_payload: usize,
    /// Mean detection rate across payloads.
    pub mean_detection_rate: f64,
}

/// Run the robustness benchmark over all (or the named) payloads.
///
/// For each payload: generate the artifact, apply random mutations, and
/// count how many mutated variants are still flagged as malicious. A
/// detection rate that decays sharply signals detectors brittle to trivial
/// evasion; healthy detectors keep a high rate under mutation.
pub fn benchmark(payload_filter: Option<&str>, mutations: usize) -> Result<RobustnessReport> {
    let mut scanner = BarzakhScanner::new(None);
    let payloads = create_all_payloads();
    let mut entries = Vec::new();

    let mut rng_state = 0xC0FF_EE01u64;
    let mut next = move || {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 7;
        rng_state ^= rng_state << 17;
        rng_state
    };

    for payload in &payloads {
        if let Some(filter) = payload_filter {
            if !payload.name().contains(filter) {
                continue;
            }
        }

        let config = PayloadConfig {
            arch: payload.arch(),
            size: 0x10000,
        };
        let original = payload.generate(&config)?;

        // Sanity: the pristine artifact must be detected.
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("payload.bin");
        std::fs::write(&path, &original)?;
        let pristine_detected = scanner.scan(&path, None).summary.bootkit_detected;
        drop(dir);
        if !pristine_detected {
            // Skip payloads that are not part of the detection corpus.
            continue;
        }

        let mut detected = 0usize;
        for _ in 0..mutations {
            let strategy = MutationStrategy::all()[next() as usize % MutationStrategy::all().len()];
            let mutated = mutate_payload(&original, strategy);
            let dir = tempfile::tempdir()?;
            let path = dir.path().join("mutated.bin");
            std::fs::write(&path, &mutated)?;
            if scanner.scan(&path, None).summary.bootkit_detected {
                detected += 1;
            }
        }

        entries.push(RobustnessEntry {
            payload: payload.name().to_string(),
            mutations,
            detected,
            detection_rate: detected as f64 / mutations as f64,
        });
    }

    let mean = if entries.is_empty() {
        0.0
    } else {
        entries.iter().map(|e| e.detection_rate).sum::<f64>() / entries.len() as f64
    };

    Ok(RobustnessReport {
        entries,
        mutations_per_payload: mutations,
        mean_detection_rate: mean,
    })
}

/// Touch the Payload trait so the import is exercised even when no filter
/// matches any payload.
#[allow(dead_code)]
fn _payload_trait_use(_p: &dyn Payload) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benchmark_runs_and_reports() {
        // A tiny run over one well-detected payload family.
        let report = benchmark(Some("blacklotus_mok"), 4).unwrap();
        if let Some(entry) = report.entries.first() {
            assert_eq!(entry.mutations, 4);
            assert!(entry.detection_rate >= 0.0 && entry.detection_rate <= 1.0);
        }
    }
}
