//! Isolation-forest anomaly detection over firmware feature vectors.

use serde::{Deserialize, Serialize};
use std::path::Path;

use barzakh_core::{Detector, DetectorError, Finding, Severity};

use crate::features::FirmwareFeatures;

/// A single isolation tree (random binary splits on random features).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IsolationTree {
    /// Split feature index, or None for a leaf.
    feature: Option<usize>,
    threshold: f64,
    left: Option<Box<IsolationTree>>,
    right: Option<Box<IsolationTree>>,
}

impl IsolationTree {
    fn build(samples: &[Vec<f64>], depth: u32, max_depth: u32, rng: &mut Rng) -> Self {
        if samples.len() <= 1 || depth >= max_depth || samples[0].is_empty() {
            return Self {
                feature: None,
                threshold: 0.0,
                left: None,
                right: None,
            };
        }
        let dims = samples[0].len();
        let feature = (rng.next() % dims as u64) as usize;

        let mut min = f64::MAX;
        let mut max = f64::MIN;
        for s in samples {
            min = min.min(s[feature]);
            max = max.max(s[feature]);
        }
        if (max - min).abs() < 1e-12 {
            return Self {
                feature: None,
                threshold: 0.0,
                left: None,
                right: None,
            };
        }
        let t = (rng.next() % 10_000) as f64 / 10_000.0;
        let threshold = min + t * (max - min);

        let (mut left, mut right) = (Vec::new(), Vec::new());
        for s in samples {
            if s[feature] < threshold {
                left.push(s.clone());
            } else {
                right.push(s.clone());
            }
        }
        if left.is_empty() || right.is_empty() {
            return Self {
                feature: None,
                threshold: 0.0,
                left: None,
                right: None,
            };
        }

        Self {
            feature: Some(feature),
            threshold,
            left: Some(Box::new(Self::build(&left, depth + 1, max_depth, rng))),
            right: Some(Box::new(Self::build(&right, depth + 1, max_depth, rng))),
        }
    }

    fn path_length(&self, sample: &[f64]) -> f64 {
        let mut node = self;
        let mut depth = 0u32;
        while let Some(feature) = node.feature {
            let next = if sample[feature] < node.threshold {
                node.left.as_deref()
            } else {
                node.right.as_deref()
            };
            match next {
                Some(child) => {
                    node = child;
                    depth += 1;
                }
                None => break,
            }
        }
        depth as f64
    }
}

/// Tiny deterministic xorshift RNG (keeps the crate dependency-free).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

/// Isolation forest anomaly detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationForest {
    trees: Vec<IsolationTree>,
    /// Subsample size used per tree.
    subsample_size: usize,
    /// Normalization factor (harmonic number of the subsample size).
    normalizer: f64,
    /// Per-feature `[min, max]` observed in training, used for an
    /// out-of-range penalty blended into the score. Empty for models
    /// trained before ranges were tracked (no penalty applied).
    #[serde(default)]
    feature_ranges: Vec<(f64, f64)>,
}

/// Weight of the out-of-range penalty blended into the anomaly score.
const RANGE_PENALTY_WEIGHT: f64 = 0.8;

fn harmonic(n: u64) -> f64 {
    (n as f64).ln() + std::f64::consts::EULER_GAMMA
}

impl IsolationForest {
    /// Train a forest of `n_trees` with the given subsample size.
    pub fn fit(samples: &[Vec<f64>], n_trees: usize, subsample_size: usize, seed: u64) -> Self {
        let subsample_size = subsample_size.max(2).min(samples.len().max(2));
        let max_depth = (subsample_size as f64).log2().ceil() as u32 + 2;
        let mut rng = Rng(seed.max(1));

        let mut trees = Vec::with_capacity(n_trees);
        for _ in 0..n_trees {
            let mut subsample: Vec<Vec<f64>> = Vec::with_capacity(subsample_size);
            for _ in 0..subsample_size {
                let idx = (rng.next() % samples.len() as u64) as usize;
                subsample.push(samples[idx].clone());
            }
            trees.push(IsolationTree::build(&subsample, 0, max_depth, &mut rng));
        }

        // Track the observed feature envelope for the out-of-range penalty.
        let dims = samples.first().map(|s| s.len()).unwrap_or(0);
        let mut feature_ranges = Vec::with_capacity(dims);
        for d in 0..dims {
            let mut min = f64::MAX;
            let mut max = f64::MIN;
            for s in samples {
                min = min.min(s[d]);
                max = max.max(s[d]);
            }
            feature_ranges.push((min, max));
        }

        Self {
            trees,
            subsample_size,
            normalizer: harmonic(subsample_size as u64),
            feature_ranges,
        }
    }

    /// Anomaly score in 0..1 — values close to 1 indicate anomalies, close
    /// to 0.5 indicate normal samples.
    ///
    /// The score blends the classic isolation path-length score with a
    /// penalty for features that fall outside the training envelope: pure
    /// path-length scoring cannot distinguish points beyond the training
    /// range (random blobs, all-zero images) from in-distribution samples,
    /// because splits never isolate them further than the boundary.
    pub fn anomaly_score(&self, sample: &[f64]) -> f64 {
        if self.trees.is_empty() {
            return 0.5;
        }
        let avg_length: f64 = self
            .trees
            .iter()
            .map(|t| t.path_length(sample))
            .sum::<f64>()
            / self.trees.len() as f64;
        let base = 2f64.powf(-avg_length / self.normalizer);

        // Fraction of ranged features outside the training envelope
        // (with a 5%-of-range tolerance band).
        let mut ranged = 0usize;
        let mut outside = 0usize;
        for (d, &(min, max)) in self.feature_ranges.iter().enumerate() {
            if d >= sample.len() || (max - min).abs() < 1e-12 {
                continue;
            }
            ranged += 1;
            let tolerance = (max - min) * 0.05;
            if sample[d] < min - tolerance || sample[d] > max + tolerance {
                outside += 1;
            }
        }
        if ranged == 0 {
            return base;
        }
        let penalty = (outside as f64 / ranged as f64) * RANGE_PENALTY_WEIGHT;
        (base + penalty * (1.0 - base)).min(1.0)
    }
}

/// Scanning threshold — above this score a firmware image is anomalous.
pub const ANOMALY_THRESHOLD: f64 = 0.72;

/// Scanner detector backed by an isolation forest trained on synthetic
/// clean-firmware feature profiles.
///
/// The default model is trained on synthetic distributions that mimic
/// well-formed firmware (low-entropy headers, moderate printable ratios,
/// zero-heavy padding, occasional PE/FV signatures) — enough to separate the
/// statistically-weird structures typical of implants from ordinary images.
pub struct MlAnomalyDetector {
    forest: IsolationForest,
}

impl MlAnomalyDetector {
    /// Train the default model (deterministic seed).
    pub fn with_default_model() -> Self {
        let clean_profiles = synthetic_clean_profiles();
        Self {
            forest: IsolationForest::fit(&clean_profiles, 32, 64, 0x0B42_A2C7),
        }
    }

    pub fn with_forest(forest: IsolationForest) -> Self {
        Self { forest }
    }

    pub fn forest(&self) -> &IsolationForest {
        &self.forest
    }
}

impl Default for MlAnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MlAnomalyDetector {
    pub fn new() -> Self {
        Self::with_default_model()
    }
}

/// Deterministic synthetic clean-firmware feature profiles.
///
/// The distributions model the span of well-formed firmware images: from
/// zero-padded golden images (near-zero entropy, huge zero runs, few
/// strings) to code-dense compressed updates (high entropy, many PE/FV
/// signatures).
pub fn synthetic_clean_profiles() -> Vec<Vec<f64>> {
    let mut profiles = Vec::new();
    let mut state = 0x5EED_1234u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for i in 0..256 {
        let t = i as f64 / 256.0;
        let jitter = (next() % 1000) as f64 / 1000.0 * 0.05;
        // Clean firmware spans zero-heavy golden images to dense updates:
        // entropy 0.005..7.2 bits/byte, printable 0.001..0.45,
        // zero ratio 0.02..0.999, occasional PEs/FVs, run lengths up to
        // tens of kilobytes of padding, up to a thousand strings.
        let features = FirmwareFeatures {
            size_bytes: (1u64 << 14) << (next() % 4),
            entropy: 0.005 + t * 7.195 + jitter,
            printable_ratio: 0.001 + t * 0.44 + jitter * 0.2,
            zero_ratio: 0.02 + (1.0 - t) * 0.979,
            mz_count: next() % 16,
            fvh_count: next() % 8,
            max_run_length: 16 + next() % 65536,
            high_entropy_window: next() % 64,
            string_count: 1 + next() % 1000,
        };
        profiles.push(features.to_vector());
    }
    profiles
}

impl Detector for MlAnomalyDetector {
    fn name(&self) -> &str {
        "ml_anomaly"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let features = FirmwareFeatures::extract(&data);
        let score = self.forest.anomaly_score(&features.to_vector());

        if score < ANOMALY_THRESHOLD {
            return Ok(Vec::new());
        }

        Ok(vec![Finding::new(
            "ml_anomaly",
            Severity::Medium,
            "Statistically anomalous firmware structure",
            &format!(
                "Isolation-forest anomaly score {score:.3} exceeds the {ANOMALY_THRESHOLD} \
                 threshold. The image's structural profile (entropy {:.2}, printable ratio \
                 {:.2}, zero ratio {:.2}, {} PE signatures) is a strong outlier relative to \
                 well-formed firmware.",
                features.entropy, features.printable_ratio, features.zero_ratio, features.mz_count,
            ),
        )
        .with_confidence(0.5 + ((score - ANOMALY_THRESHOLD).clamp(0.0, 0.25) / 0.25) * 0.4)
        .with_details(serde_json::json!({
            "anomaly_score": score,
            "threshold": ANOMALY_THRESHOLD,
            "features": features,
        }))
        .with_recommendation(
            "Triage manually: compare against a vendor-known-good image and run the \
             full detector suite; anomalies may indicate packed/encrypted implants.",
        )])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_profiles_score_low() {
        let detector = MlAnomalyDetector::with_default_model();
        // Typical clean firmware: zero-padded image with header strings.
        let mut data = b"UEFI FIRMWARE IMAGE header strings here...".to_vec();
        data.extend_from_slice(&[0u8; 32768]);
        let features = FirmwareFeatures::extract(&data);
        let score = detector.forest.anomaly_score(&features.to_vector());
        assert!(
            score < ANOMALY_THRESHOLD,
            "clean-ish firmware scored {score:.3} >= {ANOMALY_THRESHOLD}"
        );
    }

    #[test]
    fn uniform_random_blob_scores_high() {
        let detector = MlAnomalyDetector::with_default_model();
        let mut state = 0xFEEDu64;
        let data: Vec<u8> = (0..16384)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state & 0xFF) as u8
            })
            .collect();
        let features = FirmwareFeatures::extract(&data);
        let score = detector.forest.anomaly_score(&features.to_vector());
        assert!(
            score > 0.60,
            "random blob scored only {score:.3} — expected high"
        );
    }

    #[test]
    fn forest_fit_runs_and_scores_deterministically() {
        let profiles = synthetic_clean_profiles();
        let a = IsolationForest::fit(&profiles, 8, 16, 42);
        let b = IsolationForest::fit(&profiles, 8, 16, 42);
        let sample = profiles[0].clone();
        assert!((a.anomaly_score(&sample) - b.anomaly_score(&sample)).abs() < 1e-12);
    }

    #[test]
    fn score_bounds() {
        let profiles = synthetic_clean_profiles();
        let forest = IsolationForest::fit(&profiles, 16, 32, 7);
        for p in &profiles {
            let s = forest.anomaly_score(p);
            assert!((0.0..=1.0).contains(&s), "score out of range: {s}");
        }
    }
}
