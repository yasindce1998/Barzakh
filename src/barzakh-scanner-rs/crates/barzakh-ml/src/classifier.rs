//! Logistic-regression malicious/benign classifier over firmware features.
//!
//! Trained with plain gradient descent on labeled feature vectors; the model
//! serializes to JSON so it can be shipped between the training CLI and the
//! evaluation/scanning paths.

use serde::{Deserialize, Serialize};

use crate::features::FirmwareFeatures;

/// A trained logistic-regression model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogisticModel {
    /// Feature weights.
    pub weights: Vec<f64>,
    /// Bias term.
    pub bias: f64,
    /// Training metadata.
    pub trained_on: usize,
    pub epochs: usize,
    pub final_loss: f64,
}

/// Training hyperparameters.
#[derive(Debug, Clone)]
pub struct TrainConfig {
    pub epochs: usize,
    pub learning_rate: f64,
    pub l2: f64,
}

impl Default for TrainConfig {
    fn default() -> Self {
        Self {
            epochs: 400,
            learning_rate: 0.15,
            l2: 0.001,
        }
    }
}

fn sigmoid(z: f64) -> f64 {
    if z >= 0.0 {
        1.0 / (1.0 + (-z).exp())
    } else {
        let e = z.exp();
        e / (1.0 + e)
    }
}

/// A labeled training sample.
#[derive(Debug, Clone)]
pub struct LabeledSample {
    pub features: Vec<f64>,
    pub malicious: bool,
}

impl LogisticModel {
    /// Train a model on labeled samples.
    pub fn train(samples: &[LabeledSample], config: &TrainConfig) -> Self {
        let dims = samples
            .iter()
            .map(|s| s.features.len())
            .max()
            .unwrap_or(FirmwareFeatures::FEATURE_NAMES.len());
        let mut weights = vec![0.0f64; dims];
        let mut bias = 0.0;

        let mut final_loss = 0.0;
        for _ in 0..config.epochs {
            let mut grad_w = vec![0.0f64; dims];
            let mut grad_b = 0.0;
            let mut loss = 0.0;

            for sample in samples {
                let mut z = bias;
                for (i, &x) in sample.features.iter().enumerate() {
                    z += weights[i] * x;
                }
                let p = sigmoid(z);
                let y = if sample.malicious { 1.0 } else { 0.0 };
                let err = p - y;
                loss -= y * p.ln() + (1.0 - y) * (1.0 - p).ln();
                for (i, &x) in sample.features.iter().enumerate() {
                    grad_w[i] += err * x;
                }
                grad_b += err;
            }

            let n = samples.len().max(1) as f64;
            for i in 0..dims {
                grad_w[i] = grad_w[i] / n + config.l2 * weights[i];
                weights[i] -= config.learning_rate * grad_w[i];
            }
            bias -= config.learning_rate * (grad_b / n);
            final_loss = loss / n;
        }

        Self {
            weights,
            bias,
            trained_on: samples.len(),
            epochs: config.epochs,
            final_loss,
        }
    }

    /// Probability that a feature vector is malicious (0..1).
    pub fn predict(&self, features: &[f64]) -> f64 {
        let mut z = self.bias;
        for (i, &x) in features.iter().enumerate() {
            if i < self.weights.len() {
                z += self.weights[i] * x;
            }
        }
        sigmoid(z)
    }

    /// Save the model as JSON.
    pub fn save(&self, path: &std::path::Path) -> anyhow::Result<()> {
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    /// Load a model from JSON.
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
    }
}

/// Classification outcome with explanation.
#[derive(Debug, Clone, Serialize)]
pub struct Classification {
    pub malicious_probability: f64,
    pub verdict: &'static str,
    /// Top contributing features (name, weight × value).
    pub contributions: Vec<(String, f64)>,
}

impl Classification {
    pub fn from_model(model: &LogisticModel, features: &FirmwareFeatures) -> Self {
        let vector = features.to_vector();
        let probability = model.predict(&vector);

        let mut contributions: Vec<(String, f64)> = vector
            .iter()
            .zip(&model.weights)
            .enumerate()
            .map(|(i, (&x, &w))| (FirmwareFeatures::FEATURE_NAMES[i].to_string(), w * x))
            .collect();
        contributions.sort_by(|a, b| b.1.abs().partial_cmp(&a.1.abs()).unwrap());
        contributions.truncate(5);

        Self {
            malicious_probability: probability,
            verdict: if probability > 0.7 {
                "malicious"
            } else if probability > 0.4 {
                "suspicious"
            } else {
                "benign"
            },
            contributions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_samples() -> Vec<LabeledSample> {
        // Malicious: high entropy, tiny printable ratio, high mz count.
        // Benign: low entropy, moderate printable ratio, zero heavy.
        let mut samples = Vec::new();
        for i in 0..60 {
            let t = i as f64 / 60.0;
            let clean = FirmwareFeatures {
                size_bytes: 1 << 16,
                entropy: 4.0 + t * 2.0,
                printable_ratio: 0.1 + t * 0.25,
                zero_ratio: 0.4 + (1.0 - t) * 0.4,
                mz_count: 1,
                fvh_count: 1,
                max_run_length: 1024,
                high_entropy_window: 2,
                string_count: 200,
            };
            let malicious = FirmwareFeatures {
                size_bytes: 1 << 16,
                entropy: 7.2 + t * 0.5,
                printable_ratio: 0.01,
                zero_ratio: 0.01,
                mz_count: 12,
                fvh_count: 0,
                max_run_length: 4,
                high_entropy_window: 40,
                string_count: 2,
            };
            samples.push(LabeledSample {
                features: clean.to_vector(),
                malicious: false,
            });
            samples.push(LabeledSample {
                features: malicious.to_vector(),
                malicious: true,
            });
        }
        samples
    }

    #[test]
    fn learns_separable_classes() {
        let samples = synthetic_samples();
        let model = LogisticModel::train(&samples, &TrainConfig::default());

        let clean = FirmwareFeatures {
            size_bytes: 1 << 16,
            entropy: 5.0,
            printable_ratio: 0.2,
            zero_ratio: 0.6,
            mz_count: 1,
            fvh_count: 1,
            max_run_length: 2048,
            high_entropy_window: 1,
            string_count: 150,
        };
        let malicious = FirmwareFeatures {
            size_bytes: 1 << 16,
            entropy: 7.6,
            printable_ratio: 0.01,
            zero_ratio: 0.01,
            mz_count: 15,
            fvh_count: 0,
            max_run_length: 3,
            high_entropy_window: 45,
            string_count: 1,
        };

        let p_clean = model.predict(&clean.to_vector());
        let p_mal = model.predict(&malicious.to_vector());
        assert!(p_clean < 0.3, "clean classified malicious: {p_clean}");
        assert!(p_mal > 0.7, "malicious classified clean: {p_mal}");
    }

    #[test]
    fn classification_reports_contributions() {
        let samples = synthetic_samples();
        let model = LogisticModel::train(&samples, &TrainConfig::default());
        let features = FirmwareFeatures {
            size_bytes: 1 << 16,
            entropy: 7.6,
            printable_ratio: 0.01,
            zero_ratio: 0.01,
            mz_count: 15,
            fvh_count: 0,
            max_run_length: 3,
            high_entropy_window: 45,
            string_count: 1,
        };
        let class = Classification::from_model(&model, &features);
        assert_eq!(class.contributions.len(), 5);
        assert!(class.malicious_probability > 0.5);
    }

    #[test]
    fn model_round_trips_json() {
        let samples = synthetic_samples();
        let model = LogisticModel::train(
            &samples,
            &TrainConfig {
                epochs: 10,
                ..Default::default()
            },
        );
        let json = serde_json::to_string(&model).unwrap();
        let parsed: LogisticModel = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.weights.len(), model.weights.len());
        let v = vec![0.5; 9];
        assert!((parsed.predict(&v) - model.predict(&v)).abs() < 1e-12);
    }
}
