//! Corpus training and evaluation for the combined ML model.
//!
//! The corpus layout matches `barzakh-adversary corpus` output: a flat
//! directory of `malicious_<payload>.bin` / `clean_<payload>.bin` pairs,
//! with labels encoded in the filename prefix.
//!
//! The trained model serializes to a versioned JSON document
//! (`barzakh-ml-model`) embedding both the isolation forest and the
//! logistic-regression classifier.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::classifier::{LabeledSample, LogisticModel, TrainConfig};
use crate::features::FirmwareFeatures;
use crate::iforest::IsolationForest;

/// Model document format identifier.
pub const MODEL_FORMAT: &str = "barzakh-ml-model";
/// Model document version.
pub const MODEL_VERSION: u32 = 1;
/// Default anomaly threshold applied to isolation-forest scores.
pub const DEFAULT_ANOMALY_THRESHOLD: f64 = 0.62;

/// Corpus composition statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusStats {
    pub samples: usize,
    pub malicious: usize,
    pub benign: usize,
}

/// The combined model: isolation forest + logistic regression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainedModel {
    pub format: String,
    pub version: u32,
    pub trained_at: String,
    pub features: Vec<String>,
    pub isolation_forest: IsolationForest,
    pub logistic_regression: LogisticModel,
    pub anomaly_threshold: f64,
    pub corpus_stats: CorpusStats,
}

/// One corpus sample on disk.
struct CorpusSample {
    path: PathBuf,
    malicious: bool,
}

fn corpus_samples(dir: &Path) -> Result<Vec<CorpusSample>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("reading corpus directory {}", dir.display()))?
    {
        let path = entry?.path();
        if !path.is_file() {
            continue;
        }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let malicious = name.starts_with("malicious");
        let benign = name.starts_with("clean");
        if !malicious && !benign {
            continue; // not a labeled corpus file
        }
        out.push(CorpusSample { path, malicious });
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

impl TrainedModel {
    /// Train on a corpus directory (`malicious_*` / `clean_*` files).
    pub fn train_from_corpus(dir: &Path) -> Result<Self> {
        let samples = corpus_samples(dir)?;
        anyhow::ensure!(
            !samples.is_empty(),
            "no labeled corpus files (malicious_*/clean_*) found in {}",
            dir.display()
        );

        let mut clean_vectors = Vec::new();
        let mut labeled = Vec::new();
        let mut stats = CorpusStats {
            samples: 0,
            malicious: 0,
            benign: 0,
        };

        for sample in &samples {
            let data = std::fs::read(&sample.path)
                .with_context(|| format!("reading {}", sample.path.display()))?;
            let features = FirmwareFeatures::extract(&data);
            let vector = features.to_vector();
            if sample.malicious {
                stats.malicious += 1;
            } else {
                stats.benign += 1;
                clean_vectors.push(vector.clone());
            }
            labeled.push(LabeledSample {
                features: vector,
                malicious: sample.malicious,
            });
            stats.samples += 1;
        }
        anyhow::ensure!(
            stats.malicious > 0 && stats.benign > 0,
            "corpus needs both malicious_* and clean_* samples (got {} malicious, {} clean)",
            stats.malicious,
            stats.benign
        );

        // Isolation forest trained on benign corpus profiles only: the
        // anomaly detector models this deployment's clean distribution, so
        // "anomalous" means "statistically unlike your clean firmware".
        // (Corpus clean files are often near-identical, collapsing many
        // trees into leaves and inflating all scores equally — the
        // data-driven percentile threshold below absorbs that shift.)
        let subsample = clean_vectors.len().min(64);
        let forest = IsolationForest::fit(&clean_vectors, 32, subsample.max(2), 0x0B42_A2C7);

        // Data-driven anomaly threshold: the 95th percentile of scores over
        // the training clean vectors, so ~5% of benign images sit at the
        // boundary regardless of the corpus's absolute score scale.
        let mut clean_scores: Vec<f64> = clean_vectors
            .iter()
            .map(|v| forest.anomaly_score(v))
            .collect();
        clean_scores.sort_by(|a, b| a.partial_cmp(b).expect("scores are finite"));
        let anomaly_threshold = match clean_scores.len() {
            0 => DEFAULT_ANOMALY_THRESHOLD,
            n => clean_scores[(n as f64 * 0.95) as usize % n],
        };

        // Classifier trained on the full labeled set.
        let classifier = LogisticModel::train(&labeled, &TrainConfig::default());

        Ok(Self {
            format: MODEL_FORMAT.to_string(),
            version: MODEL_VERSION,
            trained_at: chrono::Utc::now().to_rfc3339(),
            features: FirmwareFeatures::FEATURE_NAMES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            isolation_forest: forest,
            logistic_regression: classifier,
            anomaly_threshold,
            corpus_stats: stats,
        })
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let model: TrainedModel = serde_json::from_str(&std::fs::read_to_string(path)?)
            .with_context(|| format!("parsing model {}", path.display()))?;
        anyhow::ensure!(
            model.format == MODEL_FORMAT,
            "unrecognized model format '{}' (expected '{MODEL_FORMAT}')",
            model.format
        );
        Ok(model)
    }

    /// Evaluate both models on a corpus; returns detection metrics.
    pub fn evaluate_corpus(&self, dir: &Path) -> Result<EvalReport> {
        let samples = corpus_samples(dir)?;
        anyhow::ensure!(
            !samples.is_empty(),
            "no labeled corpus files found in {}",
            dir.display()
        );

        let mut report = EvalReport::default();
        for sample in &samples {
            let data = std::fs::read(&sample.path)
                .with_context(|| format!("reading {}", sample.path.display()))?;
            let features = FirmwareFeatures::extract(&data);
            let vector = features.to_vector();

            report.samples += 1;
            if sample.malicious {
                report.malicious += 1;
            } else {
                report.benign += 1;
            }

            // Isolation forest: anomaly score above threshold → flagged.
            let iforest_flag =
                self.isolation_forest.anomaly_score(&vector) > self.anomaly_threshold;
            if sample.malicious {
                if iforest_flag {
                    report.iforest_true_positives += 1;
                } else {
                    report.iforest_false_negatives += 1;
                }
            } else if iforest_flag {
                report.iforest_false_positives += 1;
            } else {
                report.iforest_true_negatives += 1;
            }

            // Classifier: predicted probability above 0.5 → malicious.
            let classifier_flag = self.logistic_regression.predict(&vector) > 0.5;
            let cell = if sample.malicious {
                if classifier_flag {
                    &mut report.confusion[0][0] // actual malicious, predicted malicious
                } else {
                    &mut report.confusion[0][1] // actual malicious, predicted benign
                }
            } else if classifier_flag {
                &mut report.confusion[1][0] // actual benign, predicted malicious
            } else {
                &mut report.confusion[1][1] // actual benign, predicted benign
            };
            *cell += 1;
        }

        report.iforest_tpr = rate(report.iforest_true_positives, report.malicious);
        report.iforest_fpr = rate(report.iforest_false_positives, report.benign);
        report.classifier_tpr = rate(report.confusion[0][0], report.malicious);
        report.classifier_fpr = rate(report.confusion[1][0], report.benign);
        Ok(report)
    }
}

fn rate(hits: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        hits as f64 / total as f64
    }
}

/// Evaluation metrics over a corpus.
#[derive(Debug, Clone, Default, Serialize)]
pub struct EvalReport {
    pub samples: usize,
    pub malicious: usize,
    pub benign: usize,
    pub iforest_true_positives: usize,
    pub iforest_false_positives: usize,
    pub iforest_true_negatives: usize,
    pub iforest_false_negatives: usize,
    pub iforest_tpr: f64,
    pub iforest_fpr: f64,
    pub classifier_tpr: f64,
    pub classifier_fpr: f64,
    /// Confusion matrix for the classifier:
    /// `[actual][predicted]` with `0 = malicious`, `1 = benign`.
    pub confusion: [[usize; 2]; 2],
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_corpus() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "barzakh-ml-train-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn make_corpus() -> PathBuf {
        let dir = temp_corpus();
        // Malicious-ish: high entropy, no zeros, no strings.
        let mut state = 0xABCD_u64;
        let blob: Vec<u8> = (0..32768)
            .map(|_| {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                (state >> 33) as u8
            })
            .collect();
        std::fs::write(dir.join("malicious_a.bin"), &blob).unwrap();
        // Clean-ish: header strings plus zero padding.
        let mut clean = b"UEFI FIRMWARE IMAGE _FVH header".to_vec();
        clean.extend_from_slice(&[0u8; 32768]);
        std::fs::write(dir.join("clean_a.bin"), &clean).unwrap();
        dir
    }

    #[test]
    fn train_save_load_evaluate_round_trip() {
        let corpus = make_corpus();
        let model = TrainedModel::train_from_corpus(&corpus).unwrap();
        assert_eq!(model.corpus_stats.samples, 2);
        assert_eq!(model.corpus_stats.malicious, 1);
        assert_eq!(model.corpus_stats.benign, 1);

        let model_path = corpus.join("model.json");
        model.save(&model_path).unwrap();
        let loaded = TrainedModel::load(&model_path).unwrap();
        assert_eq!(loaded.format, MODEL_FORMAT);
        assert_eq!(loaded.corpus_stats.samples, 2);

        let report = loaded.evaluate_corpus(&corpus).unwrap();
        assert_eq!(report.samples, 2);
        // The classifier must perfectly separate this trivial corpus.
        assert_eq!(report.confusion[0][0], 1); // malicious → malicious
        assert_eq!(report.confusion[1][1], 1); // benign → benign
        assert!((report.classifier_tpr - 1.0).abs() < 1e-9);
        assert!(report.classifier_fpr < 1e-9);

        let _ = std::fs::remove_dir_all(&corpus);
    }

    #[test]
    fn rejects_empty_and_unlabeled_dirs() {
        let dir = temp_corpus();
        std::fs::write(dir.join("unlabeled.bin"), [0u8; 16]).unwrap();
        assert!(TrainedModel::train_from_corpus(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
