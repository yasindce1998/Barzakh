//! Manifest-labeled validation, separated from generated regression corpora.
use std::collections::{BTreeMap, HashSet};
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

use crate::{BarzakhScanner, ScanContext, ScanStatus};

#[derive(Debug, Serialize, Deserialize)]
pub struct CorpusManifest {
    pub version: u32,
    /// `synthetic` or `independent`; never conflate the two in reports.
    pub provenance: String,
    pub samples: Vec<CorpusSample>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CorpusSample {
    pub path: String,
    pub sha256: String,
    pub malicious: bool,
    pub family: String,
    pub vendor: String,
    pub arch: String,
    /// A family must belong to only one split (train, validation, or test).
    pub split: String,
    /// Reviewed ground truth, not an assertion that every detector applies.
    #[serde(default)]
    pub expected_detectors: Vec<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct ConfusionMatrix {
    pub true_positives: usize,
    pub false_positives: usize,
    pub true_negatives: usize,
    pub false_negatives: usize,
}
impl ConfusionMatrix {
    fn record(&mut self, expected: bool, detected: bool) {
        match (expected, detected) {
            (true, true) => self.true_positives += 1,
            (true, false) => self.false_negatives += 1,
            (false, true) => self.false_positives += 1,
            (false, false) => self.true_negatives += 1,
        }
    }
    pub fn recall(&self) -> Option<f64> {
        ratio(
            self.true_positives,
            self.true_positives + self.false_negatives,
        )
    }
    pub fn precision(&self) -> Option<f64> {
        ratio(
            self.true_positives,
            self.true_positives + self.false_positives,
        )
    }
    pub fn false_positive_rate(&self) -> Option<f64> {
        ratio(
            self.false_positives,
            self.false_positives + self.true_negatives,
        )
    }
}
fn ratio(n: usize, d: usize) -> Option<f64> {
    (d > 0).then(|| n as f64 / d as f64)
}

#[derive(Debug, Serialize)]
pub struct CorpusReport {
    pub provenance: String,
    pub split: Option<String>,
    pub evaluated: usize,
    pub skipped: Vec<String>,
    pub verdict: ConfusionMatrix,
    pub recall: Option<f64>,
    pub precision: Option<f64>,
    pub false_positive_rate: Option<f64>,
    pub per_detector: BTreeMap<String, DetectorMetrics>,
}

#[derive(Debug, Default, Serialize)]
pub struct DetectorMetrics {
    pub confusion: ConfusionMatrix,
    pub recall: Option<f64>,
    pub precision: Option<f64>,
}

pub fn validate_manifest(
    scanner: &mut BarzakhScanner,
    path: &Path,
    strict: bool,
    split: Option<&str>,
) -> anyhow::Result<CorpusReport> {
    let manifest: CorpusManifest = toml::from_str(&std::fs::read_to_string(path)?)?;
    anyhow::ensure!(manifest.version == 1, "unsupported corpus version");
    anyhow::ensure!(
        split.is_none_or(|s| matches!(s, "train" | "validation" | "test")),
        "invalid evaluation split"
    );
    anyhow::ensure!(
        matches!(manifest.provenance.as_str(), "synthetic" | "independent"),
        "invalid provenance"
    );
    let root = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .canonicalize()?;
    let mut families = BTreeMap::new();
    let mut hashes = HashSet::new();
    let mut paths = HashSet::new();
    // Check all splits before filtering: prevent train/test family leakage.
    for sample in &manifest.samples {
        anyhow::ensure!(
            matches!(sample.split.as_str(), "train" | "validation" | "test"),
            "invalid split"
        );
        anyhow::ensure!(
            !sample.family.is_empty() && !sample.vendor.is_empty() && !sample.arch.is_empty(),
            "sample metadata cannot be empty"
        );
        if let Some(previous) = families.insert(&sample.family, &sample.split) {
            anyhow::ensure!(
                previous == &sample.split,
                "family {} leaks across splits",
                sample.family
            );
        }
        anyhow::ensure!(paths.insert(&sample.path), "duplicate sample path");
        // Identical binaries in separate entries inflate accuracy.
        anyhow::ensure!(
            hashes.insert(sample.sha256.to_lowercase()),
            "duplicate sample hash"
        );
        anyhow::ensure!(
            sample.sha256.len() == 64 && sample.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid SHA-256 for {}",
            sample.path
        );
        anyhow::ensure!(
            !Path::new(&sample.path).is_absolute()
                && !sample.path.is_empty()
                && Path::new(&sample.path)
                    .components()
                    .all(|c| matches!(c, Component::Normal(_))),
            "unsafe sample path"
        );
        anyhow::ensure!(
            sample
                .expected_detectors
                .iter()
                .all(|d| scanner.has_detector(d)),
            "unknown expected detector"
        );
    }
    let mut report = CorpusReport {
        provenance: manifest.provenance,
        split: split.map(str::to_owned),
        evaluated: 0,
        skipped: Vec::new(),
        verdict: ConfusionMatrix::default(),
        recall: None,
        precision: None,
        false_positive_rate: None,
        per_detector: BTreeMap::new(),
    };
    for sample in &manifest.samples {
        let target = root.join(&sample.path);
        if !target.exists() {
            anyhow::ensure!(!strict, "required sample missing: {}", sample.path);
            if split.is_none_or(|s| s == sample.split) {
                report.skipped.push(sample.path.clone());
            }
            continue;
        }
        let target = target.canonicalize()?;
        anyhow::ensure!(target.starts_with(&root), "sample escapes corpus directory");
        let context = ScanContext::load_with_limit(&target, scanner.max_image_bytes)?;
        anyhow::ensure!(
            context.sha256().eq_ignore_ascii_case(&sample.sha256),
            "sample hash mismatch: {}",
            sample.path
        );
        if split.is_some_and(|s| s != sample.split) {
            continue;
        }
        let result = scanner.scan_context(&context, None);
        anyhow::ensure!(
            result.status == ScanStatus::Complete,
            "incomplete scan cannot count as a validation success: {} ({:?})",
            sample.path,
            result.detector_runs
        );
        report.evaluated += 1;
        report
            .verdict
            .record(sample.malicious, result.summary.bootkit_detected);
        for name in scanner.detector_names() {
            if !sample.malicious
                && result
                    .detector_runs
                    .iter()
                    .any(|r| r.detector == name && r.status == crate::DetectorStatus::NotApplicable)
            {
                continue;
            }
            // Clean samples are negative controls; malicious samples only
            // contribute where detector-specific ground truth is supplied.
            if sample.malicious && !sample.expected_detectors.iter().any(|d| d == name) {
                continue;
            }
            let detected = result
                .findings
                .iter()
                .any(|f| f.detector == name && f.severity >= crate::Severity::High);
            report
                .per_detector
                .entry(name.into())
                .or_default()
                .confusion
                .record(sample.malicious, detected);
        }
    }
    anyhow::ensure!(report.evaluated > 0, "no samples evaluated");
    report.recall = report.verdict.recall();
    report.precision = report.verdict.precision();
    report.false_positive_rate = report.verdict.false_positive_rate();
    if strict {
        anyhow::ensure!(
            report.recall.is_some() && report.false_positive_rate.is_some(),
            "strict validation requires both positive and negative samples"
        );
    }
    for metrics in report.per_detector.values_mut() {
        metrics.recall = metrics.confusion.recall();
        metrics.precision = metrics.confusion.precision();
    }
    Ok(report)
}
