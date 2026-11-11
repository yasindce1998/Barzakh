use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

use chrono::Utc;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::baseline::Baseline;
use crate::detector::{Detector, DetectorError, Finding, Severity};
use crate::detectors;
use crate::reports::{ReportFormat, ReportGenerator};
use crate::scoring::{RiskScore, VerdictPolicy};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub bootkit_detected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanInfo {
    pub target: String,
    pub start_time: String,
    pub end_time: String,
    pub duration_seconds: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    #[serde(default)]
    pub status: ScanStatus,
    #[serde(default)]
    pub detector_runs: Vec<DetectorRun>,
    #[serde(default)]
    pub errors: Vec<String>,
    #[serde(default)]
    pub input_sha256: Option<String>,
    #[serde(default)]
    pub event_log_sha256: Option<String>,
    pub summary: ScanSummary,
    pub findings: Vec<Finding>,
    pub scan_info: ScanInfo,
    /// Confidence-weighted aggregate risk assessment.
    #[serde(default)]
    pub risk: RiskScore,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    #[default]
    Complete,
    Partial,
    Failed,
}

impl ScanStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorStatus {
    Passed,
    Findings,
    NotApplicable,
    InsufficientEvidence,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorRun {
    pub detector: String,
    pub status: DetectorStatus,
    pub finding_count: usize,
    pub error: Option<String>,
    pub duration_seconds: f64,
}

impl ScanResult {
    /// 0: completed without a positive verdict, 1: detection, 2: incomplete/failed.
    pub fn exit_code(&self) -> i32 {
        if self.status != ScanStatus::Complete {
            2
        } else if self.summary.bootkit_detected {
            1
        } else {
            0
        }
    }
}

pub struct BarzakhScanner {
    detectors: HashMap<String, Box<dyn Detector>>,
    pub baseline: Option<Baseline>,
    pub findings: Vec<Finding>,
    last_result: Option<ScanResult>,
    /// Bootkit verdict policy (default reproduces the historical heuristic).
    pub verdict_policy: VerdictPolicy,
    pub max_image_bytes: u64,
}

impl BarzakhScanner {
    pub fn new(baseline: Option<Baseline>) -> Self {
        let mut scanner = Self {
            detectors: HashMap::new(),
            baseline: baseline.clone(),
            findings: Vec::new(),
            last_result: None,
            verdict_policy: VerdictPolicy::default(),
            max_image_bytes: crate::context::DEFAULT_MAX_IMAGE_BYTES,
        };
        scanner.register_detectors(baseline);
        scanner
    }

    pub fn from_baseline_path(path: &Path) -> anyhow::Result<Self> {
        let baseline = Baseline::load(path)?;
        Ok(Self::new(Some(baseline)))
    }

    fn register_detectors(&mut self, baseline: Option<Baseline>) {
        let all = detectors::create_all_detectors(baseline);
        for detector in all {
            self.detectors.insert(detector.name().to_string(), detector);
        }
    }

    /// Register an additional detector at runtime (plugins, YARA rules,
    /// IOC feeds, ML models, ...).
    pub fn register_detector(&mut self, detector: Box<dyn Detector>) {
        self.detectors.insert(detector.name().to_string(), detector);
    }

    /// Names of all registered detectors.
    pub fn detector_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.detectors.keys().map(|s| s.as_str()).collect();
        names.sort_unstable();
        names
    }

    pub fn detector_count(&self) -> usize {
        self.detectors.len()
    }

    pub fn has_detector(&self, name: &str) -> bool {
        self.detectors.contains_key(name)
    }

    pub fn scan(&mut self, target: &Path, scan_types: Option<&[&str]>) -> ScanResult {
        let start = Instant::now();
        let start_time = Utc::now();
        let context = crate::ScanContext::load_with_limit(target, self.max_image_bytes);
        let mut result = self.run_scan(
            target,
            context.as_ref().map_err(ToString::to_string),
            scan_types,
        );
        result.scan_info.start_time = start_time.to_rfc3339();
        result.scan_info.duration_seconds = start.elapsed().as_secs_f64();
        self.last_result = Some(result.clone());
        result
    }

    pub fn scan_context(
        &mut self,
        context: &crate::ScanContext,
        scan_types: Option<&[&str]>,
    ) -> ScanResult {
        self.run_scan(context.path(), Ok(context), scan_types)
    }

    fn run_scan(
        &mut self,
        target: &Path,
        context: Result<&crate::ScanContext, String>,
        scan_types: Option<&[&str]>,
    ) -> ScanResult {
        let start = Instant::now();
        let start_time = Utc::now();

        let selected: Vec<&Box<dyn Detector>> = if let Some(types) = scan_types {
            self.detectors
                .iter()
                .filter(|(name, _)| types.contains(&name.as_str()))
                .map(|(_, d)| d)
                .collect()
        } else {
            self.detectors.values().collect()
        };

        let mut errors = Vec::new();
        if let Some(types) = scan_types {
            for name in types {
                if !self.has_detector(name) {
                    errors.push(format!("unknown detector: {name}"));
                }
            }
        }
        if selected.is_empty() {
            errors.push("no detectors selected".into());
        }
        let mut input_sha256 = None;
        let mut event_log_sha256 = None;
        let mut runs = Vec::new();
        let mut findings = Vec::new();
        match context {
            Err(error) => errors.push(error),
            Ok(context)
                if context.data().is_empty()
                    || context.data().len() as u64 > self.max_image_bytes =>
            {
                errors.push("invalid or oversized image snapshot".into());
            }
            Ok(context) => {
                input_sha256 = Some(context.sha256().to_owned());
                event_log_sha256 = context.event_log_sha256().map(str::to_owned);
                let results: Vec<_> = selected
                    .par_iter()
                    .map(|detector| {
                        let timer = Instant::now();
                        let outcome =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                detector.detect_context(context)
                            }))
                            .unwrap_or_else(|_| {
                                Err(DetectorError::Other("detector panicked".into()))
                            });
                        let (status, found, mut error) = match outcome {
                            Ok(found) => (
                                if found.iter().any(|f| {
                                    f.evidence_kind == crate::detector::EvidenceKind::Insufficient
                                }) {
                                    DetectorStatus::InsufficientEvidence
                                } else if found.is_empty() {
                                    DetectorStatus::Passed
                                } else {
                                    DetectorStatus::Findings
                                },
                                found,
                                None,
                            ),
                            Err(DetectorError::NotApplicable(e)) => {
                                (DetectorStatus::NotApplicable, Vec::new(), Some(e))
                            }
                            Err(DetectorError::InsufficientEvidence(e)) => {
                                (DetectorStatus::InsufficientEvidence, Vec::new(), Some(e))
                            }
                            Err(e) => (DetectorStatus::Error, Vec::new(), Some(e.to_string())),
                        };
                        if status == DetectorStatus::InsufficientEvidence && error.is_none() {
                            error = Some(
                                "one or more findings have insufficient supporting evidence".into(),
                            );
                        }
                        (
                            DetectorRun {
                                detector: detector.name().to_owned(),
                                status,
                                finding_count: found.len(),
                                error,
                                duration_seconds: timer.elapsed().as_secs_f64(),
                            },
                            found,
                        )
                    })
                    .collect();
                for (run, found) in results {
                    runs.push(run);
                    findings.extend(found);
                }
            }
        }
        runs.sort_by(|a, b| a.detector.cmp(&b.detector));
        findings.sort_by(|a, b| a.detector.cmp(&b.detector).then(a.title.cmp(&b.title)));
        let successful = runs
            .iter()
            .filter(|r| matches!(r.status, DetectorStatus::Passed | DetectorStatus::Findings))
            .count();
        let incomplete = runs.iter().any(|r| {
            matches!(
                r.status,
                DetectorStatus::Error | DetectorStatus::InsufficientEvidence
            )
        });
        let status = if successful == 0 {
            ScanStatus::Failed
        } else if incomplete || !errors.is_empty() {
            ScanStatus::Partial
        } else {
            ScanStatus::Complete
        };

        let elapsed = start.elapsed().as_secs_f64();
        let end_time = Utc::now();

        let risk = RiskScore::from_findings(&findings);
        let summary = Self::build_summary(&findings, &self.verdict_policy, risk.score);
        let scan_info = ScanInfo {
            target: target.display().to_string(),
            start_time: start_time.to_rfc3339(),
            end_time: end_time.to_rfc3339(),
            duration_seconds: elapsed,
        };

        let result = ScanResult {
            status,
            detector_runs: runs,
            errors,
            input_sha256,
            event_log_sha256,
            summary,
            findings: findings.clone(),
            scan_info,
            risk,
        };

        self.findings = findings;
        self.last_result = Some(result.clone());
        result
    }

    fn build_summary(findings: &[Finding], policy: &VerdictPolicy, risk_score: u32) -> ScanSummary {
        let critical_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let high_count = findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count();
        let medium_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count();
        let low_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Low)
            .count();
        let info_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Info)
            .count();

        ScanSummary {
            total_findings: findings.len(),
            critical_count,
            high_count,
            medium_count,
            low_count,
            info_count,
            bootkit_detected: policy.is_bootkit(critical_count, high_count, risk_score),
        }
    }

    pub fn generate_report(&self, output: &Path, format: ReportFormat) -> anyhow::Result<()> {
        let result = self
            .last_result
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No scan results available. Run scan() first."))?;
        if format == ReportFormat::Json {
            let mut value = serde_json::to_value(result)?;
            value["timestamp"] = serde_json::json!(result.scan_info.start_time);
            std::fs::write(output, serde_json::to_string_pretty(&value)?)?;
            return Ok(());
        }
        anyhow::ensure!(
            result.status == ScanStatus::Complete,
            "refusing to render a findings-only report for a {} scan; use the full ScanResult JSON",
            result.status.as_str()
        );

        let generator = ReportGenerator::new(&result.findings, self.baseline.as_ref())
            .with_risk(result.risk.clone())
            .with_target(&result.scan_info.target);
        generator.generate(output, format)
    }

    pub fn validate_against_corpus(&self, corpus_path: &Path) -> anyhow::Result<ValidationMetrics> {
        let mut true_positives = 0u64;
        let mut false_positives = 0u64;
        let mut true_negatives = 0u64;
        let mut false_negatives = 0u64;
        let mut incomplete_samples = Vec::new();

        let entries = std::fs::read_dir(corpus_path)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            // Legacy mode accepts only explicit filename prefixes. Manifests,
            // reports, and unrelated files must not become negative controls.
            if !name.starts_with("malicious_")
                && !name.starts_with("infected_")
                && !name.starts_with("clean_")
            {
                continue;
            }
            let is_malicious = name.starts_with("malicious_") || name.starts_with("infected_");

            let mut scanner = BarzakhScanner::new(self.baseline.clone());
            scanner.max_image_bytes = self.max_image_bytes;
            scanner.verdict_policy = self.verdict_policy.clone();
            let result = scanner.scan(&path, None);
            if result.status != ScanStatus::Complete {
                incomplete_samples.push(name.to_owned());
                continue;
            }
            let detected = result.summary.bootkit_detected;

            match (is_malicious, detected) {
                (true, true) => true_positives += 1,
                (true, false) => false_negatives += 1,
                (false, true) => false_positives += 1,
                (false, false) => true_negatives += 1,
            }
        }

        let tpr = if true_positives + false_negatives > 0 {
            true_positives as f64 / (true_positives + false_negatives) as f64
        } else {
            0.0
        };
        let fpr = if false_positives + true_negatives > 0 {
            false_positives as f64 / (false_positives + true_negatives) as f64
        } else {
            0.0
        };

        incomplete_samples.sort();
        Ok(ValidationMetrics {
            incomplete_samples,
            true_positives,
            false_positives,
            true_negatives,
            false_negatives,
            true_positive_rate: tpr,
            false_positive_rate: fpr,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationMetrics {
    /// Excluded from accuracy denominators, never counted as true negatives.
    #[serde(default)]
    pub incomplete_samples: Vec<String>,
    pub true_positives: u64,
    pub false_positives: u64,
    pub true_negatives: u64,
    pub false_negatives: u64,
    pub true_positive_rate: f64,
    pub false_positive_rate: f64,
}
