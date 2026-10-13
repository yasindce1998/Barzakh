use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

use chrono::Utc;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::baseline::Baseline;
use crate::detector::{Detector, Finding, Severity};
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
    pub summary: ScanSummary,
    pub findings: Vec<Finding>,
    pub scan_info: ScanInfo,
    /// Confidence-weighted aggregate risk assessment.
    #[serde(default)]
    pub risk: RiskScore,
}

pub struct BarzakhScanner {
    detectors: HashMap<String, Box<dyn Detector>>,
    pub baseline: Option<Baseline>,
    pub findings: Vec<Finding>,
    last_result: Option<ScanResult>,
    /// Bootkit verdict policy (default reproduces the historical heuristic).
    pub verdict_policy: VerdictPolicy,
}

impl BarzakhScanner {
    pub fn new(baseline: Option<Baseline>) -> Self {
        let mut scanner = Self {
            detectors: HashMap::new(),
            baseline: baseline.clone(),
            findings: Vec::new(),
            last_result: None,
            verdict_policy: VerdictPolicy::default(),
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

        let selected: Vec<&Box<dyn Detector>> = if let Some(types) = scan_types {
            self.detectors
                .iter()
                .filter(|(name, _)| types.contains(&name.as_str()))
                .map(|(_, d)| d)
                .collect()
        } else {
            self.detectors.values().collect()
        };

        let findings: Vec<Finding> = selected
            .par_iter()
            .flat_map(|detector| match detector.detect(target) {
                Ok(findings) => findings,
                Err(e) => {
                    vec![Finding::new(
                        detector.name(),
                        Severity::Info,
                        &format!("Detector {} encountered an error", detector.name()),
                        &e.to_string(),
                    )]
                }
            })
            .collect();

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

        let entries = std::fs::read_dir(corpus_path)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let is_malicious = path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.contains("malicious") || n.contains("infected"))
                .unwrap_or(false);

            let mut scanner = BarzakhScanner::new(self.baseline.clone());
            let result = scanner.scan(&path, None);
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

        Ok(ValidationMetrics {
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
    pub true_positives: u64,
    pub false_positives: u64,
    pub true_negatives: u64,
    pub false_negatives: u64,
    pub true_positive_rate: f64,
    pub false_positive_rate: f64,
}
