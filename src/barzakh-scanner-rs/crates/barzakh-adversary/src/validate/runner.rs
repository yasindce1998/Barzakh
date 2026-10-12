use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use barzakh_core::BarzakhScanner;

use crate::Payload;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub payload_name: String,
    pub detected: bool,
    pub expected_findings: usize,
    pub matched_findings: usize,
    pub extra_findings: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    pub results: Vec<ValidationResult>,
    pub total_payloads: usize,
    pub detected_count: usize,
    pub missed_count: usize,
    pub true_positive_rate: f64,
    pub false_positives: usize,
    pub true_negatives: usize,
    pub false_positive_rate: f64,
}

impl ValidationReport {
    pub fn from_results(results: Vec<ValidationResult>) -> Self {
        Self::from_results_with_fp(results, 0, 0)
    }

    pub fn from_results_with_fp(
        results: Vec<ValidationResult>,
        false_positives: usize,
        true_negatives: usize,
    ) -> Self {
        let total_payloads = results.len();
        let detected_count = results.iter().filter(|r| r.detected).count();
        let missed_count = total_payloads - detected_count;
        let true_positive_rate = if total_payloads > 0 {
            detected_count as f64 / total_payloads as f64
        } else {
            0.0
        };
        let false_positive_rate = if false_positives + true_negatives > 0 {
            false_positives as f64 / (false_positives + true_negatives) as f64
        } else {
            0.0
        };

        Self {
            results,
            total_payloads,
            detected_count,
            missed_count,
            true_positive_rate,
            false_positives,
            true_negatives,
            false_positive_rate,
        }
    }
}

pub fn validate_payload(payload: &dyn Payload, dump_path: &Path) -> Result<ValidationResult> {
    let mut scanner = BarzakhScanner::new(None);
    let scan_result = scanner.scan(dump_path, None);

    let expected = payload.expected_detections();
    let mut matched = 0;

    for exp in &expected {
        let found = scan_result
            .findings
            .iter()
            .any(|f| f.detector == exp.detector && f.severity >= exp.min_severity);
        if found {
            matched += 1;
        }
    }

    let extra = scan_result
        .findings
        .iter()
        .filter(|f| !expected.iter().any(|e| e.detector == f.detector))
        .count();

    Ok(ValidationResult {
        payload_name: payload.name().to_string(),
        detected: matched > 0,
        expected_findings: expected.len(),
        matched_findings: matched,
        extra_findings: extra,
    })
}

pub fn validate_all(payloads: &[Box<dyn Payload>], dump_dir: &Path) -> Result<ValidationReport> {
    let mut results = Vec::new();

    for payload in payloads {
        let dump_path = dump_dir.join(format!("malicious_{}.bin", payload.name()));
        if dump_path.exists() {
            results.push(validate_payload(payload.as_ref(), &dump_path)?);
        }
    }

    // Scan clean_*.bin files to compute false positive rate
    let mut false_positives = 0usize;
    let mut true_negatives = 0usize;

    if let Ok(entries) = std::fs::read_dir(dump_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let file_name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            if !file_name.starts_with("clean_") {
                continue;
            }

            let mut scanner = BarzakhScanner::new(None);
            let scan_result = scanner.scan(&path, None);
            if scan_result.summary.bootkit_detected {
                false_positives += 1;
            } else {
                true_negatives += 1;
            }
        }
    }

    Ok(ValidationReport::from_results_with_fp(
        results,
        false_positives,
        true_negatives,
    ))
}
