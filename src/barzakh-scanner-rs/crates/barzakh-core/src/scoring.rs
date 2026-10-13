//! Confidence-weighted aggregate risk scoring for scan results.
//!
//! Every finding carries a severity and a confidence value. The risk score
//! aggregates both into a single 0-100 number plus a qualitative level and a
//! CVSS-style vector string that summarises the finding mix.

use crate::detector::{Finding, Severity};
use serde::{Deserialize, Serialize};

/// Qualitative risk level derived from the numeric score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Clean,
    Low,
    Medium,
    Elevated,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Clean => "clean",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::Elevated => "elevated",
            Self::High => "high",
            Self::Critical => "critical",
        };
        write!(f, "{s}")
    }
}

impl RiskLevel {
    /// Map a 0-100 score to a level.
    pub fn from_score(score: u32) -> Self {
        match score {
            0 => Self::Clean,
            1..=19 => Self::Low,
            20..=39 => Self::Medium,
            40..=59 => Self::Elevated,
            60..=79 => Self::High,
            _ => Self::Critical,
        }
    }
}

/// Severity weight used by the aggregate score.
fn severity_weight(severity: Severity) -> f64 {
    match severity {
        Severity::Info => 0.5,
        Severity::Low => 2.0,
        Severity::Medium => 5.0,
        Severity::High => 9.0,
        Severity::Critical => 15.0,
    }
}

/// Confidence-weighted aggregate risk assessment of a scan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RiskScore {
    /// Aggregate score, 0 (clean) to 100 (worst case).
    pub score: u32,
    /// Qualitative level.
    pub level: RiskLevel,
    /// CVSS-style vector summarising the finding mix.
    pub vector: String,
    /// Sum of severity-weight × confidence across all findings.
    pub weighted_sum: f64,
    /// Mean confidence across findings (0 when no findings).
    pub mean_confidence: f64,
    /// Number of distinct detectors that raised findings.
    pub detector_count: usize,
}

impl Default for RiskScore {
    fn default() -> Self {
        Self::from_findings(&[])
    }
}

impl RiskScore {
    /// Compute the aggregate risk from a slice of findings.
    pub fn from_findings(findings: &[Finding]) -> Self {
        let weighted_sum: f64 = findings
            .iter()
            .map(|f| severity_weight(f.severity) * f.confidence.clamp(0.0, 1.0))
            .sum();

        let mean_confidence = if findings.is_empty() {
            0.0
        } else {
            findings.iter().map(|f| f.confidence).sum::<f64>() / findings.len() as f64
        };

        let detector_count = findings
            .iter()
            .map(|f| f.detector.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len();

        // 25 weighted points saturate the scale.
        let score = ((weighted_sum * 4.0).clamp(0.0, 100.0)).round() as u32;
        let level = RiskLevel::from_score(score);

        Self {
            score,
            level,
            vector: Self::build_vector(findings, score, mean_confidence),
            weighted_sum,
            mean_confidence,
            detector_count,
        }
    }

    /// Build a CVSS-inspired vector: dominant severity, exploit primitives and
    /// scope, derived from the finding mix.
    fn build_vector(findings: &[Finding], score: u32, mean_confidence: f64) -> String {
        let dominant = findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Info);

        let (vc, vi) = match dominant {
            Severity::Critical => ("H", "H"),
            Severity::High => ("H", "H"),
            Severity::Medium => ("L", "L"),
            Severity::Low => ("L", "N"),
            Severity::Info => ("N", "N"),
        };

        // Attack vector is firmware (pre-OS) whenever the platform is a target.
        let av = if findings.iter().any(|f| {
            f.detector.contains("spi") || f.detector.contains("fv") || f.detector.contains("boot")
        }) {
            "F"
        } else {
            "L"
        };

        // Privileges required: firmware implants need no privileges once flashed.
        let pr = if dominant >= Severity::High { "N" } else { "L" };

        format!(
            "BARZKH:1.0/AV:{av}/AC:L/PR:{pr}/UI:N/S:F/VC:{vc}/VI:{vi}/VA:L/SC:{score}/CF:{:.2}",
            mean_confidence
        )
    }
}

/// Pluggable bootkit verdict policy.
///
/// The default reproduces the historical heuristic
/// (`critical > 0 || high >= 3`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictPolicy {
    pub critical_threshold: usize,
    pub high_threshold: usize,
    /// When set, a risk score at or above this value also triggers the verdict.
    pub risk_score_threshold: Option<u32>,
}

impl Default for VerdictPolicy {
    fn default() -> Self {
        Self {
            critical_threshold: 1,
            high_threshold: 3,
            risk_score_threshold: None,
        }
    }
}

impl VerdictPolicy {
    /// Evaluate the bootkit verdict for a summary of counts plus risk score.
    pub fn is_bootkit(&self, critical_count: usize, high_count: usize, risk_score: u32) -> bool {
        if critical_count >= self.critical_threshold {
            return true;
        }
        if high_count >= self.high_threshold {
            return true;
        }
        if let Some(threshold) = self.risk_score_threshold {
            return risk_score >= threshold;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(severity: Severity, confidence: f64) -> Finding {
        Finding::new("test", severity, "t", "d").with_confidence(confidence)
    }

    #[test]
    fn clean_when_no_findings() {
        let risk = RiskScore::from_findings(&[]);
        assert_eq!(risk.score, 0);
        assert_eq!(risk.level, RiskLevel::Clean);
        assert_eq!(risk.detector_count, 0);
    }

    #[test]
    fn single_low_confidence_critical_is_medium_not_max() {
        let risk = RiskScore::from_findings(&[finding(Severity::Critical, 0.5)]);
        assert_eq!(risk.score, 30);
        assert_eq!(risk.level, RiskLevel::Medium);
    }

    #[test]
    fn two_confident_criticals_saturate() {
        let risk = RiskScore::from_findings(&[
            finding(Severity::Critical, 0.95),
            finding(Severity::Critical, 0.95),
        ]);
        assert_eq!(risk.score, 100);
        assert_eq!(risk.level, RiskLevel::Critical);
    }

    #[test]
    fn info_findings_stay_low() {
        let risk = RiskScore::from_findings(&[
            finding(Severity::Info, 0.9),
            finding(Severity::Info, 0.9),
            finding(Severity::Low, 0.8),
        ]);
        assert!(risk.score < 20, "score {}", risk.score);
        assert_eq!(risk.level, RiskLevel::Low);
    }

    #[test]
    fn vector_has_expected_shape() {
        let risk = RiskScore::from_findings(&[finding(Severity::High, 0.9)]);
        assert!(risk.vector.starts_with("BARZKH:1.0/"));
        assert!(risk.vector.contains("VC:H"));
        assert!(risk.vector.contains("/SC:"));
    }

    #[test]
    fn default_policy_matches_historical_heuristic() {
        let policy = VerdictPolicy::default();
        assert!(policy.is_bootkit(1, 0, 10));
        assert!(policy.is_bootkit(0, 3, 10));
        assert!(!policy.is_bootkit(0, 2, 30));
        assert!(!policy.is_bootkit(0, 0, 0));
    }

    #[test]
    fn risk_threshold_policy() {
        let policy = VerdictPolicy {
            risk_score_threshold: Some(60),
            ..Default::default()
        };
        assert!(policy.is_bootkit(0, 0, 75));
        assert!(!policy.is_bootkit(0, 0, 59));
    }

    #[test]
    fn mean_confidence_computed() {
        let risk =
            RiskScore::from_findings(&[finding(Severity::Low, 0.5), finding(Severity::Low, 1.0)]);
        assert!((risk.mean_confidence - 0.75).abs() < 1e-9);
    }
}
