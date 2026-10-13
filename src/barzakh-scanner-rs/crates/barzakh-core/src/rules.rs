//! Declarative TOML rule sets — user-authored detectors without Rust.
//!
//! A rules directory contains `*.toml` files of the form:
//!
//! ```toml
//! [[rule]]
//! name = "vendor_x_backdoor"
//! severity = "critical"
//! title = "Vendor X backdoor marker"
//! description = "Firmware contains the Vendor X persistence marker."
//! recommendation = "Compare against a known-good vendor image."
//! min_occurrences = 1
//!
//! [[rule.match]]
//! pattern = "backdoor_marker_string"   # ASCII string
//!
//! [[rule.match]]
//! hex = "DE AD BE EF"                  # byte pattern (wildcards: ??)
//! offset = 4096                        # optional exact offset
//! ```
//!
//! Each `[[rule]]` becomes a detector named `rule:<name>` registered on the
//! scanner via `RuleSet::load_dir` + `RuleSetDetector`.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::detector::{Detector, DetectorError, Finding, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    /// ASCII string pattern (anywhere in the image).
    #[serde(default)]
    pub pattern: Option<String>,
    /// Hex byte pattern, e.g. "DE AD BE EF" — `??` matches any byte.
    #[serde(default)]
    pub hex: Option<String>,
    /// Require the match at exactly this offset.
    #[serde(default)]
    pub offset: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    /// "info" | "low" | "medium" | "high" | "critical"
    pub severity: String,
    pub title: String,
    pub description: String,
    #[serde(default)]
    pub recommendation: Option<String>,
    /// Minimum number of `[[rule.match]]` sections that must hit (default 1).
    #[serde(default = "default_min_occurrences")]
    pub min_occurrences: usize,
    #[serde(default)]
    pub r#match: Vec<RuleMatch>,
}

fn default_min_occurrences() -> usize {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSet {
    /// `[[rule]]` array-of-tables in the TOML source.
    #[serde(rename = "rule")]
    pub rules: Vec<Rule>,
}

/// A parsed hex pattern with wildcard bytes.
#[derive(Debug, Clone)]
pub struct HexPattern {
    pub bytes: Vec<Option<u8>>,
}

impl HexPattern {
    pub fn parse(s: &str) -> Option<Self> {
        let mut bytes = Vec::new();
        for token in s.split_whitespace() {
            let b = match token {
                "??" | "**" => None,
                _ => Some(u8::from_str_radix(token, 16).ok()?),
            };
            bytes.push(b);
        }
        if bytes.is_empty() {
            None
        } else {
            Some(Self { bytes })
        }
    }

    pub fn matches_at(&self, data: &[u8], offset: usize) -> bool {
        if offset + self.bytes.len() > data.len() {
            return false;
        }
        self.bytes
            .iter()
            .zip(&data[offset..])
            .all(|(pat, actual)| pat.is_none_or(|p| p == *actual))
    }

    pub fn find(&self, data: &[u8]) -> Option<usize> {
        if self.bytes.is_empty() || data.len() < self.bytes.len() {
            return None;
        }
        (0..=data.len() - self.bytes.len()).find(|&i| self.matches_at(data, i))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse error in {path}: {source}")]
    Parse {
        path: String,
        source: toml::de::Error,
    },
    #[error("invalid rule {rule}: {reason}")]
    Invalid { rule: String, reason: String },
}

impl RuleSet {
    pub fn from_toml_str(content: &str) -> Result<Self, RuleError> {
        let set: RuleSet = toml::from_str(content)
            .map_err(|source| RuleError::Parse {
                path: "<string>".to_string(),
                source,
            })
            .and_then(|s: RuleSet| {
                for rule in &s.rules {
                    if rule.r#match.is_empty() {
                        return Err(RuleError::Invalid {
                            rule: rule.name.clone(),
                            reason: "rule has no [[rule.match]] sections".to_string(),
                        });
                    }
                    if Severity::parse(&rule.severity).is_none() {
                        return Err(RuleError::Invalid {
                            rule: rule.name.clone(),
                            reason: format!("unknown severity '{}'", rule.severity),
                        });
                    }
                }
                Ok(s)
            })?;
        Ok(set)
    }

    /// Load and merge every `*.toml` file under `dir`.
    pub fn load_dir(dir: &Path) -> Result<Self, RuleError> {
        let mut rules = Vec::new();
        let entries = std::fs::read_dir(dir)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            let content = std::fs::read_to_string(&path)?;
            let set = Self::from_toml_str(&content).map_err(|e| match e {
                RuleError::Parse { source, .. } => RuleError::Parse {
                    path: path.display().to_string(),
                    source,
                },
                other => other,
            })?;
            rules.extend(set.rules);
        }
        Ok(Self { rules })
    }

    /// Evaluate all rules against a firmware image.
    pub fn evaluate(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();
        for rule in &self.rules {
            let severity = Severity::parse(&rule.severity).unwrap_or(Severity::Medium);
            let mut hits = 0;
            let mut offsets: Vec<String> = Vec::new();

            for m in &rule.r#match {
                let hit_offset = if let Some(pat) = &m.pattern {
                    match m.offset {
                        Some(off) => {
                            let off = off as usize;
                            (off + pat.len() <= data.len()
                                && data[off..].starts_with(pat.as_bytes()))
                            .then_some(off)
                        }
                        None => data.windows(pat.len()).position(|w| w == pat.as_bytes()),
                    }
                } else if let Some(hex) = &m.hex {
                    let parsed = HexPattern::parse(hex);
                    parsed.and_then(|p| match m.offset {
                        Some(off) if p.matches_at(data, off as usize) => Some(off as usize),
                        _ => p.find(data),
                    })
                } else {
                    None
                };

                if let Some(off) = hit_offset {
                    hits += 1;
                    offsets.push(format!("0x{off:08X}"));
                }
            }

            if hits >= rule.min_occurrences.max(1) {
                let mut finding = Finding::new(
                    &format!("rule:{}", rule.name),
                    severity,
                    &rule.title,
                    &rule.description,
                )
                .with_confidence(0.85)
                .with_details(serde_json::json!({
                    "rule": rule.name,
                    "matched": hits,
                    "offsets": offsets,
                }));
                if let Some(rec) = &rule.recommendation {
                    finding = finding.with_recommendation(rec);
                }
                findings.push(finding);
            }
        }
        findings
    }
}

impl Severity {
    /// Parse a severity from its lowercase name.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "info" => Some(Self::Info),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

/// Detector wrapper around a rule set (name: `rule:<set>` for single-rule
/// sets, or the rule's own name via `RuleSetDetector`).
pub struct RuleSetDetector {
    name: String,
    ruleset: RuleSet,
}

impl RuleSetDetector {
    pub fn new(name: &str, ruleset: RuleSet) -> Self {
        Self {
            name: name.to_string(),
            ruleset,
        }
    }

    pub fn from_dir(dir: &Path, name: &str) -> Result<Self, RuleError> {
        Ok(Self::new(name, RuleSet::load_dir(dir)?))
    }
}

impl Detector for RuleSetDetector {
    fn name(&self) -> &str {
        &self.name
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        Ok(self.ruleset.evaluate(&data))
    }
}

/// Convenience: group rule hits by rule name for reporting.
pub fn findings_by_rule(findings: &[Finding]) -> HashMap<&str, usize> {
    findings
        .iter()
        .map(|f| (f.detector.as_str(), ()))
        .fold(HashMap::new(), |mut acc, (k, _)| {
            *acc.entry(k).or_insert(0) += 1;
            acc
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TOML: &str = r#"
[[rule]]
name = "vendor_x_backdoor"
severity = "critical"
title = "Vendor X backdoor marker"
description = "Vendor X persistence marker present."
recommendation = "Reflash from vendor-signed image."
min_occurrences = 1

[[rule.match]]
pattern = "backdoor_marker"

[[rule]]
name = "hex_rule"
severity = "high"
title = "Magic marker"
description = "Magic bytes."

[[rule.match]]
hex = "DE AD ?? EF"
offset = 16
"#;

    #[test]
    fn parses_and_fires() {
        let set = RuleSet::from_toml_str(SAMPLE_TOML).unwrap();
        assert_eq!(set.rules.len(), 2);

        let mut data = vec![0u8; 64];
        data[0..15].copy_from_slice(b"backdoor_marker");
        data[16..20].copy_from_slice(&[0xDE, 0xAD, 0x42, 0xEF]);

        let findings = set.evaluate(&data);
        assert_eq!(findings.len(), 2);
        assert!(findings
            .iter()
            .any(|f| f.detector == "rule:vendor_x_backdoor" && f.severity == Severity::Critical));
        assert!(findings.iter().any(|f| f.detector == "rule:hex_rule"));
    }

    #[test]
    fn quiet_when_no_match() {
        let set = RuleSet::from_toml_str(SAMPLE_TOML).unwrap();
        assert!(set.evaluate(&[0u8; 64]).is_empty());
    }

    #[test]
    fn hex_wildcard_matches_any_byte() {
        let pat = HexPattern::parse("DE AD ?? EF").unwrap();
        assert!(pat.matches_at(&[0xDE, 0xAD, 0x99, 0xEF], 0));
        assert!(!pat.matches_at(&[0xDE, 0xAD, 0x99, 0xEE], 0));
    }

    #[test]
    fn min_occurrences_requires_multiple_hits() {
        let toml = r#"
[[rule]]
name = "multi"
severity = "medium"
title = "t"
description = "d"
min_occurrences = 2

[[rule.match]]
pattern = "aaa"

[[rule.match]]
pattern = "bbb"
"#;
        let set = RuleSet::from_toml_str(toml).unwrap();
        let mut data = b"xxx aaa xxx".to_vec();
        assert!(set.evaluate(&data).is_empty());
        data.extend_from_slice(b" bbb");
        assert_eq!(set.evaluate(&data).len(), 1);
    }

    #[test]
    fn rejects_rule_without_matches() {
        let toml = r#"
[[rule]]
name = "bad"
severity = "low"
title = "t"
description = "d"
"#;
        assert!(RuleSet::from_toml_str(toml).is_err());
    }
}
