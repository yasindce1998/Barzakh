//! SARIF 2.1.0 output — enables GitHub Code Scanning integration.
//!
//! Produces a Static Analysis Results Interchange Format document from scan
//! findings so results can be uploaded with `github/codeql-action/upload-sarif`
//! and rendered as pull-request annotations.

use std::path::Path;

use serde_json::json;

use crate::detector::{Finding, Severity};

/// Map a Barzakh severity to a SARIF level.
fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// Render findings as a SARIF 2.1.0 JSON document.
pub fn render_sarif(findings: &[Finding], target: &str, tool_version: &str) -> String {
    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let mut result = json!({
                "ruleId": f.detector,
                "level": sarif_level(f.severity),
                "message": {
                    "text": format!("{} — {}", f.title, f.description),
                },
                "properties": {
                    "severity": f.severity.to_string(),
                    "confidence": f.confidence,
                    "barzakh:detector": f.detector,
                },
            });

            // Attach a logical location when the detector reported an offset.
            if let Some(details) = &f.details {
                if let Some(offset) = details
                    .get("offset")
                    .or_else(|| details.get("first_offset"))
                {
                    result["locations"] = json!([{
                        "logicalLocations": [{
                            "name": offset.to_string(),
                            "fullyQualifiedName": format!("{}@{}", target, offset),
                            "kind": "resource",
                        }],
                    }]);
                }
            }

            if let Some(rec) = &f.recommendation {
                result["properties"]["barzakh:recommendation"] = json!(rec);
            }

            result
        })
        .collect();

    let document = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "barzakh-scanner",
                        "informationUri": "https://github.com/yasindce1998/Barzakh",
                        "version": tool_version,
                        "rules": unique_rules(findings),
                    },
                },
                "originalUriBaseIds": {
                    "BARZAKH_TARGET": {
                        "uri": target,
                    },
                },
                "results": results,
            },
        ],
    });

    serde_json::to_string_pretty(&document).unwrap_or_else(|_| "{}".to_string())
}

fn unique_rules(findings: &[Finding]) -> Vec<serde_json::Value> {
    let mut seen = std::collections::BTreeSet::new();
    let mut rules = Vec::new();
    for f in findings {
        if seen.insert(f.detector.clone()) {
            rules.push(json!({
                "id": f.detector,
                "shortDescription": {
                    "text": f.title,
                },
            }));
        }
    }
    rules
}

/// Write a SARIF report to `output`.
pub fn write_sarif(
    output: &Path,
    findings: &[Finding],
    target: &str,
    tool_version: &str,
) -> anyhow::Result<()> {
    std::fs::write(output, render_sarif(findings, target, tool_version))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_valid_sarif_json() {
        let findings = vec![
            Finding::new("blacklotus", Severity::Critical, "BL", "desc")
                .with_confidence(0.92)
                .with_details(serde_json::json!({"offset": "0x1000"})),
            Finding::new("hook", Severity::Medium, "Hook", "desc2"),
        ];
        let sarif = render_sarif(&findings, "fw.bin", "0.5.0");
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(
            parsed["runs"][0]["tool"]["driver"]["name"],
            "barzakh-scanner"
        );
        assert_eq!(parsed["runs"][0]["results"].as_array().unwrap().len(), 2);
        assert_eq!(parsed["runs"][0]["results"][0]["level"], "error");
        assert_eq!(parsed["runs"][0]["results"][1]["level"], "warning");
        // Offset-bearing finding gets a logical location.
        assert!(parsed["runs"][0]["results"][0]["locations"].is_array());
    }

    #[test]
    fn dedupes_rules() {
        let findings = vec![
            Finding::new("hook", Severity::High, "a", "d"),
            Finding::new("hook", Severity::Medium, "b", "d"),
        ];
        let sarif = render_sarif(&findings, "fw.bin", "1.0");
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 1);
    }
}
