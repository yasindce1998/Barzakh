//! MISP event export — share Barzakh scan results as MISP events.

use barzakh_core::{Finding, ScanResult};
use serde_json::json;

/// Render a scan result as a MISP-compatible event JSON document.
///
/// The structure follows the MISP core event format (simplified) so it can be
/// pushed via `POST /events/add` on a MISP instance.
pub fn render_misp_event(result: &ScanResult, event_title: Option<&str>) -> serde_json::Value {
    let target = &result.scan_info.target;
    let title = event_title.unwrap_or(if result.summary.bootkit_detected {
        "Barzakh: firmware bootkit detected"
    } else {
        "Barzakh: firmware scan report"
    });

    let attributes: Vec<serde_json::Value> = result
        .findings
        .iter()
        .map(|f| finding_attribute(f, target))
        .collect();

    json!({
        "Event": {
            "info": title,
            "distribution": "0",
            "threat_level_id": if result.summary.critical_count > 0 { "1" } else { "3" },
            "analysis": "0",
            "date": result.scan_info.start_time[..10].to_string(),
            "published": false,
            "Attribute": attributes,
            "Tag": [
                { "name": "type:firmware" },
                { "name": format!("barzakh:risk:{}", result.risk.score) },
                { "name": format!("barzakh:level:{}", result.risk.level) },
            ],
        }
    })
}

fn finding_attribute(finding: &Finding, target: &str) -> serde_json::Value {
    let (category, atype) = if finding.severity >= barzakh_core::Severity::High {
        ("Payload analysis", "text")
    } else {
        ("Other", "text")
    };

    json!({
        "category": category,
        "type": atype,
        "value": format!("[{}] {} ({})", finding.detector, finding.title, target),
        "to_ids": false,
        "comment": finding.description,
        "distribution": "0",
        "timestamp": finding.details.as_ref()
            .and_then(|d| d.get("first_offset"))
            .map(|o| o.to_string())
            .unwrap_or_default(),
    })
}

/// Serialize to a pretty JSON string.
pub fn render_misp_event_string(result: &ScanResult, title: Option<&str>) -> String {
    serde_json::to_string_pretty(&render_misp_event(result, title)).unwrap_or_else(|_| "{}".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use barzakh_core::{BarzakhScanner, Severity};
    use std::path::PathBuf;

    fn sample_result() -> ScanResult {
        // Build a synthetic scan result without touching the filesystem.
        let findings = vec![
            Finding::new("blacklotus", Severity::Critical, "Bootkit", "detected")
                .with_confidence(0.92),
        ];
        let risk = barzakh_core::RiskScore::from_findings(&findings);
        let summary = barzakh_core::ScanSummary {
            total_findings: 1,
            critical_count: 1,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            info_count: 0,
            bootkit_detected: true,
        };
        ScanResult {
            summary,
            findings,
            scan_info: barzakh_core::scanner::ScanInfo {
                target: "/tmp/fw.bin".to_string(),
                start_time: "2026-10-13T00:00:00+00:00".to_string(),
                end_time: "2026-10-13T00:00:01+00:00".to_string(),
                duration_seconds: 1.0,
            },
            risk,
        }
    }

    #[test]
    fn renders_misp_event_shape() {
        let event = render_misp_event(&sample_result(), None);
        assert_eq!(event["Event"]["threat_level_id"], "1");
        assert!(event["Event"]["info"].as_str().unwrap().contains("bootkit"));
        assert_eq!(event["Event"]["Attribute"].as_array().unwrap().len(), 1);
        assert_eq!(
            event["Event"]["Attribute"][0]["category"],
            "Payload analysis"
        );
    }

    #[test]
    fn string_render_is_valid_json() {
        let s = render_misp_event_string(&sample_result(), Some("custom title"));
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed["Event"]["info"], "custom title");
    }

    #[test]
    fn scanner_still_compiles_reference() {
        // Touch the scanner type to ensure the API surface is coherent.
        let _scanner = BarzakhScanner::new(None);
        let _p = PathBuf::from("/nonexistent");
    }
}
