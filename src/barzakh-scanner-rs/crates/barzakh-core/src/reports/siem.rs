//! SIEM export formats: Elastic ECS (JSON), ArcSight CEF and IBM QRadar LEEF.
//!
//! These renderings let Barzakh findings flow into Splunk, Elastic Security,
//! ArcSight and QRadar deployments directly from the CLI or the monitoring
//! agent.

use serde_json::json;

use crate::detector::{Finding, Severity};

/// Severity → numeric rating used by CEF/LEEF.
fn severity_rating(severity: Severity) -> u8 {
    match severity {
        Severity::Info => 1,
        Severity::Low => 3,
        Severity::Medium => 5,
        Severity::High => 7,
        Severity::Critical => 9,
    }
}

fn ecs_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "informational",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

/// Render one finding as an Elastic Common Schema (ECS) JSON event.
pub fn render_ecs_event(finding: &Finding, target: &str, timestamp: &str) -> serde_json::Value {
    json!({
        "@timestamp": timestamp,
        "ecs": { "version": "8.11.0" },
        "event": {
            "kind": "alert",
            "category": ["malware"],
            "type": ["user_agent", "detector"],
            "severity": ecs_severity(finding.severity),
            "risk_score": severity_rating(finding.severity) * 10,
            "dataset": "barzakh.firmware_scan",
            "module": "barzakh-scanner",
            "provider": "barzakh",
            "action": "firmware-scan-detection",
        },
        "rule": {
            "name": finding.title,
            "description": finding.description,
            "id": finding.detector,
        },
        "file": {
            "path": target,
        },
        "barzakh": {
            "detector": finding.detector,
            "severity": finding.severity.to_string(),
            "confidence": finding.confidence,
            "recommendation": finding.recommendation,
            "details": finding.details,
        },
    })
}

/// Render all findings as ECS JSON lines (one event per line — NDJSON).
pub fn render_ecs(findings: &[Finding], target: &str, timestamp: &str) -> String {
    findings
        .iter()
        .map(|f| render_ecs_event(f, target, timestamp).to_string())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// Escape a CEF extension field value (backslash and equals).
fn ccef_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('=', "\\=")
}

/// Render findings as ArcSight Common Event Format lines.
pub fn render_cef(findings: &[Finding], target: &str, timestamp: &str) -> String {
    findings
        .iter()
        .map(|f| {
            format!(
                "CEF:0|Barzakh|Scanner|{}|{}|{}|{}|rt={} cs1={} cs1Label=Target cs2={:.3} cs2Label=Confidence cs3={} cs3Label=Recommendation",
                env!("CARGO_PKG_VERSION"),
                f.detector,
                ccef_escape(&f.title),
                severity_rating(f.severity),
                timestamp,
                ccef_escape(target),
                f.confidence,
                ccef_escape(f.recommendation.as_deref().unwrap_or("-")),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// Render findings as IBM QRadar LEEF 2.0 lines.
pub fn render_leef(findings: &[Finding], target: &str, timestamp: &str) -> String {
    findings
        .iter()
        .map(|f| {
            format!(
                "LEEF:2.0|Barzakh|Scanner|{}|{}|devTime={} devTimeFormat=yyyy-MM-dd'T'HH:mm:ss.SSSXXX sev={} src={} fName={} confidence={:.3}",
                env!("CARGO_PKG_VERSION"),
                f.detector,
                timestamp,
                severity_rating(f.severity),
                ccef_escape(target),
                ccef_escape(&f.title),
                f.confidence,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Finding {
        Finding::new("blacklotus", Severity::Critical, "Bootkit found", "desc")
            .with_confidence(0.92)
            .with_recommendation("Reflash firmware")
    }

    #[test]
    fn ecs_event_shape() {
        let ev = render_ecs_event(&sample(), "fw.bin", "2026-01-01T00:00:00Z");
        assert_eq!(ev["event"]["kind"], "alert");
        assert_eq!(ev["rule"]["id"], "blacklotus");
        assert_eq!(ev["event"]["severity"], "critical");
        assert_eq!(ev["barzakh"]["confidence"], 0.92);
    }

    #[test]
    fn cef_lines_parse_shape() {
        let out = render_cef(&[sample()], "fw.bin", "2026-01-01T00:00:00Z");
        assert!(out.starts_with("CEF:0|Barzakh|Scanner|"));
        assert!(out.contains("|blacklotus|"));
        assert!(out.contains("cs1Label=Target"));
    }

    #[test]
    fn leef_lines_parse_shape() {
        let out = render_leef(&[sample()], "fw.bin", "2026-01-01T00:00:00Z");
        assert!(out.starts_with("LEEF:2.0|Barzakh|Scanner|"));
        assert!(out.contains("sev=9"));
        assert!(out.contains("fName=Bootkit found"));
    }

    #[test]
    fn ecs_ndjson_one_event_per_line() {
        let findings = vec![sample(), sample()];
        let out = render_ecs(&findings, "fw.bin", "2026-01-01T00:00:00Z");
        assert_eq!(out.lines().count(), 2);
        for line in out.lines() {
            assert!(serde_json::from_str::<serde_json::Value>(line).is_ok());
        }
    }
}
