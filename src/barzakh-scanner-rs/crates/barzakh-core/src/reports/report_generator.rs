use std::collections::HashMap;
use std::path::Path;

use chrono::Utc;
use serde_json::json;

use crate::baseline::Baseline;
use crate::detector::{Finding, Severity};
use crate::scoring::RiskScore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Html,
    Json,
    Markdown,
    /// SARIF 2.1.0 — GitHub Code Scanning compatible.
    Sarif,
    /// Flat CSV — spreadsheet / SIEM friendly.
    Csv,
    /// Elastic Common Schema NDJSON events.
    Ecs,
    /// ArcSight Common Event Format lines.
    Cef,
    /// IBM QRadar LEEF lines.
    Leef,
}

impl ReportFormat {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "html" => Some(Self::Html),
            "json" => Some(Self::Json),
            "markdown" | "md" => Some(Self::Markdown),
            "sarif" => Some(Self::Sarif),
            "csv" => Some(Self::Csv),
            "ecs" => Some(Self::Ecs),
            "cef" => Some(Self::Cef),
            "leef" => Some(Self::Leef),
            _ => None,
        }
    }
}

pub struct ReportGenerator<'a> {
    findings: &'a [Finding],
    #[allow(dead_code)]
    baseline: Option<&'a Baseline>,
    risk: RiskScore,
    target: String,
}

impl<'a> ReportGenerator<'a> {
    pub fn new(findings: &'a [Finding], baseline: Option<&'a Baseline>) -> Self {
        Self {
            findings,
            baseline,
            risk: RiskScore::from_findings(findings),
            target: "firmware.bin".to_string(),
        }
    }

    /// Attach an explicit risk score (otherwise derived from findings).
    pub fn with_risk(mut self, risk: RiskScore) -> Self {
        self.risk = risk;
        self
    }

    /// Attach the scanned target path (used in SARIF and SIEM output).
    pub fn with_target(mut self, target: &str) -> Self {
        self.target = target.to_string();
        self
    }

    pub fn generate(&self, output: &Path, format: ReportFormat) -> anyhow::Result<()> {
        match format {
            ReportFormat::Html => self.generate_html(output),
            ReportFormat::Json => self.generate_json(output),
            ReportFormat::Markdown => self.generate_markdown(output),
            ReportFormat::Sarif => crate::reports::sarif::write_sarif(
                output,
                self.findings,
                &self.target,
                env!("CARGO_PKG_VERSION"),
            ),
            ReportFormat::Csv => crate::reports::csv::write_csv(output, self.findings),
            ReportFormat::Ecs => {
                std::fs::write(
                    output,
                    crate::reports::siem::render_ecs(
                        self.findings,
                        &self.target,
                        &Utc::now().to_rfc3339(),
                    ),
                )?;
                Ok(())
            }
            ReportFormat::Cef => {
                std::fs::write(
                    output,
                    crate::reports::siem::render_cef(
                        self.findings,
                        &self.target,
                        &Utc::now().to_rfc3339(),
                    ),
                )?;
                Ok(())
            }
            ReportFormat::Leef => {
                std::fs::write(
                    output,
                    crate::reports::siem::render_leef(
                        self.findings,
                        &self.target,
                        &Utc::now().to_rfc3339(),
                    ),
                )?;
                Ok(())
            }
        }
    }

    fn generate_json(&self, output: &Path) -> anyhow::Result<()> {
        let report = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "target": self.target,
            "summary": {
                "total_findings": self.findings.len(),
                "critical": self.findings.iter().filter(|f| f.severity == Severity::Critical).count(),
                "high": self.findings.iter().filter(|f| f.severity == Severity::High).count(),
                "medium": self.findings.iter().filter(|f| f.severity == Severity::Medium).count(),
                "low": self.findings.iter().filter(|f| f.severity == Severity::Low).count(),
            },
            "risk": self.risk,
            "findings": self.findings,
            "correlated_threats": self.correlate_findings(),
        });

        let content = serde_json::to_string_pretty(&report)?;
        std::fs::write(output, content)?;
        Ok(())
    }

    fn generate_html(&self, output: &Path) -> anyhow::Result<()> {
        let critical = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let high = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count();
        let medium = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count();
        let low = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Low)
            .count();
        let info = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Info)
            .count();

        let mut findings_html = String::new();
        for finding in self.findings {
            let severity_class = match finding.severity {
                Severity::Critical => "critical",
                Severity::High => "high",
                Severity::Medium => "medium",
                Severity::Low => "low",
                Severity::Info => "info",
            };
            findings_html.push_str(&format!(
                r#"<div class="finding {cls}" data-sev="{sev}"><h3>{title}</h3><p class="severity">{sev} · {detector} · confidence {conf:.2}</p><p>{desc}</p>{rec}</div>"#,
                cls = severity_class,
                sev = finding.severity,
                title = html_escape(&finding.title),
                detector = html_escape(&finding.detector),
                conf = finding.confidence,
                desc = html_escape(&finding.description),
                rec = finding
                    .recommendation
                    .as_ref()
                    .map(|r| format!("<p class=\"rec\"><b>Recommendation:</b> {}</p>", html_escape(r)))
                    .unwrap_or_default(),
            ));
        }

        let risk_color = match self.risk.level {
            crate::scoring::RiskLevel::Clean => "#0a0",
            crate::scoring::RiskLevel::Low => "#0a0",
            crate::scoring::RiskLevel::Medium => "#fa0",
            crate::scoring::RiskLevel::Elevated => "#f80",
            crate::scoring::RiskLevel::High => "#f60",
            crate::scoring::RiskLevel::Critical => "#d00",
        };

        let html = format!(
            r#"<!DOCTYPE html>
<html><head><title>Barzakh Scanner Report</title>
<style>
body {{ font-family: sans-serif; margin: 2em; }}
.summary {{ margin-bottom: 2em; }}
.risk {{ border: 2px solid {risk_color}; border-radius: 8px; padding: 1em; margin-bottom: 1em; background: #fafafa; }}
.risk .score {{ font-size: 2em; font-weight: bold; color: {risk_color}; }}
.finding {{ border: 1px solid #ccc; padding: 1em; margin: 0.5em 0; border-radius: 4px; }}
.finding.critical {{ border-color: #d00; background: #fff0f0; }}
.finding.high {{ border-color: #f60; background: #fff5f0; }}
.finding.medium {{ border-color: #fa0; background: #fffaf0; }}
.finding.low {{ border-color: #0a0; background: #f0fff0; }}
.finding.info {{ border-color: #aaa; background: #f5f5f5; }}
.severity {{ font-weight: bold; text-transform: uppercase; }}
.rec {{ margin-top: 0.5em; }}
.filters button {{ margin-right: 0.5em; padding: 0.3em 0.8em; cursor: pointer; }}
.vector {{ font-family: monospace; font-size: 0.85em; color: #555; }}
</style></head><body>
<h1>Barzakh Scanner Report</h1>
<div class="risk">
  <span class="score">{score}/100</span> <b>{level}</b> risk
  <p class="vector">{vector}</p>
</div>
<div class="summary">
<h2>Summary</h2>
<p>Total findings: {total}</p>
<p>Critical: {critical} | High: {high} | Medium: {medium} | Low: {low} | Info: {info}</p>
</div>
<h2>Findings</h2>
<div class="filters">
  <button onclick="filter('all')">All</button>
  <button onclick="filter('critical')">Critical</button>
  <button onclick="filter('high')">High</button>
  <button onclick="filter('medium')">Medium</button>
  <button onclick="filter('low')">Low</button>
  <button onclick="filter('info')">Info</button>
</div>
{findings}
<script>
function filter(sev) {{
  document.querySelectorAll('.finding').forEach(el => {{
    el.style.display = (sev === 'all' || el.dataset.sev === sev) ? '' : 'none';
  }});
}}
</script>
</body></html>"#,
            risk_color = risk_color,
            score = self.risk.score,
            level = self.risk.level,
            vector = html_escape(&self.risk.vector),
            total = self.findings.len(),
            critical = critical,
            high = high,
            medium = medium,
            low = low,
            info = info,
            findings = findings_html,
        );

        std::fs::write(output, html)?;
        Ok(())
    }

    fn generate_markdown(&self, output: &Path) -> anyhow::Result<()> {
        let critical = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let high = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count();
        let medium = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count();
        let low = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Low)
            .count();

        let mut md = String::new();
        md.push_str("# Barzakh Scanner Report\n\n");
        md.push_str(&format!("Generated: {}\n\n", Utc::now().to_rfc3339()));
        md.push_str("## Risk Assessment\n\n");
        md.push_str(&format!(
            "**Risk score:** {}/100 (**{}**)\n\n",
            self.risk.score, self.risk.level
        ));
        md.push_str(&format!("**Vector:** `{}`\n\n", self.risk.vector));
        md.push_str("## Summary\n\n");
        md.push_str("| Severity | Count |\n");
        md.push_str("| --- | --- |\n");
        md.push_str(&format!("| Critical | {} |\n", critical));
        md.push_str(&format!("| High | {} |\n", high));
        md.push_str(&format!("| Medium | {} |\n", medium));
        md.push_str(&format!("| Low | {} |\n", low));
        md.push_str(&format!("| **Total** | **{}** |\n\n", self.findings.len()));

        md.push_str("## Findings\n\n");
        for finding in self.findings {
            md.push_str(&format!("### [{}] {}\n\n", finding.severity, finding.title));
            md.push_str(&format!("**Detector:** {}\n\n", finding.detector));
            md.push_str(&format!("**Confidence:** {:.2}\n\n", finding.confidence));
            md.push_str(&format!("{}\n\n", finding.description));
            if let Some(ref rec) = finding.recommendation {
                md.push_str(&format!("**Recommendation:** {}\n\n", rec));
            }
            md.push_str("---\n\n");
        }

        std::fs::write(output, md)?;
        Ok(())
    }

    fn correlate_findings(&self) -> Vec<serde_json::Value> {
        let mut address_groups: HashMap<String, Vec<&Finding>> = HashMap::new();

        for finding in self.findings {
            if let Some(ref details) = finding.details {
                if let Some(addr) = details.get("address").or(details.get("offset")) {
                    let key = addr.to_string();
                    address_groups.entry(key).or_default().push(finding);
                }
            }
        }

        let mut correlations = Vec::new();
        for (address, findings) in &address_groups {
            if findings.len() > 1 {
                let max_severity = findings
                    .iter()
                    .map(|f| f.severity)
                    .max()
                    .unwrap_or(Severity::Info);
                correlations.push(json!({
                    "address": address,
                    "finding_count": findings.len(),
                    "max_severity": max_severity,
                    "detectors": findings.iter().map(|f| &f.detector).collect::<Vec<_>>(),
                }));
            }
        }

        correlations
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
