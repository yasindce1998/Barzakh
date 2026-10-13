//! CSV export of scan findings — spreadsheet / SIEM friendly.

use std::io::Write;
use std::path::Path;

use crate::detector::Finding;

/// CSV column headers.
pub const CSV_HEADERS: &[&str] = &[
    "detector",
    "severity",
    "confidence",
    "title",
    "description",
    "recommendation",
];

fn csv_escape(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// Render findings as CSV rows (no header).
pub fn render_csv_rows(findings: &[Finding]) -> String {
    let mut out = String::new();
    for f in findings {
        let recommendation = f.recommendation.as_deref().unwrap_or("");
        for part in [
            f.detector.as_str(),
            &f.severity.to_string(),
            &format!("{:.3}", f.confidence),
            f.title.as_str(),
            f.description.as_str(),
            recommendation,
        ] {
            out.push_str(&csv_escape(part));
            out.push(',');
        }
        out.pop();
        out.push('\n');
    }
    out
}

/// Render a full CSV document with header row.
pub fn render_csv(findings: &[Finding]) -> String {
    format!("{}\n{}", CSV_HEADERS.join(","), render_csv_rows(findings))
}

/// Write a CSV report to `output`.
pub fn write_csv(output: &Path, findings: &[Finding]) -> anyhow::Result<()> {
    let mut file = std::fs::File::create(output)?;
    writeln!(file, "{}", CSV_HEADERS.join(","))?;
    write!(file, "{}", render_csv_rows(findings))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::Severity;

    #[test]
    fn escapes_commas_and_quotes() {
        let f = Finding::new("d", Severity::High, "has, comma", "has \"quotes\"");
        let csv = render_csv(&[f]);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(
            lines[0],
            "detector,severity,confidence,title,description,recommendation"
        );
        assert!(lines[1].contains("\"has, comma\""));
        assert!(lines[1].contains("\"has \"\"quotes\"\"\""));
    }

    #[test]
    fn round_trips_row_count() {
        let findings = vec![
            Finding::new("a", Severity::Low, "t", "d"),
            Finding::new("b", Severity::Info, "t", "d"),
        ];
        let csv = render_csv(&findings);
        assert_eq!(csv.lines().count(), 3); // header + 2
    }
}
