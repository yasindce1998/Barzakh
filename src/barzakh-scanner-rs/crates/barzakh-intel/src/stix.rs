//! STIX 2.1 bundle ingestion.
//!
//! Parses STIX 2.1 cyber-threat-intelligence bundles (the format
//! published by CISA, MISP exports, and TAXII collections) and converts
//! firmware-relevant indicators into the internal [`IocFeed`] format,
//! where they feed the standard `ioc_feed` detector.
//!
//! Supported STIX pattern clauses (others are counted and skipped):
//!
//! | STIX pattern | IOC field |
//! |--------------|-----------|
//! | `[file:hashes.'SHA-256' = '<hex>']` | `sha256` |
//! | `[file:name = '<name>']` | `pattern` (ASCII string match) |
//!
//! Family attribution follows `relationship_type: "indicates"` edges
//! from indicators to `malware` objects: the malware name becomes the
//! IOC's `family` field, so findings read e.g. "Threat-intel match:
//! LoJax".
//!
//! ```
//! use barzakh_intel::stix::StixBundle;
//!
//! let bundle: StixBundle = serde_json::from_str(BUNDLE_JSON).unwrap();
//! let feed = bundle.to_ioc_feed("csa");
//! assert_eq!(feed.iocs.len(), 1);
//! # static BUNDLE_JSON: &str = r#"{
//! #   "type": "bundle", "id": "bundle--x",
//! #   "objects": [{
//! #     "type": "indicator", "id": "indicator--1",
//! #     "pattern": "[file:hashes.'SHA-256' = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']",
//! #     "description": "LoJax implant"
//! #   }]
//! # }"#;
//! ```

use serde::Deserialize;

use crate::ioc::{Ioc, IocFeed};

/// A STIX 2.1 bundle (`type: "bundle"`).
#[derive(Debug, Clone, Deserialize)]
pub struct StixBundle {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub objects: Vec<StixObject>,
}

/// A single STIX object; only the fields relevant to IOC conversion are
/// strongly typed — the standard mandates many more, which are ignored.
#[derive(Debug, Clone, Deserialize)]
pub struct StixObject {
    #[serde(rename = "type")]
    pub object_type: String,
    #[serde(default)]
    pub id: String,
    // Indicator fields.
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub labels: Vec<String>,
    // Malware fields.
    #[serde(default)]
    pub is_family: Option<bool>,
    // Relationship fields.
    #[serde(default)]
    pub relationship_type: Option<String>,
    #[serde(default)]
    pub source_ref: Option<String>,
    #[serde(default)]
    pub target_ref: Option<String>,
}

/// Statistics from a bundle conversion.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ConversionReport {
    /// Indicators seen in the bundle.
    pub indicators: usize,
    /// IOC entries produced.
    pub produced: usize,
    /// Pattern clauses converted.
    pub clauses_converted: usize,
    /// Pattern clauses skipped (unsupported object path / hash type).
    pub clauses_skipped: usize,
    /// Indicators that produced no IOC at all.
    pub indicators_without_iocs: usize,
    /// Family attributions resolved via `indicates` relationships.
    pub families_resolved: usize,
}

impl StixBundle {
    /// Parse a bundle from raw JSON.
    pub fn parse(json: &str) -> anyhow::Result<Self> {
        Ok(serde_json::from_str(json)?)
    }

    /// Load a bundle from a file.
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        Self::parse(&std::fs::read_to_string(path)?)
    }

    /// Convert the bundle's indicators into an [`IocFeed`] consumable by
    /// the `ioc_feed` detector.
    pub fn to_ioc_feed(&self, name: &str) -> IocFeed {
        self.convert(name).0
    }

    /// Convert with a detailed [`ConversionReport`].
    pub fn convert(&self, name: &str) -> (IocFeed, ConversionReport) {
        let mut report = ConversionReport::default();

        // Index malware objects by id for family attribution.
        let malware_names: std::collections::HashMap<String, String> = self
            .objects
            .iter()
            .filter(|o| o.object_type == "malware" && o.is_family.unwrap_or(false))
            .map(|o| {
                (
                    o.id.clone(),
                    o.name.clone().unwrap_or_else(|| "unknown".into()),
                )
            })
            .collect();

        // `indicates` relationships: indicator id -> malware family name.
        let mut indicated_family: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for object in &self.objects {
            if object.object_type == "relationship"
                && object.relationship_type.as_deref() == Some("indicates")
            {
                if let (Some(source), Some(target)) =
                    (object.source_ref.as_deref(), object.target_ref.as_deref())
                {
                    if let Some(family) = malware_names.get(target) {
                        indicated_family.insert(source.to_string(), family.clone());
                    }
                }
            }
        }

        let mut iocs = Vec::new();
        for object in &self.objects {
            if object.object_type != "indicator" {
                continue;
            }
            report.indicators += 1;
            let Some(pattern) = object.pattern.as_deref() else {
                report.indicators_without_iocs += 1;
                continue;
            };

            let family = indicated_family
                .get(&object.id)
                .cloned()
                .or_else(|| family_from_labels(&object.labels));
            if family.is_some() {
                report.families_resolved += 1;
            }
            let description = object
                .description
                .clone()
                .or_else(|| object.name.clone())
                .unwrap_or_else(|| "STIX indicator".into());

            let mut produced_here = false;
            for clause in pattern_clauses(pattern) {
                match clause {
                    PatternClause::Sha256(hex) => {
                        iocs.push(Ioc {
                            sha256: Some(hex),
                            pattern: None,
                            variable: None,
                            family: family.clone(),
                            cve: None,
                            description: description.clone(),
                        });
                        report.clauses_converted += 1;
                        produced_here = true;
                    }
                    PatternClause::FileName(file_name) => {
                        iocs.push(Ioc {
                            sha256: None,
                            pattern: Some(file_name),
                            variable: None,
                            family: family.clone(),
                            cve: None,
                            description: description.clone(),
                        });
                        report.clauses_converted += 1;
                        produced_here = true;
                    }
                    PatternClause::Unsupported => {
                        report.clauses_skipped += 1;
                    }
                }
            }
            if !produced_here {
                report.indicators_without_iocs += 1;
            }
        }

        report.produced = iocs.len();
        (
            IocFeed {
                name: name.to_string(),
                version: 1,
                updated: None,
                iocs,
            },
            report,
        )
    }
}

/// One interpreted clause of a STIX pattern.
#[derive(Debug, Clone, PartialEq)]
enum PatternClause {
    Sha256(String),
    FileName(String),
    Unsupported,
}

/// Split a STIX pattern into its comparison clauses.
///
/// Handles the common forms: `[file:hashes.'SHA-256' = '…']` and
/// `[a = '…' OR b = '…']`. Multi-bracket `AND` compound observations
/// are treated the same way (every clause inspected). Quote escaping
/// (`''`) is respected so separators inside values do not split.
fn pattern_clauses(pattern: &str) -> Vec<PatternClause> {
    // Strip brackets, tracking single-quoted strings (STIX escapes a
    // quote by doubling it).
    let mut in_quote = false;
    let mut current = String::new();
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                current.push(c);
                if in_quote && chars.peek() == Some(&'\'') {
                    // Escaped quote: keep both, stay inside the string.
                    current.push('\'');
                    chars.next();
                } else {
                    in_quote = !in_quote;
                }
            }
            '[' | ']' if !in_quote => {}
            _ => current.push(c),
        }
    }

    // Clause separators: OR / AND at top level.
    let normalized = current.replace(" OR ", "\u{0}").replace(" AND ", "\u{0}");
    normalized
        .split('\u{0}')
        .filter_map(|raw| {
            let clause = raw.trim();
            if clause.is_empty() {
                None
            } else {
                Some(parse_clause(clause))
            }
        })
        .collect()
}

/// Parse one `object-path op value` clause.
fn parse_clause(clause: &str) -> PatternClause {
    // Find the comparison operator outside quotes.
    let Some((path, rest)) = clause.split_once('=') else {
        return PatternClause::Unsupported;
    };
    let path = path.trim().to_ascii_lowercase();
    let value = rest.trim().trim_matches('\'').replace("''", "'");

    if path.starts_with("file:hashes.") {
        let hash_type = path
            .strip_prefix("file:hashes.")
            .unwrap_or("")
            .trim_matches(|c| c == '\'' || c == '"');
        if hash_type == "sha-256" || hash_type == "sha256" {
            let clean: String = value.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            if clean.len() == 64 {
                return PatternClause::Sha256(clean.to_ascii_lowercase());
            }
        }
        // MD5 / SHA-1 / SHA-512: the internal feed matches SHA-256 only.
        return PatternClause::Unsupported;
    }
    if path == "file:name" && !value.is_empty() {
        return PatternClause::FileName(value);
    }
    PatternClause::Unsupported
}

/// Some feeds tag families via labels instead of relationships.
fn family_from_labels(labels: &[String]) -> Option<String> {
    labels
        .iter()
        .map(|l| l.trim())
        .find(|l| !l.is_empty() && *l != "malicious-activity")
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic public-feed-shaped bundle (CISA-style objects with
    /// spec_version, timestamps, and full ids).
    const BUNDLE: &str = r#"{
        "type": "bundle",
        "id": "bundle--8fab937e-b694-11e3-b71c-0800271e87d0",
        "spec_version": "2.1",
        "objects": [
            {
                "type": "malware",
                "spec_version": "2.1",
                "id": "malware--faa5b705-9991-4d51-91e2",
                "name": "LoJax",
                "is_family": true,
                "malware_types": ["bootkit", "uefi-implant"]
            },
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--a",
                "created": "2026-01-01T00:00:00.000Z",
                "modified": "2026-01-01T00:00:00.000Z",
                "pattern": "[file:hashes.'SHA-256' = 'AA11AA11AA11AA11AA11AA11AA11AA11AA11AA11AA11AA11AA11AA11AA11AA11']",
                "pattern_type": "stix",
                "valid_from": "2026-01-01T00:00:00Z",
                "labels": ["bootkit"],
                "description": "LoJax SPI flash implant driver",
                "indicator_types": ["malicious-activity"]
            },
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--b",
                "created": "2026-01-01T00:00:00.000Z",
                "pattern": "[file:hashes.MD5 = '0123456789abcdef0123456789abcdef'] OR [file:name = 'systemd_joined.efi']",
                "description": "LoJax dropper component"
            },
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--c",
                "pattern": "[process:command_line = 'not relevant']",
                "description": "host-level indicator"
            },
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--1",
                "relationship_type": "indicates",
                "source_ref": "indicator--a",
                "target_ref": "malware--faa5b705-9991-4d51-91e2"
            }
        ]
    }"#;

    #[test]
    fn parses_public_shaped_bundle() {
        let bundle = StixBundle::parse(BUNDLE).unwrap();
        assert_eq!(bundle.objects.len(), 5);
    }

    #[test]
    fn converts_indicators_to_iocs() {
        let bundle = StixBundle::parse(BUNDLE).unwrap();
        let (feed, report) = bundle.convert("test-feed");
        assert_eq!(report.indicators, 3);
        // SHA-256 from indicator--a + file name from indicator--b.
        assert_eq!(report.produced, 2);
        assert_eq!(report.clauses_skipped, 2); // MD5 + process:command_line
        assert_eq!(report.indicators_without_iocs, 1);

        // Family attribution through the `indicates` relationship.
        let sha_ioc = feed
            .iocs
            .iter()
            .find(|i| i.sha256.is_some())
            .expect("sha256 ioc");
        assert_eq!(sha_ioc.family.as_deref(), Some("LoJax"));
        assert_eq!(
            sha_ioc.sha256.as_deref(),
            Some("aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11")
        );

        let name_ioc = feed
            .iocs
            .iter()
            .find(|i| i.pattern.as_deref() == Some("systemd_joined.efi"))
            .expect("file-name ioc");
        assert!(name_ioc.sha256.is_none());
    }

    #[test]
    fn round_trips_into_scan_findings() {
        use sha2::{Digest, Sha256};

        // A firmware image whose SHA-256 is the indicator's value.
        let image = b"fake lojax implant image contents".to_vec();
        let digest = Sha256::digest(&image);
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        let bundle_json = format!(
            r#"{{
                "type": "bundle",
                "id": "bundle--t",
                "objects": [
                    {{"type": "malware", "id": "malware--f", "name": "LoJax", "is_family": true}},
                    {{"type": "indicator", "id": "indicator--h", "pattern": "[file:hashes.'SHA-256' = '{hex}']", "description": "implant by hash"}},
                    {{"type": "relationship", "id": "rel--1", "relationship_type": "indicates", "source_ref": "indicator--h", "target_ref": "malware--f"}}
                ]
            }}"#
        );
        let bundle = StixBundle::parse(&bundle_json).unwrap();
        let feed = bundle.to_ioc_feed("round-trip");

        // Feed → detector → findings.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("image.bin");
        std::fs::write(&target, &image).unwrap();

        let detector = crate::ioc::IocFeedDetector::new(feed);
        let findings = barzakh_core::Detector::detect(&detector, &target).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, "ioc_feed");
        assert_eq!(findings[0].severity, barzakh_core::Severity::Critical);
        // The family attribution from the `indicates` relationship
        // surfaces in the finding title.
        assert!(
            findings[0].title.contains("LoJax"),
            "title: {}",
            findings[0].title
        );
        assert!(findings[0].description.contains("implant by hash"));
    }

    #[test]
    fn pattern_clause_parsing() {
        assert_eq!(
            pattern_clauses("[file:hashes.'SHA-256' = 'AB']"),
            vec![PatternClause::Unsupported] // not 64 hex digits
        );
        assert_eq!(
            pattern_clauses("[file:name = 'x''y.efi']"),
            vec![PatternClause::FileName("x'y.efi".into())]
        );
        // OR splits into two clauses.
        let clauses = pattern_clauses("[file:name = 'a.efi' OR file:name = 'b.efi']");
        assert_eq!(clauses.len(), 2);
    }
}
