//! IOC feed ingestion and matching.
//!
//! Feed format (JSON):
//!
//! ```json
//! {
//!   "name": "barzakh-default",
//!   "version": 1,
//!   "iocs": [
//!     {
//!       "sha256": "aaaa...",
//!       "pattern": "hex:DEADBEEF",
//!       "family": "LoJax",
//!       "cve": null,
//!       "description": "LoJax SPI implant marker"
//!     }
//!   ]
//! }
//! ```

use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use barzakh_core::{Detector, DetectorError, Finding, Severity};

/// A single indicator of compromise.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ioc {
    /// Full SHA-256 of a known-malicious image.
    #[serde(default)]
    pub sha256: Option<String>,
    /// Byte pattern: `hex:DE AD BE EF` (wildcards `??`) or plain ASCII.
    #[serde(default)]
    pub pattern: Option<String>,
    /// Suspicious UEFI variable name.
    #[serde(default)]
    pub variable: Option<String>,
    /// Malware family (LoJax, BlackLotus, ...).
    #[serde(default)]
    pub family: Option<String>,
    /// Related CVE.
    #[serde(default)]
    pub cve: Option<String>,
    pub description: String,
}

/// A threat-intelligence feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocFeed {
    pub name: String,
    pub version: u32,
    #[serde(default)]
    pub updated: Option<String>,
    pub iocs: Vec<Ioc>,
}

impl IocFeed {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&content)?)
    }

    /// Save the feed as JSON.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    /// Match a firmware image against the feed.
    pub fn match_image(&self, data: &[u8]) -> Vec<(&Ioc, String)> {
        let mut hits = Vec::new();

        let hash: String = {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher
                .finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        };

        for ioc in &self.iocs {
            if let Some(needle) = &ioc.sha256 {
                if needle.eq_ignore_ascii_case(&hash) {
                    hits.push((ioc, format!("sha256 match ({hash})")));
                    continue;
                }
            }
            if let Some(pattern) = &ioc.pattern {
                if let Some(hex) = pattern.strip_prefix("hex:") {
                    if let Some(pos) = find_hex_pattern(data, hex) {
                        hits.push((ioc, format!("pattern at 0x{pos:08X}")));
                        continue;
                    }
                } else if let Some(pos) = data
                    .windows(pattern.len())
                    .position(|w| w == pattern.as_bytes())
                {
                    hits.push((ioc, format!("string at 0x{pos:08X}")));
                    continue;
                }
            }
            if let Some(variable) = &ioc.variable {
                if data
                    .windows(variable.len())
                    .any(|w| w == variable.as_bytes())
                {
                    hits.push((ioc, "variable name present".to_string()));
                }
            }
        }

        hits
    }
}

/// Find a hex pattern (space-separated bytes, `??` wildcard).
fn find_hex_pattern(data: &[u8], hex: &str) -> Option<usize> {
    let bytes: Vec<Option<u8>> = hex
        .split_whitespace()
        .map(|tok| match tok {
            "??" | "**" => None,
            _ => Some(u8::from_str_radix(tok, 16).ok()?),
        })
        .collect();
    if bytes.is_empty() || bytes.len() > data.len() {
        return None;
    }
    (0..=data.len() - bytes.len()).find(|&i| {
        bytes
            .iter()
            .zip(&data[i..])
            .all(|(pat, actual)| pat.is_none_or(|p| p == *actual))
    })
}

/// Detector that matches firmware against an IOC feed.
pub struct IocFeedDetector {
    feed: IocFeed,
}

impl IocFeedDetector {
    pub fn new(feed: IocFeed) -> Self {
        Self { feed }
    }

    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        Ok(Self::new(IocFeed::load(path)?))
    }
}

impl Detector for IocFeedDetector {
    fn name(&self) -> &str {
        "ioc_feed"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let hits = self.feed.match_image(&data);

        Ok(hits
            .into_iter()
            .map(|(ioc, evidence)| {
                Finding::new(
                    "ioc_feed",
                    Severity::Critical,
                    &format!(
                        "Threat-intel match: {}",
                        ioc.family.as_deref().unwrap_or("unknown family")
                    ),
                    &format!(
                        "Image matches an IOC from feed '{}': {}. Evidence: {}.{}",
                        self.feed.name,
                        ioc.description,
                        evidence,
                        ioc.cve
                            .as_deref()
                            .map(|c| format!(" Related: {c}."))
                            .unwrap_or_default(),
                    ),
                )
                .with_confidence(0.95)
                .with_details(serde_json::json!({
                    "feed": self.feed.name,
                    "family": ioc.family,
                    "cve": ioc.cve,
                    "evidence": evidence,
                }))
                .with_recommendation(
                    "Treat the image as malicious: isolate the source, compare against \
                     a known-good vendor image, and check related advisories.",
                )
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_feed() -> IocFeed {
        IocFeed {
            name: "test-feed".to_string(),
            version: 1,
            updated: None,
            iocs: vec![
                Ioc {
                    sha256: None,
                    pattern: Some("hex:DE AD BE EF".to_string()),
                    variable: None,
                    family: Some("LoJax".to_string()),
                    cve: None,
                    description: "LoJax marker".to_string(),
                },
                Ioc {
                    sha256: None,
                    pattern: Some("MokManagerTUI".to_string()),
                    variable: None,
                    family: Some("BlackLotus".to_string()),
                    cve: Some("CVE-2023-24932".to_string()),
                    description: "BlackLotus MOK tool".to_string(),
                },
                Ioc {
                    sha256: Some(
                        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                            .to_string(),
                    ),
                    pattern: None,
                    variable: None,
                    family: Some("CosmicStrand".to_string()),
                    cve: None,
                    description: "Known-bad image hash".to_string(),
                },
            ],
        }
    }

    #[test]
    fn matches_hex_pattern() {
        let feed = sample_feed();
        let mut data = vec![0u8; 128];
        data[64..68].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let hits = feed.match_image(&data);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0.family.as_deref(), Some("LoJax"));
        assert!(hits[0].1.contains("0x00000040"));
    }

    #[test]
    fn matches_string_pattern() {
        let feed = sample_feed();
        let data = b"\x00\x00MokManagerTUI\x00".to_vec();
        let hits = feed.match_image(&data);
        assert!(hits
            .iter()
            .any(|(ioc, _)| ioc.family.as_deref() == Some("BlackLotus")));
    }

    #[test]
    fn matches_sha256() {
        let feed = sample_feed();
        // sha256("abc")
        let data = b"abc".to_vec();
        let hits = feed.match_image(&data);
        assert!(hits
            .iter()
            .any(|(ioc, _)| ioc.family.as_deref() == Some("CosmicStrand")));
    }

    #[test]
    fn quiet_on_clean_data() {
        let feed = sample_feed();
        assert!(feed.match_image(&[0u8; 512]).is_empty());
    }

    #[test]
    fn round_trips_json() {
        let feed = sample_feed();
        let json = serde_json::to_string(&feed).unwrap();
        let parsed: IocFeed = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.iocs.len(), 3);
    }
}
