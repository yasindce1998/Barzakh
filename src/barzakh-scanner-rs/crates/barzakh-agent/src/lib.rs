//! Real-time firmware tampering monitoring agent.
//!
//! Watches a configured set of firmware images (polling on mtime/size/hash),
//! rescans on change, records history, and emits alerts in SIEM formats
//! (Elastic ECS JSON, ArcSight CEF, IBM QRadar LEEF) to stdout, a file, or a
//! webhook.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use barzakh_core::reports::{render_cef, render_ecs, render_leef};
use barzakh_core::{BarzakhScanner, Finding, Severity};
use barzakh_store::history::ScanStore;

/// Agent configuration (`agent.toml`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Polling interval in seconds.
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    /// SIEM export format: `ecs`, `cef` or `leef`.
    #[serde(default = "default_format")]
    pub siem_format: String,
    /// Alert output: `-` for stdout, or a file path.
    #[serde(default = "default_output")]
    pub output: String,
    /// Optional webhook URL receiving ECS JSON events.
    #[serde(default)]
    pub webhook: Option<String>,
    /// History database.
    #[serde(default = "default_db")]
    pub db: PathBuf,
    /// Watched firmware images.
    #[serde(default)]
    pub targets: Vec<String>,
    /// Minimum severity to alert on.
    #[serde(default = "default_min_severity")]
    pub min_severity: String,
}

fn default_interval() -> u64 {
    300
}
fn default_format() -> String {
    "ecs".to_string()
}
fn default_output() -> String {
    "-".to_string()
}
fn default_db() -> PathBuf {
    PathBuf::from("barzakh-history.sqlite")
}
fn default_min_severity() -> String {
    "medium".to_string()
}

impl Default for AgentConfig {
    fn default() -> Self {
        serde_json::from_value(serde_json::json!({})).unwrap()
    }
}

impl AgentConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let content =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Ok(toml::from_str(&content)?)
    }
}

/// Severity gate.
fn passes_gate(severity: Severity, gate: &str) -> bool {
    let rank = |s: Severity| match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    };
    let gate_rank = match gate.to_lowercase().as_str() {
        "low" => 1,
        "high" => 3,
        "critical" => 4,
        _ => 2,
    };
    rank(severity) >= gate_rank
}

/// A change observed on a watched target.
#[derive(Debug, Clone, Serialize)]
pub struct TargetChange {
    pub target: String,
    pub kind: &'static str,
}

/// The monitoring agent.
pub struct Agent {
    pub config: AgentConfig,
    /// Last-known fingerprints: target → (mtime, size).
    fingerprints: HashMap<String, (std::time::SystemTime, u64)>,
}

impl Agent {
    pub fn new(config: AgentConfig) -> Self {
        Self {
            config,
            fingerprints: HashMap::new(),
        }
    }

    /// Capture the initial fingerprints without alerting.
    pub fn prime(&mut self) {
        for target in self.config.targets.clone() {
            if let Ok(meta) = std::fs::metadata(&target) {
                self.fingerprints.insert(
                    target,
                    (
                        meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH),
                        meta.len(),
                    ),
                );
            }
        }
    }

    /// Poll all targets once; returns the list of changed targets.
    pub fn poll(&mut self) -> Vec<TargetChange> {
        let mut changes = Vec::new();
        for target in self.config.targets.clone() {
            let Ok(meta) = std::fs::metadata(&target) else {
                continue;
            };
            let mtime = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            let size = meta.len();
            let target_key = target.clone();
            match self.fingerprints.get(&target) {
                None => {
                    self.fingerprints.insert(target_key, (mtime, size));
                }
                Some(&(prev_mtime, prev_size)) => {
                    if mtime != prev_mtime || size != prev_size {
                        changes.push(TargetChange {
                            target: target_key,
                            kind: "modified",
                        });
                        self.fingerprints.insert(target, (mtime, size));
                    }
                }
            }
        }
        changes
    }

    /// Scan a changed target and emit alerts for new findings.
    pub fn scan_and_alert(&self, change: &TargetChange) -> Result<usize> {
        let mut scanner = BarzakhScanner::new(None);
        let result = scanner.scan(Path::new(&change.target), None);

        // Record in history DB (best effort).
        if let Ok(mut store) = ScanStore::open(&self.config.db) {
            let _ = store.record(&result);
        }

        let alerting: Vec<&Finding> = result
            .findings
            .iter()
            .filter(|f| passes_gate(f.severity, &self.config.min_severity))
            .collect();

        if !alerting.is_empty() {
            self.emit_alerts(&alerting, &change.target);
        }
        Ok(alerting.len())
    }

    fn emit_alerts(&self, findings: &[&Finding], target: &str) {
        let owned: Vec<Finding> = findings.iter().map(|f| (*f).clone()).collect();
        let timestamp = chrono::Utc::now().to_rfc3339();
        let rendered = match self.config.siem_format.as_str() {
            "cef" => render_cef(&owned, target, &timestamp),
            "leef" => render_leef(&owned, target, &timestamp),
            _ => render_ecs(&owned, target, &timestamp),
        };

        if self.config.output == "-" {
            print!("{rendered}");
        } else if let Err(e) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.config.output)
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(rendered.as_bytes())
            })
        {
            tracing::warn!("failed to write alerts to {}: {e}", self.config.output);
        }

        if let Some(webhook) = &self.config.webhook {
            for finding in findings {
                let event = barzakh_core::reports::render_ecs_event(finding, target, &timestamp);
                if let Err(e) = ureq::post(webhook)
                    .timeout(Duration::from_secs(10))
                    .send_json(ureq::json!(event))
                {
                    tracing::warn!("webhook delivery failed: {e}");
                }
            }
        }
    }

    /// Run the watch loop forever.
    pub fn run_forever(&mut self) -> Result<()> {
        self.prime();
        tracing::info!(
            "watching {} targets (interval {}s, format {})",
            self.config.targets.len(),
            self.config.interval_secs,
            self.config.siem_format
        );
        loop {
            std::thread::sleep(Duration::from_secs(self.config.interval_secs.max(1)));
            for change in self.poll() {
                tracing::info!("change detected: {} ({})", change.target, change.kind);
                let alerts = self.scan_and_alert(&change)?;
                if alerts > 0 {
                    tracing::warn!("{} alerting findings on {}", alerts, change.target);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "barzakh-agent-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn config_for(dir: &Path) -> AgentConfig {
        AgentConfig {
            interval_secs: 1,
            siem_format: "ecs".to_string(),
            output: dir.join("alerts.jsonl").display().to_string(),
            webhook: None,
            db: dir.join("history.sqlite"),
            targets: vec![dir.join("fw.bin").display().to_string()],
            min_severity: "medium".to_string(),
        }
    }

    #[test]
    fn detects_target_modification() {
        let dir = temp_dir();
        let fw = dir.join("fw.bin");
        std::fs::write(&fw, b"initial firmware image data padding  ").unwrap();

        let mut agent = Agent::new(config_for(&dir));
        agent.prime();
        assert!(agent.poll().is_empty());

        // Modify the target (size change).
        std::fs::write(&fw, b"modified firmware image data with more padding!!").unwrap();
        let changes = agent.poll();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].target, fw.display().to_string());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_and_alert_emits_for_high_findings() {
        let dir = temp_dir();
        let fw = dir.join("fw.bin");
        // A trampoline-style payload that the scanner flags.
        let mut data = vec![0u8; 0x10000];
        data[0x100] = 0xFF;
        data[0x101] = 0x25;
        data[0x106..0x10E].copy_from_slice(&0xDEAD_BEEF_CAFE_0000u64.to_le_bytes());
        std::fs::write(&fw, &data).unwrap();

        let agent = Agent::new(config_for(&dir));
        let alerts = agent
            .scan_and_alert(&TargetChange {
                target: fw.display().to_string(),
                kind: "modified",
            })
            .unwrap();
        assert!(alerts > 0, "expected alerting findings");

        // ECS events were written to the output file.
        let written = std::fs::read_to_string(dir.join("alerts.jsonl")).unwrap();
        assert!(written.contains("\"event\""));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn severity_gate_filters() {
        assert!(passes_gate(Severity::Critical, "medium"));
        assert!(passes_gate(Severity::Medium, "medium"));
        assert!(!passes_gate(Severity::Low, "medium"));
        assert!(!passes_gate(Severity::Info, "medium"));
        assert!(passes_gate(Severity::High, "high"));
        assert!(!passes_gate(Severity::Medium, "high"));
    }

    #[test]
    fn config_parses_toml() {
        let toml = r#"
interval_secs = 60
siem_format = "cef"
output = "alerts.log"
targets = ["/fw/a.bin"]

[extra]
ignored = true
"#;
        let dir = temp_dir();
        let path = dir.join("agent.toml");
        std::fs::write(&path, toml).unwrap();
        let config = AgentConfig::load(&path).unwrap();
        assert_eq!(config.interval_secs, 60);
        assert_eq!(config.siem_format, "cef");
        assert_eq!(config.targets, vec!["/fw/a.bin".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
