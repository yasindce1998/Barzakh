//! Attack scenario builder: chain multiple adversary payloads into a
//! multi-stage intrusion simulation.
//!
//! Scenarios are TOML files:
//!
//! ```toml
//! [scenario]
//! name = "smm-persistence-chain"
//! description = "DXE foothold → SMM persistence → runtime hook"
//! architecture = "x86_64"
//! mitre = ["T1542.001", "T1542.003"]
//!
//! [[stages]]
//! payload = "boot_services_hook"
//! label = "foothold"
//!
//! [[stages]]
//! payload = "smm_timing_anomaly"
//! label = "smm-persistence"
//! depends_on = ["foothold"]
//! ```
//!
//! `run_scenario` generates every stage payload in dependency order, scans
//! each generated artifact, and verifies the detection chain — later stages
//! must still be detected for the scenario to validate.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use barzakh_core::BarzakhScanner;

use crate::{create_all_payloads, Payload, PayloadConfig};

/// Scenario metadata (`[scenario]` table).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioMeta {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub architecture: Option<String>,
    #[serde(default)]
    pub mitre: Vec<String>,
}

/// One stage of the attack chain (`[[stages]]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage {
    /// Payload generator name (as in `barzakh-adversary generate --list`).
    pub payload: String,
    /// Short label referenced by `depends_on`.
    pub label: String,
    #[serde(default)]
    pub depends_on: Vec<String>,
}

/// A parsed scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    pub scenario: ScenarioMeta,
    pub stages: Vec<Stage>,
}

/// Result of running one stage.
#[derive(Debug, Clone, Serialize)]
pub struct StageResult {
    pub label: String,
    pub payload: String,
    pub generated_file: PathBuf,
    /// Detectors that fired on this stage artifact.
    pub detected_by: Vec<String>,
    pub risk_score: u32,
    pub detected: bool,
}

/// Full scenario run report.
#[derive(Debug, Clone, Serialize)]
pub struct ScenarioRunReport {
    pub name: String,
    pub stages: Vec<StageResult>,
    /// True when every stage produced at least one detection.
    pub chain_validated: bool,
    pub chain_rendering: String,
}

impl Scenario {
    pub fn parse(content: &str) -> Result<Self> {
        let scenario: Scenario =
            toml::from_str(content).context("failed to parse scenario TOML")?;
        if scenario.stages.is_empty() {
            bail!("scenario {} has no stages", scenario.scenario.name);
        }

        // Validate dependency graph: labels unique, deps resolvable, acyclic.
        let labels: Vec<&str> = scenario.stages.iter().map(|s| s.label.as_str()).collect();
        for label in &labels {
            if labels.iter().filter(|l| **l == *label).count() > 1 {
                bail!("duplicate stage label '{label}'");
            }
        }
        for stage in &scenario.stages {
            for dep in &stage.depends_on {
                if !labels.contains(&dep.as_str()) {
                    bail!("stage '{}' depends on unknown label '{dep}'", stage.label);
                }
            }
        }

        // Topological check via Kahn's algorithm.
        let mut indegree: HashMap<&str, usize> = HashMap::new();
        let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();
        for stage in &scenario.stages {
            indegree.insert(&stage.label, stage.depends_on.len());
            for dep in &stage.depends_on {
                dependents
                    .entry(dep.as_str())
                    .or_default()
                    .push(&stage.label);
            }
        }
        let mut queue: Vec<&str> = indegree
            .iter()
            .filter(|(_, &d)| d == 0)
            .map(|(&l, _)| l)
            .collect();
        let mut visited = 0usize;
        while let Some(label) = queue.pop() {
            visited += 1;
            if let Some(children) = dependents.get(label) {
                for child in children {
                    let d = indegree.get_mut(*child).unwrap();
                    *d -= 1;
                    if *d == 0 {
                        queue.push(child);
                    }
                }
            }
        }
        if visited != scenario.stages.len() {
            bail!("scenario {} has a dependency cycle", scenario.scenario.name);
        }

        Ok(scenario)
    }

    pub fn load(path: &Path) -> Result<Self> {
        Self::parse(&std::fs::read_to_string(path)?)
    }

    /// Render the attack chain as ASCII art.
    pub fn render_chain(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("┌─ {} ─────────────\n", self.scenario.name));
        if let Some(desc) = &self.scenario.description {
            out.push_str(&format!("│  {desc}\n"));
        }
        if !self.scenario.mitre.is_empty() {
            out.push_str(&format!(
                "│  MITRE ATT&CK: {}\n",
                self.scenario.mitre.join(", ")
            ));
        }
        out.push_str("▼\n");
        for (i, stage) in self.stages.iter().enumerate() {
            let deps = if stage.depends_on.is_empty() {
                String::new()
            } else {
                format!("  (after {})", stage.depends_on.join(", "))
            };
            out.push_str(&format!(
                "  [{}/{}] {} → payload '{}'{}\n",
                i + 1,
                self.stages.len(),
                stage.label,
                stage.payload,
                deps
            ));
        }
        out.push_str("  ▼ end of chain\n");
        out
    }
}

/// Bundled scenarios embedded at compile time: (name, TOML).
pub const BUNDLED_SCENARIOS: &[(&str, &str)] = &[
    (
        "blacklotus-chain",
        include_str!("../../../scenarios/blacklotus-chain.toml"),
    ),
    (
        "smm-persistence-chain",
        include_str!("../../../scenarios/smm-persistence-chain.toml"),
    ),
    (
        "mobile-bootchain",
        include_str!("../../../scenarios/mobile-bootchain.toml"),
    ),
];

/// Parse all bundled scenarios.
pub fn bundled() -> Vec<(String, Scenario)> {
    BUNDLED_SCENARIOS
        .iter()
        .filter_map(|(name, toml)| Scenario::parse(toml).ok().map(|s| (name.to_string(), s)))
        .collect()
}

/// Run a scenario: generate every stage payload into `output_dir`, scan each
/// artifact, and validate the detection chain.
pub fn run_scenario(scenario: &Scenario, output_dir: &Path) -> Result<ScenarioRunReport> {
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("creating {}", output_dir.display()))?;

    let payloads = create_all_payloads();
    let payload_index: HashMap<&str, &dyn Payload> =
        payloads.iter().map(|p| (p.name(), p.as_ref())).collect();

    let mut scanner = BarzakhScanner::new(None);
    let mut stages = Vec::new();
    let mut all_detected = true;

    for stage in &scenario.stages {
        let payload = payload_index
            .get(stage.payload.as_str())
            .copied()
            .or_else(|| {
                // Fall back to a prefix match for robustness.
                payloads
                    .iter()
                    .find(|p| p.name().contains(stage.payload.as_str()))
                    .map(|p| p.as_ref())
            });
        let Some(payload) = payload else {
            bail!(
                "scenario stage '{}' references unknown payload '{}'",
                stage.label,
                stage.payload
            );
        };

        let config = PayloadConfig {
            arch: crate::Arch::X86_64,
            size: 0x10000,
        };
        let data = payload.generate(&config)?;
        let file = output_dir.join(format!("stage-{:02}-{}.bin", stages.len() + 1, stage.label));
        std::fs::write(&file, &data)?;

        let result = scanner.scan(&file, None);
        let mut detected_by: Vec<String> =
            result.findings.iter().map(|f| f.detector.clone()).collect();
        detected_by.sort();
        detected_by.dedup();
        let detected = !detected_by.is_empty();
        if !detected {
            all_detected = false;
        }

        stages.push(StageResult {
            label: stage.label.clone(),
            payload: stage.payload.clone(),
            generated_file: file,
            detected_by,
            risk_score: result.risk.score,
            detected,
        });
    }

    Ok(ScenarioRunReport {
        name: scenario.scenario.name.clone(),
        stages,
        chain_validated: all_detected,
        chain_rendering: scenario.render_chain(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[scenario]
name = "test-chain"
description = "two stage test"
architecture = "x86_64"
mitre = ["T1542.001"]

[[stages]]
payload = "trampoline"
label = "entry"

[[stages]]
payload = "boot_services_hook"
label = "hook"
depends_on = ["entry"]
"#;

    #[test]
    fn parses_and_validates_graph() {
        let scenario = Scenario::parse(SAMPLE).unwrap();
        assert_eq!(scenario.stages.len(), 2);
        assert_eq!(scenario.scenario.mitre, vec!["T1542.001"]);
        assert_eq!(scenario.stages[1].depends_on, vec!["entry"]);
    }

    #[test]
    fn rejects_unknown_dependency() {
        let bad = SAMPLE.replace("[\"entry\"]", "[\"nonexistent\"]");
        assert!(Scenario::parse(&bad).is_err());
    }

    #[test]
    fn rejects_cycles() {
        let cyclic = r#"
[scenario]
name = "cycle"

[[stages]]
payload = "a"
label = "one"
depends_on = ["two"]

[[stages]]
payload = "b"
label = "two"
depends_on = ["one"]
"#;
        assert!(Scenario::parse(cyclic).is_err());
    }

    #[test]
    fn rejects_duplicate_labels_and_empty() {
        let dup = SAMPLE.replace("label = \"hook\"", "label = \"entry\"");
        assert!(Scenario::parse(&dup).is_err());
        let empty = "[scenario]\nname = \"empty\"\n";
        assert!(Scenario::parse(empty).is_err());
    }

    #[test]
    fn renders_chain() {
        let scenario = Scenario::parse(SAMPLE).unwrap();
        let rendering = scenario.render_chain();
        assert!(rendering.contains("test-chain"));
        assert!(rendering.contains("[1/2] entry"));
        assert!(rendering.contains("(after entry)"));
    }

    #[test]
    fn bundled_scenarios_parse() {
        let bundled = bundled();
        assert!(bundled.len() >= 3, "expected at least 3 bundled scenarios");
        for (name, scenario) in &bundled {
            assert!(!scenario.stages.is_empty(), "scenario {name} has no stages");
        }
    }

    #[test]
    fn runs_two_stage_scenario() {
        let dir = std::env::temp_dir().join(format!(
            "barzakh-scenario-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let scenario = Scenario::parse(SAMPLE).unwrap();
        let report = run_scenario(&scenario, &dir).unwrap();
        assert_eq!(report.stages.len(), 2);
        assert!(
            report.stages.iter().all(|s| s.detected),
            "all stages must be detected"
        );
        assert!(report.chain_validated);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
