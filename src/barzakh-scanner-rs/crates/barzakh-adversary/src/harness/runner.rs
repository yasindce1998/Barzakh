use std::path::PathBuf;
use std::time::Instant;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use barzakh_core::BarzakhScanner;

use crate::harness::gap::{GapEntry, GapReport};
use crate::harness::mutator::{mutate_payload, MutationStrategy};
use crate::payloads::create_all_payloads;
use crate::{Payload, PayloadConfig};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessConfig {
    pub iterations: u32,
    pub output_dir: PathBuf,
    pub mutate: bool,
    pub parallel: bool,
}

impl Default for HarnessConfig {
    fn default() -> Self {
        Self {
            iterations: 1,
            output_dir: PathBuf::from("./fuzz_corpus"),
            mutate: false,
            parallel: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResult {
    pub total_runs: usize,
    pub gap_report: GapReport,
    pub duration_secs: f64,
}

pub struct FuzzHarness {
    payloads: Vec<Box<dyn Payload>>,
    config: HarnessConfig,
}

impl FuzzHarness {
    pub fn new(config: HarnessConfig) -> Self {
        Self {
            payloads: create_all_payloads(),
            config,
        }
    }

    pub fn run(&self) -> Result<FuzzResult> {
        let start = Instant::now();
        std::fs::create_dir_all(&self.config.output_dir)?;

        let mut all_gaps: Vec<GapEntry> = Vec::new();
        let mut total_runs: usize = 0;

        // Base pass: generate each payload and scan it
        let base_gaps = self.run_base_pass()?;
        total_runs += self.payloads.len();
        all_gaps.extend(base_gaps);

        // Mutation passes
        if self.config.mutate {
            for iteration in 0..self.config.iterations {
                let mutation_gaps = self.run_mutation_pass(iteration)?;
                total_runs += self.payloads.len() * MutationStrategy::all().len();
                all_gaps.extend(mutation_gaps);
            }
        }

        all_gaps.sort_by(|a, b| a.payload_name.cmp(&b.payload_name));
        all_gaps.dedup_by(|a, b| {
            a.payload_name == b.payload_name && a.mutation_variant == b.mutation_variant
        });

        let gap_report = GapReport::from_entries(all_gaps, self.payloads.len());

        Ok(FuzzResult {
            total_runs,
            gap_report,
            duration_secs: start.elapsed().as_secs_f64(),
        })
    }

    fn run_base_pass(&self) -> Result<Vec<GapEntry>> {
        let mut gaps = Vec::new();

        for payload in &self.payloads {
            let config = PayloadConfig {
                arch: payload.arch(),
                size: 0x10000,
                dormant: false,
            };

            let data = payload.generate(&config)?;
            let file_path = self
                .config
                .output_dir
                .join(format!("fuzz_{}.bin", payload.name()));
            std::fs::write(&file_path, &data)?;

            let gap = self.check_detection(payload.as_ref(), &file_path, None)?;
            if let Some(entry) = gap {
                gaps.push(entry);
            }
        }

        Ok(gaps)
    }

    fn run_mutation_pass(&self, _iteration: u32) -> Result<Vec<GapEntry>> {
        let mut gaps = Vec::new();

        for payload in &self.payloads {
            let config = PayloadConfig {
                arch: payload.arch(),
                size: 0x10000,
                dormant: false,
            };

            let base_data = payload.generate(&config)?;

            for strategy in MutationStrategy::all() {
                let mutated = mutate_payload(&base_data, *strategy);
                let file_path = self.config.output_dir.join(format!(
                    "fuzz_{}_{}.bin",
                    payload.name(),
                    strategy.name()
                ));
                std::fs::write(&file_path, &mutated)?;

                let gap = self.check_detection(
                    payload.as_ref(),
                    &file_path,
                    Some(strategy.name().to_string()),
                )?;
                if let Some(entry) = gap {
                    gaps.push(entry);
                }
            }
        }

        Ok(gaps)
    }

    fn check_detection(
        &self,
        payload: &dyn Payload,
        file_path: &std::path::Path,
        mutation_variant: Option<String>,
    ) -> Result<Option<GapEntry>> {
        let mut scanner = BarzakhScanner::new(None);
        let result = scanner.scan(file_path, None);
        anyhow::ensure!(
            !result
                .detector_runs
                .iter()
                .any(|r| r.status == barzakh_core::DetectorStatus::Error),
            "detector execution failed while fuzzing {}: {:?}",
            file_path.display(),
            result.detector_runs
        );

        let expected = payload.expected_detections();
        let mut missed = Vec::new();

        for exp in &expected {
            let found = result
                .findings
                .iter()
                .any(|f| f.detector == exp.detector && f.severity >= exp.min_severity);
            if !found {
                missed.push(exp.detector.clone());
            }
        }

        if missed.is_empty() {
            Ok(None)
        } else {
            Ok(Some(GapEntry {
                payload_name: payload.name().to_string(),
                expected_detectors: expected.iter().map(|e| e.detector.clone()).collect(),
                missed_detectors: missed,
                mutation_variant,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn harness_runs_without_error() {
        let tmp = TempDir::new().unwrap();
        let config = HarnessConfig {
            iterations: 0,
            output_dir: tmp.path().to_path_buf(),
            mutate: false,
            parallel: false,
        };
        let harness = FuzzHarness::new(config);
        let result = harness.run().unwrap();
        assert!(result.total_runs > 0);
    }
}
