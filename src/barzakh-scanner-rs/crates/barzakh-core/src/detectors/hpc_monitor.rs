use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const PROFILE_HEADER: &[u8] = b"# barzakh-hpc-profile v1";

const EXFIL_MARKERS: &[&[u8]] = &[b"smi_timing_exfil", b"cache_probe_loop"];

#[derive(Default)]
struct HpcProfile {
    cache_miss_rate: Option<f64>,
    branch_mispredict_rate: Option<f64>,
    smi_count: Option<f64>,
    dcache_evictions: Option<f64>,
}

pub struct HpcMonitorDetector;

impl Default for HpcMonitorDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl HpcMonitorDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn parse_profile(data: &[u8]) -> HpcProfile {
        let text = String::from_utf8_lossy(data);
        let mut profile = HpcProfile::default();
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let Ok(parsed) = value.trim().parse::<f64>() else {
                continue;
            };
            match key.trim() {
                "cache_miss_rate" => profile.cache_miss_rate = Some(parsed),
                "branch_mispredict_rate" => profile.branch_mispredict_rate = Some(parsed),
                "smi_count" => profile.smi_count = Some(parsed),
                "dcache_evictions" => profile.dcache_evictions = Some(parsed),
                _ => {}
            }
        }
        profile
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !Self::contains(data, PROFILE_HEADER) {
            return findings;
        }

        let profile = Self::parse_profile(data);
        let Some(cache_miss_rate) = profile.cache_miss_rate else {
            return findings;
        };
        let Some(branch_mispredict_rate) = profile.branch_mispredict_rate else {
            return findings;
        };

        if cache_miss_rate >= 0.5 && branch_mispredict_rate >= 0.4 {
            let exfil_hits: Vec<String> = EXFIL_MARKERS
                .iter()
                .filter(|m| Self::contains(data, m))
                .map(|m| String::from_utf8_lossy(m).into_owned())
                .collect();

            findings.push(
                Finding::new(
                    "hpc_monitor",
                    Severity::High,
                    "HPC covert-channel pattern",
                    &format!(
                        "Hardware performance counter profile shows anomalous behavior: \
                         cache_miss_rate={cache_miss_rate}, \
                         branch_mispredict_rate={branch_mispredict_rate}. Sustained high \
                         cache-miss and branch-mispredict rates are consistent with \
                         cache-timing covert channels such as Flush+Reload or Prime+Probe.",
                    ),
                )
                .with_confidence(0.8)
                .with_details(serde_json::json!({
                    "cache_miss_rate": cache_miss_rate,
                    "branch_mispredict_rate": branch_mispredict_rate,
                    "smi_count": profile.smi_count,
                    "dcache_evictions": profile.dcache_evictions,
                }))
                .with_recommendation(
                    "Profile the same workload on a known-clean reference system; \
                     correlate the anomalous windows with scheduled tasks; enable \
                     performance-counter monitoring to identify the responsible process.",
                ),
            );

            if !exfil_hits.is_empty() {
                findings.push(
                    Finding::new(
                        "hpc_monitor",
                        Severity::Critical,
                        "Active cache-probe exfiltration loop",
                        &format!(
                            "Hardware performance counter profile contains an active \
                             exfiltration loop indicator(s): {}. Combined with anomalous \
                             cache-miss and branch-mispredict rates, this indicates \
                             malware is actively using cache-probing or SMI-timing \
                             channels to exfiltrate data.",
                            exfil_hits.join(", "),
                        ),
                    )
                    .with_confidence(0.9)
                    .with_details(serde_json::json!({
                        "indicators": exfil_hits,
                        "cache_miss_rate": cache_miss_rate,
                        "branch_mispredict_rate": branch_mispredict_rate,
                        "smi_count": profile.smi_count,
                        "dcache_evictions": profile.dcache_evictions,
                    }))
                    .with_recommendation(
                        "Isolate the system immediately; capture memory for forensic \
                         analysis; identify and terminate the process driving the \
                         cache-probe loop; assume data has been exfiltrated.",
                    ),
                );
            }
        }

        findings
    }
}

impl Detector for HpcMonitorDetector {
    fn name(&self) -> &str {
        "hpc_monitor"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        Ok(self.scan(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fires_on_anomalous_rates() {
        let v = b"# barzakh-hpc-profile v1\ncache_miss_rate=0.8\nbranch_mispredict_rate=0.6\nsmi_count=4\ndcache_evictions=1200\n".to_vec();
        let findings = HpcMonitorDetector::new().scan(&v);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::High && f.title == "HPC covert-channel pattern"));
        assert!(!findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn fires_on_active_exfil_loop() {
        let mut v =
            b"# barzakh-hpc-profile v1\ncache_miss_rate=0.9\nbranch_mispredict_rate=0.5\n".to_vec();
        v.extend_from_slice(b"cache_probe_loop=1\n");
        let findings = HpcMonitorDetector::new().scan(&v);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical
            && f.title == "Active cache-probe exfiltration loop"));
    }

    #[test]
    fn quiet_on_normal_profile() {
        let v = b"# barzakh-hpc-profile v1\ncache_miss_rate=0.05\nbranch_mispredict_rate=0.02\nsmi_count=1\ndcache_evictions=40\n".to_vec();
        assert!(HpcMonitorDetector::new().scan(&v).is_empty());
    }

    #[test]
    fn quiet_without_profile_header() {
        let v = b"cache_miss_rate=0.9\nbranch_mispredict_rate=0.6\ncache_probe_loop=1\n".to_vec();
        assert!(HpcMonitorDetector::new().scan(&v).is_empty());
    }
}
