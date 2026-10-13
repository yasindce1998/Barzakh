use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct HpcCovertProfilePayload;

impl Payload for HpcCovertProfilePayload {
    fn name(&self) -> &str {
        "hpc_covert_profile"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, _config: &PayloadConfig) -> Result<Vec<u8>> {
        // Text profile; not zero-padded — the full string is the payload.
        let profile = concat!(
            "# barzakh-hpc-profile v1\n",
            "cpu_cycles=9812456231\n",
            "cache_miss_rate=0.97\n",
            "branch_mispredict_rate=0.85\n",
            "smi_count=1187\n",
            "dcache_evictions=4123378\n",
            "smi_timing_exfil=active\n",
            "cache_probe_loop=1\n",
        );
        Ok(profile.as_bytes().to_vec())
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "hpc_monitor".to_string(),
            min_severity: Severity::High,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn hpc_covert_profile_markers_present() {
        let payload = HpcCovertProfilePayload;
        let data = payload.generate(&PayloadConfig::default()).unwrap();
        assert!(contains(&data, b"# barzakh-hpc-profile v1\n"));
        assert!(contains(&data, b"smi_timing_exfil=active\n"));
        assert!(contains(&data, b"cache_probe_loop=1\n"));
        assert!(contains(&data, b"cache_miss_rate=0.97\n"));
    }
}
