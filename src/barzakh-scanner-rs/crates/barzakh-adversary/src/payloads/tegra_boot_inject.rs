use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct TegraBootInjectPayload;

impl Payload for TegraBootInjectPayload {
    fn name(&self) -> &str {
        "tegra_boot_inject"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x800);
        let mut data = vec![0u8; size];

        // NVIDIA Tegra Jetson platform marker
        let platform = b"NVIDIA Tegra Jetson Xavier boot firmware";
        let end = platform.len().min(size);
        data[0..end].copy_from_slice(&platform[..end]);

        // BPMP hook and public key hash override
        let bpmp_off = 0x80;
        let bpmp_str = b"bpmp_dmce_hook=enabled\noverride_pk_hash=0xDEADBEEF\n";
        let end = (bpmp_off + bpmp_str.len()).min(size);
        data[bpmp_off..end].copy_from_slice(&bpmp_str[..end - bpmp_off]);

        // Security engine flash skip and JTAG pinmux force
        let se_off = 0x140;
        let se_str = b"skip_se_flash=true\npinmux_jtag_force=1\n";
        let end = (se_off + se_str.len()).min(size);
        data[se_off..end].copy_from_slice(&se_str[..end - se_off]);

        // NSP firmware patch flag
        let nsp_off = 0x1C0;
        let nsp_str = b"nsp_fw_patch=1\n";
        let end = (nsp_off + nsp_str.len()).min(size);
        data[nsp_off..end].copy_from_slice(&nsp_str[..end - nsp_off]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "nvidia_tegra".to_string(),
            min_severity: Severity::Critical,
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
    fn tegra_boot_inject_markers_present() {
        let payload = TegraBootInjectPayload;
        let data = payload.generate(&PayloadConfig::default()).unwrap();
        assert!(contains(&data, b"NVIDIA Tegra Jetson Xavier boot firmware"));
        assert!(contains(&data, b"bpmp_dmce_hook=enabled\n"));
        assert!(contains(&data, b"override_pk_hash=0xDEADBEEF\n"));
        assert!(contains(&data, b"skip_se_flash=true\n"));
        assert!(contains(&data, b"pinmux_jtag_force=1\n"));
        assert!(contains(&data, b"nsp_fw_patch=1\n"));
    }
}
