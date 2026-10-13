use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct RiscVDmiUnlockPayload;

impl Payload for RiscVDmiUnlockPayload {
    fn name(&self) -> &str {
        "riscv_dmi_unlock"
    }

    fn arch(&self) -> Arch {
        Arch::RiscV64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x800);
        let mut data = vec![0u8; size];

        // RISC-V Debug Module platform marker
        let platform = b"RISC-V DebugModule dmi dtm";
        let end = platform.len().min(size);
        data[0..end].copy_from_slice(&platform[..end]);

        // DMI unlock and hart debug enable
        let unlock_off = 0x80;
        let unlock_str = b"dmi_unlock=hart0\nhart_debug_enable=all\n";
        let end = (unlock_off + unlock_str.len()).min(size);
        data[unlock_off..end].copy_from_slice(&unlock_str[..end - unlock_off]);

        // Abstract command injection
        let inject_off = 0xE0;
        let inject_str = b"abstract_cmd_inject=cmdexec\n";
        let end = (inject_off + inject_str.len()).min(size);
        data[inject_off..end].copy_from_slice(&inject_str[..end - inject_off]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "riscv_debug".to_string(),
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
    fn riscv_dmi_unlock_markers_present() {
        let payload = RiscVDmiUnlockPayload;
        let data = payload.generate(&PayloadConfig::default()).unwrap();
        assert!(contains(&data, b"RISC-V DebugModule dmi dtm"));
        assert!(contains(&data, b"dmi_unlock=hart0\n"));
        assert!(contains(&data, b"hart_debug_enable=all\n"));
        assert!(contains(&data, b"abstract_cmd_inject=cmdexec\n"));
    }
}
