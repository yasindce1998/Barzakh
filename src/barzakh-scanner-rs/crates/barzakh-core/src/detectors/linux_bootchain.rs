use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const GRUB_VERIFIERS_PATTERN: &[u8] = b"grub_verifiers_open";
const VMLINUZ_MAGIC: &[u8] = b"vmlinuz";
const SHIM_LOCK_GUID: &[u8] = b"\x67\x2b\x1e\x30\x99\xcd\x5e\x9e";

pub struct LinuxBootchainDetector;

impl Default for LinuxBootchainDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxBootchainDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_grub_integrity(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for i in 0..data.len().saturating_sub(GRUB_VERIFIERS_PATTERN.len() + 32) {
            if data[i..].starts_with(GRUB_VERIFIERS_PATTERN) {
                let region_start = i.saturating_sub(64);
                let region_end = (i + GRUB_VERIFIERS_PATTERN.len() + 64).min(data.len());
                let region = &data[region_start..region_end];

                let nop_count = region.iter().filter(|&&b| b == 0x90).count();
                if nop_count >= 8 {
                    findings.push(
                        Finding::new(
                            "linux_bootchain",
                            Severity::Critical,
                            "Bootkitty: GRUB signature verification patched with NOP sled",
                            &format!(
                                "Found grub_verifiers_open at offset 0x{:08X} with {} NOP (0x90) bytes \
                                 in surrounding code. Indicates Bootkitty-style patch to disable \
                                 GRUB module signature verification.",
                                i, nop_count
                            ),
                        )
                        .with_confidence(0.92)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", i),
                            "nop_count": nop_count,
                            "technique": "Bootkitty (Nov 2024)",
                            "cve": "N/A - first Linux UEFI bootkit in the wild",
                        }))
                        .with_recommendation(
                            "Re-install GRUB from trusted source and verify shim signature chain",
                        ),
                    );
                }

                let ret_nop_pattern: &[u8] = &[0xC3, 0x90, 0x90, 0x90];
                if region.windows(4).any(|w| w == ret_nop_pattern) {
                    findings.push(
                        Finding::new(
                            "linux_bootchain",
                            Severity::Critical,
                            "Bootkitty: GRUB verifier function replaced with RET",
                            &format!(
                                "grub_verifiers_open at 0x{:08X} has been patched with RET+NOP \
                                 pattern, completely bypassing signature verification.",
                                i
                            ),
                        )
                        .with_confidence(0.95)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", i),
                            "pattern": "C3 90 90 90 (RET + NOP padding)",
                        })),
                    );
                }
            }
        }

        findings
    }

    fn check_kernel_integrity(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for i in 0..data.len().saturating_sub(VMLINUZ_MAGIC.len() + 128) {
            if data[i..].starts_with(VMLINUZ_MAGIC) {
                let post_region_end = (i + 256).min(data.len());
                let post_region = &data[i..post_region_end];

                let module_sig_pattern = b"module.sig_enforce";
                if let Some(sig_pos) = post_region
                    .windows(module_sig_pattern.len())
                    .position(|w| w == module_sig_pattern)
                {
                    let after_sig = i + sig_pos + module_sig_pattern.len();
                    if after_sig + 4 < data.len() {
                        let disable_markers = [0x00u8, 0x90, 0xC3];
                        if disable_markers.contains(&data[after_sig]) {
                            findings.push(
                                Finding::new(
                                    "linux_bootchain",
                                    Severity::High,
                                    "Linux kernel module signature enforcement disabled",
                                    &format!(
                                        "Found module.sig_enforce at offset 0x{:08X} with \
                                         disable marker (0x{:02X}) immediately following. \
                                         Indicates kernel integrity bypass.",
                                        i + sig_pos,
                                        data[after_sig]
                                    ),
                                )
                                .with_confidence(0.80)
                                .with_details(serde_json::json!({
                                    "offset": format!("0x{:08X}", i + sig_pos),
                                    "disable_byte": format!("0x{:02X}", data[after_sig]),
                                })),
                            );
                        }
                    }
                }
            }
        }

        findings
    }

    fn check_shim_bypass(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(SHIM_LOCK_GUID.len())
            .position(|w| w == SHIM_LOCK_GUID)
        {
            let region_end = (pos + 128).min(data.len());
            let region = &data[pos..region_end];

            let zero_runs = region
                .windows(16)
                .filter(|w| w.iter().all(|&b| b == 0))
                .count();
            if zero_runs > 4 {
                findings.push(
                    Finding::new(
                        "linux_bootchain",
                        Severity::High,
                        "Shim lock protocol GUID with zeroed verification data",
                        &format!(
                            "Shim lock GUID at offset 0x{:08X} followed by excessive zero runs, \
                             suggesting shim verification tables have been nulled out.",
                            pos
                        ),
                    )
                    .with_confidence(0.75)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", pos),
                        "zero_runs": zero_runs,
                    })),
                );
            }
        }

        findings
    }
}

impl Detector for LinuxBootchainDetector {
    fn name(&self) -> &str {
        "linux_bootchain"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_grub_integrity(&data));
        findings.extend(self.check_kernel_integrity(&data));
        findings.extend(self.check_shim_bypass(&data));

        Ok(findings)
    }
}
