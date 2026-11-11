use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const BOOTCONFIG_MAGIC: &[u8] = b"#BOOTCONFIG\n";
const DANGEROUS_INIT_PARAM: &[u8] = b"androidboot.init=";
const VERIFIED_STATE_PARAM: &[u8] = b"androidboot.verifiedbootstate=";
const SELINUX_PARAM: &[u8] = b"androidboot.selinux=";

pub struct AndroidBootconfigDetector;

impl Default for AndroidBootconfigDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AndroidBootconfigDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_malicious_init_override(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(BOOTCONFIG_MAGIC.len())
            .position(|w| w == BOOTCONFIG_MAGIC)
        {
            let config_end = (pos + 4096).min(data.len());
            let config_region = &data[pos..config_end];

            let has_init_override = config_region
                .windows(DANGEROUS_INIT_PARAM.len())
                .any(|w| w == DANGEROUS_INIT_PARAM);

            if has_init_override {
                findings.push(
                    Finding::new(
                        "android_bootconfig",
                        Severity::Critical,
                        "Bootconfig contains androidboot.init= parameter override",
                        &format!(
                            "Found bootconfig section at offset 0x{:08X} containing an \
                             androidboot.init= parameter. This overrides the default init \
                             binary path, allowing an attacker to execute arbitrary code as \
                             PID 1 (root) at the earliest stage of Android userspace boot.",
                            pos
                        ),
                    )
                    .with_confidence(0.95)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", pos),
                        "parameter": "androidboot.init=",
                        "technique": "Bootconfig init override for arbitrary root execution",
                    }))
                    .with_recommendation(
                        "Remove malicious bootconfig entries; verify boot image integrity",
                    ),
                );
            }
        }

        findings
    }

    fn check_verified_boot_state_spoof(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(BOOTCONFIG_MAGIC.len())
            .position(|w| w == BOOTCONFIG_MAGIC)
        {
            let config_end = (pos + 4096).min(data.len());
            let config_region = &data[pos..config_end];

            let has_vb_state = config_region
                .windows(VERIFIED_STATE_PARAM.len())
                .any(|w| w == VERIFIED_STATE_PARAM);

            let has_selinux_disable = config_region
                .windows(SELINUX_PARAM.len())
                .position(|w| w == SELINUX_PARAM)
                .and_then(|p| {
                    let after = p + SELINUX_PARAM.len();
                    config_region
                        .get(after..after + 10)
                        .map(|s| s.windows(7).any(|w| w == b"permiss"))
                })
                .unwrap_or(false);

            if has_vb_state || has_selinux_disable {
                findings.push(
                    Finding::new(
                        "android_bootconfig",
                        Severity::Critical,
                        "Bootconfig spoofs verified boot state or disables SELinux enforcement",
                        &format!(
                            "Found bootconfig at offset 0x{:08X} containing {}. \
                             These parameters influence how Android reports its security posture \
                             to apps and attestation services.",
                            pos,
                            if has_vb_state && has_selinux_disable {
                                "verifiedbootstate override and SELinux=permissive"
                            } else if has_vb_state {
                                "verifiedbootstate override"
                            } else {
                                "SELinux=permissive"
                            }
                        ),
                    )
                    .with_confidence(0.92)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", pos),
                        "verified_boot_state_spoofed": has_vb_state,
                        "selinux_permissive": has_selinux_disable,
                        "technique": "Bootconfig security parameter spoofing",
                    }))
                    .with_recommendation(
                        "Remove spoofed parameters; bootconfig should not override security state",
                    ),
                );
            }
        }

        findings
    }

    fn check_oversized_bootconfig(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(BOOTCONFIG_MAGIC.len())
            .position(|w| w == BOOTCONFIG_MAGIC)
        {
            let size_offset = pos.saturating_sub(8);
            if data.len() > size_offset + 4 && pos >= 8 {
                let config_size = u32::from_le_bytes([
                    data[size_offset],
                    data[size_offset + 1],
                    data[size_offset + 2],
                    data[size_offset + 3],
                ]);

                if config_size > 0x10000 {
                    findings.push(
                        Finding::new(
                            "android_bootconfig",
                            Severity::High,
                            "Bootconfig section exceeds expected size boundary",
                            &format!(
                                "Found bootconfig trailer at offset 0x{:08X} with declared size \
                                 0x{:X} ({} KB) which exceeds the typical 64KB boundary. An \
                                 oversized bootconfig may contain injected parameters beyond \
                                 what the device manufacturer intended.",
                                pos,
                                config_size,
                                config_size / 1024
                            ),
                        )
                        .with_confidence(0.78)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", pos),
                            "config_size": config_size,
                            "size_kb": config_size / 1024,
                            "technique": "Bootconfig size inflation for parameter injection",
                        }))
                        .with_recommendation(
                            "Audit all bootconfig parameters; compare size against factory image",
                        ),
                    );
                }
            }
        }

        findings
    }
}

impl Detector for AndroidBootconfigDetector {
    fn name(&self) -> &str {
        "android_bootconfig"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }

    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_malicious_init_override(&data));
        findings.extend(self.check_verified_boot_state_spoof(&data));
        findings.extend(self.check_oversized_bootconfig(&data));

        Ok(findings)
    }
}
