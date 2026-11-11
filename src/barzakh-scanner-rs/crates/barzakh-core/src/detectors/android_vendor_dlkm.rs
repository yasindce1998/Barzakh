use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const EROFS_MAGIC: [u8; 4] = [0xE0, 0xF5, 0xE1, 0xE2];
const ELF_MAGIC: [u8; 4] = [0x7F, 0x45, 0x4C, 0x46];
const INIT_MODULE_PATTERN: &[u8] = b"init_module";
const VERITY_MAGIC: &[u8] = b"verity\x00\x00";
const KO_VERMAGIC: &[u8] = b"vermagic=";

pub struct AndroidVendorDlkmDetector;

impl Default for AndroidVendorDlkmDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AndroidVendorDlkmDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_unsigned_module_injection(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let has_erofs = data.windows(EROFS_MAGIC.len()).any(|w| w == EROFS_MAGIC);

        if !has_erofs {
            return findings;
        }

        let mut elf_positions = Vec::new();
        for (i, w) in data.windows(ELF_MAGIC.len()).enumerate() {
            if w == ELF_MAGIC {
                elf_positions.push(i);
            }
            if elf_positions.len() >= 10 {
                break;
            }
        }

        for &elf_pos in &elf_positions {
            let module_end = (elf_pos + 4096).min(data.len());
            let module_region = &data[elf_pos..module_end];

            let has_init_module = module_region
                .windows(INIT_MODULE_PATTERN.len())
                .any(|w| w == INIT_MODULE_PATTERN);

            let has_module_sig = module_region
                .windows(24)
                .any(|w| w == b"~Module signature appended");

            if has_init_module && !has_module_sig {
                findings.push(
                    Finding::new(
                        "android_vendor_dlkm",
                        Severity::Critical,
                        "Unsigned kernel module detected in vendor_dlkm EROFS partition",
                        &format!(
                            "Found ELF kernel module (.ko) at offset 0x{:08X} within an EROFS \
                             vendor_dlkm image that lacks the standard module signature trailer. \
                             GKI requires all vendor modules to be signed. An unsigned module \
                             in vendor_dlkm indicates injection of unauthorized kernel code.",
                            elf_pos
                        ),
                    )
                    .with_confidence(0.91)
                    .with_details(serde_json::json!({
                        "elf_offset": format!("0x{:08X}", elf_pos),
                        "has_init_module": true,
                        "has_signature": false,
                        "technique": "vendor_dlkm unsigned kernel module injection",
                    }))
                    .with_recommendation(
                        "Remove unsigned module; reflash vendor_dlkm from factory image",
                    ),
                );
                break;
            }
        }

        findings
    }

    fn check_verity_metadata_bypass(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let has_erofs = data.windows(EROFS_MAGIC.len()).any(|w| w == EROFS_MAGIC);

        if !has_erofs {
            return findings;
        }

        if let Some(pos) = data
            .windows(VERITY_MAGIC.len())
            .position(|w| w == VERITY_MAGIC)
        {
            let region_end = (pos + 128).min(data.len());
            let region = &data[pos..region_end];

            let has_disabled_flag = region.contains(&0x02);
            let has_zero_salt = region.len() >= 64 && region[32..64].iter().all(|&b| b == 0x00);

            if has_disabled_flag || has_zero_salt {
                findings.push(
                    Finding::new(
                        "android_vendor_dlkm",
                        Severity::Critical,
                        "vendor_dlkm dm-verity metadata with disabled flag or zeroed salt",
                        &format!(
                            "Found dm-verity metadata at offset 0x{:08X} in vendor_dlkm with {}. \
                             This allows modification of the vendor_dlkm filesystem contents \
                             without detection by the verity integrity layer.",
                            pos,
                            if has_disabled_flag && has_zero_salt {
                                "disabled verification flag and zeroed salt"
                            } else if has_disabled_flag {
                                "disabled verification flag"
                            } else {
                                "zeroed salt (allows hash table precomputation)"
                            }
                        ),
                    )
                    .with_confidence(0.89)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", pos),
                        "verity_disabled": has_disabled_flag,
                        "zeroed_salt": has_zero_salt,
                        "technique": "dm-verity bypass for vendor_dlkm modification",
                    }))
                    .with_recommendation(
                        "Re-enable dm-verity; reflash vendor_dlkm with correct verity hash tree",
                    ),
                );
            }
        }

        findings
    }

    fn check_vermagic_mismatch(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(KO_VERMAGIC.len())
            .position(|w| w == KO_VERMAGIC)
        {
            let region_end = (pos + 128).min(data.len());
            let region = &data[pos..region_end];

            let _has_preempt_mismatch = region.windows(6).any(|w| w == b"SMP pr");
            let has_debug_kernel = region.windows(5).any(|w| w == b"debug");

            if has_debug_kernel {
                findings.push(
                    Finding::new(
                        "android_vendor_dlkm",
                        Severity::High,
                        "Kernel module with debug vermagic in vendor_dlkm",
                        &format!(
                            "Found kernel module vermagic at offset 0x{:08X} containing 'debug' \
                             flag. Production GKI kernels do not include debug in vermagic. \
                             A debug-flagged module may have been compiled against a custom \
                             kernel with security checks disabled.",
                            pos
                        ),
                    )
                    .with_confidence(0.78)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", pos),
                        "debug_vermagic": true,
                        "technique": "Kernel module vermagic analysis for non-GKI detection",
                    }))
                    .with_recommendation(
                        "Verify module was compiled against official GKI kernel headers",
                    ),
                );
            }
        }

        findings
    }
}

impl Detector for AndroidVendorDlkmDetector {
    fn name(&self) -> &str {
        "android_vendor_dlkm"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }

    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_unsigned_module_injection(&data));
        findings.extend(self.check_verity_metadata_bypass(&data));
        findings.extend(self.check_vermagic_mismatch(&data));

        Ok(findings)
    }
}
