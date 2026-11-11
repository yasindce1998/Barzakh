use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const PVMFW_MAGIC: &[u8] = b"pvmf";
const PKVM_HYP_MAGIC: &[u8] = b"PKVM";
const AVF_INSTANCE_MAGIC: &[u8] = b"AVFi";
const EL2_VBAR_PATTERN: [u8; 4] = [0x00, 0x04, 0x00, 0xD4];

pub struct AndroidPkvmDetector;

impl Default for AndroidPkvmDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AndroidPkvmDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_pvmfw_tampering(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(PVMFW_MAGIC.len())
            .position(|w| w == PVMFW_MAGIC)
        {
            let region_end = (pos + 512).min(data.len());
            let region = &data[pos..region_end];

            let has_zero_signature =
                region.len() >= 64 && region[32..64].iter().all(|&b| b == 0x00);

            if has_zero_signature {
                findings.push(
                    Finding::new(
                        "android_pkvm",
                        Severity::Critical,
                        "pvmfw image with zeroed signature field detected",
                        &format!(
                            "Found pvmfw (protected VM firmware) magic at offset 0x{:08X} with \
                             signature field completely zeroed. This indicates a tampered pvmfw \
                             image that bypasses pKVM signature verification, allowing arbitrary \
                             code execution at EL2 within the Android Virtualization Framework.",
                            pos
                        ),
                    )
                    .with_confidence(0.93)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", pos),
                        "signature_zeroed": true,
                        "technique": "pvmfw signature bypass for pKVM hypervisor escape",
                    }))
                    .with_recommendation(
                        "Verify pvmfw image signature against Google-signed root of trust; reflash factory image",
                    ),
                );
            }
        }

        findings
    }

    fn check_pkvm_hypervisor_patch(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(PKVM_HYP_MAGIC.len())
            .position(|w| w == PKVM_HYP_MAGIC)
        {
            let region_end = (pos + 1024).min(data.len());
            let region = &data[pos..region_end];

            let has_el2_vector_mod = region
                .windows(EL2_VBAR_PATTERN.len())
                .any(|w| w == EL2_VBAR_PATTERN);

            let has_hvc_patch = region.windows(4).any(|w| w == [0x02, 0x00, 0x00, 0xD4]);

            if has_el2_vector_mod && has_hvc_patch {
                findings.push(
                    Finding::new(
                        "android_pkvm",
                        Severity::Critical,
                        "pKVM hypervisor image with modified EL2 vector table and HVC handler",
                        &format!(
                            "Found pKVM hypervisor header at offset 0x{:08X} containing both a \
                             modified EL2 exception vector table entry and patched HVC instruction. \
                             This is indicative of a hypervisor escape payload that intercepts \
                             hypercalls to gain EL2 execution privilege.",
                            pos
                        ),
                    )
                    .with_confidence(0.90)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", pos),
                        "el2_vector_modified": true,
                        "hvc_handler_patched": true,
                        "technique": "pKVM EL2 vector table hijack for hypervisor escape",
                    }))
                    .with_recommendation(
                        "Reinstall factory pKVM image; verify EL2 vector table integrity against known-good hash",
                    ),
                );
            }
        }

        findings
    }

    fn check_avf_instance_forgery(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(AVF_INSTANCE_MAGIC.len())
            .position(|w| w == AVF_INSTANCE_MAGIC)
        {
            let region_end = (pos + 256).min(data.len());
            let region = &data[pos..region_end];

            let has_debug_policy = region.windows(5).any(|w| w == b"debug");
            let has_all_perms = region.windows(4).any(|w| w == [0xFF, 0xFF, 0xFF, 0xFF]);

            if has_debug_policy || has_all_perms {
                findings.push(
                    Finding::new(
                        "android_pkvm",
                        Severity::High,
                        "AVF instance.img with debug policy or elevated permissions",
                        &format!(
                            "Found AVF instance image magic at offset 0x{:08X} with {} enabled. \
                             This allows a protected VM to run with relaxed security constraints, \
                             potentially exposing host secrets to guest VMs.",
                            pos,
                            if has_debug_policy && has_all_perms {
                                "debug policy and max permissions"
                            } else if has_debug_policy {
                                "debug policy"
                            } else {
                                "elevated permissions (0xFFFFFFFF)"
                            }
                        ),
                    )
                    .with_confidence(0.85)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", pos),
                        "debug_policy_present": has_debug_policy,
                        "max_permissions": has_all_perms,
                        "technique": "AVF instance image policy manipulation",
                    }))
                    .with_recommendation(
                        "Regenerate instance.img without debug flags; enforce production pVM policies",
                    ),
                );
            }
        }

        findings
    }
}

impl Detector for AndroidPkvmDetector {
    fn name(&self) -> &str {
        "android_pkvm"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }

    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_pvmfw_tampering(&data));
        findings.extend(self.check_pkvm_hypervisor_patch(&data));
        findings.extend(self.check_avf_instance_forgery(&data));

        Ok(findings)
    }
}
